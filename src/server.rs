use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use dirs::home_dir;
use env_logger::Builder;
use futures::future::try_join;
use futures::{StreamExt, TryFutureExt};
use log::LevelFilter;
use log::{error, info};
use structopt::{self, StructOpt};
use tokio::net::TcpStream;
use tokio::prelude::*;

use qtun::args;

#[derive(StructOpt, Debug)]
#[structopt(name = "qtun-server")]
struct Opt {
    /// TLS private key in PEM format
    #[structopt(
        parse(from_os_str),
        short = "k",
        long = "key",
        requires = "cert",
        default_value = "key.der"
    )]
    key: PathBuf,
    /// TLS certificate in PEM format
    #[structopt(
        parse(from_os_str),
        short = "c",
        long = "cert",
        requires = "key",
        default_value = "cert.der"
    )]
    cert: PathBuf,
    /// Enable stateless retries
    #[structopt(long = "stateless-retry")]
    stateless_retry: bool,
    /// Address to listen on
    #[structopt(long = "listen", default_value = "0.0.0.0:4433")]
    listen: SocketAddr,
    /// Address to listen on
    #[structopt(long = "relay", default_value = "127.0.0.1:8138")]
    relay: SocketAddr,
    /// Specify the host to load TLS certificates from ~/.acme.sh/host
    #[structopt(long = "acme-host")]
    acme_host: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut log_builder = Builder::new();
    log_builder.filter(None, LevelFilter::Info).default_format();
    log_builder.filter(Some("qtun-server"), LevelFilter::Debug);
    log_builder.init();

    let options = Opt::from_args();

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.stream_window_uni(0);
    let mut server_config = quinn::ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);

    if options.stateless_retry {
        server_config.use_stateless_retry(true);
    }

    // init all parameters
    let mut cert_path = options.cert;
    let mut key_path = options.key;
    let mut acme_host = options.acme_host;
    let mut listen_addr = options.listen;
    let mut relay_addr = options.relay;

    // parse environment variables
    if let Ok((ss_local_addr, ss_remote_addr, ss_plugin_opts)) = args::parse_env() {
        relay_addr = ss_local_addr;
        listen_addr = ss_remote_addr;

        if let Some(cert) = ss_plugin_opts.get("cert") {
            cert_path = PathBuf::from(cert);
        }
        if let Some(key) = ss_plugin_opts.get("key") {
            key_path = PathBuf::from(key);
        }
        if let Some(host) = ss_plugin_opts.get("acme_host") {
            acme_host = Some(host.clone());
        }
    }

    if let Some(host) = acme_host {
        key_path = PathBuf::new();
        key_path.push(home_dir().unwrap_or_else(|| PathBuf::from("~")));
        key_path.push(format!(".acme.sh/{a}/{a}.key", a = host));

        cert_path = PathBuf::new();
        cert_path.push(home_dir().unwrap_or_else(|| PathBuf::from("~")));
        cert_path.push(format!(".acme.sh/{}/fullchain.cer", host));
    }

    info!("loading cert: {:?}", cert_path);
    info!("loading key: {:?}", key_path);

    // load certificates
    let key = fs::read(&key_path).context("failed to read private key")?;
    let key = if key_path.extension().map_or(false, |x| x == "der") {
        quinn::PrivateKey::from_der(&key)?
    } else {
        quinn::PrivateKey::from_pem(&key)?
    };
    let cert_chain = fs::read(&cert_path).context("failed to read certificate chain")?;
    let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
        quinn::CertificateChain::from_certs(quinn::Certificate::from_der(&cert_chain))
    } else {
        quinn::CertificateChain::from_pem(&cert_chain)?
    };
    server_config.certificate(cert_chain, key)?;

    let mut endpoint = quinn::Endpoint::builder();
    endpoint.listen(server_config.build());

    let remote = Arc::<SocketAddr>::from(relay_addr);

    let mut incoming = {
        let (endpoint, incoming) = endpoint.bind(&listen_addr)?;
        info!("listening on {}", endpoint.local_addr()?);
        incoming
    };

    while let Some(conn) = incoming.next().await {
        info!("connection incoming");
        tokio::spawn(
            handle_connection(remote.clone(), conn).unwrap_or_else(move |e| {
                error!("connection failed: {reason}", reason = e.to_string())
            }),
        );
    }

    Ok(())
}

async fn handle_connection(remote: Arc<SocketAddr>, conn: quinn::Connecting) -> Result<()> {
    let quinn::NewConnection {
        mut bi_streams,
        ..
    } = conn.await?;

    async {
        info!("established");

        // Each stream initiated by the client constitutes a new request.
        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            tokio::spawn(
                transfer(remote.clone(), stream)
                    .unwrap_or_else(move |e| error!("failed: {reason}", reason = e.to_string())),
            );
        }
        Ok(())
    }
    .await?;

    Ok(())
}

async fn transfer(
    remote: Arc<SocketAddr>,
    inbound: (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let mut outbound = TcpStream::connect(remote.as_ref()).await?;

    let (mut wi, mut ri) = inbound;
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = io::copy(&mut ri, &mut wo);
    let server_to_client = io::copy(&mut ro, &mut wi);

    try_join(client_to_server, server_to_client).await?;

    Ok(())
}
