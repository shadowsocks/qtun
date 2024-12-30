use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use dirs::home_dir;
use env_logger::Builder;
use futures::future::try_join;
use futures::TryFutureExt;
use log::LevelFilter;
use log::{error, info};
use quinn_proto::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use structopt::{self, StructOpt};
use tokio::net::TcpStream;

mod args;
mod common;

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
    /// Client address to block
    #[structopt(long = "block")]
    block: Option<SocketAddr>,
    /// Maximum number of concurrent connections to allow
    #[structopt(long = "connection-limit")]
    connection_limit: Option<usize>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut log_builder = Builder::new();
    log_builder.filter(None, LevelFilter::Info).default_format();
    log_builder.filter(Some("qtun-server"), LevelFilter::Debug);
    log_builder.init();

    let options = Opt::from_args();

    // init all parameters
    let mut cert_path = options.cert;
    let mut key_path = options.key;
    let mut acme_host = options.acme_host;
    let mut listen_addr = options.listen;
    let mut relay_addr = options.relay;

    // parse environment variables
    if let Ok((ss_local_addr, ss_remote_addr)) = args::parse_env_addr() {
        relay_addr = ss_local_addr;
        listen_addr = ss_remote_addr;
    }
    if let Ok(ss_plugin_opts) = args::parse_env_opts() {
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

    let key = fs::read(key_path.clone()).context("failed to read private key")?;
    let key = if key_path.extension().is_some_and(|x| x == "der") {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))
    } else {
        rustls_pemfile::private_key(&mut &*key)
            .context("malformed PKCS #1 private key")?
            .ok_or_else(|| anyhow::Error::msg("no private keys found"))?
    };
    let certs = fs::read(cert_path.clone()).context("failed to read certificate chain")?;
    let certs = if cert_path.extension().is_some_and(|x| x == "der") {
        vec![CertificateDer::from(certs)]
    } else {
        rustls_pemfile::certs(&mut &*certs)
            .collect::<Result<_, _>>()
            .context("invalid PEM-encoded certificate")?
    };

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    let remote = Arc::<SocketAddr>::from(relay_addr);

    let endpoint = quinn::Endpoint::server(server_config, listen_addr)?;
    eprintln!("listening on {}", endpoint.local_addr()?);

    while let Some(conn) = endpoint.accept().await {
        if options
            .connection_limit
            .is_some_and(|n| endpoint.open_connections() >= n)
        {
            info!("refusing due to open connection limit");
            conn.refuse();
        } else if Some(conn.remote_address()) == options.block {
            info!("refusing blocked client IP address");
            conn.refuse();
        } else if options.stateless_retry && !conn.remote_address_validated() {
            info!("requiring connection to validate its address");
            conn.retry().unwrap();
        } else {
            info!("accepting connection");
            let fut = handle_connection(remote.clone(), conn);
            tokio::spawn(async move {
                if let Err(e) = fut.await {
                    error!("connection failed: {reason}", reason = e.to_string())
                }
            });
        }
    }

    Ok(())
}

async fn handle_connection(remote: Arc<SocketAddr>, conn: quinn::Incoming) -> Result<()> {
    let bi_streams = conn.await?;

    async {
        info!("established");

        // Each stream initiated by the client constitutes a new request.
        loop {
            // let (stream) = bi_streams.accept_bi().await
            let stream = match bi_streams.accept_bi().await {
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

    let client_to_server = tokio::io::copy(&mut ri, &mut wo);
    let server_to_client = tokio::io::copy(&mut ro, &mut wi);

    try_join(client_to_server, server_to_client).await?;

    Ok(())
}
