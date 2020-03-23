use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::prelude::*;

use anyhow::{Context, Result};
use futures::future::try_join;
use futures::{StreamExt, TryFutureExt};
use structopt::{self, StructOpt};
use tracing::{error, info};

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
    #[structopt(long = "local", default_value = "0.0.0.0:4433")]
    local: SocketAddr,
    /// Address to listen on
    #[structopt(long = "remote", default_value = "127.0.0.1:8138")]
    remote: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Opt::from_args();

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.stream_window_uni(0);
    let mut server_config = quinn::ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);

    if options.stateless_retry {
        server_config.use_stateless_retry(true);
    }

    // load certificates
    let key_path = &options.key;
    let cert_path = &options.cert;
    let key = fs::read(key_path).context("failed to read private key")?;
    let key = if key_path.extension().map_or(false, |x| x == "der") {
        quinn::PrivateKey::from_der(&key)?
    } else {
        quinn::PrivateKey::from_pem(&key)?
    };
    let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
    let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
        quinn::CertificateChain::from_certs(quinn::Certificate::from_der(&cert_chain))
    } else {
        quinn::CertificateChain::from_pem(&cert_chain)?
    };
    server_config.certificate(cert_chain, key)?;

    let mut endpoint = quinn::Endpoint::builder();
    endpoint.listen(server_config.build());

    let remote = Arc::<SocketAddr>::from(options.remote);

    let mut incoming = {
        let (endpoint, incoming) = endpoint.bind(&options.local)?;
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
        connection: _,
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
