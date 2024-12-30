use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use tokio::net::{TcpListener, TcpStream};

use anyhow::{anyhow, Result};
use futures::future::try_join;
use log::{error, info};
use quinn::ConnectionError;
use quinn::Endpoint;
use structopt::{self, StructOpt};

use env_logger::Builder;
use log::LevelFilter;

mod args;
mod common;

#[derive(StructOpt, Debug)]
#[structopt(name = "qtun-client")]
struct Opt {
    /// Address to listen on
    #[structopt(long = "listen", default_value = "127.0.0.1:8138")]
    listen: SocketAddr,
    /// Address to listen on
    #[structopt(long = "relay", default_value = "127.0.0.1:4433")]
    relay: SocketAddr,
    /// Override hostname used for certificate verification
    #[structopt(long = "host", default_value = "bing.com")]
    host: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // setup log
    let mut log_builder = Builder::new();
    log_builder.filter(None, LevelFilter::Info).default_format();
    log_builder.filter(Some("qtun-client"), LevelFilter::Debug);
    log_builder.init();

    // parse command line args
    let options = Opt::from_args();

    // init all parameters
    let mut listen_addr = options.listen;
    let mut relay_addr = options.relay;
    let mut host = options.host;

    // parse environment variables
    if let Ok((ss_local_addr, ss_remote_addr)) = args::parse_env_addr() {
        // init all parameters
        listen_addr = ss_local_addr;
        relay_addr = ss_remote_addr;
    }
    if let Ok(ss_plugin_opts) = args::parse_env_opts() {
        if let Some(h) = ss_plugin_opts.get("host") {
            host = h.clone();
        }
    }

    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    for certs in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        roots.add(certs).unwrap();
    }

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    client_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

    // WAR for Windows endpoint
    let mut endpoint = if cfg!(target_os = "windows") {
        Endpoint::client("0.0.0.0:0".parse().unwrap())
    } else {
        Endpoint::client("[::]:0".parse().unwrap())
    }?;
    let client_config =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));

    endpoint.set_default_client_config(client_config);

    let remote = Arc::<SocketAddr>::from(relay_addr);
    let host = Arc::<String>::from(host);
    let endpoint = Arc::<Endpoint>::from(endpoint);

    info!("listening on {}", listen_addr);

    let listener = TcpListener::bind(listen_addr).await?;

    while let Ok((inbound, _)) = listener.accept().await {
        info!("connection incoming");

        let remote = Arc::clone(&remote);
        let host = Arc::clone(&host);
        let endpoint = Arc::clone(&endpoint);

        let transfer = transfer(remote, host, endpoint, inbound);
        tokio::spawn(transfer);
    }

    Ok(())
}

async fn transfer(
    remote: Arc<SocketAddr>,
    host: Arc<String>,
    endpoint: Arc<Endpoint>,
    mut inbound: TcpStream,
) -> Result<()> {
    let new_conn = endpoint
        .connect(*remote, &host)?
        .await
        .map_err(|e| {
            if e == ConnectionError::TimedOut {
                let socket = if cfg!(target_os = "windows") {
                    std::net::UdpSocket::bind("0.0.0.0:0").unwrap()
                } else {
                    std::net::UdpSocket::bind("[::]:0").unwrap()
                };
                let addr = socket.local_addr().unwrap();
                let ret = endpoint.rebind(socket);
                match ret {
                    Ok(_) => {
                        info!("rebinding to: {}", addr);
                    }
                    Err(e) => {
                        error!("rebind fail: {:?}", e);
                    }
                }
            }
            anyhow!("failed to connect: {:?}", e)
        })
        .unwrap();

    let (mut ri, mut wi) = inbound.split();
    let (mut wo, mut ro) = new_conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {:?}", e))?;

    let client_to_server = tokio::io::copy(&mut ri, &mut wo);
    let server_to_client = tokio::io::copy(&mut ro, &mut wi);

    try_join(client_to_server, server_to_client).await?;

    Ok(())
}
