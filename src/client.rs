use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use anyhow::{anyhow, Result};
use futures::future::try_join;
use quinn::Endpoint;
use structopt::{self, StructOpt};
use tracing::info;

#[derive(StructOpt, Debug)]
#[structopt(name = "qtun-client")]
struct Opt {
    /// Address to listen on
    #[structopt(long = "local", default_value = "0.0.0.0:4433")]
    local: SocketAddr,
    /// Address to listen on
    #[structopt(long = "remote", default_value = "127.0.0.1:8138")]
    remote: SocketAddr,
    /// Override hostname used for certificate verification
    #[structopt(long = "host", default_value = "bing.com")]
    host: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Opt::from_args();

    let mut endpoint = quinn::Endpoint::builder();
    let client_config = quinn::ClientConfigBuilder::default();
    endpoint.default_client_config(client_config.build());

    let (endpoint, _) = endpoint.bind(&"[::]:0".parse().unwrap())?;

    let remote = Arc::<SocketAddr>::from(options.remote);
    let host = Arc::<String>::from(options.host);
    let endpoint = Arc::<Endpoint>::from(endpoint);

    let mut listener = TcpListener::bind(options.local).await?;

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
        .connect(&remote, &host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;

    let quinn::NewConnection {
        connection: conn, ..
    } = { new_conn };

    let (mut ri, mut wi) = inbound.split();
    let (mut wo, mut ro) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;

    let client_to_server = io::copy(&mut ri, &mut wo);
    let server_to_client = io::copy(&mut ro, &mut wi);

    try_join(client_to_server, server_to_client).await?;

    Ok(())
}
