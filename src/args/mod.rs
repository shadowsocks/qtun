use anyhow::Result;
use std::collections::HashMap;
use std::env::var;
use std::net::{SocketAddr, ToSocketAddrs};

pub fn parse_env_addr() -> Result<(SocketAddr, SocketAddr)> {
    let ss_remote_host = var("SS_REMOTE_HOST")?;
    let ss_remote_port = var("SS_REMOTE_PORT")?;
    let ss_local_host = var("SS_LOCAL_HOST")?;
    let ss_local_port = var("SS_LOCAL_PORT")?;

    let ss_local_addr = format!("{}:{}", ss_local_host, ss_local_port)
        .to_socket_addrs()?
        .next()
        .unwrap();
    let ss_remote_addr = format!("{}:{}", ss_remote_host, ss_remote_port)
        .to_socket_addrs()?
        .next()
        .unwrap();

    Ok((ss_local_addr, ss_remote_addr))
}

pub fn parse_env_opts() -> Result<HashMap<String, String>> {
    let ss_plugin_options = var("SS_PLUGIN_OPTIONS")?;

    let ss_plugin_options = parse_plugin_options(&ss_plugin_options);

    Ok(ss_plugin_options)
}

/// Parse a name–value mapping as from SS_PLUGIN_OPTIONS.
///
/// "<value> is a k=v string value with options that are to be passed to the
/// transport. semicolons, equal signs and backslashes must be escaped
/// with a backslash."
/// Example: secret=nou;cache=/tmp/cache;secret=yes
///
fn parse_plugin_options(options: &str) -> HashMap<String, String> {
    let mut plugin_options = HashMap::<String, String>::new();

    let opts: Vec<&str> = options.split(';').collect();

    // FIXME: backslash is not escaped in this plugin
    for opt in opts {
        let o: Vec<&str> = opt.splitn(2, '=').collect();
        plugin_options.insert(o[0].to_string(), o[1].to_string());
    }

    plugin_options
}
