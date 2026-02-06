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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_parse_plugin_options_single() {
        let opts = parse_plugin_options("host=example.com");
        assert_eq!(opts.get("host").unwrap(), "example.com");
        assert_eq!(opts.len(), 1);
    }

    #[test]
    fn test_parse_plugin_options_multiple() {
        let opts = parse_plugin_options("host=example.com;cert=/path/to/cert;key=/path/to/key");
        assert_eq!(opts.get("host").unwrap(), "example.com");
        assert_eq!(opts.get("cert").unwrap(), "/path/to/cert");
        assert_eq!(opts.get("key").unwrap(), "/path/to/key");
        assert_eq!(opts.len(), 3);
    }

    #[test]
    fn test_parse_plugin_options_value_with_equals() {
        let opts = parse_plugin_options("key=value=with=equals");
        assert_eq!(opts.get("key").unwrap(), "value=with=equals");
    }

    #[test]
    fn test_parse_plugin_options_duplicate_key_last_wins() {
        let opts = parse_plugin_options("secret=first;secret=second");
        assert_eq!(opts.get("secret").unwrap(), "second");
    }

    #[test]
    fn test_parse_env_addr_valid() {
        // Set environment variables for the test
        env::set_var("SS_LOCAL_HOST", "127.0.0.1");
        env::set_var("SS_LOCAL_PORT", "1080");
        env::set_var("SS_REMOTE_HOST", "127.0.0.1");
        env::set_var("SS_REMOTE_PORT", "8388");

        let result = parse_env_addr();
        assert!(result.is_ok());

        let (local, remote) = result.unwrap();
        assert_eq!(local.port(), 1080);
        assert_eq!(remote.port(), 8388);

        // Clean up
        env::remove_var("SS_LOCAL_HOST");
        env::remove_var("SS_LOCAL_PORT");
        env::remove_var("SS_REMOTE_HOST");
        env::remove_var("SS_REMOTE_PORT");
    }

    #[test]
    fn test_parse_env_addr_missing_vars() {
        env::remove_var("SS_REMOTE_HOST");
        env::remove_var("SS_REMOTE_PORT");
        env::remove_var("SS_LOCAL_HOST");
        env::remove_var("SS_LOCAL_PORT");

        let result = parse_env_addr();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_env_opts_valid() {
        env::set_var("SS_PLUGIN_OPTIONS", "host=example.com;cert=/tmp/cert.pem");

        let result = parse_env_opts();
        assert!(result.is_ok());

        let opts = result.unwrap();
        assert_eq!(opts.get("host").unwrap(), "example.com");
        assert_eq!(opts.get("cert").unwrap(), "/tmp/cert.pem");

        env::remove_var("SS_PLUGIN_OPTIONS");
    }

    #[test]
    fn test_parse_env_opts_missing_var() {
        env::remove_var("SS_PLUGIN_OPTIONS");

        let result = parse_env_opts();
        assert!(result.is_err());
    }
}
