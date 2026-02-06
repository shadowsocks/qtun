#[allow(unused)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_protocol_value() {
        assert_eq!(ALPN_QUIC_HTTP.len(), 1);
        assert_eq!(ALPN_QUIC_HTTP[0], b"hq-29");
    }
}
