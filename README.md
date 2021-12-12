# qtun

Yet another SIP003 plugin based on IETF-QUIC

## Install

```bash
# Install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

cargo install --git https://github.com/madeye/qtun
```

## Examples

### Issue a cert for TLS and QUIC

qtun will look for TLS certificates signed by acme.sh by default. Here's some sample commands for issuing a certificate using CloudFlare. You can find commands for issuing certificates for other DNS providers at acme.sh.

```bash
curl https://get.acme.sh | sh
~/.acme.sh/acme.sh --issue --dns dns_cf -d mydomain.me
```

### Server

```bash
./ssserver -s 0.0.0.0:443 -k example -m aes-256-gcm --plugin ./qtun-server --plugin-opts "acme_host=example.com"
```

### Client

```bash
./sslocal -s example.com:443 -k example -m aes-256-gcm --plugin ./qtun-client --plugin-opts "host=example.com"
```

## License

The MIT License (MIT)

Copyright (c) 2020 Max Lv

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
