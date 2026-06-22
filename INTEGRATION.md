# Integration Notes

This public release supports the following integration path:

1. Install and run `tamizdat-server` on a Linux host.
2. Use the admin panel to create users and generate profile values.
3. Run `tamizdat-client` locally and expose a SOCKS5 listener.
4. Configure applications to use the local SOCKS5 listener.

Example client command:

```bash
tamizdat-client \
  -server server.example.com:443 \
  -servername cover.example.com \
  -pubkey <server-public-key-hex> \
  -shortid <user-short-id-hex> \
  -listen 127.0.0.1:1080
```

Do not publish real generated profile values.
