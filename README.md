# Tamizdat

Tamizdat is a self-hosted encrypted proxy protocol and client/server stack for carrying regular application traffic over a TLS 1.3 + HTTP/2 connection. It is in the same general category as self-hosted proxy transports such as Shadowsocks, Trojan, VLESS/REALITY, or small VPN gateways, but it is built around its own authenticated TLS handshake, HTTP/2 CONNECT tunnels, per-user profiles, and a lightweight management panel.

The practical goal is simple: run your own server, create client profiles, install a client on Linux or Windows, and send selected traffic through a transport that looks and behaves like normal HTTPS infrastructure instead of a custom open proxy port.

This repository is prepared as a clean public source release: it contains source code and neutral examples only. It does not include deployment databases, private keys, certificates, logs, local operator notes, or generated binaries.

## What it does

At a high level Tamizdat provides:

- a Go server that accepts authenticated client connections over TLS 1.3 and HTTP/2;
- local clients that expose a SOCKS5 or TUN-style entry point for applications;
- per-user profile URIs/keys instead of one shared server password;
- a small admin panel for users, routing rules, outbounds, and service settings;
- Linux release bundles with systemd services and a `tamizdat` management command;
- Windows tray client source with an embedded TUN engine.
- OpenWrt/LuCI aarch64 router client archive for policy-routed LAN tunneling.

## How it works

1. The server owns a normal TLS endpoint on a public host.
2. A client connects to that endpoint and authenticates during the TLS handshake using profile-specific key material.
3. Authenticated sessions switch into HTTP/2 CONNECT tunnels. TCP traffic is carried directly; UDP-like flows are carried through CONNECT-style streams.
4. Unauthenticated or invalid traffic can fall through to a configured cover/masquerade origin, so the public endpoint does not have to expose a separate obvious proxy service.
5. On the client side, applications can use a local SOCKS5 listener, or the Windows tray client can route broader traffic through its embedded TUN engine.

## Transport modes

Tamizdat currently documents two transport families for release users:

- **H2 mode** — the default and recommended mode. The client authenticates inside the TLS 1.3 handshake, then carries traffic through HTTP/2 CONNECT streams. It is the normal server/client path, works with the Linux SOCKS client and Windows tray client, and is the mode most deployments should start with.
- **TURN relay mode** — an optional relay path for restricted networks where direct H2 connections are unreliable or blocked. In this mode, supported clients can use TURN-style relay credentials/profile data pushed by the server or supplied by the operator. It is useful as a fallback/advanced deployment mode, not a replacement for the default H2 path.

Operationally, keep H2 as the primary profile and add TURN only when the deployment has a TURN-capable server/client setup and you have tested it on the target network. Treat TURN credentials and room/profile data as secrets, like normal Tamizdat profile URIs.

## Why use it

Tamizdat is designed for operators who want a small self-hosted transport rather than a large VPN appliance. Its main strengths are:

- **Self-hosted and auditable** — the server, clients, panel, and packaging scripts are in this repository.
- **HTTPS-shaped transport** — traffic runs over TLS 1.3 and HTTP/2 instead of a plaintext or obviously custom protocol.
- **Per-user control** — users get separate profiles that can be rotated or disabled independently.
- **Routing flexibility** — deployments can define routing rules and outbound chains instead of sending everything through one path.
- **Simple operations** — the Linux installer creates services, stores config under `/etc/tamizdat`, and provides `tamizdat status`, `tamizdat logs`, `tamizdat panel-url`, and uninstall helpers.
- **Desktop/client coverage** — Linux CLI/SOCKS client and Windows tray/TUN sources live in the same tree as the protocol.

Tamizdat is not a hosted anonymity network and does not magically make unsafe endpoints safe. It is a transport toolkit: security still depends on server hardening, private profile handling, sane routing rules, and keeping the admin panel protected.

## Functionality overview

- Default H2 transport over TLS 1.3 + HTTP/2 CONNECT.
- Optional TURN relay mode for restricted-network fallback deployments.
- TCP and UDP-over-CONNECT style forwarding.
- Local SOCKS5 client for desktop or server-side use.
- Windows client source: a tray app with an embedded TUN engine.
- OpenWrt/LuCI router client archive with aarch64 prebuilt binaries.
- Multi-user server with per-user configuration profiles.
- SQLite-backed admin panel for users, routing rules, and outbound chains.
- Optional routing rules based on domain/IP/geosite/geoip data.
- S-UI-style Linux release installer with a `tamizdat` management command.

## Repository layout

```text
cmd/              Command-line entry points: server, client, node, and Windows tray client
pkg/tamizdat/     Core protocol/client/server library
internal/         Internal support packages
node/             Node configuration/runtime package
panel/            Admin panel implementation and tests
scripts/          Install/uninstall/package/test helpers
```

The Windows client is the tray app. It is released as a single Windows GUI executable with the TUN engine and Wintun DLL embedded.

## Quick start

Preview install on a Linux host with systemd:

```bash
curl -fsSL https://github.com/funnybones69/tamizdat/releases/download/<tag>/install.sh -o install.sh
sudo bash install.sh
```

Use the exact tag from the GitHub Releases page, for example `v0.1.0-preview.5`. After a stable non-prerelease is published, the `/latest/download/` URL can be used instead. Preview installers are baked with a tag-specific release base so they download matching tarballs instead of relying on `/latest`.

Or install from a downloaded release tarball:

```bash
tar xf tamizdat-linux-amd64.tar.gz
cd tamizdat
sudo ./install.sh
```

The installer detects CPU architecture, downloads or uses the bundled release tarball, installs into `/usr/local/tamizdat`, creates `/usr/bin/tamizdat`, writes two systemd units (`tamizdat-server-app.service` and `tamizdat-panel.service`), binds the panel to `127.0.0.1` by default, and prints the generated panel URL and credentials. The panel URL base path is random unless explicitly set.

After installation:

```bash
tamizdat status
tamizdat panel-url
tamizdat logs
```

See [INSTALL.md](INSTALL.md) for full installation, upgrade, backup, and uninstall instructions.

## Build from source

Prerequisites:

- Go 1.25 or newer
- Python 3.9 or newer for the panel
- Linux/systemd for the installer and services
- WSL/Linux shell for `scripts/package-windows.sh` when producing Windows preview zips

Run tests:

```bash
go test ./...
python3 -m unittest panel/test_panel_shortid.py
python3 -m unittest scripts/test_install.py
```

Build release assets:

```bash
GOARCH=amd64 ./scripts/package-linux.sh
GOARCH=arm64 ./scripts/package-linux.sh
./scripts/package-windows.sh
```

This writes `dist/install.sh`, Linux tarballs, `dist/tamizdat-windows-amd64.zip`, and `dist/SHA256SUMS`. The OpenWrt/LuCI router archive is published as a separate release asset when available.

Linux tarballs contain:

```text
tamizdat/
  tamizdat-server-app
  tamizdat-client
  tamizdat-panel.py
  tamizdat
  install.sh
  uninstall.sh
  README.md
  INSTALL.md
  OPENWRT.md
  LICENSE
```

OpenWrt/LuCI archive contains an on-router installer, LuCI app, procd service, UCI config, routing helpers, and aarch64 prebuilt binaries. See [OPENWRT.md](OPENWRT.md).

Windows zip contains:

```text
tamizdat-windows-amd64/
  tamizdat-tray.exe
  config.example.uri
  README-WINDOWS.txt
  LICENSE.txt
  LICENSE-WINTUN.txt
```

`package-windows.sh` downloads the official Wintun 0.14.1 zip at build time, verifies the pinned amd64 DLL SHA-256, and embeds the TUN engine and Wintun DLL into `tamizdat-tray.exe`.

## Client usage

Create a user in the panel first, then copy that user's generated profile values.

### Linux CLI

The Linux CLI is a local SOCKS5 proxy. Prefer a profile URI file generated by the panel so the short ID and public key are not exposed in the process command line:

```bash
install -m 0600 /path/to/panel-profile.uri ./profile.uri
tamizdat-client -config-file ./profile.uri -listen 127.0.0.1:1080
```

Equivalent explicit-field form, useful for scripts that already split the URI:

```bash
tamizdat-client \
  -transport h2 \
  -server server.example.com:443 \
  -servername cover.example.com \
  -pubkey <server-public-key-hex> \
  -shortid <user-short-id-hex> \
  -listen 127.0.0.1:1080
```

Configure TCP applications to use remote-DNS SOCKS:

```text
socks5h://127.0.0.1:1080
```

The SOCKS listener also supports SOCKS5 UDP ASSOCIATE for UDP-capable clients. Keep the listener on loopback unless you intentionally protect it with local SOCKS authentication.

### Windows tray

Download `tamizdat-windows-amd64.zip`, extract it, copy `config.example.uri` to `config.uri`, replace the example with one generated `tamizdat://` profile URI from the panel, and run `tamizdat-tray.exe` as Administrator. The TUN engine and Wintun DLL are embedded in the tray executable.

### OpenWrt / LuCI router client

Download `tamizdat-openwrt-luci-aarch64-20260622.tar`, extract it, copy `openwrt-tamizdat/` to the router, and run its on-router installer. The LuCI UI appears under **Services → Tamizdat VPN**. See [OPENWRT.md](OPENWRT.md) for the full install and routing guide.

Do not commit or publish real profile URIs, short IDs, private keys, panel passwords, certificates, databases, or logs.

## Admin panel

The panel manages:

- server status;
- users and profile URIs;
- routing folders/rules;
- outbound definitions;
- basic service settings.

For public deployments, bind the panel to localhost or a private management network, use a strong admin password, and place it behind authenticated HTTPS if remote access is needed. See [INSTALL.md](INSTALL.md) for nginx/certbot reverse-proxy examples and the port conflict between Tamizdat protocol `443` and panel HTTPS `443`.

## Security best practices

- Keep `/etc/tamizdat/` readable only by root or the service user.
- Back up the SQLite database and key material before upgrades.
- Do not expose the panel directly to the public Internet without an additional authentication layer.
- Rotate user profiles when a device is lost or a URI may have leaked.
- Keep logs free of secrets; avoid pasting full profile URIs into issue reports.

## License

MIT. See [LICENSE](LICENSE).
