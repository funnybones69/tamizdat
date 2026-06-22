# Protocol Overview

Tamizdat is an encrypted client/server transport that carries TCP and UDP traffic over authenticated transport sessions. The primary release transport is TLS 1.3 + HTTP/2 CONNECT; optional relay modes can be layered in for restricted-network deployments.

## H2 transport

H2 is the default mode. At a high level:

1. The client opens a TLS connection to the server.
2. The client proves knowledge of its per-user short identifier during the TLS handshake.
3. Authenticated clients receive HTTP/2 CONNECT streams for TCP and UDP-style forwarding.
4. Unauthenticated probes receive ordinary cover behavior instead of a protocol banner.
5. The server can provide a small configuration bundle to authenticated clients.

This is the mode used by the normal Linux SOCKS client and by the Windows tray client unless a profile explicitly selects another transport.

## TURN relay mode

TURN relay mode is an optional advanced path. It is intended for deployments where the direct H2 connection is unreliable or blocked and the operator has a compatible relay setup. Clients can receive or be configured with TURN-style credentials/profile data and use that relay path as a fallback.

TURN credentials, room/profile data, generated profile URIs, short IDs, and private keys are credentials. Public documentation must use placeholders only.
