# QUIC implementation {#rdma_doc}

The quic plugin provides an IETF QUIC protocol implementation. It is based on
the [quicly](https://github.com/h2o/quicly) library.

This plugin adds the QUIC protocol to VPP's Host Stack. As a result QUIC is
usable both in internal VPP applications and in external apps.


## Maturity level
Under development: it should mostly work, but has not been thoroughly tested and
should not be used in production.


## Features
 - only bidirectional streams are supported currently.


## Getting started

QUIC constructs are exposed as follows:

- QUIC connections and streams are both regular host stack sessions.
- QUIC connections can be created and destroyed with regular `connect` and
  `close` calls with `TRANSPORT_PROTO_QUIC`.
- Streams can be opened in a connection by calling `connect`again and passing
  the ID of the connection to which the new stream should belong.
- Streams can be closed with a regular `close`call.
- Streams opened by peers can be accepted from the sessions corresponding to
  QUIC connections.
- Data can ba exchanged by using the regular `send` and `recv` calls on the
  stream sessions.

Example code can be found in:
`src/vnet/session-apps/echo_client.c`: Test client using the internal API
`src/vnet/session-apps/echoo_server.c`: Test server using the internal API
`src/tests/vnet/session/quic_echo.c`: Client and server, using the external API

