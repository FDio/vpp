# Valscale

Valscale is an experimental VPP HostStack application that accepts Valkey TCP
connections and proxies them to local Valkey servers over Unix domain sockets.
It keeps the TCP data path in VPP while allowing unmodified Valkey servers to
use their normal socket interface.

## Routing model

Valscale parses the first RESP2 command received on a TCP connection. If the
command has a key, it applies FNV-1a to the key (or to the first `{...}` hash
tag) and selects a backend modulo the number of configured backends. A command
without a key selects backend zero. The selected backend remains pinned for the
lifetime of the connection.

This connection-level pinning is intentional, because transparently routing
each command would require multiplexing responses and preserving transaction
semantics. Clients must therefore keep all keys used on one connection on the
same backend. Authentication or protocol-negotiation commands sent before the
first keyed command also pin the connection to backend zero. These constraints
make the current implementation suitable for controlled benchmarks and
connection-sharded deployments, not as a transparent Valkey Cluster proxy.

## CLI

Add one or more Unix-socket backends before enabling the listener:

```text
valscale add-backend /run/valkey/valkey-0.sock
valscale add-backend /run/valkey/valkey-1.sock
valscale enable port 6379 fifo-size 8m segment-size 512m backend-socket-buffer 16m
show valscale
```

The same configuration can be provided in `startup.conf`:

```text
valscale {
  port 6379
  fifo-size 8m
  segment-size 512m
  backend-socket-buffer 16m
  backend /run/valkey/valkey-0.sock
  backend /run/valkey/valkey-1.sock
}
```

The startup stanza configures values and backends but does not start the TCP
listener. Run `valscale enable` from an `exec` file after interface setup.

## Threading

VPP worker threads execute the HostStack callbacks. Linux file-descriptor
callbacks for the Unix sockets execute on the VPP main thread. A global lock
currently serializes connection state changes across both paths. Multiple Unix
sockets avoid queueing all traffic behind one Valkey process, but the main
thread and global lock remain scalability limits of this experimental version.
