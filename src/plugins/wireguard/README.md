# Wireguard vpp-plugin

## Overview
This plugin is an implementation of [wireguard protocol](https://www.wireguard.com/) for VPP. It allows one to create secure VPN tunnels.
This implementation is based on [wireguard-openbsd](https://git.zx2c4.com/wireguard-openbsd/).

## Crypto

The crypto protocols:

- blake2s [[Source]](https://github.com/BLAKE2/BLAKE2)

OpenSSL:

- curve25519
- chachapoly1305

## Plugin usage example

### Create wireguard interface

```
> vpp# wireguard create listen-port <port> private-key <priv_key> src <src_ip4> [generate-key]
> *wg_interface*
> vpp# set int state <wg_interface> up
> vpp# set int ip address <wg_interface> <wg_ip4>
```

### Add a peer configuration:
```
> vpp# wireguard peer add <wg_interface> public-key <pub_key_other> endpoint <ip4_dst> allowed-ip <prefix> dst-port <port_dst> persistent-keepalive [keepalive_interval]
> vpp# *peer_idx*
```

### Show config
```
> vpp# show wireguard interface
> vpp# show wireguard peer
```

### Remove peer
```
> vpp# wireguard peer remove <peer_idx>
```


### Delete interface 
```
> vpp# wireguard delete <wg_interface>
```

## Main next steps for improving this implementation
1. Use all benefits of VPP-engine.
2. Add IPv6 support (currently only supports IPv4)
3. Add DoS protection as in original protocol (using cookie)
