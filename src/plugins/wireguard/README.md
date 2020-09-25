# Wireguard vpp-plugin {#wireguard_plugin_doc}

## Overview
This plugin is an implementation of [wireguard protocol](https://www.wireguard.com/) for VPP. It allows one to create secure VPN tunnels.
This implementation is based on [wireguard-openbsd](https://git.zx2c4.com/wireguard-openbsd/), using the implementaiton of *ipip-tunnel*.

## Crypto

The crypto protocols:

- blake2s [[Source]](https://github.com/BLAKE2/BLAKE2)

OpenSSL:

- curve25519
- chachapoly1305

## Plugin usage example
Usage is very similar to other wireguard implementations.

### Create connection
Create keys:

```
> vpp# wg genkey
> *my_private_key*
> vpp# wg pubkey <my_private_key>
> *my_pub_key*
```

Create tunnel:
```
> vpp# create ipip tunnel src <ip4_src> dst <ip4_dst>
> *tun_name*
> vpp# set int state <tun_name> up
> vpp# set int ip address <tun_name> <tun_ip4>
```

After this we can create wg-device. The UDP port is opened automatically.
```
> vpp# wg set device private-key <my_private_key> src-port <my_port>
```

Now, we can add a peer configuration:
```
> vpp# wg set peer public-key <peer_pub_key> endpoint <peer_ip4> allowed-ip <peer_tun_ip4> dst-port <peer_port> tunnel <tun_name> persistent-keepalive <keepalive_interval>
```
If you need to add more peers, don't forget to first create another ipip-tunnel.
Ping.
```
> vpp# ping <peer_tun_ip4>
```
### Show config
To show device and all peer configurations:
```
> vpp# show wg
```

### Remove peer
Peer can be removed by its public-key.
```
> vpp# wg remove peer <peer_pub_key>
```
This removes the associated ipip tunnel as well

### Clear all connections
```
> vpp# wg remove device
```

## main next steps for improving this implementation
1. Use all benefits of VPP-engine.
2. Add IP6 support (currently only supports IPv4))
3. Add DoS protection as in original protocol (using cookie)
