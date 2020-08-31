# Wireguard vpp-plugin

## Overview
This plugin is an implementation of [wireguard protocol](https://www.wireguard.com/) for VPP. It allows to create secure VPN-tunnel.   
The alghorithm based on [wireguard-openbsd](https://git.zx2c4.com/wireguard-openbsd/) implementation. Here is the adaptation for the VPP.  
The tunnels used are based on the *ipip-tunnel* implementation.


## Crypto

The crypto protocols:

- blake2s [[Source]](https://github.com/BLAKE2/BLAKE2)

OpenSSL:

- curve25519
- chachapoly1305

## Plugin usage example
The usage is very similar as original wireguard implementation.

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

After that we can create wg-device. UDP port is open automatically.
```
> vpp# wg set device private-key <my_private_key> port-src <my_port>  
```

Now, we can add peer configuration:
```
> vpp# wg set peer public-key <peer_pub_key> endpoint <peer_ip4> allowed-ip <peer_tun_ip4> port-dst <peer_port> tunnel <tun_name> persistent-keepalive <keepalive_interval>  
```
If you need to add more peers, don't forget create another ipip-tunnel before.  
Ping.
```
> vpp# ping <peer_tun_ip4>
```
### Show config
To show device and all peers configurations:
```
> vpp# show wg 
```

### Remove peer
Peer can be removed by its public-key.
```
> vpp# wg remove peer <peer_pub_key> 
```
It removes ipip tunnel also.

### Clear all connections
```
> vpp# wg remove device
```

## Next main steps for improvig
1. Use all benefits of VPP-engine.
2. Add IP6 support (now it is working only with IP4)
3. Add DoS protection as in original protocol (using cookie)
