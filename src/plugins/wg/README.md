# Wireguard vpp-plugin

## About
This code is a simple implementation of wireguard protocol for vpp.  
The plugin works only with IP4.  
Tunnels based on ipip-tinnel.

The alghorithm based on [wireguard-linux-compat](https://github.com/WireGuard/wireguard-linux-compat/).  

## License
It is necessary to clarify the use of licenses.
The crypto protocols:

- blake2s [[Source]](https://github.com/BLAKE2/BLAKE2). **Apache2**
- curve25519-donna [[Source]](https://code.google.com/archive/p/curve25519-donna/). **MIT**
- chacha20 [[Source]](https://github.com/grigorig/chachapoly). **Public**
- poly1305 [[Source]](https://github.com/grigorig/chachapoly). **Public**
- chachapoly1305 [[Source]](https://github.com/WireGuard/wireguard-linux-compat/tree/master/src/crypto).**GPL-2.0 OR MIT License**

Other crypto-files:

 - ecrypt-config.h, ecrypt-machine.h, ecrypt-portable.h. [[Source]](https://www.ecrypt.eu.org/stream/e2-salsa20.html). **License not specified. Public?**

From [here](https://github.com/WireGuard/wireguard-linux-compat/tree/master/src) also were taken (**GPL-2.0**):

- noise-protocol
- cookie
- message structures
- peer structure

wg_convert.h has functions from [source](https://github.com/WireGuard/wireguard-tools/blob/master/src/encoding.h). **GPL-2.0**

For GPL2 licenses left GPL2 in the headers. It’s not clear what to do.

## Plugin usage example:

### Create connection:
>\# wg genkey  
> Private key: *my_private_key*  
> Public key: *my_pub_key*


>\# create ipip tunnel src <*ip4_src*> dst <*ip4_dst*>  
>*tun_int*  
>\# set int state <*tun_int*> up  
>\# set int ip address <*tun_int*> <*tun_ip4*>

> \# wg set device private-key <*my_private_key*> port-src <*my_port*>  

> \# wg set peer public-key <*peer_pub_key*> endpoint <*peer_ip4*> allowed-ip <*peer_tun_ip4*> port-dst <*peer_port*> tunnel <*tun_int*> persistent-keepalive <*keepalive_interval*>  
> \# ...  
> \# wg set peer .... <*parameters*>

The same steps for the other side.

>\# ping <*peer_tun_ip4*>

### Remove peer
> \# wg remove peer <*peer_pub_key*>  
Remove ipip tunnel also

### Clear all connections:
> \# wg remove device






