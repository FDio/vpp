# VPP IPSec implementation using DPDK Cryptodev API    {#dpdk_crypto_ipsec_doc}

This document is meant to contain all related information about implementation and usability.


## VPP IPsec with DPDK Cryptodev

DPDK Cryptodev is an asynchronous crypto API that supports both Hardware and Software implementations (for more details refer to [DPDK Cryptography Device Library documentation](http://dpdk.org/doc/guides/prog_guide/cryptodev_lib.html)).

When DPDK Cryptodev support is enabled, the node graph is modified by adding and replacing some of the nodes.

The following nodes are replaced:
* esp-encrypt -> dpdk-esp-encrypt
* esp-decrypt -> dpdk-esp-decrypt

The following nodes are added:
* dpdk-crypto-input : polling input node, basically dequeuing from crypto devices.
* dpdk-esp-encrypt-post : internal node.
* dpdk-esp-decrypt-post : internal node.


### How to enable VPP IPSec with DPDK Cryptodev support

To enable DPDK Cryptodev support (disabled by default), we need the following env option:

    vpp_uses_dpdk_cryptodev=yes

A couple of ways to achive this:
* uncomment/add it in the platforms config (ie. build-data/platforms/vpp.mk)
* set the option when building vpp (ie. make vpp_uses_dpdk_cryptodev=yes build-release)


### Crypto Resources allocation

VPP allocates crypto resources based on a best effort approach:
* first allocate Hardware crypto resources, then Software.
* if there are not enough crypto resources for all workers, all packets will be dropped if they reach ESP encrypt/decrypt nodes, displaying the warning:

      0: dpdk_ipsec_init: not enough cryptodevs for ipsec


### Configuration example

No especial IPsec configuration is required.

Once DPDK Cryptodev is enabled, the user just needs to provide cryptodevs in the startup.conf.

Example startup.conf:

```
dpdk {
    socket-mem 1024,1024
    num-mbufs 131072
    dev 0000:81:00.0
    dev 0000:81:00.1
    dev 0000:85:01.0
    dev 0000:85:01.1
    vdev cryptodev_aesni_mb_pmd,socket_id=1
    vdev cryptodev_aesni_mb_pmd,socket_id=1
}
```

In the above configuration:
* 0000:85:01.0 and 0000:85:01.1 are crypto BDFs and they require the same driver binding as DPDK Ethernet devices but they do not support any extra configuration options.
* Two AESNI-MB Software Cryptodev PMDs are created in NUMA node 1.

For further details refer to [DPDK Crypto Device Driver documentation](http://dpdk.org/doc/guides/cryptodevs/index.html)

### Operational data

The following CLI command displays the Cryptodev/Worker mapping:

    show crypto device mapping [verbose]
