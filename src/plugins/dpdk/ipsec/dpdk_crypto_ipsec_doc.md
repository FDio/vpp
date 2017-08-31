# VPP IPSec implementation using DPDK Cryptodev API    {#dpdk_crypto_ipsec_doc}

This document is meant to contain all related information about implementation and usability.


## VPP IPsec with DPDK Cryptodev

DPDK Cryptodev is an asynchronous crypto API that supports both Hardware and Software implementations (for more details refer to [DPDK Cryptography Device Library documentation](http://dpdk.org/doc/guides/prog_guide/cryptodev_lib.html)).

When there are enough Cryptodev resources for all workers, the node graph is reconfigured by adding and changing the default next nodes.

The following nodes are added:
* dpdk-crypto-input : polling input node, dequeuing from crypto devices.
* dpdk-esp-encrypt : internal node.
* dpdk-esp-decrypt : internal node.
* dpdk-esp-encrypt-post : internal node.
* dpdk-esp-decrypt-post : internal node.

Set new default next nodes:
* for esp encryption: esp-encrypt -> dpdk-esp-encrypt
* for esp decryption: esp-decrypt -> dpdk-esp-decrypt


### How to enable VPP IPSec with DPDK Cryptodev support

When building DPDK with VPP, Cryptodev support is always enabled.

Additionally, on x86_64 platforms, DPDK is built with SW crypto support.


### Crypto Resources allocation

VPP allocates crypto resources based on a best effort approach:
* first allocate Hardware crypto resources, then Software.
* if there are not enough crypto resources for all workers, the graph node is not modifed and the default VPP IPsec implementation based in OpenSSL is used. The following message is displayed:

      0: dpdk_ipsec_init: not enough Cryptodevs, default to OpenSSL IPsec


### Configuration example

To enable DPDK Cryptodev the user just need to provide cryptodevs in the startup.conf.

Below is an example startup.conf, it is not meant to be a default configuration:

```
dpdk {
    dev 0000:81:00.0
    dev 0000:81:00.1
    dev 0000:85:01.0
    dev 0000:85:01.1
    vdev crypto_aesni_mb0,socket_id=1
    vdev crypto_aesni_mb1,socket_id=1
}
```

In the above configuration:
* 0000:81:01.0 and 0000:81:01.1 are Ethernet device BDFs.
* 0000:85:01.0 and 0000:85:01.1 are Crypto device BDFs and they require the same driver binding as DPDK Ethernet devices but they do not support any extra configuration options.
* Two AESNI-MB Software (Virtual) Cryptodev PMDs are created in NUMA node 1.

For further details refer to [DPDK Crypto Device Driver documentation](http://dpdk.org/doc/guides/cryptodevs/index.html)

### Operational data

The following CLI command displays the Cryptodev/Worker mapping:

    show crypto device mapping [verbose]


### nasm

Building the DPDK Crypto Libraries requires the open source project nasm (The Netwide
Assembler) to be installed. Recommended version of nasm is 2.12.02. Minimum supported
version of nasm is 2.11.06. Use the following command to determine the current nasm version:

    nasm -v

CentOS 7.3 and earlier and Fedora 21 and earlier use unsupported versions
of nasm. Use the following set of commands to build a supported version:

    wget http://www.nasm.us/pub/nasm/releasebuilds/2.12.02/nasm-2.12.02.tar.bz2
    tar -xjvf nasm-2.12.02.tar.bz2
    cd nasm-2.12.02/
    ./configure
    make
    sudo make install
