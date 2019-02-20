How to build a vpp dispatch trace aware Wireshark
=================================================

The vpp pcap dispatch trace dissector has been merged into the wireshark
main branch, so the process is simple. Download wireshark, compile it,
and install it.

Download wireshark source code
------------------------------

The wireshark git repo is large, so it takes a while to clone.

```
    git clone https://code.wireshark.org/review/wireshark
```

Install prerequisite packages
------------------------------------

Here is a list of prerequisite packages which must be present in order
to compile wireshark, beyond what's typically installed on an Ubuntu
18.04 system:

```
    libgcrypt11-dev flex bison qtbase5-dev qttools5-dev-tools qttools5-dev
    qtmultimedia5-dev libqt5svg5-dev libpcap-dev qt5-default
```

Compile Wireshark
-----------------

Mercifully, Wireshark uses cmake, so it's relatively easy to build, at
least on Ubuntu 18.04.


```
    $ cd wireshark
    $ mkdir build
    $ cd build
    $ cmake -G Ninja ../
    $ ninja -j 8
    $ sudo ninja install
```

Make a pcap dispatch trace
--------------------------

Configure vpp to pass traffic in some fashion or other, and then:


```
    vpp# pcap dispatch trace on max 10000 file vppcapture buffer-trace dpdk-input 1000
```


or similar. Run traffic for long enough to capture some data. Save the
dispatch trace capture like so:

```
    vpp# pcap dispatch trace off
```

Display in Wireshark
--------------------

Display /tmp/vppcapture in the vpp-enabled version of wireshark. With
any luck, normal version of wireshark will refuse to process vpp
dispatch trace pcap files because they won't understand the encap type.

Set wireshark to filter on vpp.bufferindex to watch a single packet
traverse the forwarding graph. Otherwise, you'll see a vector of packets
in e.g. ip4-lookup, then a vector of packets in ip4-rewrite, etc.
