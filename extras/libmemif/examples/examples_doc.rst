.. _libmemif_examples_doc:

Libmemif Examples
=================

Example source code is located in `.../vpp/extras/libmemif/examples/` directory.
The compiled binaries are located in `.../vpp/extras/libmemif/build/examples/`.


ICMP Responder
--------------
**Application Source Code**: `.../vpp/extras/libmemif/examples/icmp_responder`

In this example, memif endpoint connects to an external application. The example
application can resolve ARP and reply to ICMPv4 packets. The program will exit
once the interface is disconnected Memif receive mode: interrupt.

VPP (memif master) <--> icmp_responder app (memif slave)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Start VPP and configure memif interface::

    make run
    ...
    DBGvpp# create interface memif id 0 master
    DBGvpp# set int state memif0/0 up
    DBGvpp# set int ip address memif0/0 192.168.1.2/24

Start icmp_responder example app::

    ./examples/icmp_responder

Memif in slave mode will try to connect every 2 seconds. If connection
establishment is successful, the `memif connected` message will show::

    INFO: memif connected!

**Note**: Error messages like "unmatched interface id" are printed only in debug mode.

Verify that the memif is connected on VPP side::

    DBGvpp# sh memif
    interface memif0/0
    remote-name "ICMP_Responder"
    remote-interface "memif_connection"
    id 0 mode ethernet file /run/vpp/memif.sock
    flags admin-up connected
    listener-fd 12 conn-fd 13
    num-s2m-rings 1 num-m2s-rings 1 buffer-size 0
        master-to-slave ring 0:
        region 0 offset 32896 ring-size 1024 int-fd 16
        head 0 tail 0 flags 0x0000 interrupts 0
        master-to-slave ring 0:
        region 0 offset 0 ring-size 1024 int-fd 15
        head 0 tail 0 flags 0x0001 interrupts 0

Send ping from VPP to icmp_responder (Default IPv4: 192.168.1.1)::

    DBGvpp# ping 192.168.1.1
    64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=.1888 ms
    64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=.1985 ms
    64 bytes from 192.168.1.1: icmp_seq=4 ttl=64 time=.1813 ms
    64 bytes from 192.168.1.1: icmp_seq=5 ttl=64 time=.1929 ms

    Statistics: 5 sent, 4 received, 20% packet loss


Loopback
--------
**Application Source Code**: `.../vpp/extras/libmemif/examples/loopback`

In this example, two memif endpoints are connected to create a loopback.
Once connected, a test packet is sent out the memif master interface to
the memif slave interface, which replies with the same packet in a
zero-copy way.
In reverse mode, the packet is sent from the slave interface and is
looped back by the master interface.

Running The Loopback Application
++++++++++++++++++++++++++++++++
Start the loopback example::

    ./examples/loopback

You should see the `Received correct data.` message::

    INFO: Received correct data.
    INFO: Stopping the program
