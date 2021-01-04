## Examples    {#libmemif_examples_doc}

Example source code is located in `libmemif/examples/` directory. The compiled binaries are located in `build/examples/`.

Example app | Description
------------|------------
@ref extras/libmemif/examples/icmp_responder | In this example, memif endpoint connects to an external application. The example application can resolve ARP and reply to ICMPv4 packets. The program will exit once the interface is disconnected Memif receive mode: interrupt.
@ref extras/libmemif/examples/loopback | In this example, two memif endpoints are connected to create a loopback Once connected, Master sends a test packet to slave Slave responds with the same packet in zero-copy way.
