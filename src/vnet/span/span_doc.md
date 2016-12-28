# VPP SPAN implementation    {#span_doc}

This is a memo intended to contain documentation of the VPP SPAN implementation.
Everything that is not directly obvious should come here.


## Switched Port Analyzer (SPAN)
Port mirroring is used on a network switch to send a copy of network packets seen on one switch port to a network monitoring connection on another switch port.
Can be used by network engineers or administrators to measure performnce, analyze and debug data or diagnose errors on a network.

### RX traffic node
There is one static node to mirror incomming packets.
* span-input: Creates a copy of incomming buffer due to incomming buffers can be reused internally.

Chaining: dpdk-input -> span-input ->
* original buffer is sent to ethernet-input for processing
* buffer copy is sent to interface-output

### Configuration
SPAN supports the following CLI configuration commands:

#### Enable/Disable SPAN (CLI)
	set interface span <if-name> [disable | destination <if-name>]

<if-name>: mirrored interface name
destination <if-name>: monitoring interface name
disable: delete mirroring

#### Enable/Disabl SPAN (API)
SPAN supports the following API configuration command:
	sw_interface_span_enable_disable src GigabitEthernet0/8/0 dst GigabitEthernet0/9/0
	sw_interface_span_enable_disable src_sw_if_index 1 dst_sw_if_index 2

src/src_sw_if_index: mirrored interface name
dst/dst_sw_if_index: monitoring interface name

#### Remove SPAN entry (API)
SPAN supports the following API configuration command:
	sw_interface_span_enable_disable src_sw_if_index 1 dst_sw_if_index 2 disable

src_sw_if_index: mirrored interface name
dst_sw_if_index: monitoring interface name

### Configuration example

Mirror all packets on interface GigabitEthernet0/10/0 to interface GigabitEthernet0/11/0.

Configure IPv4 addresses on mirrored interface:
set interface ip address GigabitEthernet0/10/0 192.168.1.13/24
set interface state GigabitEthernet0/10/0 up

Configure IPv4 addresses on monitoring interface:
set interface ip address GigabitEthernet0/11/0 192.168.2.13/24
set interface state GigabitEthernet0/11/0 up

Configure SPAN
set span src GigabitEthernet0/10/0 dst GigabitEthernet0/11/0

### Operational data

Active SPAN mirroring CLI show command:
    show interfaces span

Active SPAN mirroring API dump command:
    sw_interface_span_dump
