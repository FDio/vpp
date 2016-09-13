# VPP SPAN implementation

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

### TX traffic node
There is one dynamic node per interface for outgoing packets created dynamically as SPAN config changes:
* <interface name>-span (e.g. GigabitEthernet0/10/0-span): Creates a reference to outgoing buffer due to incomming buffers can be reused internally.

Chaining: <mirrored interface name>-output -> <mirrored interface name>-span -> 
* original buffer is sent to <mirrored interface name>-tx
* buffer copy is sent to <monitoring interface name>-tx

There is a pool of unused span out nodes which is empty at the beginning. Upon request of new Span out node first attempts to reuse free node from the pool, if pool is empty, new node is allocated.
Unnecessary Span out nodes are put back into the pool and renamed to <interface name>-span-free.


### Configuration
SPAN supports the following CLI configuration commands:

#### Add/Remove SPAN entry (CLI)
	set span src <interface-name> dst <interface-name> [disable]

src: mirrored interface name
dst: monitoring interface name
disable: delete mirroring

#### Add SPAN entry (API)
SPAN supports the following API configuration command:
	span_create src <src interface name> dst <dst interface name>

src: mirrored interface name
dst: monitoring interface name

#### Remove SPAN entry (API)
SPAN supports the following API configuration command:
	span_delete src <src interface name>

src: mirrored interface name

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
    sh span

Active SPAN mirroring API dump command:
    span_dump
