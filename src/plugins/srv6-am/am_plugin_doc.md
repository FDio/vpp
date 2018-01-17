# SRv6 endpoint to SR-unaware appliance via masquerading (End.AM) {#srv6_am_plugin_doc}

## Overview

The "Endpoint to SR-unaware appliance via masquerading" (End.AM) is a two-parts
function for processing SRv6 **inserted** traffic on behalf of an SR-unaware
appliance. The first part decrements the Segments Left value and **replaces the
IPv6 Destination Address with the last segment in the SRH**, while the second
restores the IPv6 Destination Address with the active segment in the traffic
coming back from the appliance.

In this scenario, we assume that the appliance can only inspect, drop or perform
limited changes to the packets. In particular, the appliance must not change the
IP Destination Address of the packet, terminate a transport connection nor
generate arbitrary packets. For example, Firewalls, Intrusion Detection Systems,
Deep Packet Inspectors are among the appliances that can be supported in this
scenario.

## Pseudo-code

When instantiating an End.AM SID, the following parameters are required:

- APP-ADDR: IP or Ethernet address of the appliance
- IFACE-OUT: local interface for sending traffic towards the appliance
- IFACE-IN: local interface receiving the traffic coming back from the appliance

Packets can be sent to and received from an appliance on the same interface
(IFACE-IN = IFACE-OUT).

### Masquerading

Upon receiving a packet destined to S, where S is a local End.AM SID, a node N
does:

	IF NH=SRH & SL > 0 THEN                      			;; Ref1
		Decrement SL
		Write the last SID in the DA
		Forward the packet on IFACE-OUT
	ELSE
		Drop the packet

**Ref1:** an End.AM must not be the last SID.

### De-masquerading

Upon receiving a non-link-local IPv6 packet on IFACE-IN, a node N does:

	IF NH=SRH THEN
		Replace IP DA with SRH[SL]
		Lookup DA in the appropriate table and proceed accordingly

De-masquerading is a policy attached to IFACE-IN that intercepts all packets
coming back from the appliance and restores the destination address.  This
occurs before any lookup on the packet destination address (e.g. in "My Local
SIDs" table or in the FIB) is performed.

## Benefits

The End.AM masquerading function brings the following benefits:

1. The appliance receives a packet with the source and destination addresses
respectively set as the original source and the final destination.
2. The appliance does not try and inspect the SRH, as RFC2460 specifies that
routing extension headers are not examined or processed by transit nodes.

## Limitations

An End.AM SID may be present in any number of segment lists at the same time.

However, since the returning traffic from the appliance is processed based on
the receiving interface (IFACE-IN), this interface may only be bound to a single
End.AM SID at a time.

In the case of a bi-directional service chain, the same End.AM SID and receiving
interface (IFACE-IN) may be used in both directions.

## Configuration

The following CLI instantiates a new End.AM segment that sends masqueraded
traffic on interface `IFACE-OUT` towards an appliance at address `APP-ADDR` and
restores the active segment in the IPv6 header of the packets coming back on
interface `IFACE-IN`.

	sr localsid address SID behavior end.am nh APP-ADDR oif IFACE-OUT iif IFACE-IN

For example, the following command configures the SID `1::A1` with an End.AM
function for sending traffic on interface `GigabitEthernet0/8/0` to the appliance at
address `A1::`, and receiving it back on interface `GigabitEthernet0/9/0`.

	sr localsid address 1::A1 behavior end.am nh A1:: oif GigabitEthernet0/8/0 iif GigabitEthernet0/9/0

