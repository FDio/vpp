# VPP Link Layer Discovery Protocol (LLDP) implementation    {#lldp_doc}

This is a memo intended to contain documentation of the VPP LLDP implementation
Everything that is not directly obvious should come here.


## LLDP
LLDP is a link layer protocol to advertise the capabilities and current status of the system.

There are 2 nodes handling LLDP

1.) input-node which processes incoming packets and updates the local database
2.) process-node which is responsible for sending out LLDP packets from VPP side


### Configuration

LLDP has a global configuration and a per-interface enable setting.

Global configuration is modified using the "set lldp" command

set lldp [system-name <string>] [tx-hold <value>] [tx-interval <value>]

system-name: the name of the VPP system sent to peers in the system-name TLV
tx-hold: multiplier for tx-interval when setting time-to-live (TTL) value in the LLDP packets (TTL = tx-hold * tx-interval + 1, if TTL > 65535, then TTL = 65535)
tx-interval: time interval between sending out LLDP packets

Per interface setting is done using the "set interface lldp" command

set interface lldp <interface> | if_index <idx> [port-desc <string>] [disable]

interface: the name of the interface for which to enable/disable LLDP
if_index: sw interface index can be used if interface name is not used.
port-desc: port description
disable: LLDP feature can be enabled or disabled per interface.

### Configuration example

Configure system-name as "VPP" and transmit interval to 10 seconds:

set lldp system-name VPP tx-interval 10

Enable LLDP on interface TenGigabitEthernet5/0/1 with port description

set interface lldp TenGigabitEthernet5/0/1 port-desc vtf:eth0


### Operational data

The list of LLDP-enabled interfaces which are up can be shown using "show lldp" command

Example:
DBGvpp# show lldp
Local interface           Peer chassis ID           Remote port ID               Last heard      Last sent      Status
GigabitEthernet2/0/1                                                               never         27.0s ago     inactive
TenGigabitEthernet5/0/1   8c:60:4f:dd:ca:52         Eth1/3/3                     20.1s ago       18.3s ago      active

All LLDP configuration data with all LLDP-enabled interfaces can be shown using "show lldp detail" command

Example:
DBGvpp# show lldp detail
LLDP configuration:
Configured system name: vpp
Configured tx-hold: 4
Configured tx-interval: 30

LLDP-enabled interface table:

Interface name: GigabitEthernet2/0/1
Interface/peer state: inactive(timeout)
Last known peer chassis ID:
Last known peer port ID:
Last packet sent: 12.4s ago
Last packet received: never

Interface name: GigabitEthernet2/0/2
Interface/peer state: interface down
Last packet sent: never

Interface name: TenGigabitEthernet5/0/1
Interface/peer state: active
Peer chassis ID: 8c:60:4f:dd:ca:52(MAC address)
Remote port ID: Eth1/3/3(Locally assigned)
Last packet sent: 3.6s ago
Last packet received: 5.5s ago

