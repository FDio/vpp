# VPP Link Aggregation Control Protocol (LACP) implementation    {#lacp_doc}

This document is to describe the usage of VPP LACP implementation.


## LACP

The Link Aggregation Control Protocol (LACP) is an 802.3ad standard which
provides a protocol for exchanging information between Partner Systems on a
link to allow their protocol instances to reach agreement on the Link Aggregation
Group to which the link belongs and enable transmission and reception for the
higher layer. Multiple links may be bundled to the same Aggregation Group to form
a high bandwidth transmission medium and create a fault-tolerant link.


### Configuration

1. Create the bundle interface
create bundle <id> mode lacp [hw-addr <mac-address>] [load-balance
{ src-dst-mac | src-mac | dst-mac | src-dst-ip | src-ip | dst-ip }]

2. Enslave the physical interface to the bundle
enslave interface <interface> bundle <id> [passive] [long-timeout]"

3. Delete the bundle interface
delete bundle {<interface> | sw_if_index <sw_idx>}

4. Detach the slave interface from the bundle
detach interface <interface>

### Configuration example

create bundle 1 mode lacp
set interface state bundle1/0 up
enslave interface TenGigabitEthernet7/0/0 bundle 1
enslave interface TenGigabitEthernet7/0/1 bundle 1
enslave interface TenGigabitEthernet5/0/0 bundle 1
enslave interface TenGigabitEthernet5/0/1 bundle 1

detach interface TenGigabitEthernet5/0/1

delete bundle bundle1/0

### Operational data

show lacp [<interface>]

Example:

show lacp


DBGvpp# sh lacp
sh lacp
  TenGigabitEthernet7/0/0
    debug: 0
    Actor
      system: 02:fe:0d:48:d0:f0
      system priority: 65535
      key: 1
      port priority: 255
      port number: 1
      state: 0x3f
        LACP_STATE_LACP_ACTIViTY (0)
        LACP_STATE_LACP_TIMEOUT (1)
        LACP_STATE_AGGREGATION (2)
        LACP_STATE_SYNCHRONIZATION (3)
        LACP_STATE_COLLECTIING (4)
        LACP_STATE_DISTRIBUTING (5)
    Partner
      system: 90:e2:ba:76:cd:70
      system priority: 65535
      key: 15
      port priority: 255
      port number: 1
      state: 0x3f
        LACP_STATE_LACP_ACTIViTY (0)
        LACP_STATE_LACP_TIMEOUT (1)
        LACP_STATE_AGGREGATION (2)
        LACP_STATE_SYNCHRONIZATION (3)
        LACP_STATE_COLLECTIING (4)
        LACP_STATE_DISTRIBUTING (5)
      last heard: 10.1f
    RX-state: CURRENT
    PTX-state: FAST_PERIODIC
    MUX-state: COLLECTING_DISTRIBUTING
    TX-state: TRANSMIT

  TenGigabitEthernet7/0/1
    debug: 0
    Actor
      system: 02:fe:0d:48:d0:f0
      system priority: 65535
      key: 1
      port priority: 255
      port number: 2
      state: 0x3f
        LACP_STATE_LACP_ACTIViTY (0)
        LACP_STATE_LACP_TIMEOUT (1)
        LACP_STATE_AGGREGATION (2)
        LACP_STATE_SYNCHRONIZATION (3)
        LACP_STATE_COLLECTIING (4)
        LACP_STATE_DISTRIBUTING (5)
    Partner
      system: 90:e2:ba:76:cd:70
      system priority: 65535
      key: 15
      port priority: 255
      port number: 2
      state: 0x3f
        LACP_STATE_LACP_ACTIViTY (0)
        LACP_STATE_LACP_TIMEOUT (1)
        LACP_STATE_AGGREGATION (2)
        LACP_STATE_SYNCHRONIZATION (3)
        LACP_STATE_COLLECTIING (4)
        LACP_STATE_DISTRIBUTING (5)
      last heard: 10.1f
    RX-state: CURRENT
    PTX-state: FAST_PERIODIC
    MUX-state: COLLECTING_DISTRIBUTING
    TX-state: TRANSMIT

  TenGigabitEthernet5/0/0
    debug: 0
    Actor
      system: 02:fe:0d:48:d0:f0
      system priority: 65535
      key: 1
      port priority: 255
      port number: 3
      state: 0x3f
        LACP_STATE_LACP_ACTIViTY (0)
        LACP_STATE_LACP_TIMEOUT (1)
        LACP_STATE_AGGREGATION (2)
        LACP_STATE_SYNCHRONIZATION (3)
        LACP_STATE_COLLECTIING (4)
        LACP_STATE_DISTRIBUTING (5)
    Partner
      system: 90:e2:ba:76:cd:70
      system priority: 65535
      key: 15
      port priority: 255
      port number: 3
      state: 0x3f
        LACP_STATE_LACP_ACTIViTY (0)
        LACP_STATE_LACP_TIMEOUT (1)
        LACP_STATE_AGGREGATION (2)
        LACP_STATE_SYNCHRONIZATION (3)
        LACP_STATE_COLLECTIING (4)
        LACP_STATE_DISTRIBUTING (5)
      last heard: 10.1f
    RX-state: CURRENT
    PTX-state: FAST_PERIODIC
    MUX-state: COLLECTING_DISTRIBUTING
    TX-state: TRANSMIT

  TenGigabitEthernet5/0/1
    debug: 0
    Actor
      system: 02:fe:0d:48:d0:f0
      system priority: 65535
      key: 1
      port priority: 255
      port number: 4
      state: 0x3f
        LACP_STATE_LACP_ACTIViTY (0)
        LACP_STATE_LACP_TIMEOUT (1)
        LACP_STATE_AGGREGATION (2)
        LACP_STATE_SYNCHRONIZATION (3)
        LACP_STATE_COLLECTIING (4)
        LACP_STATE_DISTRIBUTING (5)
    Partner
      system: 90:e2:ba:76:cd:70
      system priority: 65535
      key: 15
      port priority: 255
      port number: 4
      state: 0x3f
        LACP_STATE_LACP_ACTIViTY (0)
        LACP_STATE_LACP_TIMEOUT (1)
        LACP_STATE_AGGREGATION (2)
        LACP_STATE_SYNCHRONIZATION (3)
        LACP_STATE_COLLECTIING (4)
        LACP_STATE_DISTRIBUTING (5)
      last heard: 10.1f
    RX-state: CURRENT
    PTX-state: FAST_PERIODIC
    MUX-state: COLLECTING_DISTRIBUTING
    TX-state: TRANSMIT

DBGvpp#

show bundle


DBGvpp# sh bundle
bundle2/0
  number of active slaves: 1
    GigabitEthernet2/0/1
  number of slaves: 1
    GigabitEthernet2/0/1
  device instance: 0
  sw_if_index: 8
  hw_if_index: 8
bundle1/1
  number of active slaves: 4
    TenGigabitEthernet7/0/0
    TenGigabitEthernet7/0/1
    TenGigabitEthernet5/0/1
    TenGigabitEthernet5/0/0
  number of slaves: 4
    TenGigabitEthernet7/0/0
    TenGigabitEthernet7/0/1
    TenGigabitEthernet5/0/0
    TenGigabitEthernet5/0/1
  device instance: 1
  sw_if_index: 9
  hw_if_index: 9
DBGvpp#

### Debugging

debug lacp [<interface>] <on | off>