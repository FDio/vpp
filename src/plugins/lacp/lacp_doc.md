# VPP Link Aggregation Control Protocol (LACP) implementation    {#lacp_plugin_doc}

This document is to describe the usage of VPP LACP implementation.

## LACP

The Link Aggregation Control Protocol (LACP) is an 802.3ad standard which
provides a protocol for exchanging information between Partner Systems on a
link to allow their protocol instances to reach agreement on the Link Aggregation
Group to which the link belongs and enable transmission and reception for the
higher layer. Multiple links may be bundled to the same Aggregation Group to form
a high bandwidth transmission medium and create a fault-tolerant link.


### Configuration

1. Create the bond interface
create bond mode lacp [hw-addr <mac-address>] [load-balance { l2 | l23 | l34 }]

2. Enslave the physical interface to the bond
bond add <bond-interface-name> <slave-interface> [passive] [long-timeout]"

3. Delete the bond interface
delete bond {<interface> | sw_if_index <sw_idx>}

4. Detach the slave interface from the bond
bond del <slave-interface>

### Configuration example

```
create bond mode lacp
set interface state BondEthernet0 up
bond add BondEthernet0 TenGigabitEthernet7/0/0
bond add BondEthernet0 TenGigabitEthernet7/0/1
bond add BondEthernet0 TenGigabitEthernet5/0/0
bond add BondEthernet0 TenGigabitEthernet5/0/1
```

```
bond del TenGigabitEthernet5/0/1
```

```
delete bond BondEthernet0
```

### Operational data

```
show lacp [<interface>] [details]
```

Example:

```
DBGvpp# show lacp
                                                        actor state                      partner state
interface name            sw_if_index  bond interface   exp/def/dis/col/syn/agg/tim/act  exp/def/dis/col/syn/agg/tim/act
GigabitEthernet2/0/1      1            BondEthernet0      0   0   1   1   1   1   1   1    0   0   1   1   1   1   1   1
  LAG ID: [(ffff,e4-c7-22-f3-26-71,0000,00ff,0001), (ffff,fc-99-47-4a-0c-8b,0009,00ff,0001)]
  RX-state: CURRENT, TX-state: TRANSMIT, MUX-state: COLLECTING_DISTRIBUTING, PTX-state: PERIODIC_TX
TenGigabitEthernet4/0/0   2            BondEthernet1      0   0   1   1   1   1   1   1    0   0   1   1   1   1   0   1
  LAG ID: [(ffff,90-e2-ba-76-cf-2d,0001,00ff,0001), (8000,00-2a-6a-e5-50-c1,0140,8000,011d)]
  RX-state: CURRENT, TX-state: TRANSMIT, MUX-state: COLLECTING_DISTRIBUTING, PTX-state: PERIODIC_TX
TenGigabitEthernet4/0/1   3            BondEthernet1      0   0   1   1   1   1   1   1    0   0   1   1   1   1   0   1
  LAG ID: [(ffff,90-e2-ba-76-cf-2d,0001,00ff,0002), (8000,00-2a-6a-e5-50-c1,0140,8000,011e)]
  RX-state: CURRENT, TX-state: TRANSMIT, MUX-state: COLLECTING_DISTRIBUTING, PTX-state: PERIODIC_TX
TenGigabitEthernet8/0/1   7            BondEthernet1      0   0   1   1   1   1   1   1    0   0   1   1   1   1   0   1
  LAG ID: [(ffff,90-e2-ba-76-cf-2d,0001,00ff,0003), (8000,00-2a-6a-e5-50-01,007a,8000,0114)]
  RX-state: CURRENT, TX-state: TRANSMIT, MUX-state: COLLECTING_DISTRIBUTING, PTX-state: PERIODIC_TX
TenGigabitEthernet8/0/0   6            BondEthernet1      0   0   1   1   1   1   1   1    0   0   1   1   1   1   0   1
  LAG ID: [(ffff,90-e2-ba-76-cf-2d,0001,00ff,0004), (8000,00-2a-6a-e5-50-01,007a,8000,0115)]
  RX-state: CURRENT, TX-state: TRANSMIT, MUX-state: COLLECTING_DISTRIBUTING, PTX-state: PERIODIC_TX
TenGigabitEthernet6/0/1   5            BondEthernet2      0   0   1   1   1   1   1   1    0   0   1   1   1   1   1   1
  LAG ID: [(ffff,90-e2-ba-36-31-21,0002,00ff,0001), (ffff,90-e2-ba-29-f5-31,000f,00ff,0002)]
  RX-state: CURRENT, TX-state: TRANSMIT, MUX-state: COLLECTING_DISTRIBUTING, PTX-state: PERIODIC_TX
TenGigabitEthernet6/0/0   4            BondEthernet2      0   0   1   1   1   1   1   1    0   0   1   1   1   1   1   1
  LAG ID: [(ffff,90-e2-ba-36-31-21,0002,00ff,0002), (ffff,90-e2-ba-29-f5-31,000f,00ff,0001)]
  RX-state: CURRENT, TX-state: TRANSMIT, MUX-state: COLLECTING_DISTRIBUTING, PTX-state: PERIODIC_TX
DBGvpp#
```

```
show bond [details]
````

Example:

```
DBGvpp# show bond
sh bond
interface name   sw_if_index   mode         load balance  active slaves  slaves
BondEthernet0    10            lacp         l2            1              1
BondEthernet1    11            lacp         l34           4              4
BondEthernet2    12            lacp         l23           2              2
DBGvpp#
```

### Debugging

```
debug lacp [<interface>] <on | off>
```
