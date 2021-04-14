# Active-Passive NAT HA

## Introduction

One NAT node actively manages traffic while the other is synchronized and ready to transition to the active state and takes over seamlessly and enforces the same NAT sessions when failure occur. Both nodes share the same configuration settings.

## Configuration

### NAT HA protocol
Session synchronization traffic is distributed through an IPv4 UDP connection. The active node sends NAT HA protocol events to passive node. To achieve reliable transfer NAT HA protocol uses acknowledgement with re-transmission. This require the passive node to respond with an acknowledgement message as it receives the data. The active node keeps a record of each packet it sends and maintains a timer from when the packet was sent. The active node re-transmits a packet if the timer expires before receiving the acknowledgement.

### Topology

The two NAT nodes have a dedicated link (interface GE0/0/3 on both) to synchronize NAT sessions using NAT HA protocol.

```
        +-----------------------+
        |    outside network    |
        +-----------------------+
         /                     \
        /                       \
       /                         \
      /                           \
     /                             \
+---------+                   +---------+
| GE0/0/1 | Active    Passive | GE0/0/1 |
|         |                   |         |
|  GE0/0/3|-------------------|GE0/0/3  |
|         |   sync network    |         |
| GE0/0/0 |                   | GE0/0/0 |
+---------+                   +---------+
     \                             /
      \                           /
       \                         /
        \                       /
         \                     /
        +-----------------------+
        |    inside network     |
        +-----------------------+
```

### Active node configuration

```
set interface ip address GigabitEthernet0/0/1 10.15.7.101/24
set interface ip address GigabitEthernet0/0/0 172.16.10.101/24
set interface ip address GigabitEthernet0/0/3 10.0.0.1/24
set interface state GigabitEthernet0/0/0 up
set interface state GigabitEthernet0/0/1 up
set interface state GigabitEthernet0/0/3 up
set interface nat44 in GigabitEthernet0/0/0 out GigabitEthernet0/0/1
nat44 add address 10.15.7.100
nat ha listener 10.0.0.1:1234
nat ha failover 10.0.0.2:2345
```

### Passive node configuration

```
set interface ip address GigabitEthernet0/0/1 10.15.7.102/24
set interface ip address GigabitEthernet0/0/0 172.16.10.102/24
set interface ip address GigabitEthernet0/0/3 10.0.0.2/24
set interface state GigabitEthernet0/0/0 up
set interface state GigabitEthernet0/0/1 up
set interface state GigabitEthernet0/0/3 up
set interface nat44 in GigabitEthernet0/0/0 out GigabitEthernet0/0/1
nat44 add address 10.15.7.100
nat ha listener 10.0.0.2:2345
```

