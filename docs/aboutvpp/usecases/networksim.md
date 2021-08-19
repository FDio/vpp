Network Simulator Plugin
========================

Vpp includes a fairly capable network simulator plugin, which can
simulate real-world round-trip times and a configurable network packet
loss rate. It's perfect for evaluating the performance of a TCP stack
under specified delay/bandwidth/loss conditions.

The "nsim" plugin cross-connects two physical interfaces at layer 2,
introducing the specified delay and network loss
parameters. Reconfiguration on the fly is OK, with the proviso that
packets held in the network simulator scheduling wheel will be lost.

Configuration
-------------

Configuration by debug CLI is simple. First, specify the simulator
configuration: unidirectional delay (half of the desired RTT), the
link bandwidth, and the expected average packet size. These parameters
allow the network simulator allocate the right amount of buffering to
produce the requested delay/bandwidth product.

```
    set nsim delay 25.0 ms bandwidth 10 gbit packet-size 128 
```

To simulate network packet drops, add either "packets-per-drop <nnnnn>" or
"drop-fraction [0.0 ... 1.0]" parameters:

```
    set nsim delay 25.0 ms bandwidth 10 gbit packet-size 128 packets-per-drop 10000
```
Remember to configure the layer-2 cross-connect:

```
    nsim enable-disable <interface-1> <interface-2>
```

Packet Generator Configuration
------------------------------

Here's a unit-test configuration for the vpp packet generator:

```
  loop cre
  set int ip address loop0 11.22.33.1/24
  set int state loop0 up

  loop cre
  set int ip address loop1 11.22.34.1/24
  set int state loop1 up

  set nsim delay 1.0 ms bandwidth 10 gbit packet-size 128 packets-per-drop 1000
  nsim enable-disable loop0 loop1

  packet-generator new {
      name s0
      limit 10000
      size 128-128
      interface loop0
      node ethernet-input
      data { IP4: 1.2.3 -> 4.5.6 
             UDP: 11.22.33.44 -> 11.22.34.44
             UDP: 1234 -> 2345
             incrementing 114 
      }
  } 
```

For extra realism, the network simulator drops any specific packet
with the specified probability. In this example, we see that slight
variation from run to run occurs as it should.

```
    DBGvpp# pa en
    DBGvpp# sh err
       Count                    Node                  Reason
          9991                  nsim                  Packets buffered
             9                  nsim                  Network loss simulation drop packets
          9991             ethernet-input             l3 mac mismatch

    DBGvpp# clear err
    DBGvpp# pa en
    DBGvpp# sh err
    sh err
       Count                    Node                  Reason
          9993                  nsim                  Packets buffered
             7                  nsim                  Network loss simulation drop packets
          9993             ethernet-input             l3 mac mismatch
```
