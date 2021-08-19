Vpp Stateless Traffic Generation
================================

It's simple to configure vpp as a high-performance stateless traffic
generator. A couple of vpp worker threads running on an older system
can easily generate 20 MPPS' worth of traffic.

In the configurations shown below, we connect a vpp traffic generator
and a vpp UUT using two 40 gigabit ethernet ports on each system:

```
 +-------------------+           +-------------------+
 | traffic generator |           | UUT               |
 | port 0            | <=======> | port 0            |
 | 192.168.40.2/24   |           | 192.168.40.1/24   |
 +-------------------+           +-------------------+

 +-------------------+           +-------------------+
 | traffic generator |           | UUT               |
 | port 1            | <=======> | port 1            |
 | 192.168.41.2/24   |           | 192.168.41.1/24   |
 +-------------------+           +-------------------+
```

Traffic Generator Setup Script
------------------------------

```
 set int ip address FortyGigabitEthernet2/0/0 192.168.40.2/24
 set int ip address FortyGigabitEthernet2/0/1 192.168.41.2/24
 set int state FortyGigabitEthernet2/0/0 up
 set int state FortyGigabitEthernet2/0/1 up

 comment { send traffic to the VPP UUT }

 packet-generator new {
     name worker0
     worker 0
     limit 0
     rate 1.2e7
     size 128-128
     tx-interface FortyGigabitEthernet2/0/0
     node FortyGigabitEthernet2/0/0-output
     data { IP4: 1.2.40 -> 3cfd.fed0.b6c8
            UDP: 192.168.40.10 -> 192.168.50.10
            UDP: 1234 -> 2345
            incrementing 114
     }
 }

 packet-generator new {
     name worker1
     worker 1
     limit 0
     rate 1.2e7
     size 128-128
     tx-interface FortyGigabitEthernet2/0/1
     node FortyGigabitEthernet2/0/1-output
     data { IP4: 1.2.4 -> 3cfd.fed0.b6c9
            UDP: 192.168.41.10 -> 192.168.51.10
            UDP: 1234 -> 2345
            incrementing 114
     }
 }

 comment { delete return traffic on sight }

 ip route add 192.168.50.0/24 via drop
 ip route add 192.168.51.0/24 via drop
```

Note 1: the destination MAC addresses shown in the configuration (e.g.
3cfd.fed0.b6c8 and 3cfd.fed0.b6c9) **must** match the vpp UUT port MAC
addresses.

Note 2: this script assumes that /etc/vpp/startup.conf and/or the
command-line in use specifies (at least) two worker threads. Uncomment
"workers 2" in the cpu configuration section of /etc/vpp/startup.conf:

```
 ## Specify a number of workers to be created
 ## Workers are pinned to N consecutive CPU cores while skipping "skip-cores" CPU core(s)
 ## and main thread's CPU core
 workers 2
```

Any plausible packet generator script - including one which replays
pcap captures - can be used.


UUT Setup Script
----------------

The vpp UUT uses a couple of static routes to forward traffic back to
the traffic generator:

```
 set int ip address FortyGigabitEthernet2/0/0 192.168.40.1/24
 set int ip address FortyGigabitEthernet2/0/1 192.168.41.1/24
 set int state FortyGigabitEthernet2/0/0 up
 set int state FortyGigabitEthernet2/0/1 up

 ip route add 192.168.50.10/32 via 192.168.41.2
 ip route add 192.168.51.10/32 via 192.168.40.2
```
