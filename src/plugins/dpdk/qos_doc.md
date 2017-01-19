# QoS Hierarchical Scheduler    {#qos_doc}

The Quality-of-Service (QoS) scheduler performs egress-traffic management by
prioritizing the transmission of the packets of different type services and
subcribers based on the Service Level Agreements (SLAs). The QoS scheduler can
be enabled on one or more NIC output interfaces depending upon the
requirement.


## Overview

The QoS schdeuler supports a number of scheduling and shaping levels which
construct hierarchical-tree. The first level in the hierarchy is port (i.e.
the physical interface) that constitutes the root node of the tree. The
subsequent level is subport which represents the group of the
users/subscribers. The individual user/subscriber is represented by the pipe
at the next level. Each user can have different traffic type based on the
criteria of specific loss rate, jitter, and latency. These traffic types are
represented at the traffic-class level in the form of different traffic-
classes. The last level contains number of queues which are grouped together
to host the packets of the specific class type traffic.

The QoS scheduler implementation requires flow classification, enqueue  and
dequeue operations. The flow classification is mandatory stage for HQoS where
incoming packets are classified by mapping the packet fields information to
5-tuple (HQoS subport, pipe, traffic class, queue within traffic class, and
color) and storing that information in mbuf sched field. The enqueue operation
uses this information to determine the queue for storing the packet, and at
this stage, if the specific queue is full, QoS drops the packet. The dequeue
operation consists of scheduling the packet based on its length and available
credits, and handing over the scheduled packet to the output interface.

For more information on QoS Scheduler, please refer DPDK Programmer's Guide-
http://dpdk.org/doc/guides/prog_guide/qos_framework.html


### QoS Schdeuler Parameters

Following illustrates the default HQoS configuration for each 10GbE output
port:

Single subport (subport 0):
  - Subport rate set to 100% of port rate
  - Each of the 4 traffic classes has rate set to 100% of port rate

4K pipes per subport 0 (pipes 0 .. 4095) with identical configuration:
  - Pipe rate set to 1/4K of port rate
  - Each of the 4 traffic classes has rate set to 100% of pipe rate
  - Within each traffic class, the byte-level WRR weights for the 4 queues are set to 1:1:1:1


#### Port configuration

```
port {
  rate 1250000000           /* Assuming 10GbE port */
  frame_overhead 24         /* Overhead fields per Ethernet frame:
                             * 7B (Preamble) +
                             * 1B (Start of Frame Delimiter (SFD)) + 
                             * 4B (Frame Check Sequence (FCS)) +
                             * 12B (Inter Frame Gap (IFG))
                             */
  mtu 1522                  /* Assuming Ethernet/IPv4 pkt (FCS not included) */
  n_subports_per_port 1     /* Number of subports per output interface */
  n_pipes_per_subport 4096  /* Number of pipes (users/subscribers) */
  queue_sizes 64 64 64 64   /* Packet queue size for each traffic class.
                             * All queues within the same pipe traffic class
                             * have the same size. Queues from different
                             * pipes serving the same traffic class have
                             * the same size. */
}
```


#### Subport configuration

```
subport 0 {
  tb_rate 1250000000        /* Subport level token bucket rate (bytes per second) */
  tb_size 1000000           /* Subport level token bucket size (bytes) */
  tc0_rate 1250000000       /* Subport level token bucket rate for traffic class 0 (bytes per second) */
  tc1_rate 1250000000       /* Subport level token bucket rate for traffic class 1 (bytes per second) */
  tc2_rate 1250000000       /* Subport level token bucket rate for traffic class 2 (bytes per second) */
  tc3_rate 1250000000       /* Subport level token bucket rate for traffic class 3 (bytes per second) */
  tc_period 10              /* Time interval for refilling the token bucket associated with traffic class (Milliseconds) */
  pipe 0 4095 profile 0     /* pipes (users/subscribers) configured with pipe profile 0 */
}
```


#### Pipe configuration

```
pipe_profile 0 {
  tb_rate 305175          /* Pipe level token bucket rate (bytes per second) */
  tb_size 1000000         /* Pipe level token bucket size (bytes) */
  tc0_rate 305175         /* Pipe level token bucket rate for traffic class 0 (bytes per second) */
  tc1_rate 305175         /* Pipe level token bucket rate for traffic class 1 (bytes per second) */
  tc2_rate 305175         /* Pipe level token bucket rate for traffic class 2 (bytes per second) */
  tc3_rate 305175         /* Pipe level token bucket rate for traffic class 3 (bytes per second) */
  tc_period 40            /* Time interval for refilling the token bucket associated with traffic class at pipe level (Milliseconds) */
  tc3_oversubscription_weight 1 /* Weight traffic class 3 oversubscription */
  tc0_wrr_weights 1 1 1 1     /* Pipe queues WRR weights for traffic class 0 */
  tc1_wrr_weights 1 1 1 1     /* Pipe queues WRR weights for traffic class 1 */
  tc2_wrr_weights 1 1 1 1     /* Pipe queues WRR weights for traffic class 2 */
  tc3_wrr_weights 1 1 1 1     /* Pipe queues WRR weights for traffic class 3 */
}
```


#### Random Early Detection (RED) parameters per traffic class and color (Green / Yellow / Red)

```
red {
  tc0_wred_min 48 40 32     /* Minimum threshold for traffic class 0 queue (min_th) in number of packets */
  tc0_wred_max 64 64 64     /* Maximum threshold for traffic class 0 queue (max_th) in number of packets */
  tc0_wred_inv_prob 10 10 10    /* Inverse of packet marking probability for traffic class 0 queue (maxp = 1 / maxp_inv) */
  tc0_wred_weight 9 9 9     /* Traffic Class 0 queue weight */
  tc1_wred_min 48 40 32     /* Minimum threshold for traffic class 1 queue (min_th) in number of packets */
  tc1_wred_max 64 64 64     /* Maximum threshold for traffic class 1 queue (max_th) in number of packets */
  tc1_wred_inv_prob 10 10 10    /* Inverse of packet marking probability for traffic class 1 queue (maxp = 1 / maxp_inv) */
  tc1_wred_weight 9 9 9     /* Traffic Class 1 queue weight */
  tc2_wred_min 48 40 32     /* Minimum threshold for traffic class 2 queue (min_th) in number of packets */
  tc2_wred_max 64 64 64     /* Maximum threshold for traffic class 2 queue (max_th) in number of packets */
  tc2_wred_inv_prob 10 10 10    /* Inverse of packet marking probability for traffic class 2 queue (maxp = 1 / maxp_inv) */
  tc2_wred_weight 9 9 9     /* Traffic Class 2 queue weight */
  tc3_wred_min 48 40 32     /* Minimum threshold for traffic class 3 queue (min_th) in number of packets */
  tc3_wred_max 64 64 64     /* Maximum threshold for traffic class 3 queue (max_th) in number of packets */
  tc3_wred_inv_prob 10 10 10    /* Inverse of packet marking probability for traffic class 3 queue (maxp = 1 / maxp_inv) */
  tc3_wred_weight 9 9 9     /* Traffic Class 3 queue weight */
}
```


### DPDK QoS Scheduler Integration in VPP

The Hierarchical Quaity-of-Service (HQoS) scheduler object could be seen as
part of the logical NIC output interface. To enable HQoS on specific output
interface, vpp startup.conf file has to be configured accordingly. The output
interface that requires HQoS, should have "hqos" parameter specified in dpdk
section. Another optional parameter "hqos-thread"  has been defined which can
be used to associate the output interface with specific hqos thread. In cpu
section of the config file, "corelist-hqos-threads" is introduced to assign
logical cpu cores to run the HQoS threads. A HQoS thread can run multiple HQoS
objects each associated with different output interfaces. All worker threads
instead of writing packets to NIC TX queue directly, write the packets to a
software queues. The hqos_threads read the software queues, and enqueue the
packets to HQoS objects, as well as dequeue packets from HQOS objects and
write them to NIC output interfaces. The worker threads need to be able to
send the packets to any output interface, therefore, each HQoS object
associated with NIC output interface should have software queues equal to
worker threads count.

Following illustrates the sample startup configuration file with 4x worker
threads feeding 2x hqos threads that handle each QoS scheduler for 1x output
interface.

```
dpdk {
  socket-mem 16384,16384

  dev 0000:02:00.0 {
    num-rx-queues 2
    hqos
  }
  dev 0000:06:00.0 {
    num-rx-queues 2
    hqos
  }

  num-mbufs 1000000
}

cpu {
  main-core 0
  corelist-workers  1, 2, 3, 4
  corelist-hqos-threads  5, 6
}
```


### QoS scheduler CLI Commands

Each QoS scheduler instance is initialised with default parameters required to
configure hqos port, subport, pipe and queues. Some of the parameters can be
re-configured in run-time through CLI commands.


#### Configuration

Following commands can be used to configure QoS scheduler parameters.

The command below can be used to set the subport level parameters such as
token bucket rate (bytes per seconds), token bucket size (bytes), traffic
class rates (bytes per seconds) and token update period (Milliseconds).

```
set dpdk interface hqos subport <interface> subport <subport_id> [rate <n>]
    [bktsize <n>] [tc0 <n>] [tc1 <n>] [tc2 <n>] [tc3 <n>] [period <n>]
```

For setting the pipe profile, following command can be used.    

```
set dpdk interface hqos pipe <interface> subport <subport_id> pipe <pipe_id>
    profile <profile_id>
```

To assign QoS scheduler instance to the specific thread, following command can
be used.

```
set dpdk interface hqos placement <interface> thread <n>
```

The command below is used to set the packet fields required for classifiying
the incoming packet. As a result of classification process,     packet field
information will be mapped to 5 tuples (subport, pipe, traffic class, pipe,
color) and stored in packet mbuf.

```
set dpdk interface hqos pktfield <interface> id subport|pipe|tc offset <n>
    mask <hex-mask>
```

The DSCP table entries used for idenfiying the traffic class and queue can be set using the command below;   

```  
set dpdk interface hqos tctbl <interface> entry <map_val> tc <tc_id> queue <queue_id>
```


#### Show Command

The QoS Scheduler configuration can displayed using the command below.

```
   vpp# show dpdk interface hqos TenGigabitEthernet2/0/0
   Thread:
     Input SWQ size = 4096 packets
     Enqueue burst size = 256 packets
     Dequeue burst size = 220 packets
     Packet field 0: slab position =    0, slab bitmask = 0x0000000000000000   (subport)
     Packet field 1: slab position =   40, slab bitmask = 0x0000000fff000000   (pipe)
     Packet field 2: slab position =    8, slab bitmask = 0x00000000000000fc   (tc)
     Packet field 2  tc translation table: ([Mapped Value Range]: tc/queue tc/queue ...)
     [ 0 .. 15]: 0/0 0/1 0/2 0/3 1/0 1/1 1/2 1/3 2/0 2/1 2/2 2/3 3/0 3/1 3/2 3/3
     [16 .. 31]: 0/0 0/1 0/2 0/3 1/0 1/1 1/2 1/3 2/0 2/1 2/2 2/3 3/0 3/1 3/2 3/3
     [32 .. 47]: 0/0 0/1 0/2 0/3 1/0 1/1 1/2 1/3 2/0 2/1 2/2 2/3 3/0 3/1 3/2 3/3
     [48 .. 63]: 0/0 0/1 0/2 0/3 1/0 1/1 1/2 1/3 2/0 2/1 2/2 2/3 3/0 3/1 3/2 3/3
   Port:
     Rate = 1250000000 bytes/second
     MTU = 1514 bytes
     Frame overhead = 24 bytes
     Number of subports = 1
     Number of pipes per subport = 4096
     Packet queue size: TC0 = 64, TC1 = 64, TC2 = 64, TC3 = 64 packets
     Number of pipe profiles = 1
   Subport 0:
     Rate = 120000000 bytes/second
     Token bucket size = 1000000 bytes
     Traffic class rate: TC0 = 120000000, TC1 = 120000000, TC2 = 120000000, TC3 = 120000000 bytes/second
     TC period = 10 milliseconds
   Pipe profile 0:
     Rate = 305175 bytes/second
     Token bucket size = 1000000 bytes
     Traffic class rate: TC0 = 305175, TC1 = 305175, TC2 = 305175, TC3 = 305175 bytes/second
     TC period = 40 milliseconds
     TC0 WRR weights: Q0 = 1, Q1 = 1, Q2 = 1, Q3 = 1
     TC1 WRR weights: Q0 = 1, Q1 = 1, Q2 = 1, Q3 = 1
     TC2 WRR weights: Q0 = 1, Q1 = 1, Q2 = 1, Q3 = 1
     TC3 WRR weights: Q0 = 1, Q1 = 1, Q2 = 1, Q3 = 1
```

The QoS Scheduler placement over the logical cpu cores can be displayed using
below command.

```
    vpp# show dpdk interface hqos placement
    Thread 5 (vpp_hqos-threads_0 at lcore 5):
      TenGigabitEthernet2/0/0 queue 0
    Thread 6 (vpp_hqos-threads_1 at lcore 6):
      TenGigabitEthernet4/0/1 queue 0
```


### QoS Scheduler Binary APIs

This section explans the available binary APIs for configuring QoS scheduler
parameters in run-time.

The following API can be used to set the pipe profile of a pipe that belongs
to a given subport:

```
sw_interface_set_dpdk_hqos_pipe rx <intfc> | sw_if_index <id>
    subport <subport-id> pipe <pipe-id> profile <profile-id>
```

The data structures used for set the pipe profile parameter are as follows;

```
  /** \\brief DPDK interface HQoS pipe profile set request
    @param client_index - opaque cookie to identify the sender
    @param context - sender context, to match reply w/ request
    @param sw_if_index - the interface
    @param subport - subport ID
    @param pipe - pipe ID within its subport
    @param profile - pipe profile ID
  */
  define sw_interface_set_dpdk_hqos_pipe {
    u32 client_index;
    u32 context;
    u32 sw_if_index;
    u32 subport;
    u32 pipe;
    u32 profile;
  };

  /** \\brief DPDK interface HQoS pipe profile set reply
    @param context - sender context, to match reply w/ request
    @param retval - request return code
  */
  define sw_interface_set_dpdk_hqos_pipe_reply {
    u32 context;
    i32 retval;
  };
```

The following API can be used to set the subport level parameters, for
example- token bucket rate (bytes per seconds), token bucket size (bytes),
traffic class rate (bytes per seconds) and tokens update period.

```
sw_interface_set_dpdk_hqos_subport rx <intfc> | sw_if_index <id>
    subport <subport-id> [rate <n>] [bktsize <n>]
    [tc0 <n>] [tc1 <n>] [tc2 <n>] [tc3 <n>] [period <n>]
```

The data structures used for set the subport level parameter are as follows;

```
  /** \\brief DPDK interface HQoS subport parameters set request
    @param client_index - opaque cookie to identify the sender
    @param context - sender context, to match reply w/ request
    @param sw_if_index - the interface
    @param subport - subport ID
    @param tb_rate - subport token bucket rate (measured in bytes/second)
    @param tb_size - subport token bucket size (measured in credits)
    @param tc_rate - subport traffic class 0 .. 3 rates (measured in bytes/second)
    @param tc_period - enforcement period for rates (measured in milliseconds)
  */
  define sw_interface_set_dpdk_hqos_subport {
    u32 client_index;
    u32 context;
    u32 sw_if_index;
    u32 subport;
    u32 tb_rate;
    u32 tb_size;
    u32 tc_rate[4];
    u32 tc_period;
  };

  /** \\brief DPDK interface HQoS subport parameters set reply
    @param context - sender context, to match reply w/ request
    @param retval - request return code
  */
  define sw_interface_set_dpdk_hqos_subport_reply {
    u32 context;
    i32 retval;
  };
```

The following API can be used set the DSCP table entry. The DSCP table have
64 entries to map the packet DSCP field onto traffic class and hqos input
queue.

```
sw_interface_set_dpdk_hqos_tctbl rx <intfc> | sw_if_index <id> 
    entry <n> tc <n> queue <n>
```

The data structures used for setting DSCP table entries are given below.

```
  /** \\brief DPDK interface HQoS tctbl entry set request
    @param client_index - opaque cookie to identify the sender
    @param context - sender context, to match reply w/ request
    @param sw_if_index - the interface
    @param entry - entry index ID
    @param tc - traffic class (0 .. 3)
    @param queue - traffic class queue (0 .. 3)
  */
  define sw_interface_set_dpdk_hqos_tctbl {
    u32 client_index;
    u32 context;
    u32 sw_if_index;
    u32 entry;
    u32 tc;
    u32 queue;
  };

  /** \\brief DPDK interface HQoS tctbl entry set reply
    @param context - sender context, to match reply w/ request
    @param retval - request return code
  */
  define sw_interface_set_dpdk_hqos_tctbl_reply {
    u32 context;
    i32 retval;
  };
```
