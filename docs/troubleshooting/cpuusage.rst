.. _cpuusage:

**************
CPU Load/Usage
**************

There are various commands and tools that can help users see FD.io VPP CPU and memory usage at runtime.

Linux top/htop
==============

The Linux top and htop are decent tools to look at FD.io VPP cpu and memory usage, but they will only show
preallocated memory and total CPU usage. These commands can be useful to show which cores VPP is running on.

This is an example of VPP instance that is running on cores 8 and 9. For this output type **top** and then
type **1** when the tool starts.

.. code-block:: console

    $ top

    top - 11:04:04 up 35 days,  3:16,  5 users,  load average: 2.33, 2.23, 2.16
    Tasks: 435 total,   2 running, 432 sleeping,   1 stopped,   0 zombie
    %Cpu0  :  1.0 us,  0.7 sy,  0.0 ni, 98.0 id,  0.0 wa,  0.0 hi,  0.3 si,  0.0 st
    %Cpu1  :  2.0 us,  0.3 sy,  0.0 ni, 97.7 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
    %Cpu2  :  0.7 us,  1.0 sy,  0.0 ni, 98.3 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
    %Cpu3  :  1.7 us,  0.7 sy,  0.0 ni, 97.7 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
    %Cpu4  :  2.0 us,  0.7 sy,  0.0 ni, 97.4 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
    %Cpu5  :  3.0 us,  0.3 sy,  0.0 ni, 96.7 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
    %Cpu6  :  2.3 us,  0.7 sy,  0.0 ni, 97.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
    %Cpu7  :  2.6 us,  0.3 sy,  0.0 ni, 97.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
    %Cpu8  : 96.0 us,  0.3 sy,  0.0 ni,  3.6 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
    %Cpu9  :100.0 us,  0.0 sy,  0.0 ni,  0.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
    %Cpu10 :  1.0 us,  0.3 sy,  0.0 ni, 98.7 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
    ....

VPP Memory Usage
================

For details on VPP memory usage you can use the **show memory** command

This is the example VPP memory usage on 2 cores.

.. code-block:: console

    # vppctl show memory verbose
    Thread 0 vpp_main
    22043 objects, 17878k of 20826k used, 2426k free, 2396k reclaimed, 346k overhead, 1048572k capacity
      alloc. from small object cache: 22875 hits 39973 attempts (57.23%) replacements 5143
      alloc. from free-list: 44732 attempts, 26017 hits (58.16%), 528461 considered (per-attempt 11.81)
      alloc. from vector-expand: 3430
      allocs: 52324 2027.84 clocks/call
      frees: 30280 594.38 clocks/call
    Thread 1 vpp_wk_0
    22043 objects, 17878k of 20826k used, 2427k free, 2396k reclaimed, 346k overhead, 1048572k capacity
      alloc. from small object cache: 22881 hits 39984 attempts (57.23%) replacements 5148
      alloc. from free-list: 44736 attempts, 26021 hits (58.17%), 528465 considered (per-attempt 11.81)
      alloc. from vector-expand: 3430
      allocs: 52335 2027.54 clocks/call
      frees: 30291 594.36 clocks/call
    
VPP CPU Load
============

To find the VPP CPU load or how busy VPP is use the **show runtime** command.

With at least one interface in polling mode, the VPP CPU utilization is always 100%.

A good indicator of CPU load is **"average vectors/node"**. A bigger number means VPP
is more busy but also more efficient. The Maximum value is 255 (unless you change VLIB_FRAME_SIZE in code).
It basically means how many packets are processed in batch.

If VPP is not loaded it will likely poll so fast that it will just get one or few
packets from the rx queue. This is the case shown below on Thread 1. As load goes up vpp
will have more work to do, so it will poll less frequently, and that will result in more
packets waiting in rx queue. More packets will result in more efficient execution of the
code so number of clock cycles / packet will go down. When "average vectors/node" goes up
close to 255, you will likely start observing rx queue tail drops.

.. code-block:: console

    # vppctl show run
    Thread 0 vpp_main (lcore 8)
    Time 6152.9, average vectors/node 0.00, last 128 main loops 0.00 per node 0.00
      vector rates in 0.0000e0, out 0.0000e0, drop 0.0000e0, punt 0.0000e0
                 Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call  
    acl-plugin-fa-cleaner-process  event wait                0               0               1          3.66e4            0.00
    admin-up-down-process          event wait                0               0               1          2.54e3            0.00
    ....
    ---------------
    Thread 1 vpp_wk_0 (lcore 9)
    Time 6152.9, average vectors/node 1.00, last 128 main loops 0.00 per node 0.00
      vector rates in 1.3073e2, out 1.3073e2, drop 6.5009e-4, punt 0.0000e0
                 Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call  
    TenGigabitEthernet86/0/0-outpu   active             804395          804395               0          6.17e2            1.00
    TenGigabitEthernet86/0/0-tx      active             804395          804395               0          7.29e2            1.00
    arp-input                        active                  2               2               0          3.82e4            1.00
    dpdk-input                       polling       24239296364          804398               0          1.59e7            0.00
    error-drop                       active                  4               4               0          4.65e3            1.00
    ethernet-input                   active                  2               2               0          1.08e4            1.00
    interface-output                 active                  1               1               0          3.78e3            1.00
    ip4-glean                        active                  1               1               0          6.98e4            1.00
    ip4-icmp-echo-request            active             804394          804394               0          5.02e2            1.00
    ip4-icmp-input                   active             804394          804394               0          4.63e2            1.00
    ip4-input-no-checksum            active             804394          804394               0          8.51e2            1.00
    ip4-load-balance                 active             804394          804394               0          5.46e2            1.00
    ip4-local                        active             804394          804394               0          5.79e2            1.00
    ip4-lookup                       active             804394          804394               0          5.71e2            1.00
    ip4-rewrite                      active             804393          804393               0          5.69e2            1.00
    ip6-input                        active                  2               2               0          5.72e3            1.00
    ip6-not-enabled                  active                  2               2               0          1.56e4            1.00
    unix-epoll-input                 polling            835722               0               0         3.03e-3            0.00
