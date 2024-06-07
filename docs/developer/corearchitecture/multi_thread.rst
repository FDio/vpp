.. _vpp_multi_thread:

Multi-threading in VPP
======================

Modes
-----

VPP can work in 2 different modes:

-  single-thread
-  multi-thread with worker threads

Single-thread
~~~~~~~~~~~~~

In a single-thread mode there is one main thread which handles both
packet processing and other management functions (Command-Line Interface
(CLI), API, stats). This is the default setup. There is no special
startup config needed.

Multi-thread with Worker Threads
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this mode, the main threads handles management functions(debug CLI,
API, stats collection) and one or more worker threads handle packet
processing from input to output of the packet.

Each worker thread polls input queues on subset of interfaces.

With RSS (Receive Side Scaling) enabled multiple threads can service one
physical interface (RSS function on NIC distributes traffic between
different queues which are serviced by different worker threads).

Thread placement
----------------

Thread placement is defined in the startup config under the cpu { … }
section.

The VPP platform can place threads automatically or manually. Automatic
placement works in the following way:

-  if “skip-cores X” is defined first X cores will not be used
-  if “main-core X” is defined, VPP main thread will be placed on core
   X, otherwise 1st available one will be used
-  if “workers N” is defined vpp will allocate first N available cores
   and it will run threads on them
-  if “corelist-workers A,B1-Bn,C1-Cn” is defined vpp will automatically
   assign those CPU cores to worker threads
-  if "translate" is defined, vpp will consider cores it has affinity
   (using sched_getaffinity) rather than all cores available on the
   host machine. This is useful if running in a containerized environment which
   is only allowed to use a subset of the host's CPUs.

User can see active placement of cores by using the VPP debug CLI
command show threads:

.. code-block:: console

   vpd# show threads
   ID     Name                Type        LWP     lcore  Core   Socket State
   0      vpe_main                        59723   2      2      0      wait
   1      vpe_wk_0            workers     59755   4      4      0      running
   2      vpe_wk_1            workers     59756   5      5      0      running
   3      vpe_wk_2            workers     59757   6      0      1      running
   4      vpe_wk_3            workers     59758   7      1      1      running
   5                          stats       59775
   vpd#

The sample output above shows the main thread running on core 2 (2nd
core on the CPU socket 0), worker threads running on cores 4-7.

Sample Configurations
---------------------

By default, at start-up VPP uses
configuration values from: ``/etc/vpp/startup.conf``

The following sections describe some of the additional changes that can be made to this file.
This file is initially populated from the files located in the following directory ``/vpp/vpp/conf/``

Manual Placement
~~~~~~~~~~~~~~~~

Manual placement places the main thread on core 1, workers on cores
4,5,20,21.

.. code-block:: console

   cpu {
     main-core 1
     corelist-workers  4-5,20-21
   }

Auto placement
--------------

Auto placement is likely to place the main thread on core 1 and workers
on cores 2,3,4.

.. code-block:: console

   cpu {
     skip-cores 1
     workers 3
   }

Translated Placement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Translated placement can be used in addition to manual or auto placement. It takes
into consideration that the VPP might be allowed to run on a limited subset of
logical cores on the host machine (e.g. running in a container), and automatically
remaps the user requested pinning configuration to the logical cores available to VPP
(checked using sched_getaffinity).
If a VPP instance runs with CPU set 20,25,26,27 and translate mode is enabled, a
manual placement of main thread on core 0 and workers on cores 2,3 will result
in placement of main thread on core 20 and workers on cores 26,27.

.. code-block:: console

   cpu {
   main-core 0
   corelist-workers  2-3
   translate
   }

Buffer Memory Allocation
~~~~~~~~~~~~~~~~~~~~~~~~

The VPP platform is NUMA aware. It can allocate memory for buffers on
different CPU sockets (NUMA nodes). The amount of memory allocated can
be defined in the startup config for each CPU socket by using the
socket-mem A[[,B],C] statement inside the dpdk { … } section.

For example:

.. code-block:: console

   dpdk {
     socket-mem 1024,1024
   }

The above configuration allocates 1GB of memory on NUMA#0 and 1GB on
NUMA#1. Each worker thread uses buffers which are local to itself.

Buffer memory is allocated from hugepages. VPP prefers 1G pages if they
are available. If not 2MB pages will be used.

VPP takes care of mounting/unmounting hugepages file-system
automatically so there is no need to do that manually.

’‘’NOTE’’’: If you are running latest VPP release, there is no need for
specifying socket-mem manually. VPP will discover all NUMA nodes and it
will allocate 512M on each by default. socket-mem is only needed if
bigger number of mbufs is required (default is 16384 per socket and can
be changed with num-mbufs startup config command).

Interface Placement in Multi-thread Setup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On startup, the VPP platform assigns interfaces (or interface, queue
pairs if RSS is used) to different worker threads in round robin
fashion.

The following example shows debug CLI commands to show and change
interface placement:

.. code-block:: console

   vpd# sh dpdk interface placement
   Thread 1 (vpp_wk_0 at lcore 5):
    TenGigabitEthernet2/0/0 queue 0
    TenGigabitEthernet2/0/1 queue 0
   Thread 2 (vpp_wk_1 at lcore 6):
    TenGigabitEthernet2/0/0 queue 1
    TenGigabitEthernet2/0/1 queue 1

The following shows an example of moving TenGigabitEthernet2/0/1 queue 1
processing to 1st worker thread:

.. code-block:: console

   vpd# set interface placement TenGigabitEthernet2/0/1 queue 1 thread 1

   vpp# sh dpdk interface placement
   Thread 1 (vpp_wk_0 at lcore 5):
    TenGigabitEthernet2/0/0 queue 0
    TenGigabitEthernet2/0/1 queue 0
    TenGigabitEthernet2/0/1 queue 1
   Thread 2 (vpp_wk_1 at lcore 6):
    TenGigabitEthernet2/0/0 queue 1
