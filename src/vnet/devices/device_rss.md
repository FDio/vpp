# VPP Queue placement and RSS configuration    {#rss_doc}

VPP runs different types of threads. The main thread handles CLI, API, processes, etc... While the worker threads perform network RX, processing, and TX.

Each thread continuously runs a processing loop. During that loop, a thread executes the following steps:
1. Do pre-input (not really used).
2. Try to receive packets from some interfaces and queues (mostly done by workers).
3. Execute processes (main thread only).
4. Process received packets until completion.

Each interface and queue pair is assigned to a single worker thread, but all the packets that are received during a single loop are processed together. 
As a consequence, if a single worker thread polls 4 different RX queues, and transmits the packets on 4 TX queues, packets received on each RX queue might be transmitted arbitrarily on any TX queue.

## RSS Support Overview

VPP RSS support introduces an additional level of granularity in VPP RX and TX scheduling. In addition to traditional RX and TX queue assignment to threads, it becomes possible to isolate the processing of each RX queues, and deterministically control on which TX queue a given RX queue will be forwarded. Hence protecting RSS classification done by input devices.

For example, in the case of an interface with 4 queues, it is possible to make sure that a working thread will first receive and process packets from queue 0, then receive and process packets from queue 1, then from queue 2, then from queue 3, and repeat. In such a situation, the thread is configured to separate its RX work in 4 different rss slots. Queue 0 is said to be assigned to rss-slot 0, queue 1 is said to be assigned to rss-slot 1, etc...

Similarly, it becomes possible to define which TX queue is used by which thread for which rss slot. Since VPP assumes packets can flow in any direction, each thread (including the main thread) must be assigned a queue for all interfaces as well as all RSS slots.

Although this behavior might look similar to having more threads, it is worth pointing out that the same TX queue can be used in a lock-less fashion even if it is used on multiple rss slots. But a lock has to be used if two threads are using the same queue (even if the rss slots are different).

Combining RX and TX queue assignment, it is possible to make sure that packets received from different queues are transmitted on different queues as well, hence leveraging RSS classification performed by the input devices.

## Configuration Model

### Number of slots

The number of RSS slots can be configured for each interface and thread. The number of slots can also be different on RX and TX. Valid values are power of twos from 1 to 2^15.

For example, using the CLI:
set interface rx-placement FortyGigabitEthernet88/0/0 worker 0 rss 4
set interface rx-placement FortyGigabitEthernet88/0/0 worker 1 rss 2
set interface rx-placement VirtualEthernet0/0/0       worker 0 rss 2
set interface rx-placement VirtualEthernet0/0/0       worker 1 rss 4

set interface tx-placement FortyGigabitEthernet88/0/0 thread 1 rss 4
set interface tx-placement FortyGigabitEthernet88/0/0 thread 2 rss 2
set interface tx-placement VirtualEthernet0/0/0       thread 1 rss 2
set interface tx-placement VirtualEthernet0/0/0       thread 2 rss 4

By default, the number of RSS slots is always 1. Which is equivalent to not using the RSS feature.

### Queue assignment

Each active RX queue of each device is assigned to exactly one RSS slot of one worker thread, either automatically, or manually.

For example, using the CLI:
set int rx-placement FortyGigabitEthernet88/0/0 queue 0 worker 0 rss-slot 0
set int rx-placement FortyGigabitEthernet88/0/0 queue 1 worker 0 rss-slot 1
set int rx-placement FortyGigabitEthernet88/0/0 queue 2 worker 1
set int rx-placement FortyGigabitEthernet88/0/0 queue 3 worker 1 rss-slot 1

When rss-slot is not specified, "rss-slot 0" is used.

Each thread must be able to send packets on any active interface. Therefore,
each RSS slot of each thread is assigned a unique active TX queue for each device. This is also done automatically, or manually.

For example, using the CLI:
set int tx-placement VirtualEthernet0/0/0 thread 0 queue 0
set int tx-placement VirtualEthernet0/0/0 thread 1 rss-slot 0 queue 1
set int tx-placement VirtualEthernet0/0/0 thread 1 rss-slot 1 queue 2
set int tx-placement VirtualEthernet0/0/0 thread 1 rss-slot 2 queue 3
set int tx-placement VirtualEthernet0/0/0 thread 1 rss-slot 3 queue 4

When rss-slot is not specified, "rss-slot 0" is used.
 
