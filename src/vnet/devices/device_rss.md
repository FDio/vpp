# VPP Queue placement and RSS configuration    {#rss_doc}

VPP runs two different types of threads. The main thread handles CLI, API, processes, etc... While the worker threads perform network RX, processing, and TX.

Each thread continuously runs a processing loop. During that loop, a thread executes the following steps:
1. Do pre-input (not really used).
2. Try to receive packets from some interfaces and queues (mostly done by workers).
3. Execute processes (main thread only).
4. Process received packets (including TX).

Each interface and queue pair is assigned to a single worker thread, but all the packets that are received during a single loop are processed together. 
As a consequence, if a single worker thread polls 4 different RX queues, and transmits the packets on 4 TX queues, packets received on each RX queue might be transmitted arbitrarily on any TX queue.
Before RSS support was introduced in VPP, the solution to this problem would be to run 4 worker threads, each of which would be assigned a single RX queue, and a single TX queue.

RSS support introduces an additional level of granularity in VPP RX and TX scheduling. In addition to assigning RX and TX queues to threads, it is possible to make sure that packets from a given interface and queue will only be received one every few execution loops.

For example, in the case of an interface with 4 queues, it is possible to make sure that a working thread will first receive and process packets from queue 0, then receive and process packets from queue 1, etc... In such a situation, the thread is configured to separate its RX work in 4 different rss slots. Queue 0 is said to be assigned to rss-slot 0, queue 1 is said to be assigned to rss-slot 1, etc...

Similarly, it becomes important to define which TX queues are used by which threads, and on which rss slots. Since VPP assumes packets can flow in any direction, each thread (including the main thread) must be assigned a queue for all interfaces as well as all rss slots (By default, there is a single rss slot on all interfaces, and the configuration is done automatically).

In the same situation as previously, with a single interface with 4 TX queues, it is possible to make sure that a worker thread will use queue 0 on rss-slot 0, queue 1 on rss-slot 1, queue 2 on rss-slot 2, and queue 3 on rss-slot 3, with 4 rss slots in total.

Combining those two techniques, it is possible to make sure that packets received from different queues are transmitted on different queues as well, hence preventing packets from the same flows from being enqueued on different queues.




 





