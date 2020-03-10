## Examples    {#libmemif_examples_doc}

Demo examples can be executed after building without installing the library. Example apps binaries can be found in build/examples folder.


Example app | Description
------------|------------
<<<<<<< HEAD
@ref extras/libmemif/examples/icmp_responder | Simplest implementation. Event polling is handled by libmemif. Single memif connection in slave mode is created (id 0). Use Ctrl + C to exit app. Memif receive mode: interrupt.
@ref extras/libmemif/examples/icmp_responder-epoll (run in container by default) | Supports multiple connections and master mode. User can create/delete connections, set ip addresses, print connection information. @ref libmemif_example_setup_doc contains instructions on basic connection use cases setups. Memif receive mode: interrupt. App provides functionality to disable interrupts for specified queue/s for testing purposes. Polling mode is not implemented in this example.
@ref extras/libmemif/examples/icmp_responder-mt) | Multi-thread example, very similar to icmpr-epoll. Packets are handled in threads assigned to specific queues. Slave mode only. Memif receive mode: polling (memif_rx_poll function), interrupt (memif_rx_interrupt function). Receive modes differ per queue.
=======
@ref extras/libmemif/examples/ping_responder | Simplest implementaion. Event polling is handled by libmemif. Single memif conenction in slave mode is created (id 0). Use Ctrl + C to exit app. Memif receive mode: interrupt.
@ref extras/libmemif/examples/ping | Supports multiple interfaces in master or slave mode. User can specify interface options. See @ref libmemif_ping_doc for more details and example setup. Memif receive mode: interrupt and polling. App implements command ping on specific queue. Core list can be assigned to each interface. Polling queues pick cpus from this core list. Queue id 0 is handled by main thread in interrupt rx mode.
@ref extras/libmemif/examples/ping_responder-per_thread | Each thread holds unique instance of memif driver (utilizing memif_per_thread_ namespace). Interface indexing is incrementing from 0 for each thread. Creates 4 threads, 3 interfaces per thread. All interfaces are in slave role and use interrupt rx mode.

- @subpage libmemif_ping_doc
- @subpage libmemif_ping_responder_doc
- @subpage libmemif_ping_responder-per_thread_doc
>>>>>>> libmemif: update example applications and documentation
