## Examples    {#libmemif_examples_doc}

Demo examples can be executed after building without installing the library. Example apps binaries can be found in build/examples folder.


Example app | Description
------------|------------
@ref extras/libmemif/examples/ping_responder | Simplest implementaion. Event polling is handled by libmemif. Single memif conenction in slave mode is created (id 0). Use Ctrl + C to exit app. Memif receive mode: interrupt.
@ref extras/libmemif/examples/ping | Supports multiple interfaces in master or slave mode. User can specify interface options. See @ref libmemif_ping_doc for more details and example setup. Memif receive mode: interrupt and polling. App implements command ping on specific queue. Core list can be assigned to each interface. Polling queues pick cpus from this core list. Queue id 0 is handled by main thread in interrupt rx mode.
@ref extras/libmemif/examples/ping_responder-per_thread | Each thread holds unique instance of memif driver (utilizing memif_per_thread_ namespace). Interface indexing is incrementing from 0 for each thread. Creates 4 threads, 3 interfaces per thread. All interfaces are in slave role and use interrupt rx mode.

- @subpage libmemif_ping_doc
- @subpage libmemif_ping_responder_doc
- @subpage libmemif_ping_responder-per_thread_doc
