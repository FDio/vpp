Shared Memory Packet Interface (memif) Library    {#libmemif_doc}
==============================================

## Introduction

Shared memory packet interface (memif) provides high performance packet transmit and receive between user application and Vector Packet Processing (VPP) or multiple user applications. Using libmemif, user application can create shared memory interface in master or slave mode and connect to VPP or another application using libmemif. Once the connection is established, user application can receive or transmit packets using libmemif API.

![Architecture](docs/architecture.png)

## Features

- [x] Slave mode
  - [x] Connect to VPP over memif
  - [x] ICMP responder example app
- [x] Transmit/receive packets
- [x] Interrupt mode support
- [x] File descriptor event polling in libmemif (optional)
  - [x] Simplify file descriptor event polling (one handler for control and interrupt channel)
- [x] Multiple connections
- [x] Multiple queues
  - [x] Multi-thread support
- [x] Master mode
	- [ ] Multiple regions (Obsolete)
- [ ] Performance testing (TODO)

## Quickstart

When application is started without any parameters, output should look like this:

```
sudo ./build/examples/ping
LIBMEMIF EXAMPLE APP: ICMP_Responder (debug)
==============================
libmemif version: 3.1 (debug)
memif version: 512
starting arguments:
	./ping --aff={cpu0,cpu1,..,cpun}
	--vdev=<id0_name>,[i=id],[ip=address],[r=master|slave],[s=socket_name],
	[domain=id],[q0=poll|interrupt],[qn=qn_count],[rs=ring_size],
	[bs=buffer_size],[aff={cpu0,cpu1,..,cpun}] --vdev=<id1_name>...
	where --aff - setting affinity of cpu on specific id numbers of cpu for
		main thread of program
	in --vdev:
		id for domain - numeric id. interface with same domain id will be bridged
		id for i - index of connetion
		address - address of this example
		socket_name - name of socket for communication
		qn_count - number of queues
		ring_size - size of ring
		buffer_size - size of buffer
		q0 - setting of mode for qid 0
		aff - setting affinity of cpu on specific id numbers of cpu for qid0
			(in interrupt mode will be this parameter ignored).
```
			


Continue with @ref libmemif_example_setup which contains instructions on how to set up conenction between icmpr-epoll example app and VPP-memif.

#### Next steps

- @subpage libmemif_build_doc
- @subpage libmemif_examples_doc
- @subpage libmemif_gettingstarted_doc
