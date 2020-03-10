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
LIBMEMIF EXAMPLE APP: Ping
==============================
libmemif version: 3.1
memif version: 512

Example usage: ping --vdev=memif0 --master-lcore=0
	Creates one memif interface named memif0 and sets the affinity of main thread to cpu 0.

Arguments:
	--vdev=<name>,[opt1=<val>,opt2=<val>,...] - Create memif interface with specific options.
	--master-lcore=<id_cpu> - Set affinity of main thread to specific cpu.

Options for --vdev:
	id=<num>                   : Unique interface id.
	ip=<ip4>                   : Ipv4 address.
	role=<master|slave>        : Role in which interface operates.
	socket=<filename>          : Controll channel socket filename.
	domain=<num>               : Bridge domain, packets are replicated to all interfaces
	                             assigned to the same bridge domain. Interfaces in
	                             bridge domain won't respond to ICMP requests.
	qpairs=<num>               : Number of queue pairs.
	q0-rxmode=<interrupt|poll> : Mode in which qid0 operates.
	rsize=<num>                : Log2 of ring size. If rsize is 10, actual ring size is 1024.
	bsize=<num>                : Size of single packet buffer.
	lcores=[0,1,...]           : Core list. Polling queues are assigned cores from this list.
```

Continue with @ref libmemif_example_setup which contains instructions on how to set up connection between icmpr-epoll example app and VPP-memif.

#### Next steps

- @subpage libmemif_build_doc
- @subpage libmemif_examples_doc
- @subpage libmemif_gettingstarted_doc
