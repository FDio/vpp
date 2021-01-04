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
	- [x] Multiple regions
- [x] Loopback

## Quickstart

This setup will run libmemif ICMP responder example app in container. Install [docker](https://docs.docker.com/engine/installation) engine.
Useful link: [Docker documentation](https://docs.docker.com/get-started).

Build the docker image:
```
# docker build . -t libmemif
```

Now you should be able to see libmemif image on your local machine:
```
# docker images
REPOSITORY                       TAG                 IMAGE ID            CREATED              SIZE
libmemif						 latest              32ecc2f9d013        About a minute ago   468MB
...
```

Run container:
```
# docker run -it --rm --name icmp-responder --hostname icmp-responder --privileged -v "/run/vpp/:/run/vpp/" libmemif
```

The interface will by default connect to a master interface listening on `/run/vpp/master.sock`. The example will handle ARP requests and respond to ICMPv4 requests to `192.168.1.1`.

Continue with @ref libmemif_example_setup which contains instructions on how to set up connection between icmpr-epoll example app and VPP-memif.

#### Next steps

- @subpage libmemif_build_doc
- @subpage libmemif_examples_doc
- @subpage libmemif_example_setup_doc
- @subpage libmemif_gettingstarted_doc
