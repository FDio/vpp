.. _libmemif_doc:

Shared Memory Packet Interface (memif) Library
==============================================

Features
--------

-  ✅ Slave mode

   -  ✅ Connect to VPP over memif
   -  ✅ ICMP responder example app

-  ✅ Transmit/receive packets
-  ✅ Interrupt mode support
-  ✅ File descriptor event polling in libmemif (optional)

   -  ✅ Simplify file descriptor event polling (one handler for control
      and interrupt channel)

-  ✅ Multiple connections
-  ✅ Multiple queues

   -  ✅ Multi-thread support

-  ✅ Master mode

   -  ✅ Multiple regions

-  ✅ Loopback

Quickstart
----------

This setup will run libmemif ICMP responder example app in container.
Install `docker <https://docs.docker.com/engine/installation>`__ engine.
Useful link: `Docker
documentation <https://docs.docker.com/get-started>`__.

Build the docker image:

::

   # docker build . -t libmemif

Now you should be able to see libmemif image on your local machine:

::

   # docker images
   REPOSITORY                       TAG                 IMAGE ID            CREATED              SIZE
   libmemif                         latest              32ecc2f9d013        About a minute ago   468MB
   ...

Run container:

::

   # docker run -it --rm --name icmp-responder --hostname icmp-responder --privileged -v "/run/vpp/:/run/vpp/" libmemif

The interface will by default connect to a master interface listening on
``/run/vpp/master.sock``. The example will handle ARP requests and
respond to ICMPv4 requests to ``192.168.1.1``.

Continue with :ref:`libmemif_example_setup_doc` which contains instructions on
how to set up connection between icmpr-epoll example app and VPP-memif.

