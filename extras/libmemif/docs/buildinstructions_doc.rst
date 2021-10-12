.. _libmemif_build_doc:

Build Instructions
==================

Install dependencies
--------------------

::

   # sudo apt-get install -y git cmake autoconf pkg_config libtool

Libmemif is now part of VPP repository. Follow fd.io wiki to pull source
code from VPP repository.
https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code#Pushing_Patches

Libmemif is located under extras/libmemif. From extras/libmemif:

::

   # mkdir build
   # cd build
   # cmake ..
   # make install

Verify installation:
--------------------

::

   build# ./examples/icmp_responder -?

Use ``-?`` flag to display help:

::

   LIBMEMIF EXAMPLE APP: icmp_responder_example
   ==============================
   libmemif version: 4.0, memif version: 2.0
   ==============================
   In this example, memif endpoint connects to an external application.
   The example application can resolve ARP and reply to ICMPv4 packets.
   The program will exit once the interface is disconnected.
   ==============================
   Usage: icmp_responder [OPTIONS]

   Options:
           -r      Interface role <slave|master>. Default: slave
           -s      Socket path. Supports abstract socket using @ before the path. Default: /run/vpp/memif.sock
           -i      Interface id. Default: 0
           -a      IPv4 address. Default: 192.168.1.1
           -h      Mac address. Default: aa:aa:aa:aa:aa:aa
           -?      Show help and exit.
           -v      Show libmemif and memif version information and exit.

Examples
--------

Once the library is built/installed, refer to :ref:`libmemif_examples_doc`
and :ref:`libmemif_gettingstarted_doc` for additional information on basic
use cases and API usage.
