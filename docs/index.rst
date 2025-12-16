.. fdio-vpp documentation master file, created by
   sphinx-quickstart on Thu Apr 12 11:02:31 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

#########################################
What is the Vector Packet Processor (VPP)
#########################################

DO NOT COMMIT: FD.io's Vector Packet Processor (VPP) is a fast, scalable layer 2-4
multi-platform network stack. It runs in `Linux Userspace <https://en.wikipedia.org/wiki/User_space>`_
on multiple architectures including x86, ARM, and Power architectures.

VPP's high performance network stack is quickly becoming the network stack of
choice for applications around the world.

VPP is continually being enhanced through the extensive use of plugins. The
`Data Plane Development Kit (DPDK) <https://en.wikipedia.org/wiki/Data_Plane_Development_Kit>`_
is a great example of this. It provides some important features and drivers
for VPP.

VPP supports integration with OpenStack and Kubernetes. Network
management features include configuration, counters, sampling and
more. For developers, VPP includes high-performance event-logging,
and multiple kinds of packet tracing. Development debug images
include complete symbol tables, and extensive consistency checking.

Some VPP Use-cases include vSwitches, vRouters, Gateways, Firewalls
and Load-Balancers, to name a few.

For more details click on the links below or press next.

.. toctree::
   :caption: About VPP
   :maxdepth: 1

   aboutvpp/scalar-vs-vector-packet-processing
   aboutvpp/extensible
   aboutvpp/networkstack
   aboutvpp/hoststack
   aboutvpp/developer
   aboutvpp/supported
   aboutvpp/performance
   aboutvpp/releasenotes/index
   aboutvpp/featurelist

.. toctree::
   :caption: Use Cases
   :maxdepth: 1

   usecases/containers/index
   usecases/simpleperf/index
   usecases/vppcloud/index
   usecases/vhost/index
   usecases/vmxnet3
   usecases/home_gateway
   usecases/acls
   usecases/networksim
   usecases/webapp
   usecases/container_test
   usecases/trafficgen
   usecases/ikev2/index
   usecases/contiv/index
   usecases/vpp_testbench/index


.. toctree::
   :caption: Getting started
   :maxdepth: 2

   gettingstarted/installing/index
   gettingstarted/running/index
   gettingstarted/progressivevpp/index
   gettingstarted/troubleshooting/index

.. toctree::
    :caption: Developer Documentation
    :maxdepth: 2

    developer/build-run-debug/index
    developer/corearchitecture/index
    developer/corefeatures/index
    developer/plugindoc/index
    developer/plugins/index
    developer/devicedrivers/index
    developer/tests/overview
    developer/extras/index

.. toctree::
    :caption: Interfacing with VPP
    :maxdepth: 2

    interfacing/binapi/index
    interfacing/c/index
    interfacing/cpp/index
    interfacing/go/index
    interfacing/rust/index
    interfacing/libmemif/index
    interfacing/vat2/index



.. toctree::
    :caption: Contributing
    :maxdepth: 2

    contributing/gitreview
    contributing/writingdocs
    contributing/reportingissues/index


.. toctree::
    :caption: Debug CLI
    :maxdepth: 2

    cli-reference/gettingstarted/index
    cli-reference/interface/index
    cli-reference/index


.. toctree::
    :caption: Configuration file
    :maxdepth: 2

    configuration/config_getting_started
    configuration/reference


About this documentation

::

    VPP Version : __VPP_VERSION__
    Built on    : __BUILT_ON__
