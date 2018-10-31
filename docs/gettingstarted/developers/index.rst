.. _gstarteddevel:

###############
For Developers
###############

The Developers section covers the following areas:

* Describes how to build different types of VPP images
* Explains how to run VPP with and without GDB, with some GDB examples
* Describes the steps required to get a patch reviewed and merged
* Describes the VPP software architecture and identifies the associated four VPP layers
* Describes the different components that are associated with each VPP layer 
* Explains how to Create, Add, Enable/Disable different ARC features
* Discusses different aspects of Bounded-index Extensible Hashing (bihash), and how it is used in database lookups
* Describes the different types of API support and how to integrate a plugin

.. toctree::
   :maxdepth: 2

   building
   running_vpp
   gdb_examples
   add_plugin
   gitreview
   softwarearchitecture
   infrastructure
   vlib
   plugins
   vnet
   featurearcs
   multiarch/index.rst
   bihash
   vpp_api_module
   binary_api_support
   buildsystem/index.rst
   eventviewer
   fib20/index.rst
