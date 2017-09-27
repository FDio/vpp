Vector Packet Processing
========================

## Introduction

The VPP platform is an extensible framework that provides out-of-the-box
production quality switch/router functionality. It is the open source version
of Cisco's Vector Packet Processing (VPP) technology: a high performance,
packet-processing stack that can run on commodity CPUs.

The benefits of this implementation of VPP are its high performance, proven
technology, its modularity and flexibility, and rich feature set.

For more information on VPP and its features please visit the
[FD.io website](http://fd.io/) and
[What is VPP?](https://wiki.fd.io/view/VPP/What_is_VPP%3F) pages.


## Changes

Details of the changes leading up to this version of VPP can be found under
@ref release_notes.


## Directory layout

Directory name         | Description
---------------------- | -------------------------------------------
     build-data        | Build metadata
     build-root        | Build output directory
     doxygen           | Documentation generator configuration
     dpdk              | DPDK patches and build infrastructure
@ref extras/libmemif   | Client library for memif
@ref src/examples      | VPP example code
@ref src/plugins       | VPP bundled plugins directory
@ref src/svm           | Shared virtual memory allocation library
     src/tests         | Standalone tests (not part of test harness)
     src/vat           | VPP API test program
@ref src/vlib          | VPP application library
@ref src/vlibapi       | VPP API library
@ref src/vlibmemory    | VPP Memory management
@ref src/vlibsocket    | VPP Socket I/O
@ref src/vnet          | VPP networking
@ref src/vpp           | VPP application
@ref src/vpp-api       | VPP application API bindings
@ref src/vppinfra      | VPP core library
@ref src/vpp/api       | Not-yet-relocated API bindings
     test              | Unit tests and Python test harness

## Getting started

In general anyone interested in building, developing or running VPP should
consult the [VPP wiki](https://wiki.fd.io/view/VPP) for more complete
documentation.

In particular, readers are recommended to take a look at [Pulling, Building,
Running, Hacking, Pushing](https://wiki.fd.io/view/VPP/Pulling,_Building,_Run
ning,_Hacking_and_Pushing_VPP_Code) which provides extensive step-by-step
coverage of the topic.

For the impatient, some salient information is distilled below.


### Quick-start: On an existing Linux host

To install system dependencies, build VPP and then install it, simply run the
build script. This should be performed a non-privileged user with `sudo`
access from the project base directory:

    ./extras/vagrant/build.sh

If you want a more fine-grained approach because you intend to do some
development work, the `Makefile` in the root directory of the source tree
provides several convenience shortcuts as `make` targets that may be of
interest. To see the available targets run:

    make


### Quick-start: Vagrant

The directory `extras/vagrant` contains a `VagrantFile` and supporting
scripts to bootstrap a working VPP inside a Vagrant-managed Virtual Machine.
This VM can then be used to test concepts with VPP or as a development
platform to extend VPP. Some obvious caveats apply when using a VM for VPP
since its performance will never match that of bare metal; if your work is
timing or performance sensitive, consider using bare metal in addition or
instead of the VM.

For this to work you will need a working installation of Vagrant. Instructions
for this can be found [on the Setting up Vagrant wiki page]
(https://wiki.fd.io/view/DEV/Setting_Up_Vagrant).


## More information

Several modules provide documentation, see @subpage user_doc for more
end-user-oriented information. Also see @subpage dev_doc for developer notes.

Visit the [VPP wiki](https://wiki.fd.io/view/VPP) for details on more
advanced building strategies and other development notes.


## Test Framework

There is PyDoc generated documentation available for the VPP test framework.
See @ref test_framework_doc for details.
