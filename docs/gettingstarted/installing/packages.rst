.. _packages:

Packages
==========

This section identifies the different VPP packages and describes their contents.

.. toctree::

vpp
---

Vector Packet Processing executables. This is the primary package that must be
installed to use VPP. This package contains:

* vpp - the vector packet engine
* vpp_api_test - vector packet engine API test tool
* vpp_json_test - vector packet engine JSON test tool

vpp-lib
-------

Vector Packet Processing runtime libraries. The *'vpp'* package depends on this
package, so it will always be installed. This package contains the VPP shared
libraries, including:

* vppinfra - Foundation library supporting vectors, hashes, bitmaps, pools, and string formatting.
* svm - vm library
* vlib - vector processing library
* vlib-api - binary API library
* vnet -  network stack library

vpp-plugins
-----------

Vector Packet Processing plugin modules.

.. include:: ../../dynamic_includes/plugin_list.inc

vpp-dbg
-------

Vector Packet Processing debug symbols.

vpp-dev
-------

Vector Packet Processing development support. This package contains
development support files for the VPP libraries.

vpp-api-python 
--------------

Python binding for the VPP Binary API.

vpp-api-lua
-----------

Lua binding for the VPP Binary API.

vpp-selinux-policy
------------------

This package contains the VPP Custom SELinux Policy. It is only generated for
Fedora and CentOS distros. For those distros, the *'vpp'* package depends on
this package, so it will always be installed. It will not enable SELinux on
the system. It will install a Custom VPP SELinux policy that will be used if
SELinux is enabled at any time.
