# Release Notes    {#release_notes}

* @subpage release_notes_1707
* @subpage release_notes_1704
* @subpage release_notes_17011
* @subpage release_notes_1701
* @subpage release_notes_1609
* @subpage release_notes_1606

@page release_notes_1707 Release notes for VPP 17.07

More than 400 commits since the 1704 release.

## Features
- Infrastructure
  - make test; improved debuggability.
  - TAB auto-completion on the CLI
  - DPDK 17.05
  - python 3 support in test infra

- Host stack
  - Improved Linux TCP stack compatibility using IWL test suite (https://jira.fd.io/browse/VPP-720)
  - Improved loss recovery (RFC5681, RFC6582, RF6675)
  - Basic implementation of Eifel detection algorithm (RFC3522)
  - Basic support for buffer chains
  - Refactored session layer API
  - Overall performance, scale and hardening

- Interfaces
  - memif: IP mode, jumbo frames, multi queue
  - virtio-user support
  - vhost-usr; adaptive (poll/interupt) support.

- Network features
  - MPLS Multicast FIB

  - BFD FIB integration

  - NAT64 support

  - GRE over IPv6

  - Segement routing MPLS

  - IOAM configuration for SRv6 localsid

  - LISP
    - NSH support
    - native forward static routes
    - L2 ARP

  - ACL multi-core suuport

  - Flowprobe:
    - Add flowstartns, flowendns and tcpcontrolbits
    - Stateful flows and IPv6, L4 recording

  - GTP-U support

  - VXLAN GPE support for FIB2.0 and bypass.


## Known issues

For the full list of issues please reffer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please reffer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1707)

@page release_notes_1704 Release notes for VPP 17.04

More than 500 commits since the 1701 release.

## Features
- Infrastructure
  - make test improvements
  - vnet: add device-input threadplacement infra
  - 64 bit per-thread counters
  - process restart cli
  - High performance timer wheels
  - Plugin infrastructure improvements
    - Support for .default_disabled, .version_required
  - Added MAINTAINERS file

- Host stack
  - TCP stack (experimental)
  - DHCPv4 / DHCPv6 relay multi-destination
  - DHCPv4 option 82
  - ND proxy
  - Attached hosts
  - Consolidated DHCPv4 and DHCPv6 implementation

- Interfaces
  - DPDK 17.02 (retire support for DPDK 16.07)
  - Add memif - packet memory interface for intra-host communication
  - vhost: support interrupt mode
  - DPDK as plugin (retired vpp_lite)
  - DPDPK input optimizations
  - Loopback interface allocation scheme

- Network features
  - IP Multicast FIB

  - Bridging
    - Learning on local interfaces
    - Flushing of MACs from the L2 FIB

  - SNAT
    - CGN (Deterministic and dynamic)
    - CGN configurable port allocation algorithm
    - ICMP support
    - Tentant VRF id for SNAT outside addresses
    - Session dump / User dump
    - Port allocation per protocol

  - Security groups
    - Routed interface support
    - L2+L3 unified processing node
    - Improve fragment handling

  - Segement routing v6
    - SR policies with weighted SID lists
    - Binding SID
    - SR steering policies
    - SR Local SIDs
    - Framework to expand local SIDs w/plugins
    - Documentation

  - IOAM
    - UDP Pinger w/path fault isolation
    - IOAM as type 2 metadata in NSH
    - IAOM raw IPFIX collector and analyzer
    - Anycast active server selection
    - Documentation
    - SRv6 Local SID
    - IP6 HBH header and SR header co-existence
    - Active probe

  - LISP
    - Statistics collection
    - Generalize encap for overlay transport (vxlan-gpe support)
    - Improve data plane speed

  - GPE
    - CLI
    - NSH added to encap/decap path
    - Renamed LISP GPE API to GPE

  - MPLS
    - Performance improvements (quad loop)

  - BFD
    - Command line interface
    - Echo function
    - Remote demand mode
    - SHA1 authentication

  - IPsec
    - IKEv2 initiator features

  - VXLAN
    - unify IP4/IP6 control plane handling

## API changes

- Python API: To avoid conflicts between VPP API messages names and
  the Python API binding function names, VPP API methods are put in a
  separate proxy object.
  https://gerrit.fd.io/r/#/c/5570/
  The api methods are now referenced as:
    vpp_handle = VPP(jsonfiles)
    vpp_handle.connect(...)
    vpp = vpp_handle.api
    vpp.show_version()
    vpp_handle.disconnect()

  For backwards compatibility VPP API methods are left in the main
  name space (VPP), but will be removed from 17.07.

  - Python API: Change from cPython to CFFI.

- create_loopback message to be replaced with create_loopback_instance
  create_loopback will be removed from 17.07.
  https://gerrit.fd.io/r/#/c/5572/

## Known issues

For the full list of issues please reffer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please reffer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1704)

@page release_notes_17011 Release notes for VPP 17.01.1

This is bug fix release.

For the full list of fixed issues please reffer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1701)


@page release_notes_17011 Release notes for VPP 17.01.1

This is bug fix release.

For the full list of fixed issues please reffer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1701)

@page release_notes_1701 Release notes for VPP 17.01

@note This release was for a while known as 16.12.

## Features

- [Integrated November 2016 DPDK release](http://www.dpdk.org/doc/guides/rel_notes/release_16_11.html)

- Complete rework of Forwarding Information Base (FIB)

- Performance Improvements
  - Improvements in DPDK input and output nodes
  - Improvements in L2 path
  - Improvmeents in IPv4 lookup node

- Feature Arcs Improvements
  - Consolidation of the code
  - New feature arcs
    - device-input
    - interface-output

- DPDK Cryptodev Support
  - Software and Hardware Crypto Support

- DPDK HQoS support

- Simple Port Analyzer (SPAN)

- Bidirectional Forwarding Detection
  - Basic implementation

- IPFIX Improvements

- L2 GRE over IPSec tunnels

- Link Layer Discovery Protocol (LLDP)

- Vhost-user Improvements
  - Performance Improvements
  - Multiqueue
  - Reconnect

- LISP Enhancements
  - Source/Dest control plane support
  - L2 over LISP and GRE
  - Map-Register/Map-Notify/RLOC-probing support
  - L2 API improvements, overall code hardening

- Plugins:
  - New: ACL
  - New: Flow per Packet
  - Improved: SNAT
    - Mutlithreading
    - Flow export

- Doxygen Enhancements

- Luajit API bindings

- API Refactoring
  - file split
  - message signatures

- Python and Scapy based unit testing infrastructure
  - Infrastructure
  - Various tests

- Packet Generator improvements

- TUN/TAP jumbo frames support

- Other various bug fixes and improvements

## Known issues

For the full list of issues please reffer to fd.io [JIRA](https://jira.fd.io).

## Issues fixed

For the full list of fixed issues please reffer to:
- fd.io [JIRA](https://jira.fd.io)
- git [commit log](https://git.fd.io/vpp/log/?h=stable/1701)

@page release_notes_1609 Release notes for VPP 16.09

## Features

- [Integrated July 2016 DPDK release](http://www.dpdk.org/doc/guides/rel_notes/release_16_07.html)
  - DPDK-vhost is depreciated pending a complete rework of the original integration and
    addressing of rx performance deltas.
  - Patches required for DPDK 16.07:
    - Correctly setting the Packet Type in the IGB, IXGBE and i40e drivers.
    - Correctly setting checksum in the i40e driver.
    - NXP DPAA2 PMD Driver.
    - rte_delay (yield) functionality.

- Add “in tree” plugins:
  - IPv6 ILA.
  - iOAM.
  - Load Balancer.
  - SNAT.

- High-performance (line-rate) “neutron like” L4 port-filtering.

- API refactoring - addressing some of the issues around JVPP bindings.
  - Accommodating plugins [(e.g. NSH_SFC)](https://wiki.fd.io/view/NSH_SFC)
  - Binding for [python](https://wiki.fd.io/view/VPP/Python_API)

- LISP
  - L2 LISP overlays
  -  Multitenancy
  - Multihoming
  - RTR mode
  - Map-resolver failover algorithm

- Support 64-bit vector lengths, huge shared-memory segments.

- Dynamic IP Feature ordering
  - IP Features can now specify features they appear before and after

- 16.09 Builds
  - Ubuntu 14.04 LTS - Trusty Tahr
  - Ubuntu 16.04 LTS - Xenial Xerus
  - CentOS 7
  - More information on [VPP wiki](https://wiki.fd.io/view/VPP/Installing_VPP_binaries_from_packages)

- Performance, characterize and document performance for this release
  [(more information on CSIT page)](https://wiki.fd.io/view/CSIT)

   - IPv4 and IPv6 Scale - performance tests.
     - Bidirectional 10k/100k/1M flows.
     - 64B,570B, 1518B,9000B packet sizes.
   - IPv6 iACL - performance
     - DUT1 and DUT2 are configured with IPv6 routing, two static IPv6 /64 routes and IPv6 iAcl
       security whitelist ingress /64 filter entries applied on links.
     - TG traffic profile contains two L3 flow-groups (flow-group per direction, 253 flows per
       flow-group) with all packets containing Ethernet header, IPv6 header and generated payload.
       MAC addresses are matching MAC addresses of the TG node interfaces.

   - L2XC VXLANoIPv4 - performance
     - DUT1 and DUT2 are configured with L2 cross-connect. VXLAN tunnels are configured between
       L2XCs on DUT1 and DUT2.
     - TG traffic profile contains two L3 flow-groups (flow-group per direction, 253 flows per
       flow-group) with all packets containing Ethernet header, IPv4 header with IP protocol=61
       and generated payload. MAC addresses are matching MAC addresses of the TG node interfaces.

- Documentation
  - Autogenerated CLI documentation.
  - Using doxygen to automate API/Node documentation.
  - [(available online)](https://docs.fd.io/vpp/16.09/)

- Resolved all static analysis issues found by Coverity
  - Beginning of 16.09 cycle: 505 issues.
  - Release: 0 outstanding issues.


## Known issues

Issues in fd.io are tracked in [JIRA](https://jira.fd.io).

Issue | Description
--- | ---
VPP-391 |   vpp debug version assert appeared in the process of start
VPP-380 |   Mapping algorithm compute wrong ea-bits when IPv4 prefix 0.0.0.0/0
VPP-371 |   load_one_plugin:63: Loaded plugin: message from vppctl
VPP-367 |   vpp packages need to depend on specific versions of each other
VPP-312 |   IP6 FIB gets in indeterminate state by duplicating commands
VPP-224 |   Lookup-in-vrf can not be set correctly
VPP-206 |   Fix classify table delete
VPP-203 |   Fix binary API for reading vpp node graph
VPP-147 |   Inconsistent behaviour when adding L2 FIB filter entry
VPP-99  |  VPP doesn't discard DHCPOFFER message with wrong XID


## Issues fixed

Issues in fd.io are tracked in [JIRA](https://jira.fd.io).

Issue | Description
--- | ---
VPP-396 |   Ubuntu systems Graphviz bug
VPP-390 |   vpp-lib rpm fails to include *.so symlinks, causing linking problems with out of tree builds
VPP-388 |   IPSec output feature assumes packets have been ethernet rewritten
VPP-385 |   ARP for indirect adjacencies not working correctly
VPP-361 |   Memory leak on delete of VXLAN over IPv6 tunnel
VPP-357 |   VNI not set correctly when removing LISP fwd entries
VPP-349 |   sw_interface_vhost_user_dump not working
VPP-345 |   net/enic: bad L4 checksum ptype set on ICMP packets
VPP-340 |   MAP-T wrong destination address
VPP-330 |   Use fifo to store LISP pending map-requests
VPP-326 |   map_add_domain VAT command: unable to configure domain with mtu parameter
VPP-318 |   The map_add_domain VAT command accepts invalid arguments
VPP-315 |   Fix "show vxlan-gpe" issue
VPP-310 |   Mapping algorithm compute wrong ea-bits
VPP-239 |   LISP IP forwarding does not tag packets that hit negative mapping entries
VPP-235 |   Invalid help in VAT for sw_interface_set_l2_bridge
VPP-228 |   Mapping algorithm sends packet to wrong IPv6 address
VPP-214 |   vpp-api-test: api_ipsec_sad_add_del_entry: vector "ck" not initialized
VPP-200 |   VPP - TAP port create problem
VPP-189 |   Coverity Issues for 16.09
VPP-184 |   u16 translating to char ,not short
VPP-179 |   Adjacency share-count botch
VPP-163 |   "show ip6 interface" ignores non-global addresses
VPP-155 |   Netmap: Inconsistency in interface state between "show hardware" and "show interface"
VPP-145 |   Dynamically compute IP feature ordering based on constraints
VPP-137 |   VPP sends ARP with wrong requested IP
VPP-118 |   JVpp: 0 length arrays not handled properly in VPP responses
VPP-112 |   linux kernel info missing from build log
VPP-110 |   vxlan encap node should never touch a deleted tunnel
VPP-107 |   RPM build broken in master
VPP-92  |   segment routing is not properly filling out the segment list
VPP-91  |   segment routing add/del tunnel lookup doesn't work
VPP-84  |   af_packet throws a fatal error on EAGAIN
VPP-74  |   Clang compile fails due to warning in vlib/unix/cli.c
VPP-64  |   Top level "make pkg-deb" fails if CDPATH is set in user env.
VPP-48  |   Traceroute does not terminate when VPP is the target
VPP-23  |   CLI pager does not gracefully handle lines longer than the terminal width


@page release_notes_1606 Release notes for VPP 16.06


The FD.io Project, relentlessly focused on data IO speed and efficiency
supporting the creation of high performance, flexible, and scalable software
defined infrastructures, announces the availability of the community’s first
software release (16.06).

In the four months since launching, FD.io has brought together more than 75
developers from 11 different companies including network operators, solution
providers chip vendors, and network equipment vendors who are collaborating to
enhance and innovate around the Vector Packet Processing (VPP) technology. The
FD.io community has quickly formed to grow the number of projects from the
initial VPP project to an additional 6 projects addressing a diverse set of
requirements and usability across a variety of deployment environments.

The 16.06 release brings unprecedented performance: 480Gbps/200mpps with 8
million routes and 2k whitelist entries on standard high volume x86 servers.


## Features

In addition to the existing full suite of vswitch/vrouter features, the new
16.06 release adds:

* Enhanced Switching and Routing:
  * IPv6 Segment Routing multicast support.
  * LISP xTR support.
  * VXLAN over IPv6 underlay.
  * Per interface whitelists.
  * Shared adjacencies in FIB.

* New and improved interface support:
  * Jumbo frame support for vhost-user.
  * Netmap interface support.
  * AF_Packet interface support.

* Expanded and improved programmability:
  * Python API bindings.
  * Enhanced JVPP Java API bindings.
  * Debugging CLI.

* Expanded Hardware and Software Support:
  * Support for ARM 32 targets including Rasberry Pi single-board computer.
  * Support for DPDK 16.04.

