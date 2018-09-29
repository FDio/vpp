# A plugin to help accelerate IPv4 routing

This repository provides a plugin to hook up data plane interfaces, via
tap interfaces, to a host operating system. The host operating system
can run a route daemon referencing the tap interface(s) as if they were
the data plane interfaces. IPv4 packet forwarding decisions are taken
in the data path, while control traffic is sent to and handled by the host.

More information can be found on the wiki page:
- http://wiki.fd.io/view/VPP_Sandbox/router

## Build/Install

The router is implemented as a plugin to inject, e.g. arp, icmp4, traffic
from data plane devices. To use it, you must build the plugin and put it
in VPPs runtime plugin directory. The plugin depends on vpp and the netlink
repository from the vppsb project. This README assumes familiarity with the
build environment for both projects.

Build vpp, netlink, and router all at once by creating symbolic links in the
top level vpp directory to the netlink and router directories as well as
symbolic links to the respective .mk files in 'build-data/packages'.

```
$ cd /git/vpp
$ ln -sf /git/vppsb/netlink
$ ln -sf /git/vppsb/router
$ ln -sf ../../netlink/netlink.mk build-data/packages/
$ ln -sf ../../router/router.mk build-data/packages/
```

Now build everything and create a link to the plugin in vpp's plugin path.

```
$ cd build-root
$ ./bootstrap.sh
$ make V=0 PLATFORM=vpp TAG=vpp_debug netlink-install router-install
$ ln -sf /git/vpp/build-root/install-vpp_debug-native/router/lib64/router.so.0.0.0 \
         /usr/lib/vpp_plugins/router.so
```

Once VPP is running and the plugin is loaded, data plane interfaces can
be tapped.

```
$ vppctl enable tap-inject
```

The host operating system should see a tap named 'vpp0' with the same hardware
address as 'TenGigabitEthernet2/0/0'. Adding an IPv4 interface address to 'vpp0'
should cause the address to be added to the data plane interface as well. If
the address is a network address, a route should be added to the data
plane's default fib.

## Administrative

### Current status

Currently the router plugin handles ARP, locally destined ICMPv4 and OSPF
traffic. It supports the classifier directing packets from an ip4-table to
the 'tap-inject-neighbor' node (for handling multicast OSPF and IGMP).

### Objective

The objective of this project is to continue to build out better integration
with host operating system and for providing a basis to enable completely
or partially unmodified applications to take advantage of a fast datapath.

### MPLS related enhancement to router plugin

Some changes made to router plugin enable it to support mpls label encapsulation.

To test this feature, first install router plugin using instructions
in section "Build/Install", and then run following commands

$vppctl enable tap-inject
$ifconfig vpp0 <IP> up
$ip route add <IP> encap mpls <LABELS> via <IP> dev vpp0
$vppctl show ip fib

You should see labels in ip fib table.

you can also run following commands

$vppctl enable tap-inject
$vppctl mpls table add 0
$vppctl set int mpls <INTERFACE> enable
$ip -f mpls route add 333 dev vpp0
$vppctl show mpls fib

You should see dst label and interface in mpls table.

### Selinux

Router plugin needs those rules to work under selinux enforcing mode:

```
allow vpp_t self:netlink_route_socket nlmsg_read;
```

### Main contributors

Jeff Shaw - LF-ID:jbshaw, Chad Chengwei Wang - LF-ID:flinter (MPLS)
