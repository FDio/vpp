Simulating networks with VPP
============================

The “make test” framework provides a good way to test individual
features. However, when testing several features at once - or validating
nontrivial configurations - it may prove difficult or impossible to use
the unit-test framework.

This note explains how to set up lxc/lxd, and a 5-container testbed to
test a split-tunnel nat + ikev2 + ipsec + ipv6 prefix-delegation
scenario.

OS / Distro test results
------------------------

This setup has been tested on an Ubuntu 18.04 LTS system. If you’re
feeling adventurous, the same scenario also worked on a recent Ubuntu
20.04 “preview” daily build.

Other distros may work fine, or not at all.

Proxy Server
------------

If you need to use a proxy server e.g. from a lab system, you’ll
probably need to set HTTP_PROXY, HTTPS_PROXY, http_proxy and https_proxy
in /etc/environment. Directly setting variables in the environment
doesn’t work. The lxd snap *daemon* needs the proxy settings, not the
user interface.

Something like so:

::

       HTTP_PROXY=http://my.proxy.server:8080
       HTTPS_PROXY=http://my.proxy.server:4333
       http_proxy=http://my.proxy.server:8080
       https_proxy=http://my.proxy.server:4333

Install and configure lxd
-------------------------

Install the lxd snap. The lxd snap is up to date, as opposed to the
results of “sudo apt-get install lxd”.

::

       # snap install lxd
       # lxd init

“lxd init” asks several questions. With the exception of the storage
pool, take the defaults. To match the configs shown below, create a
storage pool named “vpp.” Storage pools of type “zfs” and “files” have
been tested successfully.

zfs is more space-efficient. “lxc copy” is infinitely faster with zfs.
The path for the zfs storage pool is under /var. Do not replace it with
a symbolic link, unless you want to rebuild all of your containers from
scratch. Ask me how I know that.

Create three network segments
-----------------------------

Aka, linux bridges.

::

       # lxc network create respond
       # lxc network create internet
       # lxc network create initiate

We’ll explain the test topology in a bit. Stay tuned.

Set up the default container profile
------------------------------------

Execute “lxc profile edit default”, and install the following
configuration. Note that the “shared” directory should mount your vpp
workspaces. With that trick, you can edit code from any of the
containers, run vpp without installing it, etc.

::

       config: {}
       description: Default LXD profile
       devices:
         eth0:
           name: eth0
           network: lxdbr0
           type: nic
         eth1:
           name: eth1
           nictype: bridged
           parent: internet
           type: nic
         eth2:
           name: eth2
           nictype: bridged
           parent: respond
           type: nic
         eth3:
           name: eth3
           nictype: bridged
           parent: initiate
           type: nic
         root:
           path: /
           pool: vpp
           type: disk
         shared:
           path: /scratch
           source: /scratch
           type: disk
       name: default

Set up the network configurations
---------------------------------

Edit the fake “internet” backbone:

::

     # lxc network edit internet

Install the ip addresses shown below, to avoid having to rebuild the vpp
and host configuration:

::

       config:
         ipv4.address: 10.26.68.1/24
         ipv4.dhcp.ranges: 10.26.68.10-10.26.68.50
         ipv4.nat: "true"
         ipv6.address: none
         ipv6.nat: "false"
       description: ""
       name: internet
       type: bridge
       used_by:
       managed: true
       status: Created
       locations:
       - none

Repeat the process with the “respond” and “initiate” networks, using
these configurations:

respond network configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

       config:
         ipv4.address: 10.166.14.1/24
         ipv4.dhcp.ranges: 10.166.14.10-10.166.14.50
         ipv4.nat: "true"
         ipv6.address: none
         ipv6.nat: "false"
       description: ""
       name: respond
       type: bridge
       used_by:
       managed: true
       status: Created
       locations:
       - none

initiate network configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

       config:
         ipv4.address: 10.219.188.1/24
         ipv4.dhcp.ranges: 10.219.188.10-10.219.188.50
         ipv4.nat: "true"
         ipv6.address: none
         ipv6.nat: "false"
       description: ""
       name: initiate
       type: bridge
       used_by:
       managed: true
       status: Created
       locations:
       - none

Create a “master” container image
---------------------------------

The master container image should be set up so that you can build vpp,
ssh into the container, edit source code, run gdb, etc.

Make sure that e.g. public key auth ssh works.

::

       # lxd launch ubuntu:18.04 respond
       <spew>
       # lxc exec respond bash
       respond# cd /scratch/my-vpp-workspace
       respond# apt-get install make ssh
       respond# make install-dep
       respond# exit
       # lxc stop respond

Mark the container image privileged. If you forget this step, you’ll
trip over a netlink error (-11) aka EAGAIN when you try to roll in the
vpp configurations.

::

       # lxc config set respond security.privileged "true"

Duplicate the “master” container image
--------------------------------------

To avoid having to configure N containers, be sure that the master
container image is fully set up before you help it have children:

::

       # lxc copy respond respondhost
       # lxc copy respond initiate
       # lxc copy respond initiatehost
       # lxc copy respond dhcpserver    # optional, to test ipv6 prefix delegation

Install handy script
--------------------

See below for a handy script which executes lxc commands across the
current set of running containers. I call it “lxc-foreach,” feel free to
call the script Ishmael if you like.

Examples:

::

       $ lxc-foreach start
       <issues "lxc start" for each container in the list>

After a few seconds, use this one to open an ssh connection to each
container. The ssh command parses the output of “lxc info,” which
displays container ip addresses.

::

       $ lxc-foreach ssh

Here’s the script:

::

       #!/bin/bash

       set -u
       export containers="respond respondhost initiate initiatehost dhcpserver"

       if [ x$1 = "x" ] ; then
           echo missing command
           exit 1
       fi

       if [ $1 = "ssh" ] ; then
           for c in $containers
           do
               inet=`lxc info $c | grep eth0 | grep -v inet6 | head -1 | cut -f 3`
               if [ x$inet = "x" ] ; then
                   echo $c not started
               else
                   gnome-terminal --command "/usr/bin/ssh $inet"
               fi
           done
       exit 0
       fi

       for c in $containers
       do
           echo lxc $1 $c
           lxc $1 $c
       done

       exit 0

Test topology
-------------

Finally, we’re ready to describe a test topology. First, a picture:

::

       ===+======== management lan/bridge lxdbr0 (dhcp) ===========+===
          |                             |                          |
          |                             |                          |
          |                             |                          |
          v                             |                          v
         eth0                           |                         eth0
       +------+ eth1                                       eth1 +------+
       | respond | 10.26.88.100 <= internet bridge => 10.26.88.101 | initiate |
       +------+                                                 +------+
         eth2 / bvi0 10.166.14.2        |       10.219.188.2 eth3 / bvi0
          |                             |                          |
          | ("respond" bridge)             |          ("initiate" bridge) |
          |                             |                          |
          v                             |                          v
         eth2 10.166.14.3               |           eth3 10.219.188.3
       +----------+                     |                   +----------+
       | respondhost |                     |                   | respondhost |
       +----------+                     |                   +----------+
         eth0 (management lan) <========+========> eth0 (management lan)

Test topology discussion
~~~~~~~~~~~~~~~~~~~~~~~~

This topology is suitable for testing almost any tunnel encap/decap
scenario. The two containers “respondhost” and “initiatehost” are
end-stations connected to two vpp instances running on “respond” and
“initiate”.

We leverage the Linux end-station network stacks to generate traffic of
all sorts.

The so-called “internet” bridge models the public internet. The
“respond” and “initiate” bridges connect vpp instances to local hosts

End station configs
-------------------

The end-station Linux configurations set up the eth2 and eth3 ip
addresses shown above, and add tunnel routes to the opposite end-station
networks.

respondhost configuration
~~~~~~~~~~~~~~~~~~~~~~~~~

::

       ifconfig eth2 10.166.14.3/24 up
       route add -net 10.219.188.0/24 gw 10.166.14.2

initiatehost configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

       sudo ifconfig eth3 10.219.188.3/24 up
       sudo route add -net 10.166.14.0/24 gw 10.219.188.2

VPP configs
-----------

Split nat44 / ikev2 + ipsec tunneling, with ipv6 prefix delegation in
the “respond” config.

respond configuration
~~~~~~~~~~~~~~~~~~~~~

::

       set term pag off

       comment { "internet" }
       create host-interface name eth1
       set int ip address host-eth1 10.26.68.100/24
       set int ip6 table host-eth1 0
       set int state host-eth1 up

       comment { default route via initiate }
       ip route add 0.0.0.0/0 via 10.26.68.101

       comment { "respond-private-net" }
       create host-interface name eth2
       bvi create instance 0
       set int l2 bridge bvi0 1 bvi
       set int ip address bvi0 10.166.14.2/24
       set int state bvi0 up
       set int l2 bridge host-eth2 1
       set int state host-eth2 up


       nat44 add interface address host-eth1
       set interface nat44 in host-eth2 out host-eth1
       nat44 add identity mapping external host-eth1 udp 500
       nat44 add identity mapping external host-eth1 udp 4500
       comment { nat44 untranslated subnet 10.219.188.0/24 }

       comment { responder profile }
       ikev2 profile add initiate
       ikev2 profile set initiate udp-encap
       ikev2 profile set initiate auth rsa-sig cert-file /scratch/setups/respondcert.pem
       set ikev2 local key /scratch/setups/initiatekey.pem
       ikev2 profile set initiate id local fqdn initiator.my.net
       ikev2 profile set initiate id remote fqdn responder.my.net
       ikev2 profile set initiate traffic-selector remote ip-range 10.219.188.0 - 10.219.188.255 port-range 0 - 65535 protocol 0
       ikev2 profile set initiate traffic-selector local ip-range 10.166.14.0 - 10.166.14.255 port-range 0 - 65535 protocol 0
       create ipip tunnel src 10.26.68.100 dst 10.26.68.101
       ikev2 profile set initiate tunnel ipip0

       comment { ipv6 prefix delegation }
       ip6 nd address autoconfig host-eth1 default-route
       dhcp6 client host-eth1
       dhcp6 pd client host-eth1 prefix group hgw
       set ip6 address bvi0 prefix group hgw ::2/56
       ip6 nd address autoconfig bvi0 default-route
       ip6 nd bvi0 ra-interval 5 3 ra-lifetime 180

       set int mtu packet 1390 ipip0
       set int unnum ipip0 use host-eth1
       ip route add 10.219.188.0/24 via ipip0

initiate configuration
~~~~~~~~~~~~~~~~~~~~~~

::

       set term pag off

       comment { "internet" }
       create host-interface name eth1
       comment { set dhcp client intfc host-eth1 hostname initiate }
       set int ip address host-eth1 10.26.68.101/24
       set int state host-eth1 up

       comment { default route via "internet gateway" }
       comment { ip route add 0.0.0.0/0 via 10.26.68.1 }

       comment { "initiate-private-net" }
       create host-interface name eth3
       bvi create instance 0
       set int l2 bridge bvi0 1 bvi
       set int ip address bvi0 10.219.188.2/24
       set int state bvi0 up
       set int l2 bridge host-eth3 1
       set int state host-eth3 up

       nat44 add interface address host-eth1
       set interface nat44 in bvi0 out host-eth1
       nat44 add identity mapping external host-eth1 udp 500
       nat44 add identity mapping external host-eth1 udp 4500
       comment { nat44 untranslated subnet 10.166.14.0/24 }

       comment { initiator profile }
       ikev2 profile add respond
       ikev2 profile set respond udp-encap
       ikev2 profile set respond auth rsa-sig cert-file /scratch/setups/initiatecert.pem
       set ikev2 local key /scratch/setups/respondkey.pem
       ikev2 profile set respond id local fqdn responder.my.net
       ikev2 profile set respond id remote fqdn initiator.my.net

       ikev2 profile set respond traffic-selector remote ip-range 10.166.14.0 - 10.166.14.255 port-range 0 - 65535 protocol 0
       ikev2 profile set respond traffic-selector local ip-range 10.219.188.0 - 10.219.188.255 port-range 0 - 65535 protocol 0

       ikev2 profile set respond responder host-eth1 10.26.68.100
       ikev2 profile set respond ike-crypto-alg aes-cbc 256  ike-integ-alg sha1-96  ike-dh modp-2048
       ikev2 profile set respond esp-crypto-alg aes-cbc 256  esp-integ-alg sha1-96  esp-dh ecp-256
       ikev2 profile set respond sa-lifetime 3600 10 5 0

       create ipip tunnel src 10.26.68.101 dst 10.26.68.100
       ikev2 profile set respond tunnel ipip0
       ikev2 initiate sa-init respond

       set int mtu packet 1390 ipip0
       set int unnum ipip0 use host-eth1
       ip route add 10.166.14.0/24 via ipip0

IKEv2 certificate setup
-----------------------

In both of the vpp configurations, you’ll see “/scratch/setups/xxx.pem”
mentioned. These certificates are used in the ikev2 key exchange.

Here’s how to generate the certificates:

::

       openssl req -x509 -nodes -newkey rsa:4096 -keyout respondkey.pem -out respondcert.pem -days 3560
       openssl x509 -text -noout -in respondcert.pem
       openssl req -x509 -nodes -newkey rsa:4096 -keyout initiatekey.pem -out initiatecert.pem -days 3560
       openssl x509 -text -noout -in initiatecert.pem

Make sure that the “respond” and “initiate” configurations point to the
certificates.

DHCPv6 server setup
-------------------

If you need an ipv6 dhcp server to test ipv6 prefix delegation, create
the “dhcpserver” container as shown above.

Install the “isc-dhcp-server” Debian package:

::

       sudo apt-get install isc-dhcp-server

/etc/dhcp/dhcpd6.conf
~~~~~~~~~~~~~~~~~~~~~

Edit the dhcpv6 configuration and add an ipv6 subnet with prefix
delegation. For example:

::

       subnet6 2001:db01:0:1::/64 {
               range6 2001:db01:0:1::1 2001:db01:0:1::9;
               prefix6 2001:db01:0:100:: 2001:db01:0:200::/56;
       }

Add an ipv6 address on eth1, which is connected to the “internet”
bridge, and start the dhcp server. I use the following trivial bash
script, which runs the dhcp6 server in the foreground and produces dhcp
traffic spew:

::

       #!/bin/bash
       ifconfig eth1 inet6 add 2001:db01:0:1::10/64 || true
       dhcpd -6 -d -cf /etc/dhcp/dhcpd6.conf

The “\|\| true” bit keeps going if eth1 already has the indicated ipv6
address.

Container / Host Interoperation
-------------------------------

Host / container interoperation is highly desirable. If the host and a
set of containers don’t run the same distro *and distro version*, it’s
reasonably likely that the glibc versions won’t match. That, in turn,
makes vpp binaries built in one environment fail in the other.

Trying to install multiple versions of glibc - especially at the host
level - often ends very badly and is *not recommended*. It’s not just
glibc, either. The dynamic loader ld-linux-xxx-so.2 is glibc version
specific.

Fortunately, it’s reasonable easy to build lxd container images based on
specific Ubuntu or Debian versions.

Create a custom root filesystem image
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First, install the “debootstrap” tool:

::

       sudo apt-get install debootstrap

Make a temp directory, and use debootstrap to populate it. In this
example, we create an Ubuntu 20.04 (focal fossa) base image:

::

       # mkdir /tmp/myroot
       # debootstrap focal /tmp/myroot http://archive.ubuntu.com/ubuntu

To tinker with the base image (if desired):

::

       # chroot /tmp/myroot
       <add packages, etc.>
       # exit

Make a compressed tarball of the base image:

::

       # tar zcf /tmp/rootfs.tar.gz -C /tmp/myroot .

Create a “metadata.yaml” file which describes the base image:

::

       architecture: "x86_64"
       # To get current date in Unix time, use `date +%s` command
       creation_date: 1458040200
       properties:
       architecture: "x86_64"
       description: "My custom Focal Fossa image"
       os: "Ubuntu"
       release: "focal"

Make a compressed tarball of metadata.yaml:

::

       # tar zcf metadata.tar.gz metadata.yaml

Import the image into lxc / lxd:

::

       $ lxc image import metadata.tar.gz rootfd.tar.gz --alias focal-base

Create a container which uses the customized base image:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

       $ lxc launch focal-base focaltest
       $ lxc exec focaltest bash

The next several steps should be executed in the container, in the bash
shell spun up by “lxc exec…”

Configure container networking
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In the container, create /etc/netplan/50-cloud-init.yaml:

::

       network:
           version: 2
           ethernets:
               eth0:
                   dhcp4: true

Use “cat > /etc/netplan/50-cloud-init.yaml”, and cut-’n-paste if your
favorite text editor is AWOL.

Apply the configuration:

::

       # netplan apply

At this point, eth0 should have an ip address, and you should see a
default route with “route -n”.

Configure apt
~~~~~~~~~~~~~

Again, in the container, set up /etc/apt/sources.list via cut-’n-paste
from a recently update “focal fossa” host. Something like so:

::

       deb http://us.archive.ubuntu.com/ubuntu/ focal main restricted
       deb http://us.archive.ubuntu.com/ubuntu/ focal-updates main restricted
       deb http://us.archive.ubuntu.com/ubuntu/ focal universe
       deb http://us.archive.ubuntu.com/ubuntu/ focal-updates universe
       deb http://us.archive.ubuntu.com/ubuntu/ focal multiverse
       deb http://us.archive.ubuntu.com/ubuntu/ focal-updates multiverse
       deb http://us.archive.ubuntu.com/ubuntu/ focal-backports main restricted universe multiverse
       deb http://security.ubuntu.com/ubuntu focal-security main restricted
       deb http://security.ubuntu.com/ubuntu focal-security universe
       deb http://security.ubuntu.com/ubuntu focal-security multiverse

“apt-get update” and “apt-install” should produce reasonable results.
Suggest “apt-get install make git”.

At this point, you can use the “/scratch” sharepoint (or similar) to
execute “make install-dep install-ext-deps” to set up the container with
the vpp toolchain; proceed as desired.
