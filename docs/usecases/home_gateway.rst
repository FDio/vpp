VPP as a Home Gateway
=====================

Vpp running on a small system (with appropriate NICs) makes a fine home
gateway. The resulting system performs far in excess of requirements: a
debug image runs at a vector size of ~1.2 terminating a 150-mbit down /
10-mbit up cable modem connection.

At a minimum, install sshd and the isc-dhcp-server. If you prefer, you
can use dnsmasq.

System configuration files
--------------------------

/etc/vpp/startup.conf:

.. code-block:: c

   unix {
     nodaemon
     log /var/log/vpp/vpp.log
     full-coredump
     cli-listen /run/vpp/cli.sock
     startup-config /setup.gate
     poll-sleep-usec 100
     gid vpp
   }
   api-segment {
     gid vpp
   }
   dpdk {
        dev 0000:03:00.0
        dev 0000:14:00.0
        etc.
    }

    plugins {
      ## Disable all plugins, selectively enable specific plugins
          ## YMMV, you may wish to enable other plugins (acl, etc.)
      plugin default { disable }
      plugin dpdk_plugin.so { enable }
      plugin nat_plugin.so { enable }
          ## if you plan to use the time-based MAC filter
      plugin mactime_plugin.so { enable }
    }

/etc/dhcp/dhcpd.conf:

.. code-block:: c

   subnet 192.168.1.0 netmask 255.255.255.0 {
     range 192.168.1.10 192.168.1.99;
     option routers 192.168.1.1;
     option domain-name-servers 8.8.8.8;
   }

If you decide to enable the vpp dns name resolver, substitute
192.168.1.2 for 8.8.8.8 in the dhcp server configuration.

/etc/default/isc-dhcp-server:

.. code-block:: c

   # On which interfaces should the DHCP server (dhcpd) serve DHCP requests?
   # Separate multiple interfaces with spaces, e.g. "eth0 eth1".
   INTERFACESv4="lstack"
   INTERFACESv6=""

/etc/ssh/sshd_config:

.. code-block:: c

   # What ports, IPs and protocols we listen for
   Port <REDACTED-high-number-port>
   # Change to no to disable tunnelled clear text passwords
   PasswordAuthentication no

For your own comfort and safety, do NOT allow password authentication
and do not answer ssh requests on port 22. Experience shows several hack
attempts per hour on port 22, but none (ever) on random high-number
ports.

Systemd configuration
---------------------

In a typical home-gateway use-case, vpp owns the one-and-only WAN link
with a prayer of reaching the public internet. Simple things like
updating distro software requires use of the "lstack" interface created
above, and configuring a plausible upstream DNS name resolver.

Configure /etc/systemd/resolved.conf as follows.

/etc/systemd/resolved.conf:

.. code-block:: c

   [Resolve]
   DNS=8.8.8.8
   #FallbackDNS=
   #Domains=
   #LLMNR=no
   #MulticastDNS=no
   #DNSSEC=no
   #Cache=yes
   #DNSStubListener=yes

Netplan configuration
---------------------

If you want to configure a static IP address on one of your home-gateway
Ethernet ports on Ubuntu 18.04, you'll need to configure netplan.
Netplan is relatively new. It and the network manager GUI and can be
cranky. In the configuration shown below, s/enp4s0/<your-interface>/...

/etc/netplan-01-netcfg.yaml:

.. code-block:: c

   # This file describes the network interfaces available on your system
   # For more information, see netplan(5).
   network:
     version: 2
     renderer: networkd
     ethernets:
       enp4s0:
         dhcp4: no
         addresses: [192.168.2.254/24]
         gateway4: 192.168.2.100
         nameservers:
           search: [my.local]
           addresses: [8.8.8.8]

/etc/systemd/network-10.enp4s0.network:

.. code-block:: c

   [Match]
   Name=enp4s0

   [Link]
   RequiredForOnline=no

   [Network]
   ConfigureWithoutCarrier=true
   Address=192.168.2.254/24

Note that we've picked an IP address for the home gateway which is on an
independent unrouteable subnet. This is handy for installing (and
possibly reverting) new vpp software.

VPP Configuration Files
-----------------------

Here we see a nice use-case for the vpp debug CLI macro expander:

/setup.gate:

.. code-block:: c

   define HOSTNAME vpp1
   define TRUNK GigabitEthernet3/0/0

   comment { Specific MAC address yields a constant IP address }
   define TRUNK_MACADDR 48:f8:b3:00:01:01
   define BVI_MACADDR 48:f8:b3:01:01:02

   comment { inside subnet 192.168.<inside_subnet>.0/24 }
   define INSIDE_SUBNET 1

   define INSIDE_PORT1 GigabitEthernet6/0/0
   define INSIDE_PORT2 GigabitEthernet6/0/1
   define INSIDE_PORT3 GigabitEthernet8/0/0
   define INSIDE_PORT4 GigabitEthernet8/0/1

   comment { feature selections }
   define FEATURE_NAT44 comment
   define FEATURE_CNAT uncomment
   define FEATURE_DNS comment
   define FEATURE_IP6 comment
   define FEATURE_MACTIME uncomment

   exec /setup.tmpl

/setup.tmpl:

.. code-block:: c

   show macro

   set int mac address $(TRUNK) $(TRUNK_MACADDR)
   set dhcp client intfc $(TRUNK) hostname $(HOSTNAME)
   set int state $(TRUNK) up

   bvi create instance 0
   set int mac address bvi0 $(BVI_MACADDR)
   set int l2 bridge bvi0 1 bvi
   set int ip address bvi0 192.168.$(INSIDE_SUBNET).1/24
   set int state bvi0 up

   set int l2 bridge $(INSIDE_PORT1) 1
   set int state $(INSIDE_PORT1) up
   set int l2 bridge $(INSIDE_PORT2) 1
   set int state $(INSIDE_PORT2) up
   set int l2 bridge $(INSIDE_PORT3) 1
   set int state $(INSIDE_PORT3) up
   set int l2 bridge $(INSIDE_PORT4) 1
   set int state $(INSIDE_PORT4) up

   comment { dhcp server and host-stack access }
   create tap host-if-name lstack host-ip4-addr 192.168.$(INSIDE_SUBNET).2/24 host-ip4-gw 192.168.$(INSIDE_SUBNET).1
   set int l2 bridge tap0 1
   set int state tap0 up

   service restart isc-dhcp-server

   $(FEATURE_NAT44) { nat44 enable users 50 user-sessions 750 sessions 63000 }
   $(FEATURE_NAT44) { nat44 add interface address $(TRUNK) }
   $(FEATURE_NAT44) { set interface nat44 in bvi0 out $(TRUNK) }

   $(FEATURE_NAT44) { nat44 add static mapping local 192.168.$(INSIDE_SUBNET).2 22432 external $(TRUNK) 22432 tcp }

   $(FEATURE_CNAT) { cnat snat with $(TRUNK) }
   $(FEATURE_CNAT) { set interface feature bvi0 ip4-cnat-snat arc ip4-unicast }
   $(FEATURE_CNAT) { cnat translation add proto tcp real $(TRUNK) 22432 to -> 192.168.$(INSIDE_SUBNET).2 22432 }
   $(FEATURE_CNAT) { $(FEATURE_DNS) { cnat translation add proto udp real $(TRUNK) 53053 to -> 192.168.$(INSIDE_SUBNET).1 53053 } }

   $(FEATURE_DNS) { $(FEATURE_NAT44) { nat44 add identity mapping external $(TRUNK) udp 53053 } }
   $(FEATURE_DNS) { bin dns_name_server_add_del 8.8.8.8 }
   $(FEATURE_DNS) { bin dns_enable_disable }

   comment { set ct6 inside $(TRUNK) }
   comment { set ct6 outside $(TRUNK) }

   $(FEATURE_IP6) { set int ip6 table $(TRUNK) 0 }
   $(FEATURE_IP6) { ip6 nd address autoconfig $(TRUNK) default-route }
   $(FEATURE_IP6) { dhcp6 client $(TRUNK) }
   $(FEATURE_IP6) { dhcp6 pd client $(TRUNK) prefix group hgw }
   $(FEATURE_IP6) { set ip6 address bvi0 prefix group hgw ::1/64 }
   $(FEATURE_IP6) { ip6 nd address autoconfig bvi0 default-route }
   comment { iPhones seem to need lots of RA messages... }
   $(FEATURE_IP6) { ip6 nd bvi0 ra-managed-config-flag ra-other-config-flag ra-interval 5 3 ra-lifetime 180 }
   comment { ip6 nd bvi0 prefix 0::0/0  ra-lifetime 100000 }


   $(FEATURE_MACTIME) { bin mactime_add_del_range name cisco-vpn mac a8:b4:56:e1:b8:3e allow-static }
   $(FEATURE_MACTIME) { bin mactime_add_del_range name old-mac mac <redacted> allow-static }
   $(FEATURE_MACTIME) { bin mactime_add_del_range name roku mac <redacted> allow-static }
   $(FEATURE_MACTIME) { bin mactime_enable_disable $(INSIDE_PORT1) }
   $(FEATURE_MACTIME) { bin mactime_enable_disable $(INSIDE_PORT2) }
   $(FEATURE_MACTIME) { bin mactime_enable_disable $(INSIDE_PORT3) }
   $(FEATURE_MACTIME) { bin mactime_enable_disable $(INSIDE_PORT4) }

Installing new vpp software
---------------------------

If you're **sure** that a given set of vpp Debian packages will install
and work properly, you can install them while logged into the gateway
via the lstack / nat path. This procedure is a bit like standing on a
rug and yanking it. If all goes well, a perfect back-flip occurs. If
not, you may wish that you'd configured a static IP address on a
reserved Ethernet interface as described above.

Installing a new vpp image via ssh to 192.168.1.2:

.. code-block:: c

   # nohup dpkg -i *.deb >/dev/null 2>&1 &

Within a few seconds, the inbound ssh connection SHOULD begin to respond
again. If it does not, you'll have to debug the issue(s).

Reasonably Robust Remote Software Installation
----------------------------------------------

Here are a couple of scripts which yield a reasonably robust software
installation scheme.

Build-host script
~~~~~~~~~~~~~~~~~

.. code-block:: c

   #!/bin/bash

   buildroot=/scratch/vpp-workspace/build-root
   if [ $1x = "testx" ] ; then
       subdir="test"
       ipaddr="192.168.2.48"
   elif [ $1x = "foox" ] ; then
       subdir="foo"
       ipaddr="foo.some.net"
   elif [ $1x = "barx" ] ; then
       subdir="bar"
       ipaddr="bar.some.net"
   else
       subdir="test"
       ipaddr="192.168.2.48"
   fi

   echo Save current software...
   ssh -p 22432 $ipaddr "rm -rf /gate_debians.prev"
   ssh -p 22432 $ipaddr "mv /gate_debians /gate_debians.prev"
   ssh -p 22432 $ipaddr "mkdir /gate_debians"
   echo Copy new software to the gateway...
   scp -P 22432 $buildroot/*.deb $ipaddr:/gate_debians
   echo Install new software...
   ssh -p 22432 $ipaddr "nohup /usr/local/bin/vpp-swupdate > /dev/null 2>&1 &"

   for i in 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1
   do
       echo Wait for $i seconds...
       sleep 1
   done

   echo Try to access the device...

   ssh -p 22432 -o ConnectTimeout=10 $ipaddr "tail -20 /var/log/syslog | grep Ping"
   if [ $? == 0 ] ; then
       echo Access test OK...
   else
       echo Access failed, wait for configuration restoration...
       for i in 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1
       do
           echo Wait for $i seconds...
           sleep 1
       done
       echo Retry access test
       ssh -p 22432 -o ConnectTimeout=10 $ipaddr "tail -20 /var/log/syslog | grep Ping"
       if [ $? == 0 ] ; then
           echo Access test OK, check syslog on the device
           exit 1
       else
           echo Access test still fails, manual intervention required.
           exit 2
       fi
   fi

   exit 0

Target script
~~~~~~~~~~~~~

.. code-block:: c

   #!/bin/bash

   logger "About to update vpp software..."
   cd /gate_debians
   service vpp stop
   sudo dpkg -i *.deb >/dev/null 2>&1 &
   sleep 20
   logger "Ping connectivity test..."
   for i in 1 2 3 4 5 6 7 8 9 10
   do
       ping -4 -c 1 yahoo.com
       if [ $? == 0 ] ; then
           logger "Ping test OK..."
           exit 0
       fi
   done

   logger "Ping test NOT OK, restore old software..."
   rm -rf /gate_debians
   mv /gate_debians.prev /gate_debians
   cd /gate_debians
   nohup sudo dpkg -i *.deb >/dev/null 2>&1 &
   sleep 20
   logger "Repeat connectivity test..."
   for i in 1 2 3 4 5 6 7 8 9 10
   do
       ping -4 -c 1 yahoo.com
       if [ $? == 0 ] ; then
           logger "Ping test OK after restoring old software..."
           exit 0
       fi
   done

   logger "Ping test FAIL after restoring software, manual intervention required"
   exit 2

Note that the target script **requires** that the user id which invokes
it will manage to “sudo dpkg …” without further authentication. If
you’re uncomfortable with the security implications of that requirement,
you’ll need to solve the problem a different way. Strongly suggest
configuring sshd as described above to minimize risk.

Testing new software
--------------------

If you frequently test new home gateway software, it may be handy to set
up a test gateway behind your production gateway. This testing
methodology reduces complaints from family members, to name one benefit.

Change the inside network (dhcp) subnet from 192.168.1.0/24 to
192.168.3.0/24, change the (dhcp) advertised router to 192.168.3.1,
reconfigure the vpp tap interface addresses onto the 192.168.3.0/24
subnet, and you should be all set.

This scenario nats traffic twice: first, from the 192.168.3.0/24 network
onto the 192.168.1.0/24 network. Next, from the 192.168.1.0/24 network
onto the public internet.

Patches
-------

You'll want this addition to src/vpp/vnet/main.c to add the "service
restart isc-dhcp-server” and "service restart vpp" commands:

.. code-block:: c

   #include <sys/types.h>
   #include <sys/wait.h>

   static int
   mysystem (char *cmd)
   {
     int rv = 0;

     if (fork())
       wait (&rv);
     else
       execl("/bin/sh", "sh", "-c", cmd);

     if (rv != 0)
       clib_unix_warning ("('%s') child process returned %d", cmd, rv);
     return rv;
   }

   static clib_error_t *
   restart_isc_dhcp_server_command_fn (vlib_main_t * vm,
                                       unformat_input_t * input,
                                       vlib_cli_command_t * cmd)
   {
     int rv;

     /* Wait a while... */
     vlib_process_suspend (vm, 2.0);

     rv = mysystem("/usr/sbin/service isc-dhcp-server restart");

     vlib_cli_output (vm, "Restarted the isc-dhcp-server, status %d...", rv);
     return 0;
   }

   VLIB_CLI_COMMAND (restart_isc_dhcp_server_command, static) =
   {
     .path = "service restart isc-dhcp-server",
     .short_help = "restarts the isc-dhcp-server",
     .function = restart_isc_dhcp_server_command_fn,
   };

   static clib_error_t *
   restart_dora_tunnels_command_fn (vlib_main_t * vm,
                                    unformat_input_t * input,
                                    vlib_cli_command_t * cmd)
   {
     int rv;

     /* Wait three seconds... */
     vlib_process_suspend (vm, 3.0);

     rv = mysystem ("/usr/sbin/service dora restart");

     vlib_cli_output (vm, "Restarted the dora tunnel service, status %d...", rv);
     return 0;
   }

   VLIB_CLI_COMMAND (restart_dora_tunnels_command, static) =
   {
     .path = "service restart dora",
     .short_help = "restarts the dora tunnel service",
     .function = restart_dora_tunnels_command_fn,
   };

   static clib_error_t *
   restart_vpp_service_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
   {
     (void) mysystem ("/usr/sbin/service vpp restart");
     return 0;
   }

   VLIB_CLI_COMMAND (restart_vpp_service_command, static) =
   {
     .path = "service restart vpp",
     .short_help = "restarts the vpp service, be careful what you wish for",
     .function = restart_vpp_service_command_fn,
   };

Using the time-based mac filter plugin
--------------------------------------

If you need to restrict network access for certain devices to specific
daily time ranges, configure the "mactime" plugin. Add it to the list of
enabled plugins in /etc/vpp/startup.conf, then enable the feature on the
NAT "inside" interfaces:

.. code-block:: c

   bin mactime_enable_disable GigabitEthernet0/14/0
   bin mactime_enable_disable GigabitEthernet0/14/1
   ...

Create the required src-mac-address rule database. There are 4 rule
entry types:

-  allow-static - pass traffic from this mac address
-  drop-static - drop traffic from this mac address
-  allow-range - pass traffic from this mac address at specific times
-  drop-range - drop traffic from this mac address at specific times

Here are some examples:

.. code-block:: c

   bin mactime_add_del_range name alarm-system mac 00:de:ad:be:ef:00 allow-static
   bin mactime_add_del_range name unwelcome mac 00:de:ad:be:ef:01 drop-static
   bin mactime_add_del_range name not-during-business-hours mac <mac> drop-range Mon - Fri 7:59 - 18:01
   bin mactime_add_del_range name monday-busines-hours mac <mac> allow-range Mon 7:59 - 18:01
