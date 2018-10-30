.. _homegateway:

.. toctree::

Using VPP as a Home Gateway
===========================

Vpp running on a small system (with appropriate NICs) makes a fine
home gateway. The resulting system performs far in excess of
requirements: a TAG=vpp_debug image runs at a vector size of ~1.1
terminating a 90-mbit down / 10-mbit up cable modem connection.

At a minimum, install sshd and the isc-dhcp-server. If you prefer, you
can use dnsmasq.

Configuration files
-------------------

/etc/vpp/startup.conf::

 unix {
   nodaemon
   log /var/log/vpp/vpp.log
   full-coredump
   cli-listen /run/vpp/cli.sock
   startup-config /setup.gate
   gid vpp
 }
 api-segment {
   gid vpp
 }
 dpdk {
      dev 0000:03:00.0
      dev 0000:14:00.0
      etc.
      poll-sleep 10
 }

isc-dhcp-server configuration::

 subnet 192.168.1.0 netmask 255.255.255.0 {
   range 192.168.1.10 192.168.1.99;
   option routers 192.168.1.1;
   option domain-name-servers 8.8.8.8;
 }

If you decide to enable the vpp dns name resolver, substitute
192.168.1.2 for 8.8.8.8 in the dhcp server configuration.

/etc/ssh/sshd_config::

 # What ports, IPs and protocols we listen for
 Port <REDACTED-high-number-port>
 # Change to no to disable tunnelled clear text passwords
 PasswordAuthentication no

For your own comfort and safety, do NOT allow password authentication
and do not answer ssh requests on port 22. Experience shows several
hack attempts per hour on port 22, but none (ever) on random
high-number ports.

vpp configuration::

  comment { This is the WAN interface }
  set int state GigabitEthernet3/0/0 up
  comment { set int mac address GigabitEthernet3/0/0 mac-to-clone-if-needed }
  set dhcp client intfc GigabitEthernet3/0/0 hostname vppgate

  comment { Create a BVI loopback interface}
  loop create
  set int l2 bridge loop0 1 bvi
  set int ip address loop0 192.168.1.1/24
  set int state loop0 up

  comment { Add more inside interfaces as needed ... }
  set int l2 bridge GigabitEthernet0/14/0 1
  set int state GigabitEthernet0/14/0 up 

  comment { dhcp server and host-stack access }
  create tap host-if-name lstack host-ip4-addr 192.168.1.2/24 host-ip4-gw 192.168.1.1 
  set int l2 bridge tap0 1
  set int state tap0 up

  comment { Configure NAT}
  nat44 add interface address GigabitEthernet3/0/0
  set interface nat44 in loop0 out GigabitEthernet3/0/0

  comment { allow inbound ssh to the <REDACTED-high-number-port>
  nat44 add static mapping local 192.168.1.2 <REDACTED> external GigabitEthernet3/0/0 <REDACTED> tcp 

  comment { if you want to use the vpp DNS server, add the following }
  comment { Remember to adjust the isc-dhcp-server configuration appropriately }
  comment { nat44 add identity mapping external GigabitEthernet3/0/0 udp 53053  }
  comment { bin dns_name_server_add_del 8.8.8.8 }
  comment { bin dns_name_server_add_del 68.87.74.166 }
  comment { bin dns_enable_disable }
  comment { see patch below, which adds these commands }
  service restart isc-dhcp-server
 
Patches
-------

You'll need this patch to add the "service restart" command::

  diff --git a/src/vpp/vnet/main.c b/src/vpp/vnet/main.c
  index 6e136e19..69189c93 100644
  --- a/src/vpp/vnet/main.c
  +++ b/src/vpp/vnet/main.c
  @@ -18,6 +18,8 @@
   #include <vlib/unix/unix.h>
   #include <vnet/plugin/plugin.h>
   #include <vnet/ethernet/ethernet.h>
  +#include <vnet/ip/ip4_packet.h>
  +#include <vnet/ip/format.h>
   #include <vpp/app/version.h>
   #include <vpp/api/vpe_msg_enum.h>
   #include <limits.h>
  @@ -400,6 +402,63 @@ VLIB_CLI_COMMAND (test_crash_command, static) = {

   #endif

  +static clib_error_t *
  +restart_isc_dhcp_server_command_fn (vlib_main_t * vm,
  +                                    unformat_input_t * input, 
  +                                    vlib_cli_command_t * cmd)
  +{
  +  int rv __attribute__((unused));
  +  /* Wait three seconds... */
  +  vlib_process_suspend (vm, 3.0);
  +  
  +  rv = system ("/usr/sbin/service isc-dhcp-server restart");
  +  
  +  vlib_cli_output (vm, "Restarted the isc-dhcp-server...");
  +  return 0;
  +}
  +
  +/* *INDENT-OFF* */
  +VLIB_CLI_COMMAND (restart_isc_dhcp_server_command, static) = {
  +  .path = "service restart isc-dhcp-server",
  +  .short_help = "restarts the isc-dhcp-server",
  +  .function = restart_isc_dhcp_server_command_fn,
  +};
  +/* *INDENT-ON* */
  +


Using the temporal mac filter plugin
------------------------------------

If you need to restrict network access for certain devices to specific
daily time ranges, configure the "mactime" plugin. Enable the feature
on the NAT "inside" interfaces::

  bin mactime_enable_disable GigabitEthernet0/14/0
  bin mactime_enable_disable GigabitEthernet0/14/1
  ...

Create the required src-mac-address rule database. There are 4 rule
entry types:

* allow-static - pass traffic from this mac address
* drop-static - drop traffic from this mac address
* allow-range - pass traffic from this mac address at specific times
* drop-range - drop traffic from this mac address at specific times

Here are some examples::

  bin mactime_add_del_range name alarm-system mac 00:de:ad:be:ef:00 allow-static
  bin mactime_add_del_range name unwelcome mac 00:de:ad:be:ef:01 drop-static
  bin mactime_add_del_range name not-during-business-hours mac <mac> drop-range Mon - Fri 7:59 - 18:01
  bin mactime_add_del_range name monday-busines-hours mac <mac> allow-range Mon 7:59 - 18:01
  
