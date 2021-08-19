.. _iperf31:

Using VPP with Iperf3
=====================

First, disable kernel IP forward in *csp2s22c03* to ensure the host cannot use
kernel forwarding (all the settings in *net2s22c05* and *csp2s22c04* remain unchanged):

.. code-block:: console

   csp2s22c03$ echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
   0
   csp2s22c03$ sysctl net.ipv4.ip_forward
   net.ipv4.ip_forward = 0

You can use DPDK’s device binding utility (./install-vpp-native/dpdk/sbin/dpdk-devbind)
to list network devices and bind/unbind them from specific drivers. The flag “-s/--status”
shows the status of devices; the flag “-b/--bind” selects the driver to bind. The
status of devices in our system indicates that the two 40-GbE XL710 devices are located
at 82:00.0 and 82:00.1. Use the device’s slots to bind them to the driver uio_pci_generic:

.. code-block:: console

   csp2s22c03$ ./install-vpp-native/dpdk/sbin/dpdk-devbind -s
   
   Network devices using DPDK-compatible driver
   ============================================
   <none>
   
   Network devices using kernel driver
   ===================================
   0000:03:00.0 'Ethernet Controller 10-Gigabit X540-AT2' if=enp3s0f0 drv=ixgbe unused=vfio-pci,uio_pci_generic *Active*
   0000:03:00.1 'Ethernet Controller 10-Gigabit X540-AT2' if=enp3s0f1 drv=ixgbe unused=vfio-pci,uio_pci_generic *Active*
   0000:82:00.0 'Ethernet Controller XL710 for 40GbE QSFP+' if=ens802f0d1,ens802f0 drv=i40e unused=uio_pci_generic                       
   0000:82:00.1 'Ethernet Controller XL710 for 40GbE QSFP+' if=ens802f1d1,ens802f1 drv=i40e unused=uio_pci_generic                        
   
   Other network devices
   =====================
   <none>
   
   csp2s22c03$ sudo modprobe uio_pci_generic
   csp2s22c03$ sudo ./install-vpp-native/dpdk/sbin/dpdk-devbind --bind uio_pci_generic 82:00.0
   csp2s22c03$ sudo ./install-vpp-native/dpdk/sbin/dpdk-devbind --bind uio_pci_generic 82:00.1

   csp2s22c03$ sudo ./install-vpp-native/dpdk/sbin/dpdk-devbind -s
   
   Network devices using DPDK-compatible driver
   ============================================
   0000:82:00.0 'Ethernet Controller XL710 for 40GbE QSFP+' drv=uio_pci_generic unused=i40e,vfio-pci
   0000:82:00.1 'Ethernet Controller XL710 for 40GbE QSFP+' drv=uio_pci_generic unused=i40e,vfio-pci
   
   Network devices using kernel driver
   ===================================
   0000:03:00.0 'Ethernet Controller 10-Gigabit X540-AT2' if=enp3s0f0 drv=ixgbe unused=vfio-pci,uio_pci_generic *Active*
   0000:03:00.1 'Ethernet Controller 10-Gigabit X540-AT2' if=enp3s0f1 drv=ixgbe unused=vfio-pci,uio_pci_generic *Active*
   
Start the VPP service, and verify that VPP is running:

.. code-block:: console

   csp2s22c03$ sudo service vpp start
   csp2s22c03$ ps -ef | grep vpp
   root     105655      1 98 17:34 ?        00:00:02 /usr/bin/vpp -c /etc/vpp/startup.conf
   :w
            105675 105512  0 17:34 pts/4    00:00:00 grep --color=auto vpp
   
To access the VPP CLI, issue the command sudo vppctl . From the VPP interface, list
all interfaces that are bound to DPDK using the command show interface:

VPP shows that the two 40-Gbps ports located at 82:0:0 and 82:0:1 are bound. Next,
you need to assign IP addresses to those interfaces, bring them up, and verify:

.. code-block:: console

   vpp# set interface ip address FortyGigabitEthernet82/0/0 10.10.1.1/24
   vpp# set interface ip address FortyGigabitEthernet82/0/1 10.10.2.1/24
   vpp# set interface state FortyGigabitEthernet82/0/0 up
   vpp# set interface state FortyGigabitEthernet82/0/1 up
   vpp# show interface address
   FortyGigabitEthernet82/0/0 (up):
     10.10.1.1/24
   FortyGigabitEthernet82/0/1 (up):
     10.10.2.1/24
   local0 (dn):

At this point VPP is operational. You can ping these interfaces either from *net2s22c05*
or *csp2s22c04*. Moreover, VPP can forward packets whose IP address are 10.10.1.0/24 and
10.10.2.0/24, so you can ping between *net2s22c05* and *csp2s22c04*. Also, you can
run iperf3 as illustrated in the previous example, and the result from running iperf3
between *net2s22c05* and *csp2s22c04* increases to 20.3 Gbits per second.

.. code-block:: console

   ET2S22C05$ iperf3 -c 10.10.1.2
   Connecting to host 10.10.1.2, port 5201
   [  4] local 10.10.2.2 port 54078 connected to 10.10.1.2 port 5201
   [ ID] Interval           Transfer     Bandwidth       Retr  Cwnd
   [  4]   0.00-1.00   sec  2.02 GBytes  17.4 Gbits/sec  460   1.01 MBytes
   [  4]   1.00-2.00   sec  3.28 GBytes  28.2 Gbits/sec    0   1.53 MBytes
   [  4]   2.00-3.00   sec  2.38 GBytes  20.4 Gbits/sec  486    693 KBytes
   [  4]   3.00-4.00   sec  2.06 GBytes  17.7 Gbits/sec  1099   816 KBytes
   [  4]   4.00-5.00   sec  2.07 GBytes  17.8 Gbits/sec  614   1.04 MBytes
   [  4]   5.00-6.00   sec  2.25 GBytes  19.3 Gbits/sec  2869   716 KBytes
   [  4]   6.00-7.00   sec  2.26 GBytes  19.4 Gbits/sec  3321   683 KBytes
   [  4]   7.00-8.00   sec  2.33 GBytes  20.0 Gbits/sec  2322   594 KBytes
   [  4]   8.00-9.00   sec  2.28 GBytes  19.6 Gbits/sec  1690  1.23 MBytes
   [  4]   9.00-10.00  sec  2.73 GBytes  23.5 Gbits/sec  573    680 KBytes
   - - - - - - - - - - - - - - - - - - - - - - - - -
   [ ID] Interval           Transfer     Bandwidth       Retr
   [  4]   0.00-10.00  sec  23.7 GBytes  20.3 Gbits/sec  13434             sender
   [  4]   0.00-10.00  sec  23.7 GBytes  20.3 Gbits/sec                  receiver
   
   iperf Done.

The **show run** command displays the graph runtime statistics. Observe that the
average vector per node is 6.76, which means on average, a vector of 6.76 packets
is handled in a graph node.

.. figure:: /_images/build-a-fast-network-stack-terminal.png
