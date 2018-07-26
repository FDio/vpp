.. _vhost03:

Bridge the Interfaces
---------------------

To connect the 2 interfaces we put them on an L2 bridge.

Use the "set interface l2 bridge" command.

.. code-block:: console

    vpp# set interface l2 bridge VirtualEthernet0/0/0 100
    vpp# set interface l2 bridge TenGigabitEthernet86/0/0 100
    vpp# show bridge
      BD-ID   Index   BSN  Age(min)  Learning  U-Forwrd  UU-Flood  Flooding  ARP-Term  BVI-Intf
       100      1      0     off        on        on        on        on       off       N/A
    vpp# show bridge 100 det
      BD-ID   Index   BSN  Age(min)  Learning  U-Forwrd  UU-Flood  Flooding  ARP-Term  BVI-Intf
       100      1      0     off        on        on        on        on       off       N/A
    
               Interface           If-idx ISN  SHG  BVI  TxFlood        VLAN-Tag-Rewrite
         VirtualEthernet0/0/0        3     1    0    -      *                 none
       TenGigabitEthernet86/0/0      1     1    0    -      *                 none
    vpp# show vhost

Bring the Interfaces Up
-----------------------

We can now bring all the pertinent interfaces up. We can then we will then be able to communicate
with the VM from the remote system running Linux.

Bring the interfaces up with :ref:`setintstate` command.

.. code-block:: console

    vpp# set interface state VirtualEthernet0/0/0 up
    vpp# set interface state TenGigabitEthernet86/0/0 up
    vpp# sh int
                  Name               Idx       State          Counter          Count
    TenGigabitEthernet86/0/0          1         up       rx packets                     2
                                                         rx bytes                     180
    TenGigabitEthernet86/0/1          2        down
    VirtualEthernet0/0/0              3         up       tx packets                     2
                                                         tx bytes                     180
    local0                            0        down

Ping from the VM
----------------

The remote Linux system has an ip address of "10.0.0.2" we can now reach it from the VM.

Use the "virsh console" command to attach to the VM. "ctrl-D" to exit.

.. code-block:: console

    $ virsh console iperf-server3
    Connected to domain iperf-server3
    Escape character is ^]

    Ubuntu 16.04.3 LTS iperfvm ttyS0
    .....

    root@iperfvm:~# ping 10.0.0.2
    64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.285 ms
    64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=0.154 ms
    64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=0.159 ms
    64 bytes from 10.0.0.2: icmp_seq=4 ttl=64 time=0.208 ms


On VPP you can now see the packet counts increasing. The packets from the VM are seen as **rx packets**
on **VirtualEthernet0/0/0**, they are then bridged to **TenGigabitEthernet86/0/0** and are seen leaving the
system as **tx packets**. The reverse is true on the way in.

.. code-block:: console

    vpp# sh int
                  Name               Idx       State          Counter          Count
    TenGigabitEthernet86/0/0          1         up       rx packets                    16
                                                         rx bytes                    1476
                                                         tx packets                    14
                                                         tx bytes                    1260
    TenGigabitEthernet86/0/1          2        down
    VirtualEthernet0/0/0              3         up       rx packets                    14
                                                         rx bytes                    1260
                                                         tx packets                    16
                                                         tx bytes                    1476
    local0                            0        down
    vpp# 
