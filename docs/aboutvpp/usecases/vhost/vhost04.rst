.. _vhost04:

Cleanup
-------

Destroy the VMs with "virsh destroy"

.. code-block:: console

    cto@tf-ucs-3:~$ virsh list
     Id    Name                           State
    ----------------------------------------------------
     65    iperf-server3                  running
    
    cto@tf-ucs-3:~$ virsh destroy iperf-server3
    Domain iperf-server3 destroyed


Delete the Virtual port in FD.io VPP

.. code-block:: console

    vpp# delete vhost-user VirtualEthernet0/0/0
    vpp# show int
                  Name               Idx       State          Counter          Count
    TenGigabitEthernet86/0/0          1         up       rx packets                    21
                                                         rx bytes                    1928
                                                         tx packets                    19
                                                         tx bytes                    1694
    TenGigabitEthernet86/0/1          2        down
    local0                            0        down

Restart FD.io VPP

.. code-block:: console

    # service vpp restart
    # vppctl show int
                  Name               Idx       State          Counter          Count
    TenGigabitEthernet86/0/0          1        down
    TenGigabitEthernet86/0/1          2        down
    local0                            0        down

