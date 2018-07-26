.. _running:

Running VPP
===========

.. toctree::

'vpp' Usergroup
---------------

When VPP is installed, a new usergroup *'vpp'* is created. To avoid running the
VPP CLI (vppctl) as root, add any existing users to the new group that need to
interact with VPP:

.. code-block:: console

    $ sudo usermod -a -G vpp user1

Update your current session for the group change to take effect: 

.. code-block:: console

    $ newgrp vpp


VPP Systemd File - 'vpp.service'
--------------------------------

When the VPP is installed, a systemd service files is also installed. This
file, vpp.service (Ubuntu: /lib/systemd/system/vpp.service and CentOS:
/usr/lib/systemd/system/vpp.service), controls how VPP is run as a service. For
example, whether or not to restart on failure and if so, with how much delay.
Also, which UIO driver should be loaded and location of the *'startup.conf'*
file.

.. code-block:: console

    $ cat /usr/lib/systemd/system/vpp.service
    [Unit]
    Description=Vector Packet Processing Process
    After=syslog.target network.target auditd.service
    
    [Service]
    ExecStartPre=-/bin/rm -f /dev/shm/db /dev/shm/global_vm /dev/shm/vpe-api
    ExecStartPre=-/sbin/modprobe uio_pci_generic
    ExecStart=/usr/bin/vpp -c /etc/vpp/startup.conf
    Type=simple
    Restart=on-failure
    RestartSec=5s

    [Install]
    WantedBy=multi-user.target

.. note::

    Some older versions of the *'uio_pci_generic'* driver don't bind all
    the supported NICs properly, so the *'igb_uio'* driver built from DPDK
    needs to be installed. This file controls which driver is loaded at boot.
    *'startup.conf'* file controls which driver is used.
