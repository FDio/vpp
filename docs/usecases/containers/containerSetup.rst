.. _containerSetup:

.. toctree::

Container packages
==================

Now we can go into container *cone* and install prerequisites such as VPP, and perform some additional commands:

To enter our container via the shell, type:

.. code-block:: console

    # lxc-attach -n cone
    root@cone:/#

Run the linux DHCP setup and install VPP:

.. code-block:: console

    root@cone:/# dhclient
    root@cone:/# apt-get install -y curl
    root@cone:/# curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | sudo bash
    root@cone:/# apt-get update
    root@cone:/# apt-get install -y --force-yes vpp
    root@cone:/# sh -c 'echo  \"\\ndpdk {\\n   no-pci\\n}\" >> /etc/vpp/startup.conf'

After this is done, start VPP in this container:

.. code-block:: console

    root@cone:/# service vpp start

Exit this container with the **exit** command (you *may* need to run **exit** twice):

.. code-block:: console

    root@cone:/# exit
    exit
    root@cone:/# exit
    exit
    root@localhost:~#

Repeat the container setup on this page for the second container **ctwo**. Go to the end of the previous page if you forgot how to start a container.




