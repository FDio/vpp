.. _runningvpp:

Running VPP
===========

Using the files we create in :ref`settingupenvironment` we will now start and
run VPP.

VPP runs in userspace. In a production environment you will often run it
with DPDK to connect to real NICs or vhost to connect to VMs. In those
circumstances you usually run a single instance of VPP.

For purposes of this tutorial, it is going to be extremely useful to run
multiple instances of VPP, and connect them to each other to form a
topology. Fortunately, VPP supports this.


Using the files we created in setup we will start VPP.

.. code-block:: console

   $ sudo /usr/bin/vpp -c startup1.conf
   vlib_plugin_early_init:361: plugin path /usr/lib/vpp_plugins:/usr/lib/vpp_plugins
   load_one_plugin:189: Loaded plugin: abf_plugin.so (ACL based Forwarding)
   load_one_plugin:189: Loaded plugin: acl_plugin.so (Access Control Lists)
   load_one_plugin:189: Loaded plugin: avf_plugin.so (Intel Adaptive Virtual Function (AVF) Device Plugin)
   .........
   $

If VPP does not start you can try adding **nodaemon** to the startup.conf file in the
**unix** section. This should provide more information in the output.

startup.conf example with nodaemon:

.. code-block:: console

   unix {nodaemon cli-listen /run/vpp/cli-vpp1.sock}
   api-segment { prefix vpp1 }
   plugins { plugin dpdk_plugin.so { disable } }

The command **vppctl** will launch a VPP shell with which you can run
VPP commands interactively.

We should now be able to execute the VPP shell and show the version.

.. code-block:: console

   $ sudo vppctl -s /run/vpp/cli-vpp1.sock
       _______    _        _   _____  ___
    __/ __/ _ \  (_)__    | | / / _ \/ _ \
    _/ _// // / / / _ \   | |/ / ___/ ___/
    /_/ /____(_)_/\___/   |___/_/  /_/
   
   vpp# show version
   vpp v18.07-release built by root on c469eba2a593 at Mon Jul 30 23:27:03 UTC 2018
   vpp#

.. note::

   Use ctrl-d or q to exit from the VPP shell.

If you are going to run several instances of VPP this way be sure to kill them
when you are finished.

You can use something like the following:

.. code-block:: console

    $ ps -eaf | grep vpp
    root      2067     1  2 05:12 ?        00:00:00 /usr/bin/vpp -c startup1.conf
    vagrant   2070   903  0 05:12 pts/0    00:00:00 grep --color=auto vpp
    $ kill -9 2067
    $ ps -eaf | grep vpp
    vagrant   2074   903  0 05:13 pts/0    00:00:00 grep --color=auto vpp
