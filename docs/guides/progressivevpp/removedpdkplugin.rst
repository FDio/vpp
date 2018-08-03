.. _removedpdkplugin:

.. toctree::

Removing the DPDK Plugin
------------------------

For the purposes of this tutorial, the dpdk plugin will be removed. 
To do this edit the *startup.conf* file with the following, 
your *startup.conf* file may already have this line commented, and may just need to 
uncomment it:

.. code-block:: console

    plugins
    {
        plugin dpdk_plugin.so { disable }
    }