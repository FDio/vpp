.. _opensuse:

.. toctree::

Installing
==========

To install VPP on openSUSE, first install the following release, and then execute
the associated commands.

openSUSE Tumbleweed (rolling release)
------------------------------------------------------------

.. code-block:: console

   sudo zypper install vpp vpp-plugins

openSUSE Leap 42.3
--------------------------------

.. code-block:: console

   sudo zypper addrepo --name network https://download.opensuse.org/repositories/network/openSUSE_Leap_42.3/network.repo
   sudo zypper install vpp vpp-plugins

Uninstall
=========

To uninstall the vpp plugins, run the following command:

.. code-block:: console

   sudo zypper remove -u vpp vpp-plugins

openSUSE Tumbleweed (rolling release)
-------------------------------------

To uninstall the openSUSE Tumbleweed, run the following command:

.. code-block:: console

   sudo zypper remove -u vpp vpp-plugins

openSUSE Leap 42.3
------------------

.. code-block:: console

   sudo zypper remove -u vpp vpp-plugins
   sudo zypper removerepo network

For More Information
====================
For more information on VPP with openSUSE, please look at the following post.

* https://www.suse.com/communities/blog/vector-packet-processing-vpp-opensuse/

