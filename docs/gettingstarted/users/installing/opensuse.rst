.. _opensuse:

.. toctree::

Installing
==========
Top install VPP on openSUSE first pick the following release and execute the appropriate commands.

openSUSE Tumbleweed (rolling release)
-------------------------------------

.. code-block:: console

   sudo zypper install vpp vpp-plugins

openSUSE Leap 42.3
------------------

.. code-block:: console

   sudo zypper addrepo --name network https://download.opensuse.org/repositories/network/openSUSE_Leap_42.3/network.repo
   sudo zypper install vpp vpp-plugins

Uninstall
=========

.. code-block:: console

   sudo zypper remove -u vpp vpp-plugins

openSUSE Tumbleweed (rolling release)
-------------------------------------

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

