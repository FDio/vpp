.. _ubuntu:

.. toctree::
 
Ubuntu 16.04 - Setup the fd.io Repository
==========================================

From the following, choose one of the releases to install.


Update the OS
-----------------------

It is probably a good idea to update and upgrade the OS before starting

.. code-block:: console

    apt-get update


Point to the Repository
-----------------------------------

Create a file **"/etc/apt/sources.list.d/99fd.io.list"** with the contents that point to
the version needed. The contents needed are shown below.

.. _install_vpp:

VPP latest Release
^^^^^^^^^^^^^^^^^^^

Create the file **/etc/apt/sources.list.d/99fd.io.list** with contents:

.. code-block:: console

   deb [trusted=yes] https://nexus.fd.io/content/repositories/fd.io.ubuntu.xenial.main/ ./


VPP stable/1804 Branch
^^^^^^^^^^^^^^^^^^^^^^^

Create the file **/etc/apt/sources.list.d/99fd.io.list** with contents:

.. code-block:: console

   deb [trusted=yes] https://nexus.fd.io/content/repositories/fd.io.stable.1804.ubuntu.xenial.main/ ./


VPP master Branch
^^^^^^^^^^^^^^^^^^^^

Create the file **/etc/apt/sources.list.d/99fd.io.list** with contents:

.. code-block:: console

   deb [trusted=yes] https://nexus.fd.io/content/repositories/fd.io.master.ubuntu.xenial.main/ ./


Install the Mandatory Packages
===============================

.. code-block:: console

  sudo apt-get update
  sudo apt-get install vpp vpp-lib vpp-plugin


Install the Optional Packages
==============================

.. code-block:: console

  sudo apt-get install vpp-dbg vpp-dev vpp-api-java vpp-api-python vpp-api-lua


Uninstall the Packages
======================

.. code-block:: console

  sudo apt-get remove --purge vpp*
