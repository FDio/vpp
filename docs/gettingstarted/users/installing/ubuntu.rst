.. _ubuntu:

.. toctree::
 
Ubuntu 16.04 - Setup the fd.io Repository
==========================================

Choose one of the following releases to install.


Update the OS
-----------------------

It is a good idea to first update and upgrade the OS before starting; run the following command to update the OS:

.. code-block:: console

    apt-get update


Point to the Repository
-----------------------------------

Create a file **/etc/apt/sources.list.d/99fd.io.list** with contents that point to
the version needed. The contents needed are shown below.

.. _install_vpp:

VPP latest Release
^^^^^^^^^^^^^^^^^^^

Create the file **/etc/apt/sources.list.d/99fd.io.list** that contain the following contents:

.. code-block:: console

   deb [trusted=yes] https://nexus.fd.io/content/repositories/fd.io.ubuntu.xenial.main/ ./


VPP stable/1804 Branch
^^^^^^^^^^^^^^^^^^^^^^^

Create the file **/etc/apt/sources.list.d/99fd.io.list** that contain the following contents:

.. code-block:: console

   deb [trusted=yes] https://nexus.fd.io/content/repositories/fd.io.stable.1804.ubuntu.xenial.main/ ./


VPP master Branch
^^^^^^^^^^^^^^^^^^^^

Create the file **/etc/apt/sources.list.d/99fd.io.list** that contain the following contents:

.. code-block:: console

   deb [trusted=yes] https://nexus.fd.io/content/repositories/fd.io.master.ubuntu.xenial.main/ ./


Install the Mandatory Packages
===============================

Install the mandatory packages by running the following commands:

.. code-block:: console

  sudo apt-get update
  sudo apt-get install vpp vpp-lib vpp-plugin


Install the Optional Packages
==============================

Install the optional packages by running the following command:

.. code-block:: console

  sudo apt-get install vpp-dbg vpp-dev vpp-api-java vpp-api-python vpp-api-lua


Uninstall the Packages
======================

Uninstall the  packages by running the following command:

.. code-block:: console

  sudo apt-get remove --purge vpp*
