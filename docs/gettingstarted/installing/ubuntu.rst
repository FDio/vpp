.. _ubuntu:

.. toctree::

Ubuntu - Setup the FD.io Repository
===================================

Choose one of the following releases to install.

Update the OS
-----------------------

It is a good idea to first update and upgrade the OS before starting; run the
following command to update the OS:

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

   deb [trusted=yes] https://packagecloud.io/fdio/release/ubuntu bionic main

Get the key:

.. code-block:: console

  curl -L https://packagecloud.io/fdio/release/gpgkey | sudo apt-key add -

VPP master Branch
^^^^^^^^^^^^^^^^^^^^

Create the file **/etc/apt/sources.list.d/99fd.io.list** that contain the following contents:

.. code-block:: console

   deb [trusted=yes] https://packagecloud.io/fdio/master/ubuntu bionic main

Get the key:

.. code-block:: console

  curl -L https://packagecloud.io/fdio/master/gpgkey | sudo apt-key add -


Install the Mandatory Packages
===============================

Install the mandatory packages by running the following commands:

.. code-block:: console

  sudo apt-get update
  sudo apt-get install vpp vpp-plugin-core vpp-plugin-dpdk

  
Install the Optional Packages
==============================

Install the optional packages by running the following command:

.. code-block:: console

  sudo apt-get install vpp-api-python python3-vpp-api vpp-dbg vpp-dev


Uninstall the Packages
======================

Uninstall the  packages by running the following command:

.. code-block:: console

  sudo apt-get remove --purge "vpp*"
