.. _ubuntu:

.. toctree::

Ubuntu - Setup the FD.io Repository
===================================

Choose one of the following releases to install.

Update the OS
-------------

It is a good idea to first update and upgrade the OS before starting; run the
following commands to upgrade the OS and install the curl package to download
the setup script from packagecloud.io:

.. code-block:: console

    sudo apt-get update
    sudo apt-get dist-upgrade -y
    sudo apt-get install curl

Configure Apt Using the Packagecloud Setup Script
-------------------------------------------------

FD.io Packagecloud Repositories provides pop-up menu that provides the
ability to copy a one-line bash command to fetch the packagecloud setup script.
In general, start at the FD.io packagecloud URL:

https://packagecloud.io/fdio

Then choose the desired repository link (e.g. 'release') and select the "Debian"
package icon in the section named "Quick install instructions".  When the pop-up
dialog appears, select the "Copy" button to copy the command to run the setup
script and paste it into a terminal on your server.


.. _install_vpp:

VPP Release Repo
^^^^^^^^^^^^^^^^^^^

The URL to install the latest VPP release is

https://packagecloud.io/fdio/release


VPP master Branch Repo
^^^^^^^^^^^^^^^^^^^^^^
The URL to install the latest VPP release is

https://packagecloud.io/fdio/release


VPP stable release Branch Repo
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Stable release branches are named "stable/YYMM" (e.g. stable/2206) and the associated
packagecloud repositories are named "YYMM" (e.g 2206).  For example, the URL to
the VPP 22.06 stable release branch package repository is:

https://packagecloud.io/fdio/2206


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


Remove FD.io Apt source lists
=============================

Remove FD.io Apt source list files created by the packagecloud apt setup script
by running the following command:

.. code-block:: console

  sudo rm /etc/apt/sources.list.d/fdio*.list
