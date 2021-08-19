.. _installingVboxVagrant:

Installing Vbox and Vagrant
===========================

Installing VirtualBox
_____________________

First download VirtualBox, which is virtualization software for creating VM's.

If you're on CentOS, follow the `steps here <https://wiki.centos.org/HowTos/Virtualization/VirtualBox>`_.


If you're on Ubuntu, perform:

.. code-block:: shell

   $ sudo apt-get install virtualbox 

If you want to download a newer version of Virtual Box or one specific to your OS and architecture, go to the `Virtual Box download page <https://www.virtualbox.org/wiki/Downloads>`_.

Installing Vagrant
__________________

Here we are on a 64-bit version of CentOS, downloading and installing Vagrant 2.1.2:

.. code-block:: shell

   $ yum -y install https://releases.hashicorp.com/vagrant/2.1.2/vagrant_2.1.2_x86_64.rpm

This is a similar command, but on a 64-bit version of Debian:

.. code-block:: shell

   $ sudo apt-get install https://releases.hashicorp.com/vagrant/2.1.2/vagrant_2.1.2_x86_64.deb


If you want to download a newer version of Vagrant or one specific to your OS and architecture, go to the `Vagrant download page <https://www.vagrantup.com/downloads.html>`_.
