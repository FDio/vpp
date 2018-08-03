.. _progressivevpp:

.. toctree::

########################
Progressive VPP Tutorial
########################

Overview
========

Learn to run FD.io VPP on a single Ubuntu 16.04 VM using Vagrant with this walkthrough
covering basic FD.io VPP senarios. Useful FD.io VPP commands will be used, and
will discuss basic operations, and the state of a running FD.io VPP on a system.

.. note::

    This is *not* intended to be a 'How to Run in a Production Environment' set of instructions.

.. _introduction-to-vpp-vagrant:

Setting up your environment
===========================

All of these exercises are designed to be performed on an Ubuntu 16.04 (Xenial) box.

* If you have an Ubuntu 16.04 box on which you have sudo or root access, you can feel free to use that.
* If you do not, a Vagrantfile is provided to setup a basic Ubuntu 16.04 box for you in the the steps below.

Running Vagrant
===============

FD.io VPP runs in userspace.  In a production environment you will often run it with DPDK to connect to real NICs or vhost to connect to VMs.
In those circumstances you usually run a single instance of FD.io VPP.

For purposes of this tutorial, it is going to be extremely useful to run multiple instances of vpp, and connect them to each other to form
a topology.  Fortunately, FD.io VPP supports this.

When running multiple FD.io VPP instances, each instance needs to have specified a 'name' or 'prefix'.  In the example below, the 'name' or 'prefix' is "vpp1". Note that only one instance can use the dpdk plugin, since this plugin is trying to acquire a lock on a file.

.. toctree::

    settingupenvironment.rst

The DPDK Plugin will be disabled for this section. The link below demonstrates how this is done.

.. toctree::

    removedpdkplugin.rst

Start a FD.io VPP shell using vppctl
====================================

The command *$ sudo vppctl* will launch a FD.io VPP shell with which you can run multiple FD.io VPP commands interactively by running:

.. code-block:: console

    $ sudo vppctl
       _______    _        _   _____  ___
    __/ __/ _ \  (_)__    | | / / _ \/ _ \
    _/ _// // / / / _ \   | |/ / ___/ ___/
    /_/ /____(_)_/\___/   |___/_/  /_/
    vpp# show ver
    vpp v18.07-release built by root on c469eba2a593 at Mon Jul 30 23:27:03 UTC 2018

Create an Interface
===================

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^

#. Create a veth interface in Linux host
#. Assign an IP address to one end of the veth interface in the Linux host
#. Create a vpp host-interface that connected to one end of a veth interface via AF_PACKET
#. Add an ip address to a vpp interface

.. toctree::

    interface.rst

Traces
======

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^

#. Setup a 'trace'
#. View a 'trace'
#. Clear a 'trace'
#. Verify using ping from host
#. Ping from vpp
#. Examine Arp Table
#. Examine ip fib

.. toctree::

    traces.rst

Routing
=======

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^

In this exercise you will learn these new skills:

#. Add route to Linux Host routing table
#. Add route to FD.io VPP routing table

And revisit the old ones:

#. Examine FD.io VPP routing table
#. Enable trace on vpp1 and vpp2
#. ping from host to FD.io VPP
#. Examine and clear trace on vpp1 and vpp2
#. ping from FD.io VPP to host
#. Examine and clear trace on vpp1 and vpp2


.. toctree::

    routing.rst

Connecting Two FD.io VPP Instances
==================================

memif is a very high performance, direct memory interface type which can
be used between FD.io VPP instances to form a topology. It uses a file socket
for a control channel to set up that shared memory.

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^

You will learn the following new skill in this exercise:

#. Create a memif interface between two FD.io VPP instances

You should be able to perform this exercise with the following skills
learned in previous exercises:

#. Run a second FD.io VPP instance
#. Add an ip address to a FD.io VPP interface
#. Ping from FD.io VPP

.. toctree::

    twovppinstances.rst

Switching
=========

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^

#. Associate an interface with a bridge domain
#. Create a loopback interaface
#. Create a BVI (Bridge Virtual Interface) for a bridge domain
#. Examine a bridge domain

.. toctree::

    switching.rst

Source NAT
==========

Skills to be Learned
^^^^^^^^^^^^^^^^^^^^

#. Abusing networks namespaces for fun and profit
#. Configuring snat address
#. Configuring snat inside and outside interfaces

.. toctree::

    sourceNAT.rst
