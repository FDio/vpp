.. _sample_plugin_doc:

Sample plugin for VPP
=====================

Overview
--------

This is the VPP sample plugin demonstrates how to create a new plugin
that integrates with VPP. The sample code implements a trivial macswap
algorithm that demonstrates plugin runtime integration with the VPP
graph hierarchy, api and cli.

For deeper dive information see the annotations in the sample code
itself. See `sample.c <@ref%20sample.c>`__

How to build and run the sample plugin.
---------------------------------------

Now (re)build VPP.

::

   $ make wipe

Define environmental variable ‘SAMPLE_PLUGIN=yes’ with a process scope

::

   $ SAMPLE_PLUGIN=yes make build

or a session scope, and build VPP.

::

   $ export SAMPLE_PLUGIN=yes
   $ make build

Now run VPP and make sure the plugin is loaded.

::

   $ make run
   ...
   load_one_plugin:184: Loaded plugin: memif_plugin.so (Packet Memory Interface (experimetal))
   load_one_plugin:184: Loaded plugin: sample_plugin.so (Sample of VPP Plugin)
   load_one_plugin:184: Loaded plugin: nat_plugin.so (Network Address Translation)
   ...
   DBGvpp#

How to create a new plugin
--------------------------

To create a new plugin based on the sample plugin, copy and rename the
sample plugin directory and automake config.

::

   cp -r src/examples/sample-plugin/sample src/plugins/newplugin
   cp src/examples/sample-plugin/sample.am src/plugins/newplugin.am

Add the following entry to the plugins section of ``src/configure.ac``.

::

   PLUGIN_ENABLED(newplugin)

Add the following entry to the plugins section of
``src/plugins/Makefile.am``

::

   if ENABLE_NEWPLUGIN
   include newplugin.am
   endif

Now (re)build VPP.

::

   $ make wipe
   $ make build

Configuration
-------------

To enable the sample plugin

::

   sample macswap <interface name>

To disable the sample plugin

::

   sample macswap <interface name> disable
