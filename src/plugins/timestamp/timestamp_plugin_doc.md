# Timestamp plugin for VPP    {#timestamp_plugin_doc}

## Overview

This is the VPP timestamp plugin.  It timestamps a packet coming INTO the device-input
feature arc in order for the another plugin to take calculate the delays between input
and their nodes.

For deeper dive information see the annotations in the  timestamp code itself. See [timestamp.c](@ref timestamp.c)

## How to build and run the timestamp plugin.

Now (re)build VPP.

	$ make wipe

Define environmental variable 'TIMESTAMP_PLUGIN=yes' with a process scope

	$ TIMESTAMP_PLUGIN=yes make build

or a session scope, and build VPP. 

	$ export TIMESTAMP_PLUGIN=yes
	$ make build

Now run VPP and make sure the plugin is loaded. 

	$ make run
	...
	load_one_plugin:184: Loaded plugin: memif_plugin.so (Packet Memory Interface (experimetal))
	load_one_plugin:184: Loaded plugin: timestamp_plugin.so (Timestamp of VPP Plugin)
	load_one_plugin:184: Loaded plugin: nat_plugin.so (Network Address Translation)
	...
	DBGvpp#

## Configuration

To enable the timestamp plugin

	timestamp <interface name>

To disable the timestamp plugin

	timestamp <interface name> disable
