.. _sample_plugin:

Integrating a plugin
=====================

.. toctree::

Overview
________
 
This section shows how a VPP plugin developer can modify VPP scripts to add and load their plugin as a node in VPP. 

As an example we will integrate the **Sample Plugin** found in *vpp/src/examples/sample-plugin/sample* The VPP Sample Plugin is a small plugin that demonstrates simple implementation of a macswap algorithim. Since it is a VPP plugin, it has runtime integration with the VPP graph hierachy, API, and CLI.

This section will not go into the details of the plugin itself. For a deeper dive into the sample plugin see the annotations in `sample.c <https://docs.fd.io/vpp/18.11/da/d30/sample_8c.html>`_,  or go to the next page for general VPP C API usage.

Setup
_____

Each plugin has their own automake file (\*.am) used by *configure.ac*, as well as a separate directory containing C files for the plugin. The directory containing these for each plugin is *vpp/src/plugins*

To get a basic idea for how a VPP automake plugin file specifies its C files, here is part of the Sample Plugin automake file, *sample.am*

.. code-block:: console
    
    sample_plugin_la_SOURCES =      \
        sample/sample.c             \
        sample/node.c               \
        sample/sample_plugin.api.h

    API_FILES += sample/sample.api

    nobase_apiinclude_HEADERS +=            \
      sample/sample_all_api_h.h             \
      sample/sample_msg_enum.h              \
      sample/sample.api.h


The Sample Plugin is located in *vpp/src/examples/sample-plugin/sample*, so as mentioned above we will need to copy its contents into *vpp/src/plugins*

In your */vpp* directory, or the directory above */src*, run:

.. code-block:: console
    
    $ cp -r src/examples/sample-plugin/sample src/plugins
    $ cp src/examples/sample-plugin/sample.am src/plugins

Modifying configure.ac and Makefile.am
______________________________________

We now need to modify the plugin sections of the VPP automake and configuration scripts so that VPP builds correctly with your new plugin.

Using a text editor such as *vi*, add the following entry to the plugins section in *vpp/src/configure.ac*

.. code-block:: console
    
    PLUGIN_ENABLED(sample)

For reference, the plugins section of that file looks like this:

.. code-block:: console

    ###############################################################################
    # Plugins
    ###############################################################################

    # Please keep alphabetical order
    PLUGIN_ENABLED(abf)
    PLUGIN_ENABLED(acl)
    PLUGIN_ENABLED(avf)
    PLUGIN_ENABLED(cdp)
    PLUGIN_ENABLED(dpdk)
    PLUGIN_ENABLED(flowprobe)


Using a text editor such as *vi*, now add the following entry to the plugins section in *vpp/src/plugins/Makefile.am*

.. code-block:: console

    if ENABLE_SAMPLE_PLUGIN
    include sample.am
    endif

For reference, the plugins section of that file looks something like this:

.. code-block:: console

    vppapitestpluginsdir = ${libdir}/vpp_api_test_plugins
    vpppluginsdir = ${libdir}/vpp_plugins

    if ENABLE_ABF_PLUGIN
    include abf.am
    endif

    if ENABLE_ACL_PLUGIN
    include acl.am
    endif

    if ENABLE_AVF_PLUGIN
    include avf.am
    endif

Building and Running
____________________


Build VPP by using the main Makefile found in */vpp/Makefile*

.. code-block:: console
    
    $ make build

.. note::

    If you want to have a fresh debug build and compile every VPP file from scratch, you can wipe all compiled files and build VPP with:

    .. code-block:: console
    
        $ make rebuild

    However this will take much longer than just running *make build*

Run VPP and make sure the plugin is loaded. Below is the command for running the VPP debug binary, accompanied with sample output.

.. code-block:: console
    
    $ make run
    vlib_plugin_early_init:361: plugin path /vpp/build-root/install-vpp_debug-native/vpp/lib/vpp_plugins:/vpp/build-root/install-vpp_debug-native/vpp/lib64/vpp_plugins
    load_one_plugin:189: Loaded plugin: abf_plugin.so (ACL based Forwarding)
    load_one_plugin:189: Loaded plugin: acl_plugin.so (Access Control Lists)
    load_one_plugin:189: Loaded plugin: avf_plugin.so (Intel Adaptive Virtual Function (AVF) Device Plugin)
    load_one_plugin:191: Loaded plugin: cdp_plugin.so
    ...
    load_one_plugin:189: Loaded plugin: sample_plugin.so (Sample of VPP Plugin)
    ...
    load_one_vat_plugin:67: Loaded plugin: avf_test_plugin.so
    load_one_vat_plugin:67: Loaded plugin: mactime_test_plugin.so
    load_one_vat_plugin:67: Loaded plugin: sample_test_plugin.so
    ...
        _______    _        _   _____  ___ 
     __/ __/ _ \  (_)__    | | / / _ \/ _ \
     _/ _// // / / / _ \   | |/ / ___/ ___/
     /_/ /____(_)_/\___/   |___/_/  /_/    

    DBGvpp# 

.. note::

    Notice when running the debug build that (\*_test_plugin.so) is also loaded, which is meant for testing your plugin.

To enable the sample plugin, use this command:

.. code-block:: console
    
    DBGvpp# sample macswap <interface name>

To disable the sample plugin, use this command:

.. code-block:: console
    
    DBGvpp# sample macswap <interface name> disable


Great! Now you've successfully added your plugin as a VPP node.


Additional remarks 
__________________

How the build process works for plugins is that the (\*.api) plugin file is automatically translated to a JSON file (\*.api.json) in *vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api/plugins*, which the code generator then parses and generates a C header file (\*.api.h) in *vpp/build-root/install-vpp_debug-native/vpp/include/vpp_plugins/\**.

After the build process is completed you finally end up with two plugin files (\*_plugin.so and \*_test_plugin.so) found in *vpp/build-root/install-vpp_debug-native/vpp/lib64/vpp_plugins* and *vpp/build-root/install-vpp_debug-native/vpp/lib64/vpp_api_test_plugins* respectively, that are loaded at runtime during a debug binary run of VPP (*make run*).

