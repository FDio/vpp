.. _libvnet_export_check:

Checking external plugin libvnet exports
========================================

The ``vpp-check-libvnet-exports`` command checks an out-of-tree plugin
binary before it is loaded by VPP. It reports function, object, and TLS
symbols that the plugin requires from libvnet but that are not present in
libvnet's dynamic export table. The command is installed with the VPP
development package and is also available in the source tree under
``src/scripts``.

The checker operates on ELF binaries. It does not require the plugin source
or integration into the VPP build. Use the libvnet binary from the VPP build
against which the plugin will run:

.. code-block:: console

    $ vpp-check-libvnet-exports \
        /path/to/unstripped/libvnet.so \
        /path/to/my_plugin.so

More than one plugin can be checked in the same invocation. The command
returns zero when all plugins are compatible, one when a required libvnet
export is missing, and two for a usage or input error.

When cross-checking binaries for another architecture, select a suitable ELF
reader explicitly:

.. code-block:: console

    $ vpp-check-libvnet-exports \
        --readelf aarch64-linux-gnu-readelf \
        /path/to/arm64/libvnet.so \
        /path/to/arm64/my_plugin.so

The ``READELF`` environment variable can also select the ELF reader.

The checker needs the regular symbol table from an unstripped libvnet binary
to identify definitions that hidden visibility removed from the dynamic
export table. VPP build-tree libraries contain this information. A stripped
runtime library is not sufficient.

For example, a failure is reported as:

.. code-block:: text

    my_plugin.so: missing required libvnet exports:
      adj_unlock (FUNC)
      ip6_main (OBJECT)
    libvnet export check failed

Each missing symbol must either be removed from the external plugin or
explicitly exported by libvnet when it is part of the supported interface.

This command checks symbol availability only. It does not detect incompatible
function prototypes or changes to data structure layouts.
