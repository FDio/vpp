.. _vpp_plugins:

=======
Plugins
=======

vlib implements a straightforward plug-in DLL mechanism. VLIB client
applications specify a directory to search for plug-in .DLLs, and a name
filter to apply (if desired). VLIB needs to load plug-ins very early.

Once loaded, the plug-in DLL mechanism uses dlsym to find and verify a
vlib\_plugin\_registration data structure in the newly-loaded plug-in.

For more on plugins please refer to :ref:`add_plugin`.


.. toctree::
    :maxdepth: 2

    quic
    cnat
    lcp
    srv6/index
    marvell
    lldp
    nat64
    nat44_ei_ha
    pnat
    lb
    lacp
    flowprobe
    map_lw4o6
    mdata
    dhcp6_pd
    ioam
    wireguard
    srtp
    acl_multicore
    acl_hash_lookup
    acl_lookup_context
    bufmon_doc
