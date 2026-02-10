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
    npol
    lcp
    srv6/index
    lldp
    nat64
    nat44_ei_ha
    nat44_ed_doc
    pnat
    lb
    lacp
    flowprobe
    sflow
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
    ip_session_redirect_doc
    bpf_trace_filter
    http
    policer
