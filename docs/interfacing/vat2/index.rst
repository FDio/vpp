.. _vat2:

====
VAT2
====

VAT2 is a CLI tool to exercise VPP's :ref:`binary API <vpp_binapi>`
via shared memory mainly for testing purposes.

History
-------

It evolved from ``vpp_api_test``, see its history in:

* `the original vat2 RFC <https://lists.fd.io/g/vpp-dev/message/18092>`_
* `vat2 discussion on the vpp-dev mailing list <https://lists.fd.io/g/vpp-dev/search?d=0&ev=0&p=Created,,vat2,20,2,0,0&ct=1>`_
* `vat2 code changes <https://gerrit.fd.io/r/q/project:vpp+message:vat2>`_

Installation
------------

When distributed in binary packages it is installed from the ``vpp`` package.
It is available since VPP `release v21.01 <https://docs.fd.io/vpp/24.10/aboutvpp/releasenotes/v21.01.html>`_.

Usage examples
--------------

Here are a few working examples to get you started.

If you started ``vpp`` with an api-segment prefix,
you must use the same prefix with ``vat2`` also:

.. code-block:: console

  # vpp "api-segment { prefix vpp0 } unix { cli-listen /run/vpp/cli-vpp0.sock log /var/log/vpp/vpp0.log } api-trace { on } statseg { socket-name /run/vpp/statseg-vpp0.sock }"
  # vat2 --prefix vpp0 show_version '{}'

But let's stick to not having a prefix.
The simplest call to print VPP's version.
``-d`` prints debug information:

.. code-block:: console

  # kill $( pgrep vpp )
  # vpp "unix { cli-listen /run/vpp/cli-vpp0.sock log /var/log/vpp/vpp0.log } api-trace { on } statseg { socket-name /run/vpp/statseg-vpp0.sock }"
  # vat2 -d show_version '{}'
  debug = 1, filename = (null), template = (null), shared memory prefix: (null)
  Non-option argument show_version
  Non-option argument {}
  Plugin Path /usr/lib/x86_64-linux-gnu/vat2_plugins
  Opening path: /usr/lib/x86_64-linux-gnu/vat2_plugins
  Loaded 138 plugins
  {
          "_msgname":     "show_version_reply",
          "_crc": "c919bde1",
          "retval":       0,
          "program":      "vpe",
          "version":      "24.06.0-2~gcd30ea1dd~b19",
          "build_date":   "2024-07-31T17:57:13",
          "build_directory":      "/w/workspace/vpp-merge-2406-ubuntu2204-x86_64"
  }

Make ``vat2`` print the API messages it knows:

.. code-block:: console

  # vat2 --dump-apis | sort
  abf_itf_attach_add_del
  abf_itf_attach_dump
  abf_plugin_get_version
  abf_policy_add_del
  abf_policy_dump
  acl_add_replace
  acl_del
  acl_dump
  acl_interface_add_del
  acl_interface_etype_whitelist_dump
  [snip]

The equivalent of ``vppctl create host-interface``.
First create a Linux interface for the sake of this exercise:

.. code-block:: console

  # ip link add dummy0 type dummy
  # ip link set up dev dummy0
  # ip link show dev dummy0
  8545: dummy0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
      link/ether be:38:84:29:27:0b brd ff:ff:ff:ff:ff:ff

``vat2`` can print a message format sample for each API message.
Save and edit it.
``vat2`` does not know which parameter is optional, it expects all parameters.
Use VPP's API documentation and source code and domain specific knowledge to
understand which parameter values and combinations are valid.

.. code-block:: console

  # vat2 -t af_packet_create_v3 > af_packet_create_v3.json
  # vi af_packet_create_v3.json
  {
      "_msgname":             "af_packet_create_v3",
      "_crc":                 "b3a809d4",
      "mode":                 "AF_PACKET_API_MODE_ETHERNET",
      "hw_addr":              "be:38:84:29:27:0b",
      "use_random_hw_addr":   false,
      "host_if_name":         "dummy0",
      "rx_frame_size":        2048,
      "tx_frame_size":        2048,
      "rx_frames_per_block":  32,
      "tx_frames_per_block":  32,
      "flags":                "AF_PACKET_API_FLAG_VERSION_2",
      "num_rx_queues":        1,
      "num_tx_queues":        1
  }

Create the host-interface:

.. code-block:: console

  # vat2 af_packet_create_v3 "$( cat af_packet_create_v3.json )"
  {
          "_msgname":     "af_packet_create_v3_reply",
          "_crc": "5383d31f",
          "retval":       0,
          "sw_if_index":  1
  }

Use VPP's source code to interpret error return values.

Dump a table of interface names and indexes:

.. code-block:: console

  # vat2 sw_interface_dump '{"sw_if_index": -1, "name_filter_valid": 0, "name_filter": ""}' | jq -r '.[] | .sw_if_index, .interface_name' | paste - -
  0       local0
  1       host-dummy0

Set interface MTU:

.. code-block:: console

  # vat2 sw_interface_set_mtu '{"sw_if_index": 1, "mtu": [1500, 1500, 1500, 1500]}'
  {
          "_msgname":     "sw_interface_set_mtu_reply",
          "_crc": "e8d4e804",
          "retval":       0
  }

Since ``vat2`` uses VPP's binary API, its calls can be traced:

.. code-block:: console

  # vppctl -s /run/vpp/cli-vpp0.sock api trace dump | tail
    sw_if_index: 4294967295
    name_filter_valid: 0
    name_filter:
  vl_api_control_ping_t:
  vl_api_sw_interface_set_mtu_t:
    sw_if_index: 1
    mtu: 1500
    mtu: 1500
    mtu: 1500
    mtu: 1500

A few more examples compiled from
`the vpp-dev mailig list archives <https://lists.fd.io/g/vpp-dev>`_:

Add an ACL with a rule (see also
`mailing list topic "vat2 crashes when passing array in json body" <https://lists.fd.io/g/vpp-dev/topic/105688147#msg24323>`_
and
`this bugfix <https://gerrit.fd.io/r/c/vpp/+/40825>`_
):

.. code-block:: console

  # vat2 acl_add_replace '{"acl_index": -1, "tag": "", "count": 1, "r": [{"is_permit": "ACL_ACTION_API_PERMIT", "src_prefix": "0.0.0.0/0", "dst_prefix": "0.0.0.0/0", "proto": "IP_API_PROTO_HOPOPT", "srcport_or_icmptype_first": 0, "srcport_or_icmptype_last": 0, "dstport_or_icmpcode_first": 0, "dstport_or_icmpcode_last": 0, "tcp_flags_mask": 0, "tcp_flags_value": 0, "ips_profile": 0, "log": 0, "policy_id": 0}]}'
  {
          "_msgname":     "acl_add_replace_reply",
          "_crc": "ac407b0c",
          "acl_index":    0,
          "retval":       0
  }

Add a NAT mapping (see
`mailing list topic "vat2 nat44_add_del_static_mapping does not handle flags correctly" <https://lists.fd.io/g/vpp-dev/topic/107138143#msg24711>`_
about possibly invalid flags):

.. code-block:: console

  # vat2 nat44_add_del_static_mapping '{"is_add": true, "flags": "NAT_IS_OUT2IN_ONLY", "local_ip_address": "10.0.0.10", "external_ip_address": "77.0.0.1", "external_sw_if_index": -1, "local_port": 0, "external_port": 0, "vrf_id": 0, "protocol": 0, "tag": ""}'
