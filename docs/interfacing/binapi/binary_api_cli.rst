.. _binary_api_cli:

==============
binary-api CLI
==============

``binary-api`` calls the binary API from the VPP CLI. It is a part of the
``unittest`` plugin, which is not loaded by default:

.. code-block:: console

  # vpp "unix { cli-listen /run/vpp/cli-vpp0.sock } plugins { plugin unittest_plugin.so { enable } }"

The messages and their fields are known from the :ref:`API descriptors
<vpp_api_descriptors>`, so every message of every plugin which is loaded is
available, without code in the plugin. There is one command for each request
message, made from its descriptor, so the arguments are typed, are
completed and have a usage.

``binary-api list [<filter>]``
  Lists the messages and the plugin each is from.

``binary-api help <message>``
  Shows the arguments of a message, with the description of each from the
  ``@param`` lines of the comment of the message in the ``.api`` file.

``binary-api <message> [<field> <value> ...] [json {...}]``
  Sends a message and shows the replies as JSON.

.. code-block:: console

  vpp# binary-api list show_ver
  show_version                             vpe
  1 messages
  vpp# binary-api help ip_route_lookup
  usage: binary-api ip_route_lookup [json <json>] [table_id <table_id>] [exact <exact>] [prefix <prefix>]
    binary-api ip_route_lookup [<field> <value> ...] [json {...}]

  arguments:
    json <text>       fields as JSON, for the ones which have no argument
    table_id <number> The IP table to look the route up in (u32)
    exact <number>    0 for normal route lookup, 1 for exact match only (u8)
    prefix <text>     The prefix (or host) for route lookup. (vl_api_prefix_t)

  output can be filtered: <cmd> | json|where|grep|head|tail|count
  vpp# binary-api show_version
  {
          "_msgname":     "show_version_reply",
          "_crc": "c919bde1",
          "retval":       0,
          "program":      "vpe",
          "version":      "27.02-rc0~657-g398195a72",
          "build_date":   "2026-11-22T17:43:02",
          "build_directory":      "/home/dmarion/vpp/no-test-api"
  }

The fields which are numbers, on/off values, enums, flags, strings, hex, interfaces,
MAC addresses and addresses are keywords with a value of the right type,
and a type made of such fields is a group of keywords. Everything else, for
example the arrays of types, is given with the ``json`` keyword, whose members
replace the ones of the arguments. The fields which are not given get their
default value, also in the types inside the message.

The request is sent by an in-process client, a dump is ended with a control
ping, and the output can be filtered with the pipes of the CLI.
