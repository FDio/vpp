.. _vpp_api_descriptors:

===============
API descriptors
===============

``vppapigen`` creates, for every ``.api`` file which defines messages, a ``const``
description of its messages and types in ``<file>.api_desc.c``, which is
compiled into the plugin or the library of the file. The plugin registers it with
``vl_api_desc_register ()`` when it sets up its message ids, so that generic code
can work with any message without functions which are generated for each message.
The messages of ``memclnt.api`` and of ``srmpls``, which are registered by hand,
have descriptors too.

A descriptor has, for the file, its name, its CRC and its options, and for every
message and type:

* the name, the kind (message, typedef, union, enum, ``enumflag`` or alias), the CRC
  and the options of a message, its brief description from the ``\brief`` of its
  comment, and for a request message the message which answers it and the message
  of the details of a dump,
* for every field its name, its kind, its offset and size in the packed C
  structure, the length of a fixed array, the field which has the length of a
  variable length array, whether it is a string, for a tagged union the field
  which has the tag and the name of the value of the tag of each arm, and its
  description from the ``@param`` line of the comment. ``vppapigen`` warns about
  a ``@param`` which is not a field,
* the values of an enum and its underlying type, and what an alias is an
  alias of.

The types of the imported files which are used are included, so a descriptor
does not depend on other descriptors. The layout is checked by the compiler,
the generated code asserts the ``sizeof`` and the ``offsetof`` of every type.

The descriptors are declared in ``src/vlibapi/api_desc.h``.
``vl_api_desc_find_msg (am, msg_id)`` returns the descriptor of a registered
message and ``am->desc_files`` has the descriptors of all the files.

What uses them
--------------

* The text which ``get_api_json`` returns for each file, the same as the
  ``<file>.api.json`` file which ``vppapigen`` writes, is rendered from the
  descriptor when it is requested, by ``vl_api_desc_schema_to_json ()``. It has
  the types, the messages, the services and the options, but not the comments,
  the imports, the counters and the paths of the file, nor the events of the
  services. Plugins do not embed a copy of it.

* ``vl_api_desc_msg_to_json ()`` converts a message to JSON. It is used by
  ``api trace save-json``, ``api trace dump-json`` and by
  ``format_vl_api_msg_json ()``. The members are ``_msgname``, ``_crc`` and the
  fields, except ``_vl_msg_id``, ``client_index`` and ``context``. The text is
  written by clib_json. VPP does not register the generated
  ``vl_api_<msg>_t_tojson`` functions any more.

* ``vl_api_desc_msg_from_json ()`` converts JSON to a message, the opposite of
  the conversion above. It is used by ``api trace replay-json``, which
  parses the file with clib_json. Every field of the message has to be in the
  JSON. VPP does not register the generated ``vl_api_<msg>_t_fromjson``
  functions any more.

* ``vl_api_desc_msg_format ()`` creates the text of a message, which is what
  ``format_vl_api_msg_text ()`` and the text output of ``api trace dump``
  print. VPP does not register the generated ``vl_api_<msg>_t_format``
  functions any more.

* ``vl_api_desc_msg_calc_size ()`` calculates the size of a received message
  from the lengths in its fields. The message handler drops a message which
  is smaller than that, as such a message could make the byte order
  conversion or the handler read past its end. VPP does not register the
  generated ``vl_api_<msg>_t_calc_size`` functions any more, and a message
  which has no descriptor is not checked.

* ``vl_api_msg_endian (am, msg_id, msg, to_net)`` converts a message to or from
  network byte order, which is big endian, by interpreting its descriptor.
  VPP does not register the generated ``vl_api_<msg>_t_endian`` functions any
  more, a message which has no descriptor is still converted by the handler it
  was registered with. The descriptor tells which fields are tags of unions
  and which are lengths, the conversion reads them before it converts them. The
  steps of a message are worked out when it is first used, and kept.

``vppapigen`` does not create the ``vl_api_<msg>_t_tojson``,
``vl_api_<msg>_t_fromjson``, ``vl_api_<msg>_t_calc_size`` and
``vl_api_<msg>_t_format`` functions of the messages, the
``<file>.api_tojson.h`` and ``<file>.api_fromjson.h`` files any more. The
``format_vl_api_<type>_t`` functions of the types are still created.

Showing the descriptors
-----------------------

``show api descriptor`` shows what is registered:

.. code-block:: console

  vpp# show api descriptor module vpe
  module vpe, crc 0xbbfa7484, 6 messages, 0 types
  Name                       Kind      ID      CRC Size Reply
  show_version               message 1594 51077d14   10 show_version_reply
  show_version_reply         message 1595 c919bde1  362
  show_vpe_system_time       message 1596 51077d14   10 show_vpe_system_time_reply
  show_vpe_system_time_reply message 1597 7ffd8193   18
  log_dump                   message 1598 6ab31753   18 log_details
  log_details                message 1599 03d61cc0  306

* ``show api descriptor`` lists the files with their CRC and the number of
  messages and types.
* ``show api descriptor module <name>`` lists the messages and the types of a
  file, with the id, the CRC, the size and the reply of a message.
* ``show api descriptor message <name>`` and ``show api descriptor type
  <name>`` show the layout of one of them, the names are completed. The
  description of a message, from the ``\brief`` of its comment in the ``.api``
  file, and the description of each of its fields, from the ``@param`` lines,
  are shown too:

.. code-block:: console

  vpp# show api descriptor message ip_route_lookup
  message ip_route_lookup
    Lookup IP route from a table
    id 1144, crc 710d6471
    size 33
  Field        Type            Kind   Offset Size Array Description
  _vl_msg_id   u16             u16         0    2
  client_index u32             u32         2    4       opaque cookie to identify the sender
  context      u32             u32         6    4
  table_id     u32             u32        10    4       The IP table to look the route up in
  exact        u8              u8         14    1       0 for normal route lookup, 1 for exact match only
  prefix       vl_api_prefix_t struct     15   18       The prefix (or host) for route lookup.

The output can be shown as JSON with ``| json``.

Descriptors from JSON
---------------------

A program which does not have the descriptors compiled in, like ``vat2``, can
get them from a running VPP. ``vl_api_desc_file_from_json ()`` creates the
descriptors of a file from the text ``get_api_json`` returns for it, and
``vl_api_desc_file_free ()`` frees them. The layout is calculated the same way
``vppapigen`` does it. What the JSON does not have is not set: which types
are converted by hand are known by their names, and which types were
imported and which messages use ``autoendian`` are not used when the
descriptors are interpreted.
