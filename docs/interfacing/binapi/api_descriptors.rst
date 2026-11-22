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
