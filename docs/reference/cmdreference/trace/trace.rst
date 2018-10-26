.. _interface:

.. toctree::

.. note:: For a complete list of CLI Debug commands refer to the Debug CLI section of the `Source Code Documents <https://docs.fd.io/vpp/18.07/clicmd.html>`_ .


API Trace 
===========

Summary/Usage
--------------

api trace [on|off][first <*n*>][last <*n*>][status][free][post-mortem-on][dump|custom-dump|save|replay <*file*>]

Description
------------

Display, replay, or save a binary API trace.

Declaration and Implementation
-------------------------------

**Declaration:** api_trace_command (src/vlibmemory/vlib_api_cli.c line 783)

**Implementation:** api_trace_command_fn

Clear Trace
=============

Summary/Usage
--------------
Clear trace buffer and free memory.
Declaration and implementation

**Declaration:** clear_trace_cli (src/vlib/trace.c line 519)

**Implementation:** cli_clear_trace_buffer

Show Trace
===========

`Show Trace <../show/show.html#show-trace>`_

Trace Add
===========

Summary/Usage
--------------

Trace given number of packets.

Declaration and Implementation
-------------------------------

**Declaration:** add_trace_cli (src/vlib/trace.c line 405)

**Implementation:** cli_add_trace_buffer