.. _debug_telnet_cli:

Debug and Telnet CLI
====================

The debug CLI is enabled with the unix interactive parameter or startup
configuration option. This causes VPP to start without daemonizing and
presents a command line interface on the terminal where it is run.

The Telnet CLI is enabled with the ``cli-listen localhost:5002`` option which
will cause VPP to listen for TCP connections on the localhost address port
``5002``. A Telnet client can then connect to this port (for example, ``telnet
localhost 5002``) and will receive a command line prompt.

This configuration will enable both mechanisms:

.. code-block:: console

    unix {
      interactive
      cli-listen localhost:5002
    }


The debug CLI can operate in line mode, which may be useful when running
inside an IDE like Emacs. This is enabled with the option
``unix cli-line-mode``. Several other options exist that alter how this
CLI works, see the @ref syscfg section for details.

The CLI starts with a banner graphic (which can be disabled) and a prompt. The
prompt will typically read ``vpp`` for a release version of VPP and ``DBGvpp#``
for a development version with debugging enabled, for example:

.. code-block:: console

        _______    _        _   _____  ___
     __/ __/ _ \  (_)__    | | / / _ \/ _ \
     _/ _// // / / / _ \   | |/ / ___/ ___/
     /_/ /____(_)_/\___/   |___/_/  /_/

    vpp#



versus:

.. code-block:: console

        _______    _        _   _____  ___
     __/ __/ _ \  (_)__    | | / / _ \/ _ \
     _/ _// // / / / _ \   | |/ / ___/ ___/
     /_/ /____(_)_/\___/   |___/_/  /_/

    DBGvpp#


This prompt can be configured with the ``unix cli-prompt`` setting and the
banner is disabled with ``unix cli-no-banner``.