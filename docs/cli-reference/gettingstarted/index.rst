.. _cli_getting_started:

Getting Started with the debug CLI
==================================

The VPP network stack comes equipped with a set of commands that are useful
for debugging.

The easiest way to access the CLI (with proper permissions) is to use the
vppctl command:

.. code-block:: console

    sudo vppctl <cli-command>


The CLI parser matches static keyword strings, eventually invoking an action
function. Unambiguous partial keyword matching always occurs. The action
functions consume input until satisfied or until they fail. This model makes
for easy coding, but does not guarantee useful "help" output. It's up to the
CLI command writer to add useful help strings.

You can find the source code of CLI commands by searching for instances of the
``VLIB_CLI_COMMAND`` macro in the code source files.

Please help maintain and improve this document to make and keep these commands
clear and useful!

.. _cli_transition:

The new CLI and the transition
------------------------------

VPP is moving its debug CLI from commands which parse their own text with
``unformat`` to commands which declare their arguments as typed data. Both
kinds live in the same command tree and are used the same way, but the
converted commands give you more:

- **Completion and help of the arguments.** TAB completes keywords, enum
  words and names such as interfaces, nodes or profiles, not only the
  command path. ``?`` after a command shows the usage of every argument.
- **Useful errors.** A mistake is reported with the line and a marker below
  the offending word, and a close match is suggested, for example
  ``unexpected argument 'cuont', did you mean 'count'?``.
- **Filters on any output.** ``| grep``, ``| head``, ``| tail`` and
  ``| count`` work on every command, converted or not.
- **Structured output.** Commands which support it print a table, or JSON
  with ``| json``, and rows can be selected with ``| where <field> <op>
  <value>``. For example ``show runtime | json`` or
  ``show runtime | where name == "fib-walk"``. A command which does not
  support it refuses ``| json`` and ``| where`` with the error "command has
  no structured output".
- **One syntax.** Keywords and flags are not abbreviated implicitly, a short
  spelling exists only where the command declares an alias, and TAB
  completes the full word. The words of the command itself can still be
  abbreviated, ``sh int`` is ``show interface``.
- **A schema.** ``show cli schema`` dumps every command and its arguments as
  JSON, which tools and the ``vppctl`` bash completion use.

Converted commands are stricter than the legacy ones. Text after the last
argument, which a legacy command ignored, is an error now, so check your
``exec`` files and scripts when you upgrade. The CLI is a debug interface and
its syntax is not guaranteed to stay the same between releases. Use the API
for anything which has to be stable.

``show cli`` tells which commands are converted:

.. code-block:: console

    vpp# show cli summary
    total    541
    legacy   330
    mp-safe  64

``show cli legacy`` lists the commands which have not been converted yet,
``show cli not-legacy`` the converted ones and ``show cli structured`` the
commands which can emit structured output. They can be combined with
``mp-safe`` and ``not-mp-safe``. The numbers above are an example, they
depend on the version and on the loaded plugins.

If you write commands, see :ref:`cli_handlers`.

.. _debug_telnet_cli:

Debug and Telnet CLI
--------------------

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

.. _cli_features:

CLI features
------------

The CLI has several editing features that make it easy to use.

- Cursor keys ``left/right`` will move the cursor within a command line;
  typing will insert at the cursor; erase will erase at the cursor.

- ``Ctrl-left/right`` will search for the start of the next word to
  the left or right.
- ``Home/end`` will jump the cursor to the start and end of the line.
- Cursor keys up/down and ``^P/^N`` iterate through the command history
  buffer. Lines from the history buffer may be edited. New commands
  are added to the end of the buffer when executed; though
  duplicates of the previous command are not added.
- ``^U`` erases the line contents from the left of the cursor to the
  start.
- ``^K`` erases the contents from the cursor to the end.
- ``^S/^R`` will search the command history forwards or in reverse for
  a command; start typing for matches to auto complete.
- ``^L`` will clear the screen (if supported by the terminal) and repaint
  the prompt and any current line. The cursor position is also
  retained.
- The CLI can be closed with the quit command. Alternatively, ``^D`` on
  an empty input line will also close the session. Closing the debug
  session will also shutdown VPP.

Output that exceeds the length of a terminal page will be buffered, up to a
limit.

- ``Space`` or ``page-down`` displays the next page.
- ``Enter`` or ``down-arrow`` displays the next line.
- ``Page-up`` goes back a page.
- ``Up-arrow`` goes up a line.
- ``Home/end`` jump to the start/end of the buffered output.
- The key ``q`` quits the pager. ``Space`` and ``enter`` will also quit the
  pager if the end of the buffer has been reached.