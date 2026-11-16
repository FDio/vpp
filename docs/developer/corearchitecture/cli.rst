.. _cli_handlers:

====================================
Writing CLI commands
====================================

A CLI command is registered with ``VLIB_CLI_COMMAND``. The arguments are
declared as typed data in ``.args``, the infrastructure parses them, and the
``.handler`` receives the parsed values. From that single declaration you get:

* tab completion of the arguments, not only of the command path,
* ``?`` and ``help`` output with the usage of each argument,
* validation, with an error pointing at the offending token and a
  "did you mean" suggestion,
* the text filters ``| grep``, ``| head``, ``| tail`` and ``| count``,
* structured output (``| json``, ``| where``) if the handler emits it,
* the schema, in ``show cli schema``, used by tools and ``vppctl`` bash
  completion.

The code lives in ``src/vppinfra/cli.[ch]`` (grammar, parser, types) and
``src/vlib/cli_decl.[ch]`` (glue to vlib). Everything works without ANSI
escape sequences.

A first command
===============

.. code-block:: c

   static clib_error_t *
   set_foo_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
   {
     u32 sw_if_index = cli_index (ctx, "interface");
     u32 count = cli_u64 (ctx, "count", 1);
     int verbose = cli_flag (ctx, "verbose");

     if (verbose)
       vlib_cli_output (vm, "setting foo on %u, %u times", sw_if_index, count);

     return foo_set (sw_if_index, count);
   }

   VLIB_CLI_COMMAND (set_foo_command, static) = {
     .path = "set foo",
     .short_help = "Set foo on an interface",
     .args =
       (cli_arg_t[]) {
         CLI_VALUE ("interface", cli_type_sw_interface),
         CLI_KEYWORD ("count", cli_type_u32, .flags = CLI_F_OPTIONAL, .min = 1, .max = 100,
                      .help = "number of times, default 1"),
         CLI_FLAG ("verbose"),
         {},
       },
     .handler = set_foo_command_fn,
   };

Accepted input::

   set foo GigabitEthernet0/8/0
   set foo GigabitEthernet0/8/0 count 5 verbose
   set foo 1 verbose count 5

The argument list is terminated by an empty element ``{}``. A command with a
``.handler`` and no ``.args`` takes no arguments. The handler returns
``NULL`` on success or a ``clib_error_t``, and writes
to the CLI with ``vlib_cli_output``.

Describing arguments
====================

An argument has a kind, a name, a type and optional modifiers.

``CLI_VALUE (name, type, ...)``
  A value identified by its position. Values are given in declaration order.

``CLI_KEYWORD (name, type, ...)``
  A keyword followed by a value: ``count 5``. Keywords can be given in any
  order, after the values.

``CLI_FLAG (name, ...)``
  A keyword without value: ``verbose``.

``CLI_ENUM (name, flags, { "text", "help", value }, ...)``
  One of a fixed list of words. The value is the third member of the chosen
  element. Use it as ``CLI_VALUE`` or, with ``CLI_KEYWORD (..., cli_type_enum,
  .choices = x)``, when the table is shared.

``CLI_ONEOF (name, flags, alt, ...)``
  Exactly one of the alternatives. An alternative is usually a ``CLI_SEQ``.

``CLI_SEQ (...)``
  An ordered group of arguments, used as an alternative of ``CLI_ONEOF``.

``CLI_GROUP (name, help, ...)``
  An optional keyword which enables its own keywords and flags, in any order:
  ``tunnel src 1.1.1.1 dst 2.2.2.2``. The child names are valid only after the
  group keyword, so they do not need to be unique in the command.

Modifiers, set with designated fields after the type:

``.flags = CLI_F_OPTIONAL``
  The argument can be omitted. Without it, a missing argument is an error.
  Flags and groups are always optional.

``.flags = CLI_F_REPEAT``
  The argument can be given more than once, read it with ``cli_foreach``.

``.min``, ``.max``
  Range of an integer. ``.max = 0`` means the maximum of the type.

``.help``
  Description shown by ``?`` and in completion.

``.alias``
  A second accepted spelling of a keyword or flag.

``.choices``
  Table for ``cli_type_enum``.

Add and delete forms are separate commands, not a ``del`` flag:

.. code-block:: c

   VLIB_CLI_COMMAND (foo_add_command, static) = { .path = "foo add", ... };
   VLIB_CLI_COMMAND (foo_del_command, static) = { .path = "foo del", ... };

Reading values
==============

Values are looked up by the declared name. The ``ctx`` is valid only during
the handler.

``cli_flag (ctx, "name")``
  Non-zero if the flag or an optional argument was given.

``cli_u64 (ctx, "name", default)``
  Integer value (``cli_type_u32`` and ``cli_type_u64``), or the default.

``cli_index (ctx, "name")``
  Index-like value: enum value, ``sw_if_index``, ``hw_if_index``, node index.
  ``~0`` if not given.

``cli_get (ctx, "name")``
  Returns a ``cli_value_t`` or ``NULL``. Use it for strings (``v->str``,
  a vector owned by the context), floats (``v->f64``), prefixes
  (``v->prefix``), and ranges (``v->range``).

``cli_foreach (v, ctx, "name")``
  Iterates over the values of a repeated argument, in the order given.

Optional arguments which were not given are not present, so test them with
``cli_flag`` or ``cli_get`` and do not rely on a zero value unless zero is
what you want as the default.

Built-in types
==============

.. list-table::
   :header-rows: 1

   * - Type
     - Value
     - Notes
   * - ``cli_type_u32``
     - ``v->u64``
     - decimal or 0x hex
   * - ``cli_type_u64``
     - ``v->u64``
     - decimal or 0x hex
   * - ``cli_type_f64``
     - ``v->f64``
     - floating point
   * - ``cli_type_string``
     - ``v->str``
     - one word or "quoted"
   * - ``cli_type_enum``
     - ``v->index``
     - completes .choices
   * - ``cli_type_range``
     - ``v->range.start, v->range.stop``
     - a-b
   * - ``cli_type_rest``
     - ``v->str``
     - see below
   * - ``cli_type_node``
     - ``v->index``
     - vlib node
   * - ``cli_type_sw_interface``
     - ``v->index``
     - name or index
   * - ``cli_type_hw_interface``
     - ``v->index``
     - name
   * - ``cli_type_ip_prefix``
     - ``v->prefix``
     - a.b.c.d/len or IPv6 prefix
   * - ``cli_type_ip_address``
     - ``v->prefix.addr, v->prefix.is_ip6``
     - IPv4 or IPv6
   * - ``cli_type_ip_range``
     - ``v->ip_range``
     - first-last

``cli_type_rest`` takes the rest of the line, up to a ``|``, exactly as it was
typed. It is meant for text (``echo``, ``define``) and for commands that
still parse a sub-language with ``unformat``. A quoted ``"|"`` is not a pipe.

Defining a new type
===================

Any component, including a plugin, can register a type. The type gives the
parser a function to convert a word into a value and a function to produce
completion candidates:

.. code-block:: c

   static u8 *
   parse_foo (const cli_arg_t *a, u8 *tok, cli_value_t *v)
   {
     foo_t *f = foo_find_by_name (tok);

     if (!f)
       return format (0, "unknown foo '%v'", tok);

     v->index = f->index;
     return 0;
   }

   static void
   complete_foo (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
   {
     foo_t *f;

     pool_foreach (f, foo_pool)
       {
         if (cli_prefix_match ((char *) f->name, prefix))
           cli_candidate_add (out, (char *) f->name, "a foo");
       }
   }

   CLIB_CLI_TYPE (cli_type_foo) = {
     .name = "foo",
     .help = "foo name",
     .parse = parse_foo,
     .complete = complete_foo,
   };

* ``parse`` returns ``NULL`` on success, or a vector with the error message.
  The infrastructure adds the command line and the marker. ``tok`` is the
  word the user typed, ``a`` is the declaration (``a->min``, ``a->max``).
* If ``v->str`` is set to a vector, set ``.owns_str = 1`` in the type so it
  is freed with the context.
* ``complete`` is optional. Candidates can have a one line help.
* Declare the type ``extern`` in a header to use it from other files, and add
  ``__clib_export`` to share it between plugins.

Registered types are listed in ``show cli schema``.

Output
======

Write human readable output with ``vlib_cli_output (vm, ...)``. The text
filters apply to it automatically.

For commands with tabular output, build a JSON tree and let the
infrastructure format it. The same data is printed as a table, or as JSON
when the user adds ``| json``, and rows can be filtered with
``| where <field> <op> <value>``:

.. code-block:: c

   static const cli_column_t foo_columns[] = {
     { "name", "Name" }, { "index", "Idx" }, { "state", "State" }, {},
   };

   static clib_error_t *
   show_foo_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
   {
     clib_json_text_t j;
     foo_t *f;

     if (!cli_is_structured (ctx))
       {
         /* usual text output */
         return 0;
       }

     clib_json_init (&j);
     clib_json_add_array (&j, 0);
     pool_foreach (f, foo_pool)
       {
         clib_json_add_object (&j, 0);
         clib_json_add_string (&j, "name", "%v", f->name);
         clib_json_add_number (&j, "index", f->index);
         clib_json_add_string (&j, "state", "%s", f->up ? "up" : "down");
         clib_json_parent (&j);
       }
     clib_json_parent (&j);

     return cli_emit_table (ctx, &j, foo_columns);
   }

* ``cli_emit_table`` takes a JSON array of objects, ``cli_emit_object`` a
  single object. Both consume the JSON text.
* Fields not listed in the columns are kept in the JSON output, so the JSON
  can carry more than the table shows.
* A command which does not emit structured output rejects ``| json`` and
  ``| where`` with an error.

The JSON API is in ``src/vppinfra/json.h``.

Errors
======

Return a ``clib_error_t`` for errors detected by the handler. Errors
detected by the parser (unknown or missing argument, bad value, value out of
range) are produced by the infrastructure, with the line and a marker below
the offending word, and a suggestion when a keyword or a name is a close
match, for example ``unexpected argument 'cuont', did you mean 'count'?``.

Anything left on the line after the declared arguments is an error. Use ``cli_type_rest`` if the rest
is meant to be free text.

Pipes
=====

All commands accept ``| grep``, ``| head``, ``| tail``
and ``| count`` after their arguments, so ``show version | grep vpp`` works
without any support in the handler. ``| json`` and ``| where`` need the handler to
emit structured output as described above.

Because ``|`` ends a command, text which contains it has to be quoted.

Free-form arguments
===================

Arguments which cannot be described statically, for example a nested
sub-language like the packet generator ``data { ... }`` block, can be taken
as ``cli_type_rest`` and parsed by the handler with ``unformat``.

Legacy unformat based commands
==============================

Commands which set ``.function`` instead of ``.handler`` are the legacy
``unformat`` based commands. They are still supported and both kinds live in
the same command tree, so a legacy command can sit next to, or even below, a
command with a grammar. A command sets either ``.function`` or ``.handler``,
never both.

A legacy command receives the unparsed arguments in an ``unformat_input_t``
and parses them itself:

.. code-block:: c

   static clib_error_t *
   set_foo_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
   {
     /* unformat (input, ...) loop */
   }

   VLIB_CLI_COMMAND (set_foo_command, static) = {
     .path = "set foo",
     .short_help = "set foo <interface> [count <n>]",
     .function = set_foo_command_fn,
   };

What a legacy command gets and what it does not:

* The command path is completed and its ``short_help`` is shown, as before.
* The text filters ``| grep``, ``| head``, ``| tail`` and ``| count`` work on
  its output, since they only need the text.
* Macros (``$(name)``) are expanded, because that happens before the line
  is dispatched.
* The arguments are not completed, there is no usage generated from them,
  and parse errors are whatever the handler returns.
* ``| json`` and ``| where`` are rejected with the error "command has no
  structured output", because the command can't emit it. The command is not
  run.

To convert a legacy command:

#. Replace ``.function`` with ``.handler`` and write the argument list. The
   handler receives ``cli_ctx_t *`` instead of ``unformat_input_t *``.
#. Turn each branch of the ``unformat`` loop into an argument. Optional
   branches get ``CLI_F_OPTIONAL``, keywords which take a value become
   ``CLI_KEYWORD``, bare words become ``CLI_FLAG``.
#. Remove the "unknown input" error path, the parser reports it.
#. Replace ``unformat_vnet_sw_interface`` and similar with the matching
   type. A grammar element which does not exist yet is a new type.
#. Expect stricter parsing. Text which the legacy code ignored after the
   last argument is an error now, so check scripts and tests which rely on
   it.
#. Check completion with ``test cli complete "<command> "``, press ``?``
   after the command, and try wrong input to see the errors.

Testing
=======

* ``test cli complete "<line>"`` prints the completion candidates for a line,
  as the TAB key would.
* ``show cli schema`` prints the full grammar as JSON.
* ``test_cli`` (``src/vppinfra/test_cli.c``) is a stand-alone unit
  test of the parser, completion, errors and filters, built with the other
  vppinfra tests. It does not need a running VPP.
* ``test/test_cli_decl.py`` tests the CLI of a running VPP.

``extras/bash/vppctl-completion.bash`` provides ``vppctl`` completion in bash,
using the same completion as the interactive CLI.
