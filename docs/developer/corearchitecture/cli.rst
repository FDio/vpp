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
     .args = CLI_ARGS (
       CLI_VALUE ("interface", cli_type_sw_interface),
       CLI_OPT_KEYWORD ("count", cli_type_u32, .min = 1, .max = 100,
                    .help = "number of times, default 1"),
       CLI_FLAG ("verbose")),
     .handler = set_foo_command_fn,
   };

Accepted input::

   set foo GigabitEthernet0/8/0
   set foo GigabitEthernet0/8/0 count 5 verbose
   set foo 1 verbose count 5

``CLI_ARGS`` builds the argument list and adds the terminating empty element,
a list written out by hand as ``CLI_ARGS ( ...)`` is equivalent. A
command with a ``.handler`` and no ``.args`` takes no arguments. The handler returns
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

``CLI_OPT_KEYWORD (name, type, ...)``, ``CLI_OPT_KEYWORD_F (name, type, flags, ...)``
  An optional keyword, same as ``CLI_KEYWORD`` with ``CLI_F_OPTIONAL``.
  ``CLI_OPT_KEYWORD_F`` takes extra flags, for example ``CLI_F_REPEAT``. Do not
  pass ``.flags`` to ``CLI_OPT_KEYWORD``, it would replace ``CLI_F_OPTIONAL``.

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

``.alt_keyword``
  A second spelling of a ``CLI_VALUE``, ``<alt_keyword> <number>``. The number
  is stored in ``v->index``, where the interface types keep their result, so
  a handler reads it as before, with ``cli_index``. It is used by the commands
  which took ``sw_if_index 5`` in place of the name of an interface, to keep
  their old syntax: ``CLI_VALUE ("interface", cli_type_sw_interface, .alt_keyword =
  "sw_if_index")``.

``.choices``
  Table for ``cli_type_enum`` and ``cli_type_flags``.

``.def``
  Default, written as it would be typed. The argument has to be optional. If
  the user does not give it, the parsed default is its value and
  ``cli_get`` finds it, with ``is_default`` set in the value. A default of a
  keyword inside a ``CLI_GROUP`` applies only if the group is given. The help
  shows it as "(default 64)".

``.requires``, ``.excludes``
  Names of other arguments, separated by ``,``. An argument with ``.requires``
  needs all of them, and one with ``.excludes`` can not be given together with
  any of them. The parser reports it with the offending word marked, for
  example "'salt' needs 'crypto'", so the handler does not have to.
  A ``CLI_GROUP`` which needs some of its keywords when it is given is declared
  with ``CLI_GROUP_REQUIRES (name, help, "src,dst", ...)``.

``.deprecated``
  Text which says what to use instead. The argument is still accepted, but it
  is not completed and not shown in the usage, and using it prints a warning
  before the command runs. ``.flags = CLI_F_HIDDEN`` hides an argument the same
  way, without the warning.

Defaults, ``.requires`` and ``.excludes`` are checked after the whole line was
parsed, so they work in any order of the keywords.

Abbreviations
-------------

Keywords, flags and enum words have to be typed in full. A command that wants
a short spelling declares it with ``.alias``, and TAB completes the full word.
The words of the command itself can still be abbreviated to a unique prefix,
``sh int`` is ``show interface``. A typed word which starts exactly one
keyword is suggested in the error message, but it is not accepted, so adding a
keyword to a command never changes how an existing line is parsed.

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
  ``cli_get ()`` returns the first one and ``cli_get_next (ctx, v)`` the next.

A value which was not typed but comes from ``.def`` is present, and has
``v->is_default`` set.

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
   * - ``cli_type_mac_address``
     - ``v->prefix.addr``, 6 bytes
     - aa:bb:cc:dd:ee:ff
   * - ``cli_type_error``
     - ``v->u64``, the error index
     - ``<node>.<error>``
   * - ``cli_type_trace_filter_function``
     - ``v->u64``, the registration
     - completes the registered packet trace filter functions
   * - ``cli_type_tmpfile``
     - ``v->str``, ``/tmp/<name>``
     - a file name, it is always in ``/tmp``

Generic types for values which are not tied to a component:

.. list-table::
   :header-rows: 1

   * - Type
     - Value
     - Notes
   * - ``cli_type_duration``
     - ``v->f64``, seconds
     - ``10``, ``1.5``, ``250ms``, ``10s``, ``5m``, ``2h``, ``1d``
   * - ``cli_type_size``
     - ``v->u64``, bytes
     - ``4096``, ``4K``, ``64M``, ``2G``, ``1T`` (powers of 1024), ``.min`` and
       ``.max`` are in bytes
   * - ``cli_type_bool``
     - ``v->index``, 0 or 1
     - ``on``, ``off``, also ``enable``, ``disable``, ``yes``, ``no``, ``true``,
       ``false``
   * - ``cli_type_hex``
     - ``v->str``, bytes
     - ``0xdeadbeef`` or ``deadbeef``, ``.max`` is the number of bytes
   * - ``cli_type_file``
     - ``v->str``, the path
     - completes the files and directories
   * - ``cli_type_percent``
     - ``v->f64``, 0 to 100
     - ``12.5`` or ``12.5%``
   * - ``cli_type_flags``
     - ``v->u64``, or of the values
     - comma separated, case is ignored, ``-`` is the same as ``_``, the names
       are the ``.choices``
   * - ``cli_type_u32_list``
     - ``v->str``, vector of ``u32``
     - ``1,2,5-7``, ``.max`` is the number of entries
   * - ``cli_type_bitmap``
     - ``v->str``, a bitmap
     - ``0-3,5``

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
* ``.usage`` is how the value is shown in the usage line instead of
  ``<name>``, for example ``{on|off}``.
* ``.greedy = 1`` makes the value the rest of the line, as
  ``cli_type_rest`` does, ``parse`` and ``complete`` are not used.
* Declare the type ``extern`` in a header to use it from other files, and add
  ``__clib_export`` to share it between plugins.

For a type which is one of a set of names, for example the objects of a pool,
give a function which returns the next name instead of the parse and complete
functions. The infrastructure matches the word exactly, completes the names
with their description and suggests the closest name for a typo:

.. code-block:: c

   static const char *
   next_foo_name (const cli_arg_t *a, u32 *iter, u32 *value, const char **help)
   {
     while (*iter < vec_len (foo_pool))
       {
         u32 i = (*iter)++;

         if (pool_is_free_index (foo_pool, i))
           continue;
         *value = i;
         if (help)
           *help = "a foo";
         return (char *) foo_pool[i].name;
       }
     return 0;
   }

   CLIB_CLI_TYPE (cli_type_foo) = {
     .name = "foo",
     .help = "foo name",
     .next_name = next_foo_name,
     .parse = cli_names_parse,
     .complete = cli_names_complete,
   };

``value`` is stored in ``v->index``.

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

The text which ``format_clib_json_text`` writes has a tab for each level of
nesting, ``:`` and a tab between the name and the value of a member, arrays
on one line, an empty object over two lines and 15 significant digits for the
numbers which are not integers. The style is a property of the text, and
``clib_json_set_indent ()``, ``clib_json_set_indent_tabs ()``,
``clib_json_set_key_separator ()``, ``clib_json_set_inline_arrays ()``,
``clib_json_set_expand_empty ()`` and ``clib_json_set_number_digits ()`` change
it. An indentation of 0 gives text without white space.

``cli_is_structured (ctx)`` is true if the user asked for ``| json`` or
``| where``, and ``cli_is_json (ctx)`` if the output has to be JSON. A handler
builds the table only then, and prints text otherwise.

Plain text
----------

``ctx->plain_text_only`` is set when the handler must not print ANSI
sequences such as colors: ``unix { nocolor }`` is set in the startup
configuration, or the session is not ANSI capable (``set terminal ansi off``,
or a session which is not interactive, like the API or ``exec``). Handlers
which color their text or use ``table_t`` check it, ``table.no_ansi`` takes the
same value:

.. code-block:: c

   table_t table = { .no_ansi = ctx->plain_text_only };

Conventions for the keys and values
-----------------------------------

The structured output is an interface which scripts depend on, so all the
commands follow the same rules:

* Keys are lower case with underscores, ``sw_if_index``, not ``swIfIndex``
  or ``SW-IF-INDEX``. A debug build warns about the keys of the columns which
  are not.
* A key which exists in the binary API has the same name, ``sw_if_index``,
  ``hw_if_index``, ``mtu``, ``name``.
* Numbers are JSON numbers, never strings with units: ``"mtu": 9000``, not
  ``"9000 bytes"``. The unit is the end of the key: ``_bytes``, ``_kbps``,
  ``_ms``, ``_pps``, ``_pct``. Time is in seconds, as a number.
* Values which are on or off are ``true`` and ``false``, not ``"yes"`` or
  ``"on"``.
* Enumerations are lower case strings, ``"state": "up"``, in the same words
  as the command accepts.
* Addresses, prefixes and MAC addresses are strings in the usual notation,
  ``"10.0.0.1/24"``, ``"de:ad:00:00:00:00"``.
* A command which shows a list emits an array of objects, a command which
  shows one thing emits an object. Each object has the name of the thing and
  its index, if it has one.
* A value which does not exist is left out of the object, not ``null``.
* A list of values is an array, ``"addresses": ["10.0.0.1/24"]``, not a
  string with separators.
* Counters are integers and keep the name of the counter.

The columns only select what the text table shows and how it is headed, the
JSON carries every key the handler emits.

Errors
======

Return a ``clib_error_t`` for errors detected by the handler. Errors
detected by the parser (unknown or missing argument, bad value, value out of
range) are produced by the infrastructure, with the line and a marker below
the offending word, and a suggestion when a keyword or a name is a close
match, for example ``unexpected argument 'cuont', did you mean 'count'?``.

Anything left on the line after the declared arguments is an error. Use ``cli_type_rest`` if the rest
is meant to be free text.

Threads and the barrier
=======================

A command runs with the worker threads stopped at the barrier, unless it is
registered with ``.is_mp_safe = 1``, which is the same field legacy commands
use. A command which only shows state should be mp-safe, so a slow command
does not stop forwarding. The handler of such a command:

* reads only state owned by the main thread, and calls only functions which
  are safe while the workers run;
* does not keep a pointer into a pool across anything which can suspend the
  process, as the pager does when it waits for a key. Keep the index, look
  the object up again after, and skip it if it is gone;
* leaves commands which change state, or reset counters, without the flag.

``show hardware-interfaces`` and ``show interface transceiver`` are examples:
they look up every interface again before they print it, and copy the bond
member bitmap before using it.

Pipes
=====

All commands accept ``| grep``, ``| head``, ``| tail``
and ``| count`` after their arguments, so ``show version | grep vpp`` works
without any support in the handler. ``| json`` and ``| where`` need the handler to
emit structured output as described above.

Because ``|`` ends a command, text which contains it has to be quoted.

The infrastructure parses the pipeline with ``cli_parse_line ()``, or with
``cli_parse_pipeline ()`` for the legacy commands which parse their own
arguments, and applies the text filters with ``cli_apply_text_filters ()``
to the output of the command. ``cli_has_text_filters ()`` tells if there
are any, so the output has to be captured first.

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

A legacy command receives the arguments as text in an ``unformat_input_t``
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
* ``show cli schema`` marks it with ``"legacy": true`` and lists no arguments for it.

To convert a legacy command:

#. Replace ``.function`` with ``.handler`` and write the argument list. The
   handler receives ``cli_ctx_t *`` instead of ``unformat_input_t *``.
#. Turn each branch of the ``unformat`` loop into an argument. Optional
   keywords which take a value become ``CLI_OPT_KEYWORD``, mandatory ones
   ``CLI_KEYWORD``, bare words become ``CLI_FLAG``.
#. Remove the "unknown input" error path, the parser reports it.
#. Replace ``unformat_vnet_sw_interface`` and similar with the matching
   type. A grammar element which does not exist yet is a new type.
#. Expect stricter parsing. Text which the legacy code ignored after the
   last argument is an error now, so check scripts and tests which rely on
   it.
#. Check completion with ``test cli complete "<command> "``, press ``?``
   after the command, and try wrong input to see the errors.

A command line without VPP
===========================

The grammar, the parser, the types, the completion and the structured output
live in vppinfra and do not need vlib. An application which has no VPP in it
can use them, it only has to provide what vlib provides to a VPP command:
a command table, reading the line, and printing the result.
``src/examples/cli-hello/cli_hello.c`` is a complete example of about 300
lines. It has five commands, a type of its own, completion, help and
structured output.

The commands are described the same way as in VPP, only the registration is
the application's own:

.. code-block:: c

   static const cli_arg_t *hello_args =
     CLI_ARGS (CLI_OPT_KEYWORD ("name", cli_type_string, .def = "world"),
               CLI_OPT_KEYWORD ("times", cli_type_u32, .def = "1", .min = 1, .max = 10),
               CLI_FLAG ("loud"));

   static clib_error_t *
   cmd_hello (cli_ctx_t *ctx, u8 **out)
   {
     cli_value_t *name = cli_get (ctx, "name");

     for (u32 i = 0; i < cli_u64 (ctx, "times", 1); i++)
       *out = format (*out, "Hello, %v%s\n", name->str, cli_flag (ctx, "loud") ? "!!!" : ".");
     return 0;
   }

Running a line takes the same steps as ``cli_dispatch ()`` in
``src/vlib/cli_decl.c``:

#. Find the command in the application's table, the rest of the line is its
   arguments.
#. ``cli_parse_line (args, rest, &ctx)`` parses the arguments and the
   ``| filter`` pipeline. On error it returns the message with the line and
   a marker below the offending token, ``err->what`` is ready to be printed.
#. If ``ctx.help`` is set the line ended with ``?``, print
   ``format_cli_help``. If ``ctx.warnings`` is not empty, print it, it
   has the notes for deprecated arguments.
#. Call the handler. It reads the values with ``cli_get ()``,
   ``cli_u64 ()``, ``cli_flag ()`` and ``cli_index ()``, and appends text
   to a vector, or emits a table with ``cli_emit_table ()``.
#. ``cli_check_output ()`` rejects ``| json`` or ``| where`` for a command
   which did not emit structured output.
#. Apply the text filters with ``cli_apply_text_filters ()`` and print.
#. ``cli_ctx_free ()``.

Completion is ``cli_complete_args (args, rest, &candidates)``, the example
has a ``complete`` command which prints what the Tab key would offer.

To build it, configure VPP, enable the vppinfra tests and build the target:

.. code-block:: console

   $ ./configure -n -t debug
   $ cmake -DVPP_BUILD_VPPINFRA_TESTS=ON .
   $ ninja cli_hello
   $ ./bin/cli_hello

or compile it by hand against ``libvppinfra``:

.. code-block:: console

   $ cc -I src -o cli_hello src/examples/cli-hello/cli_hello.c \
        -L build/lib/x86_64-linux-gnu -lvppinfra -Wl,-rpath,$PWD/build/lib/x86_64-linux-gnu

A session, the lines after ``>`` are typed:

.. code-block:: console

   > hello
   Hello, world.
   > hello name VPP times 2 loud
   Hello, VPP!!!
   Hello, VPP!!!
   > hello times 11
   '11' is out of range (1 - 10)
      times 11
            ^^
   > hello nam VPP
   unexpected argument 'nam', did you mean 'name'?
      nam VPP
      ^^^
   > calc div 1 0
   division by zero
   > wait 250ms
   would wait 250 ms
   > paint purple
   'purple' is not a color
      purple
      ^^^^^^
   > colors | where index > 0
   Name   Index
   blue   2
   green  1
   > colors | json
   [
     {
       "name": "red",
       "index": 0
     },
     ...
   ]
   > colors | count
   3
   > complete hello
   hello   Greet someone
   > complete hello na
   name    who to greet
   > hello ?
   usage: hello [name <name>] [times <times>] [loud]
     Greet someone

   arguments:
     name <string>  who to greet (default world)
     times <number> how many times (default 1)
     loud           add some enthusiasm

   output can be filtered: <cmd> | json|where|grep|head|tail|count

Testing
=======

* ``test cli complete "<line>"`` prints the completion candidates for a line,
  as the TAB key would.
* ``show cli schema`` prints the full grammar as JSON.
* ``test_cli`` (``src/vppinfra/test_cli.c``) is a stand-alone unit
  test of the parser, completion, errors and filters, built with the other
  vppinfra tests. It does not need a running VPP.
* ``test/test_cli.py`` tests the CLI of a running VPP.

``extras/bash/vppctl-completion.bash`` provides ``vppctl`` completion in bash,
using the same completion as the interactive CLI.
