.. _vlua_overview:

=============================
Lua Integration Overview
=============================

At runtime the ``lua`` process node (``src/vpp/lua/node.c``) creates a Lua
state, loads the core namespaces (``vpp``, ``vpp.cli``, etc.) and runs every Lua
script listed in the startup configuration.  Each script executes as a
 coroutine managed by the scheduler, which provides cooperative multitasking
 (``coroutine.create()``, ``vpp.sleep()``, ``coroutine.yield()``).  Coroutines run until they
yield; the scheduler wakes them up based on timer requests.  Diagnostics such
as active coroutines and hook state are available via the ``show lua`` CLI
command.

VLUA overrides the standard ``coroutine.create``/``wrap`` functions so every
coroutine is registered with the scheduler and starts running immediately.
Existing Lua code can call ``coroutine.create`` directly; no extra wrapper API
is required to integrate with VPP's scheduler.

Lua CLI diagnostics
-------------------

Use ``lua exec '<lua code>'`` or ``lua exec /path/to/file.lua`` to run code
inside the live interpreter without restarting VPP. Example::

    vpp# lua exec 'vpp.log.class("foo").warn("hello from CLI")'

``show lua`` prints allocator/GC usage, hook state, and per-coroutine details
(status, yieldability, timers, stack frames/values), making it easy to spot
blocked or failing scripts. Sample output::

    vpp# show lua
    Lua handle 0x7f12c8b1e5c0
      path prefix: vpp
      tables: 12  namespaces: 4  methods: 18
      memory: 256.00 KiB (262144 bytes)
      GC running: yes
      hook: none
      main stack depth: 0
    Coroutines:
      - task 0: status=ready, stack=3, yieldable=yes, waiting 0.500s
        #0 init.lua:33 (periodic_log_task)
        stack (1 values):
          [1] string "foo heartbeat"
        hook: none

``lua kill <task index>`` forcefully terminates a coroutine (indexes come from
``show lua``) without restarting VPP.

``lua create-stub <path>`` emits an EmmyLua stub file on demand, mirroring the
``create-stub`` startup option.
The integration gives scripts access to the same building blocks used by VPP:

* The ``vpp`` namespace exposes control-plane APIs (interfaces, logs, CLI),
  so Lua can drive configuration or react to events.
* Multiple scripts can run concurrently as cooperative coroutines, making it
  easy to implement background tasks (periodic logging, watchdogs, etc.).
* Plugins can register their own namespaces/methods, so Lua becomes an
  extension surface for new features without recompiling the core binary.

libvlua
-------

``libvlua`` acts as the glue between VPP and Lua:

* **Handle lifecycle** – wraps ``lua_State`` creation/destruction, interposes
  on ``coroutine.create/wrap/yield`` so VLUA can track and schedule every
  thread, and manages the registry of init functions provided by plugins.
* **Scheduler** – integrates with ``coroutine.create`` to register tasks,
  provides ``vlua_sleep``/``vlua_yield``, and runs the coroutine pool each frame.  It
  records wake times, detects failures, and exposes the diagnostics consumed by
  ``show lua``.
* **Binding helpers** – simplify creating namespaces, methods and signatures.
  They handle path resolution (``VLUA_PATHS``), method overloading via argument
  type vectors, and context-resolution for namespaces that need per-call
  state.
* **Value marshaling** – converts between Lua values and typed ``vlua_val_t``
  structures used by C method callbacks.  Supports numbers, strings, booleans,
  tables, etc., and ensures the Lua stack is restored after each call.
* **Diagnostics** – formats GC/memory usage, hook state, coroutine stacks,
  stack values, and timers.  The ``show lua`` CLI command prints this data to
  help debug Lua workflows.

Any VPP plugin can link against ``libvlua`` to publish new Lua bindings without
touching the core interpreter.  See :ref:`lua_bindings` below for the required
macros and APIs.

Build and configuration
-----------------------

Lua support is optional and controlled by the ``VPP_LUA`` CMake option (enabled
by default).  When ``VPP_LUA`` is ``ON`` and the Lua headers/libraries are
found, ``VPP_LUA_AVAILABLE`` is set and both ``libvlua`` and the Lua plugin are
compiled.  If Lua is missing, the build prints a warning and the runtime Lua
process/commands are disabled.

The ``lua`` config stanza in ``startup.conf`` enables the runtime script engine
and lets you pre-load scripts or emit a stub describing all registered
namespaces.  Example::

    lua {
      script /etc/vpp/init.lua
      script /etc/vpp/metrics.lua
      create-stub /tmp/vpp.lua.stub
    }

Startup configuration
---------------------

Enable Lua and load scripts via the ``lua { }`` section of ``startup.conf``::

    lua {
      script /etc/vpp/init.lua        # load this file at startup (repeatable)
      create-stub /tmp/vpp.lua.stub   # optional: dump available methods
    }

``script`` entries are processed in order; multiple lines are allowed.  The
current interpreter state is also exposed through ``lua exec`` and ``show lua``


.. _lua_bindings:

Adding new bindings
-------------------

Plugins or core components can expose functionality to Lua by registering an
init function with VLUA:

1. Create (or reuse) a dedicated ``.c`` file for Lua bindings and include
   ``<vlua/vlua.h>``. Keeping Lua-facing code in its own compilation unit lets
   the ``LUA_SOURCES`` CMake option drop it when ``VPP_LUA`` is disabled::

       #include <vlua/vlua.h>

2. Implement an init function that receives a VLUA handle plus any table handles
   you requested::

       static clib_error_t *
       log_ns_init (vlua_handle_t h, vlua_init_fn_args_t *a)
       {
         vlua_table_handle_t log_table = a->table_handles[0];
         ...
         return 0;
       }

3. Register the init function using ``VLUA_REGISTER_INIT_FN`` and provide one or
   more table paths via ``VLUA_PATHS``.  Paths beginning with ``.`` are relative
   to the ``path_prefix`` configured for the handle (``"vpp"`` in VPP)::

       VLUA_REGISTER_INIT_FN (log_ns) = {
         .init_fn = log_ns_init,
         .paths = VLUA_PATHS (".log"),
       };

4. Use ``vlua_table_add``, ``vlua_method_add`` and
   ``vlua_method_add_call_args`` to publish Lua-callable methods.  Namespaces
   that need per-call context can be created with ``vlua_ns_create`` and
   ``vlua_ns_add_call_args``::

       vlua_method_handle_t mh = vlua_method_add (h, log_table, "clear");
       vlua_method_add_call_args (mh, log_clear_method, 0);

Example (simplified from ``src/vlib/lua/log.c``)::

    static clib_error_t *
    log_ns_init (vlua_handle_t h, vlua_init_fn_args_t *a)
    {
      vlua_table_handle_t log_table = a->table_handles[0];
      vlua_method_handle_t mh = vlua_method_add (h, log_table, "clear");
      vlua_method_add_call_args (mh, log_clear_method, 0);
      return 0;
    }

    VLUA_REGISTER_INIT_FN (log_ns) = {
      .init_fn = log_ns_init,
      .paths = VLUA_PATHS (".log"),  # resolves to vpp.log
    };

The registered function runs once when the VLUA handle is created in the ``lua``
process node.  This mechanism allows plugins to add new namespaces or extend
existing ones without modifying the core init script.

To keep builds optional, place Lua-specific code in its own ``.c`` file and
list it under ``LUA_SOURCES`` when calling ``add_vpp_library``/``add_vpp_plugin``.
The build system automatically links ``libvlua`` when Lua is available and
silently drops those sources when ``VPP_LUA`` is off or ``liblua`` is missing.

Cooperative coroutines
----------------------

Lua logic runs as coroutines inside the scheduler.  Key helpers:

``coroutine.create(function() ... end)``
    Create a new coroutine and have it start executing immediately (the return
    value is the underlying thread, but you do not need to resume it manually).
    Example::

        coroutine.create(function()
          local log = vpp.log.class("foo")
          while true do
            log.warn("heartbeat")
            vpp.sleep(1.0)
          end
        end)

``coroutine.wrap(function() ... end)``
    Similar to ``coroutine.create``: the returned wrapper function is provided
    for compatibility but the coroutine itself starts running under the VLUA
    scheduler as soon as ``wrap`` is called.

``vpp.sleep(seconds)``
    Yield the current coroutine until the specified interval elapses.  Passing
    ``0`` yields for a single scheduler tick.

``coroutine.yield()``
    Explicitly yield without sleeping.  Useful when doing incremental work
    inside tight loops.

Coroutines should cooperate by yielding regularly; blocking APIs will stall the
entire Lua node.  Multiple ``coroutine.create`` calls can run in parallel, and
the ``show lua`` CLI command shows each coroutine’s status, stack and wait time.
Logging
-------

The ``vpp.log`` namespace exposes the same log framework used by C code.  Use
``vpp.log.class("name", "subclass")`` to obtain a logger (the subclass is
optional), tweak its config, and
emit messages at various levels.  Example::

    local log = vpp.log.class("foo", "lua")
    local cfg = log.get_config()
    cfg.level = "warning"
    log.set_config(cfg)
    log.warn("heartbeat")

Stubs
-----

The ``create-stub`` option in ``startup.conf`` dumps an EmmyLua stub file
(``stub.lua`` by default) that lists every namespace and method registered with
VLUA.  This file can feed IDE tooling (autocomplete, type hints) or serve as a
reference when writing new scripts.  Regenerate the stub whenever you add new
bindings so Lua developers have up-to-date API coverage.
