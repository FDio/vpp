.. _sfdp_doc:

SFDP framework
==============

SFDP
____

The StateFul Data Plane (SFDP) project aims at bringing stateful packet processing into the Vector Packet Processor (VPP) data plane on a per session basis.

Data plane overview
___________________

When entering SFDP, packets are initially matched against the **sfdp session table**. The lookup key is the conjunction of the packet's 5 tuple and a **context id**. The context id is an opaque `u32`, allowing the cohabitation of multiple address/port spaces in the same data plane.

Sessions in SFDP are bidirectional. That is why, session lookup results into a session and a **direction**. The direction of a packet is **forward** if the packet is oriented from initiator to responder (client to server) and is **reverse** otherwise. The conjunction of a session and a direction is called a **flow**. In other words, a session is composed of two flows, the **forward flow** and the **reverse flow**.

Each flow is associated a **service bitmap** defining the sequence of nodes (called **services** ) that are to be traversed by a packet belonging to this flow.

The data structure materializing a session (`sfdp_session_t`) is associated to a given thread. That is why, during the lookup phase, if the packet is found to be belonging to a thread different from the one where the lookup is happening, packet handoff is performed, so that all packets belonging to a given session (in either direction) are processed on the same thread (which is the thread associated to the session).

The session lookup might fail (because there is no corresponding session in the table). In that case, a session is created on the fly by SFDP, and the current packet is associated to this session as a forward packet (because it is the packet initiating the session, so it goes from initiator to responder). If the session pool is exhausted, session creation fails and the lookup node marks the packet for the tenant's table-overflow slow-path node (`sp-ip4-table-overflow` or `sp-ip6-table-overflow`), which defaults to an error-drop unless configured otherwise.

To avoid running out of session entries, SFDP relies on proactive eviction in the pre-input `sfdp-expire` node rather than evicting directly in the lookup path. On each pre-input cycle, the expiry module is asked to expire or evict sessions when the number of remaining sessions drops below the eviction margin. This is a best-effort mechanism designed to keep the pool above the margin so lookup-time allocations succeed.

After session lookup (and, potentially, session creation), SFDP stores private metadata in the packet buffer:
  * a flow id equal to `(session_index << 1) | direction` with `session_index` being the index of the `sfdp_session_t` structure in the current per thread data, and `direction` being equal to 0 for a forward packet and 1 for a reverse packet
  * a 64-bit service bitmap, whose bit indexes are each associated to a certain SFDP graph node (a sfdp service). Each bit is set if and only if its indexes is associated to a service that is to be traverse by the packet. This service bitmap is obtained simply by copying the aforementioned service bitmap associated to the flow
  * a tenant index, which identifies the tenant of the session to which the packet belongs

SFDP Session creation, tenants and contexts
___________________________________________

Even before entering SFDP (i.e., before the lookup), a packet must be associated a certain **tenant** (stored in the aforementioned tenant index). The way this association is done is outside of the scope of SFDP, it can be on a per-interface, per-VLAN, per VNI basis, etc... Tenants define:
  * the context id, that will be used by the lookup. Multiple tenant might share the same context id.
  * the forward and reverse service chains that are to be used whenever session creation is triggered by a packet associated with this tenant
  * various configuration options that are specific to the different services used (e.g., timeout values, etc...)

In other words, a tenant is the data structure defining the configuration of any new session, as well as the context id (i.e., address/port space) to be used for lookup

Service registration, scopes, and execution order
_________________________________________________

Services are registered at init time via the SFDP service registry, which
associates each service with a graph node name, a scope (to allow multiple
independent service sets), a bitmap index (one of 64 slots), optional ordering
constraints (runs-before / runs-after), and a terminal flag. Scopes are used
to group services into independent pipelines, while ordering constraints are
resolved into stable bitmap indices so the resulting service bitmap yields a
deterministic traversal order. Services are typically registered with
`SFDP_SERVICE_DEFINE` in their implementation code and linked into the scope
ordering list.

At runtime, the **service bitmap** in the buffer drives traversal. Each
service node calls `sfdp_next()` to find the next set bit (lowest index),
clears it, and dispatches to the corresponding node. A **terminal** service is
the last SFDP node for a packet; it must inject the packet back into the regular
VPP graph (e.g., `ip4-lookup` or `ip4-rewrite`).

Service chains are configured per tenant and per direction. Use:

::

  set sfdp services tenant <tenant-id> <service> [<service> ...] forward
  set sfdp services tenant <tenant-id> <service> [<service> ...] reverse

The equivalent API message is `sfdp_set_services`. To inspect the registered
services and their bitmap indices, use `show sfdp services`.

Scopes and scope-specific lookup injection
__________________________________________

SFDP supports multiple **scopes**, which are independent service pipelines that
share the same session table but can execute different service sets. A scope is
identified by a string in the service registration (the default scope is
named `default` when no scope is specified). During initialization, SFDP builds
separate lookup and handoff nodes for each scope and assigns the corresponding
scope index to their runtime data.

To inject a packet into a specific scope, send it directly to the scope’s
lookup node. The generated node name is the base name plus an optional
`-<scope>` suffix, where `<scope>` is the scope name string. The default scope
uses the base node names with no suffix, while non-default scopes use the
suffix:

* Default scope: `sfdp-lookup-ip4`, `sfdp-lookup-ip6`
* Scope `<scope>`: `sfdp-lookup-ip4-<scope>`, `sfdp-lookup-ip6-<scope>`

Scope-specific parser nodes (created for registered parsers) follow the same
suffix convention. This allows features or DPOs to pick a scope explicitly by
choosing the appropriate lookup node name, while keeping session lookup and
handoff behavior identical across scopes.

Parsers and parser registration
_______________________________

SFDP parsers are specialized lookup nodes used for non-IP or custom key
formats. A parser defines how to extract a lookup key from a packet
(`calc_key_fn`), how to normalize that key (`normalize_key_fn`), and the key
size to use for the parser-specific session table. During initialization, each
registered parser gets its own bihash table and a parser node is created for
each scope, following the same `-<scope>` suffix convention as the lookup
nodes.

To register a parser, use the `SFDP_PARSER_REGISTER` macro in a compilation
unit and fill in an `sfdp_parser_registration_t` with the parser name,
callbacks, and key metadata. A corresponding node is created with
`SFDP_PARSER_DEFINE_NODE`, which wires the parser into the SFDP lookup pipeline
and associates the node name with the parser registration. Once registered,
the parser node can be used as an injection point in the same way as the
standard lookup nodes, including scope-specific variants. The generated parser
node name is the parser name plus an optional `-<scope>` suffix, where
`<scope>` is the scope name string. The default scope uses the base parser name
with no suffix, while non-default scopes use the suffix.

Injecting packets in SFDP
_________________________

There are several ways to inject packets in the SFDP data plane, and it is mainly agnostic to *how* it receives packets. To inject a certain packet, code must:

1. Set the tenant index buffer metadata to define the configuration of any new session that might be initiated by the packet
2. Set the flow id buffer metadata to the context id which should be used for the session lookup (Note that this will be erased by lookup and replaced with `(session_index << 1) | direction` as per above)
3. Sent the packet to the `sfdp-lookup` node

Typically, hooks to enter the SFDP data plane could be implemented as intercepting features in VPP, or special DPO if the FIB is to be used to decide whether the SFDP data plane is to be used or not.

Injecting packet into the regular VPP data plane after SFDP processing
______________________________________________________________________

The responsibility of injecting a packet processed by SFDP back into the regular VPP graph node falls to the *last traversed service in the service bitmap of the packet*. SFDP does not specify how that should be done, but the packet would typically be sent to `ip4-lookup` to be processed by the FIB, or `ip4-rewrite` to be sent directly on an interface.

Buffer metadata layout and flags
________________________________

SFDP stores per-packet metadata in the VPP buffer `unused` area using the
`sfdp_buffer_opaque_t` layout in `src/vnet/sfdp/common.h`. The layout includes
the `service_bitmap`, the `tenant_index` associated with the packet, the
`session_version_before_handoff` used to detect stale handoff, and a few
protocol-specific fields (`flags`, `tcp_flags`, `ip6_final_proto`). The
`sfdp_buffer()` accessor hides the cast from services and lookup code.

When SFDP temporarily sends a packet outside its own graph (e.g., for IP
reassembly), the metadata is saved and restored using the secondary buffer
space (`sfdp_buffer2`). This preserves the SFDP state across the excursion so
that the packet can resume processing with a consistent service bitmap and
tenant context.

Lookup parsing
______________

The lookup path performs protocol parsing that determines what services see
after `sfdp-lookup`. Parsers provide alternate key extraction paths for
non-IP or custom protocols, but feed into the same lookup semantics described
here. IP4/IP6 headers are parsed and normalized, including the
pseudo-direction logic described earlier, and the normalized 5-tuple is used
for the session table lookup. On a hit, the lookup result is converted into a
flow index and stored in the buffer, and the packet proceeds directly into the
service chain. These behaviors live in the `src/vnet/sfdp/lookup/` sub-tree and
define which fields in `sfdp_buffer_opaque_t` are valid when services run.

Slow-path nodes
_______________

The lookup node can classify a packet as requiring special handling and send
it to a **slow-path node** instead of continuing through the service chain.
Slow-path nodes are explicit graph nodes (per-tenant and per-protocol family)
that implement exceptional handling, such as reassembly, ICMP error mapping,
or drop-on-error. This keeps the hot lookup path minimal while still allowing
controlled detours.

Slow-path nodes are tenant-configurable:

::

  set sfdp sp-node tenant <tenant-id> <sp-node> node <node-name>
  set sfdp icmp-error-node tenant <tenant-id> ip4 node <node-name>
  set sfdp icmp-error-node tenant <tenant-id> ip6 node <node-name>

The equivalent API messages are `sfdp_set_sp_node` and
`sfdp_set_icmp_error_node`.

Provided slow-path nodes
________________________

SFDP ships with a small set of built-in slow-path nodes. The most common are:

* **ICMP error handling**: ICMP error packets are parsed to recover the
  original 5-tuple so they can be mapped back to the correct session. The
  ICMP error node is configured per tenant and per address family.
* **Reassembly paths**: Fragmented packets are redirected to IP
  reassembly. Once reassembled, packets return to SFDP with their metadata
  restored so the service chain can proceed.

Other slow-path nodes include table-overflow and unknown-protocol handlers,
which default to error-drop unless configured otherwise.

Normalized lookup and pseudo-direction
______________________________________

Session lookup is implemented in such a way two 5-tuple where the source and destination are reversed (for UDP and TCP packets) must match the same session. In order to do so, a 5-tuple is **normalized** before it is used for lookup, i.e., source and destination are reversed if needed, so as to ensure that the ip address in the ip dst field (`ip_addr_hi`) is larger than the ip address in the ip src field (`ip_addr_lo`).

The **pseudo direction of a packet** is one if source and destination need be reversed before lookup, and zero otherwise.

The **pseudo direction of a session** is the pseudo direction of the first packet of this session.

Similarly the **pseudo flow index of a session** is ``(session_index << 1) | session_pseudo_direction``.

Then, the obvious following statements hold:

..  code-block::

  packet_direction = packet_pseudo_direction ^ session_pseudo_direction
  packet_flow_index = packet_pseudo_direction ^ session_pseudo_flow_index


Primary and secondary session keys
__________________________________

In some cases, a given session must be accessible through different 5-tuples. Typically, when implementing session-aware NAT, the 5-tuple of the session key for forward traffic is not equal to the 5-tuple of the session key for reverse traffic with reversed source and destination. That's why, some services need to be able to create a **secondary session key** pointing to an already-existing session. This can be done by using the `sfdp_session_try_add_secondary_key` internal API. Note that the provided secondary key must be normalized, and the **pseudo_flow_index** associated with this session and this new key must also be provided. An example is provided in `src/sfdp/nat/slowpath_node.c`.

Callbacks on session lifecycle
______________________________

SFDP exposes callbacks for external modules that need to attach state to
sessions or clean it up safely. The **notify_new_sessions** callback is
invoked after session creation but before the first packet is fully processed,
which allows services to initialize per-session state or even adjust the
service chain. The **notify_deleted_sessions** callback is invoked during
pre-input when sessions are being removed, so teardown happens in a context
where no packets are concurrently processed on that thread.

Callbacks are registered through `SFDP_REGISTER_NEW_SESSIONS_CALLBACK` and
`SFDP_REGISTER_DELETED_SESSIONS_CALLBACK` in `src/vnet/sfdp/callbacks.h`, and
can be blacklisted at init time. The callbacks run on worker threads and must
follow the same threading rules as SFDP services.

Session expiration and timer management
_______________________________________

While session creation is exclusively done upon failed session lookup, session expiration is timer-based. The expiration timer of a session is initially set to the **embryonic timeout**. This value can be set at tenant configuration time. Then, depending on the protocol, services such as the l4-lifecycle service or the tcp-check service are responsible for rearming the session timeout value, depending on the state of the session.

Services use two SFDP-provided functions to rearm session timeout:
  * `sfdp_session_timer_update` is to be used to change the timeout value so that the new expiration time is known to be **posterior** to the old expiration time
  * `sfdp_session_timer_update_maybe_past` is to be used to change the timeout value when it is unknown whether the new expiration time will happen before or after the old expiration time. Typically, using this function with a timeout of zero is the preferred way to force expiration of the session

Session expiry and eviction model
_________________________________

Session expiration is timer-driven but modular. SFDP defines an expiry
interface that a module can implement to receive enable/disable callbacks,
process expirations on each pre-input cycle, proactively evict sessions when
the pool is running low, and provide remaining time for inspection. Services
typically rearm session timers using `sfdp_session_timer_update` or
`sfdp_session_timer_update_maybe_past` based on whether the new deadline is
known to be in the future.

The **eviction margin** controls when eviction is triggered and should be
tuned based on how many new sessions can be created in a single VPP loop and
the latency of the expiry module. Operators configure per-tenant timeouts via
the CLI:

::

  set sfdp timeout tenant <tenant-id> <timeout-name> <value>

The equivalent API message is `sfdp_set_timeout`. Remaining TTL is visible in
`show sfdp session-table` and `show sfdp session-detail`, and is also returned
in the `sfdp_session_dump` / `sfdp_session_details` API messages.

CLI and API surface (configuration and inspection)
__________________________________________________

SFDP exposes a small but important configuration and inspection surface.
Tenant creation and deletion are done via:

::

  sfdp tenant add <tenant-id> context <context-id>
  sfdp tenant del <tenant-id>

The equivalent API message is `sfdp_tenant_add_del`, where `context_id`
defaults to the tenant id when omitted. Service chain configuration is done
with `set sfdp services ...` or the `sfdp_set_services` API.
Timeouts are configured with `set sfdp timeout ...` or `sfdp_set_timeout`.

For inspection, the CLI provides:

::

  show sfdp services
  show sfdp session-table [tenant <tenant-id>]
  show sfdp session-detail 0x<session-id>
  show sfdp tenant [<tenant-id> [detail]]
  show sfdp status

The API equivalents are `sfdp_session_dump` / `sfdp_session_details` and
`sfdp_tenant_dump` / `sfdp_tenant_details`. These cover the same core data
shown by the CLI, including session keys, service bitmaps, and remaining
expiry time.

SFDP plugin configuration stanza
________________________________

The SFDP plugin exposes early configuration options via the `sfdp { ... }`
stanza in VPP startup configuration. These settings control pool sizing and
eviction behavior before the plugin is initialized. Supported options are:

* `sessions-log2 <n>`: log2 of the total session pool size. Default:
  `SFDP_DEFAULT_LOG2_SESSIONS` (19).
* `sessions-per-thread-cache-log2 <n>`: log2 of the per-thread session cache
  size. Default: `SFDP_DEFAULT_LOG2_SESSIONS - SFDP_DEFAULT_LOG2_SESSIONS_CACHE_RATIO`
  (12). If not specified in the stanza, SFDP derives a cache size from
  `sessions-log2` and disables caching for very small pools to avoid
  exhaustion.
* `tenants-log2 <n>`: log2 of the tenant pool size. Default:
  `SFDP_DEFAULT_LOG2_TENANTS` (15).
* `eviction-sessions-margin <n>`: threshold below which the expiry module is
  asked to evict sessions proactively. Default:
  `SFDP_DEFAULT_EVICTION_SESSIONS_MARGIN` (65536), capped at half the session
  pool.
* `no-main`: disable SFDP on the main thread when worker threads are present.
  Default: disabled.

Example:

::

  sfdp {
    sessions-log2 19
    sessions-per-thread-cache-log2 7
    tenants-log2 15
    eviction-sessions-margin 65536
    no-main
  }
