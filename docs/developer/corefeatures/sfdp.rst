.. _sfdp_doc:

SFDP framework
==============

# SFDP

The StateFul Data Plane (SFDP) project aims at bringing stateful packet processing into the Vector Packet Processor (VPP) data plane on a per session basis. 

## Data plane overview

When entering SFDP, packets are initially matched against the **sfdp session table**. The lookup key is the conjunction of the packet's 5 tuple and a **context id**. The context id is an opaque `u32`, allowing the cohabitation of multiple address/port spaces in the same data plane.

Sessions in SFDP are bidirectional. That is why, session lookup results into a session and a **direction**. The direction of a packet is **forward** if the packet is oriented from initiator to responder (client to server) and is **reverse** otherwise. The conjunction of a session and a direction is called a **flow**. In other words, a session is composed of two flows, the **forward flow** and the **reverse flow**.

Each flow is associated a **service bitmap** defining the sequence of nodes (called **services** ) that are to be traversed by a packet belonging to this flow.

The data structure materialising a session (`sfdp_session_t`) is associated to a given thread. That is why, during the lookup phase, if the packet is found to be belonging to a thread different from the one where the lookup is happening, packet handoff is performed, so that all packets belonging to a given session (in either direction) are processed on the same thread (which is the thread associated to the session).

The session lookup might fails (because there is no corresponding session in the table). In that case, a session is created on the fly by SFDP, and the current packet is associated to this session as a forward packet (because it the packet initiating the session, so it goes from initiator to responder).

After session lookup (and, potentially, session creation), SFDP stores private metadata in the packet buffer:
* a flow id equal to `(session_index << 1) | direction` with `session_index` being the index of the `sfdp_session_t` structure in the current per thread data, and `direction` being equal to 0 for a forward packet and 1 for a reverse packet
* a 64-bit service bitmap, whose bit indices are each associated to a certain SFDP graph node (a sfdp service). Each bit is set if and only if its indice is associated to a service that is to be traverse by the packet. This service bitmap is obtained simply by copying the aforementioned service bitmap associated to the flow
* a tenant index, which identifies the tenant of the session to which the packet belongs. The notion of tenant is explicited in the following

## SFDP Session creation, tenants and contexts

Even before entering SFDP (i.e., before the lookup), a packet must be associated a certain **tenant** (stored in the aforementioned tenant index). The way this association is done is outside of the scope of SFDP, it can be on a per-interface, per-VLAN, per VNI basis, etc... Tenants define:
* the context id, that will be used by the lookup. Multiple tenant might share the same context id.
* the forward and reverse service chains that are to be used whenever session creation is triggered by a packet associated with this tenant
* various configuration options that are specific to the different services used (e.g., timeout values, etc...)

In other words, a tenant is the data structure definining the configuration of any new session, as well as the context id (i.e., address/port space) to be used for lookup

## Injecting packets in SFDP

As described in the previous section, there are several ways to inject packets in the SFDP data plane, and it is mainly agnostic to *how* it receives packets. To inject a certain packet, code must:

1. Set the tenant index buffer metadata to define the configuration of any new session that might be initiated by the packet
2. Set the flow id buffer metadata to the context id which should be used for the session lookup (Note that this will be erased by lookup and replaced with `(session_index << 1) | direction` as per above)
3. Sent the packet to the `sfdp-lookup` node

Typically, hooks to enter the SFDP data plane could be implemented as intercepting features in VPP, or special DPO if the FIB is to be used to decide whether the SFDP data plane is to be used or not.
 
## Injecting packet into the regular VPP data plane after SFDP processing

The responsibility of injecting a packet processed by SFDP back into the regular VPP graph node falls to the *last traversed service in the service bitmap of the packet*. SFDP does not specify how that should be done, but the packet would typically be sent to `ip4-lookup` to be processed by the FIB, or `ip4-rewrite` to be sent directly on an interface.

## Session expiration and timer management

While session creation is exclusively done upon failed session lookup, session expiration is timer-based. The expiration timer of a session is initially set to the **embryonic timeout**. This value can be set at tenant configuration time. Then, depending on the protocol, services such as the l4-lifecycle service or the tcp-check service are responsible for rearming the session timeout value, depending on the state of the session.

Services use two SFDP-provided functions to rearm session timeout:
  * `sfdp_session_timer_update` is to be used to change the timeout value so that the new expiration time is known to be **posterior** to the old expiration time
  * `sfdp_session_timer_update_maybe_past` is to be used to change the timeout value when it is unknown whether the new expiration time will happen before or after the old expiration time. Typically, using this function with a timeout of zero is the preferred way to force expiration of the session

## Normalised lookup and pseudo-direction
Session lookup is implemented in such a way two 5-tuple where the source and destination are reversed (for UDP and TCP packets) must match the same session. In order to do so, a 5-tuple is **normalised** before it is used for lookup, i.e., source and destination are reversed if needed, so as to ensure that the ip address in the ip dst field (`ip_addr_hi`) is larger than the ip address in the ip src field (`ip_addr_lo`).

The **pseudo direction of a packet** is one if source and destination need be reversed before lookup, and zero otherwise.

The **pseudo direction of a session** is the pseudo direction of the first packet of this session. 

Similarly the **pseudo flow index of a session** is `(session_index << 1) | session_pseudo_direction`.

Then, the obvious following statements hold:

```
packet_direction = packet_pseudo_direction ^ session_pseudo_direction
packet_flow_index = packet_pseudo_direction ^ session_pseudo_flow_index
```

## Primary and secondary session keys

In some cases, a given session must be accessible through different 5-tuples. Typically, when implementing session-aware NAT, the 5-tuple of the session key for forward traffic is not equal to the 5-tuple of the session key for reverse traffic with reversed source and destination. That's why, some services need to be able to create a **secondary session key** pointing to an already-existing session. This can be done by using the `sfdp_session_try_add_secondary_key` internal API. Note that the provided secondary key must be normalised, and the **pseudo_flow_index** associated with this session and this new key must also be provided. An example is provided in `src/sfdp/nat/slowpath_node.c`.





