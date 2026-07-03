/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef __included_bfd_public_h__
#define __included_bfd_public_h__
/**
 * @file
 * @brief Defines the public BFD notification vocabulary that remains available to vnet consumers
 */

#include <vnet/ip/ip46_address.h>

/* BFD state values */
/**
 * BFD session states exposed to non-BFD consumers.
 *
 * Keep these values aligned with the protocol state values used internally by
 * BFD.  FIB and ADJ consume only this public enum, so they do not need to
 * include the private BFD session definition.
 */
#define foreach_bfd_state(F)                                                                       \
  F (0, admin_down, "AdminDown")                                                                   \
  F (1, down, "Down")                                                                              \
  F (2, init, "Init")                                                                              \
  F (3, up, "Up")

#define BFD_STATE_NAME(t) BFD_STATE_##t

typedef enum
{
#define F(n, t, s) BFD_STATE_NAME (t) = n,
  foreach_bfd_state (F)
#undef F
} bfd_state_e;

/**
 * listener events
 */
/**
 * Events emitted by BFD for vnet consumers.
 *
 * CREATE and DELETE describe the lifetime of the tracked BFD session. UPDATE
 * describes a change in the public session attributes, most importantly the
 * local BFD state used by FIB and ADJ to update forwarding dependencies.
 */
#define foreach_bfd_listen_event(F)                                                                \
  F (CREATE, "session-created")                                                                    \
  F (UPDATE, "session-updated")                                                                    \
  F (DELETE, "session-deleted")

typedef enum
{
#define F(sym, str) BFD_LISTEN_EVENT_##sym,
  foreach_bfd_listen_event (F)
#undef F
} bfd_listen_event_e;

/**
 * Public transport identifiers needed by consumers to interpret the payload.
 *
 * The enum intentionally carries only the transport class. Transport-private
 * configuration and keys remain owned by BFD.
 */
#define foreach_bfd_transport(F)                                                                   \
  F (UDP4, "ip4-rewrite")                                                                          \
  F (UDP6, "ip6-rewrite")

typedef enum
{
#define F(t, n) BFD_TRANSPORT_##t,
  foreach_bfd_transport (F)
#undef F
} bfd_transport_e;

/**
 * hop types
 */
/**
 * Public BFD hop type identifiers.
 *
 * Single-hop sessions are consumed by adjacency tracking. Multi-hop sessions
 * are consumed by FIB entry tracking.
 */
#define foreach_bfd_hop(F)                                                                         \
  F (SINGLE)                                                                                       \
  F (MULTI)

typedef enum
{
#define F(sym) BFD_HOP_TYPE_##sym,
  foreach_bfd_hop (F)
#undef F
} bfd_hop_type_e;

/**
 * Snapshot of BFD session data required by vnet listeners.
 *
 * This payload is copied before crossing the notifier boundary. Consumers must
 * not depend on the layout or lifetime of bfd_session_t, which lets BFD move to
 * a plugin while keeping the vnet-facing event contract in the base image.
 */
typedef struct
{
  /** BFD session pool index. */
  u32 session_index;

  /** Adjacency index used by single-hop sessions, or ADJ_INDEX_INVALID. */
  u32 adj_index;

  /** FIB table index used by multi-hop sessions, or ~0 if unavailable. */
  u32 fib_index;

  /** Peer address used to find the tracked FIB entry. */
  ip46_address_t peer_addr;

  /** Current local BFD state. */
  bfd_state_e state;

  /** Whether the session tracks an adjacency or a FIB entry. */
  bfd_hop_type_e hop_type;

  /** Session transport class. */
  bfd_transport_e transport;
} vnet_bfd_event_t;

#endif /* __included_bfd_public_h__ */
