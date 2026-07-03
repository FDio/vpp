/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef __included_bfd_vnet_notifier_h__
#define __included_bfd_vnet_notifier_h__

#include <vnet/bfd/bfd_public.h>
/**
 * @file
 * @brief Declarations of vnet-owned notifier API between BFD and vnet consumers.
 *
 * The notifier is the in-process notification boundary between the BFD
 * implementation and VNET consumers. BFD publishes one public
 * vnet_bfd_event_t snapshot stream here instead of calling ADJ, FIB, or any
 * future consumer directly. This keeps the BFD implementation independent of
 * the complete consumer set when BFD is built into vnet and when it is moved to
 * an optional plugin.
 *
 * The callback_data helper owns listener storage and safe iteration/mutation
 * semantics, so this header does not define a local function-pointer list.
 * This API is for in-process VNET notifications only; it is not a control-plane
 * API and it does not carry packet data.
 */

/**
 * Listener descriptor registered by a vnet consumer.
 *
 * The notifier stores listener descriptors by value. The optional context
 * pointer is passed back to the owner through the listener argument.
 */
typedef struct bfd_vnet_notifier_listener_t bfd_vnet_notifier_listener_t;

/**
 * Arguments delivered to every BFD vnet notifier listener.
 *
 * The payload pointer is valid only for the duration of the callback. Listeners
 * that need to retain data must copy the fields they use.
 */
typedef struct
{
  bfd_listen_event_e event;
  const vnet_bfd_event_t *payload;
} bfd_vnet_notifier_args_t;

/**
 * Function type for BFD vnet notifier listeners.
 */
typedef void (*bfd_vnet_notifier_listener_fn_t) (bfd_vnet_notifier_listener_t *listener,
						 bfd_vnet_notifier_args_t *args);

/**
 * Registered listener entry.
 */
struct bfd_vnet_notifier_listener_t
{
  /** Callback invoked for each published BFD vnet event. */
  bfd_vnet_notifier_listener_fn_t fp;

  /** Listener-owned context, opaque to the notifier. */
  void *ctx;
};

/**
 * Register a listener for BFD vnet events.
 *
 * Intended callers are VNET consumers that subscribe during their init path.
 * Listener callbacks are invoked on the main thread and should treat each event
 * as a read-only snapshot.
 */
void bfd_vnet_notifier_register_listener (bfd_vnet_notifier_listener_t listener);

/**
 * Unregister listeners matching the supplied callback function.
 */
int bfd_vnet_notifier_unregister_listener (bfd_vnet_notifier_listener_fn_t fn);

/**
 * Publish a BFD vnet event to all registered listeners.
 *
 * Intended callers are the BFD implementation when a public session lifecycle
 * or state-change notification must be delivered to VNET consumers. The payload
 * must contain only public snapshot data; callers must not expose
 * bfd_session_t storage through this boundary.
 *
 * Listener callbacks are executed on the main thread. Calls from worker threads
 * are marshalled through vlib RPC with a copied payload.
 */
void bfd_vnet_notifier_publish (bfd_listen_event_e event, const vnet_bfd_event_t *payload);

#endif /* __included_bfd_vnet_notifier_h__ */
