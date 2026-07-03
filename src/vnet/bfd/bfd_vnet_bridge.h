/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef __included_bfd_vnet_bridge_h__
#define __included_bfd_vnet_bridge_h__

#include <vnet/bfd/bfd_public.h>

/**
 * Listener descriptor registered by a vnet consumer.
 *
 * The bridge stores listener descriptors by value. The optional context pointer
 * is passed back to the owner through the listener argument.
 */
typedef struct bfd_vnet_bridge_listener_t bfd_vnet_bridge_listener_t;

/**
 * Arguments delivered to every BFD vnet bridge listener.
 *
 * The payload pointer is valid only for the duration of the callback. Listeners
 * that need to retain data must copy the fields they use.
 */
typedef struct
{
  bfd_listen_event_e event;
  const vnet_bfd_event_t *payload;
} bfd_vnet_bridge_args_t;

/**
 * Function type for BFD vnet bridge listeners.
 */
typedef void (*bfd_vnet_bridge_listener_fn_t) (
  bfd_vnet_bridge_listener_t *listener, bfd_vnet_bridge_args_t *args);

/**
 * Registered listener entry.
 */
struct bfd_vnet_bridge_listener_t
{
  /** Callback invoked for each published BFD vnet event. */
  bfd_vnet_bridge_listener_fn_t fp;

  /** Listener-owned context, opaque to the bridge. */
  void *ctx;
};

/**
 * Register a listener for BFD vnet events.
 */
void bfd_vnet_bridge_register_listener (bfd_vnet_bridge_listener_t listener);

/**
 * Unregister listeners matching the supplied callback function.
 */
int bfd_vnet_bridge_unregister_listener (bfd_vnet_bridge_listener_fn_t fn);

/**
 * Publish a BFD vnet event to all registered listeners.
 *
 * Listener callbacks are executed on the main thread. Calls from worker threads
 * are marshalled through vlib RPC with a copied payload.
 */
void bfd_vnet_bridge_publish (bfd_listen_event_e event,
			      const vnet_bfd_event_t *payload);

#endif /* __included_bfd_vnet_bridge_h__ */
