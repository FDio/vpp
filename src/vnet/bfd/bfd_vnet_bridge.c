/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/bfd/bfd_vnet_bridge.h>

#include <vlib/vlib.h>
#include <vppinfra/lock.h>
#include <vppinfra/callback_data.h>

clib_callback_data_typedef (bfd_vnet_bridge_listener_set_t,
			    bfd_vnet_bridge_listener_t);

/**
 * Main state for the BFD-to-vnet notification bridge.
 *
 * The bridge belongs to vnet rather than the BFD implementation so listeners in
 * the base image can depend on this API even when BFD is built as a plugin.
 */
typedef struct
{
  bfd_vnet_bridge_listener_set_t listeners;
  clib_spinlock_t listeners_lock;
  u8 initialized;
} bfd_vnet_bridge_main_t;

static bfd_vnet_bridge_main_t bfd_vnet_bridge_main;

/**
 * Lazily initialise the listener set and its lock.
 *
 * Some consumers register from init functions and tests call listeners
 * directly, so the bridge is safe to initialise either from its VLIB init hook
 * or on first use.
 */
static void
bfd_vnet_bridge_init_once (void)
{
  bfd_vnet_bridge_main_t *bbm = &bfd_vnet_bridge_main;

  if (bbm->initialized)
    return;

  clib_spinlock_init (&bbm->listeners_lock);
  clib_callback_data_init (&bbm->listeners, &bbm->listeners_lock);
  bbm->initialized = 1;
}

/**
 * RPC payload used when BFD publishes from a worker thread.
 */
typedef struct
{
  bfd_listen_event_e event;
  vnet_bfd_event_t payload;
} bfd_vnet_bridge_rpc_args_t;

/**
 * Notify registered listeners on the current thread.
 *
 * Callers are responsible for ensuring this runs on the main thread.
 */
static void
bfd_vnet_bridge_notify_listeners (bfd_listen_event_e event,
				  const vnet_bfd_event_t *payload)
{
  bfd_vnet_bridge_main_t *bbm = &bfd_vnet_bridge_main;
  bfd_vnet_bridge_listener_t *listeners;
  bfd_vnet_bridge_args_t args = {
    .event = event,
    .payload = payload,
  };

  bfd_vnet_bridge_init_once ();
  listeners = clib_callback_data_check_and_get (&bbm->listeners);
  clib_callback_data_call_vec (listeners, &args);
}

/**
 * Main-thread RPC entry point for worker-originated bridge publications.
 */
static void
bfd_vnet_bridge_publish_rpc_cb (const bfd_vnet_bridge_rpc_args_t *args)
{
  bfd_vnet_bridge_notify_listeners (args->event, &args->payload);
}

/**
 * Register a vnet listener with callback_data duplicate suppression.
 */
void
bfd_vnet_bridge_register_listener (bfd_vnet_bridge_listener_t listener)
{
  bfd_vnet_bridge_main_t *bbm = &bfd_vnet_bridge_main;

  bfd_vnet_bridge_init_once ();
  clib_callback_data_ensure (&bbm->listeners, listener);
}

/**
 * Remove listeners by callback function.
 */
int
bfd_vnet_bridge_unregister_listener (bfd_vnet_bridge_listener_fn_t fn)
{
  bfd_vnet_bridge_main_t *bbm = &bfd_vnet_bridge_main;

  bfd_vnet_bridge_init_once ();
  return clib_callback_data_remove (&bbm->listeners, fn);
}

/**
 * Publish one copied BFD event payload to vnet listeners.
 *
 * This preserves the existing BFD notification threading model: listeners run
 * on the main thread even when a BFD state change is observed by a worker.
 */
void
bfd_vnet_bridge_publish (bfd_listen_event_e event,
			 const vnet_bfd_event_t *payload)
{
  ASSERT (payload);

  if (vlib_get_thread_index () == 0)
    {
      bfd_vnet_bridge_notify_listeners (event, payload);
    }
  else
    {
      bfd_vnet_bridge_rpc_args_t args = {
	.event = event,
	.payload = *payload,
      };
      vlib_rpc_call_main_thread (bfd_vnet_bridge_publish_rpc_cb, (u8 *) &args,
				 sizeof (args));
    }
}

/**
 * Initialise the bridge during vlib startup.
 */
static clib_error_t *
bfd_vnet_bridge_init (CLIB_UNUSED (vlib_main_t *vm))
{
  bfd_vnet_bridge_init_once ();

  return 0;
}

VLIB_INIT_FUNCTION (bfd_vnet_bridge_init);
