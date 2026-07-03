/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

/**
 * @file
 * @brief Implements the vnet-owned BFD notifier.
 */
#include <vnet/bfd/bfd_vnet_notifier.h>

#include <vlib/vlib.h>
#include <vppinfra/lock.h>
#include <vppinfra/callback_data.h>

clib_callback_data_typedef (bfd_vnet_notifier_listener_set_t, bfd_vnet_notifier_listener_t);

/**
 * Main state for the BFD-to-vnet notifier.
 *
 * The notifier belongs to vnet rather than the BFD implementation so listeners
 * in the base image can depend on this API even when BFD is built as a plugin.
 * The publisher sees one VNET notification surface, while consumers own their
 * subscription and filtering policy.
 */
typedef struct
{
  bfd_vnet_notifier_listener_set_t listeners;
  clib_spinlock_t listeners_lock;
  u8 initialized;
} bfd_vnet_notifier_main_t;

static bfd_vnet_notifier_main_t bfd_vnet_notifier_main;

/**
 * Lazily initialise the listener set and its lock.
 *
 * Some consumers register from init functions and tests call listeners
 * directly, so the notifier is safe to initialise either from its VLIB init
 * hook or on first use.
 */
static void
bfd_vnet_notifier_init_once (void)
{
  bfd_vnet_notifier_main_t *bnm = &bfd_vnet_notifier_main;

  if (bnm->initialized)
    return;

  clib_spinlock_init (&bnm->listeners_lock);
  clib_callback_data_init (&bnm->listeners, &bnm->listeners_lock);
  bnm->initialized = 1;
}

/**
 * RPC payload used when BFD publishes from a worker thread.
 */
typedef struct
{
  bfd_listen_event_e event;
  vnet_bfd_event_t payload;
} bfd_vnet_notifier_rpc_args_t;

/**
 * Notify registered listeners on the current thread.
 *
 * Callers are responsible for ensuring this runs on the main thread.
 * callback_data provides the listener-vector snapshot semantics used while
 * callbacks are running, so listeners may be managed without a local ad hoc
 * function-pointer list.
 */
static void
bfd_vnet_notifier_dispatch (bfd_listen_event_e event, const vnet_bfd_event_t *payload)
{
  bfd_vnet_notifier_main_t *bnm = &bfd_vnet_notifier_main;
  bfd_vnet_notifier_listener_t *listeners;
  bfd_vnet_notifier_args_t args = {
    .event = event,
    .payload = payload,
  };

  bfd_vnet_notifier_init_once ();
  listeners = clib_callback_data_check_and_get (&bnm->listeners);
  clib_callback_data_call_vec (listeners, &args);
}

/**
 * Main-thread RPC entry point for worker-originated notifier publications.
 */
static void
bfd_vnet_notifier_publish_rpc_cb (const bfd_vnet_notifier_rpc_args_t *args)
{
  bfd_vnet_notifier_dispatch (args->event, &args->payload);
}

/**
 * Register a vnet listener with callback_data duplicate suppression.
 */
void
bfd_vnet_notifier_register_listener (bfd_vnet_notifier_listener_t listener)
{
  bfd_vnet_notifier_main_t *bnm = &bfd_vnet_notifier_main;

  bfd_vnet_notifier_init_once ();
  clib_callback_data_ensure (&bnm->listeners, listener);
}

/**
 * Remove listeners by callback function.
 */
int
bfd_vnet_notifier_unregister_listener (bfd_vnet_notifier_listener_fn_t fn)
{
  bfd_vnet_notifier_main_t *bnm = &bfd_vnet_notifier_main;

  bfd_vnet_notifier_init_once ();
  return clib_callback_data_remove (&bnm->listeners, fn);
}

/**
 * Publish one copied BFD event payload to vnet listeners.
 *
 * This preserves the existing BFD notification threading model: listeners run
 * on the main thread even when a BFD state change is observed by a worker. The
 * worker-to-main path copies the public snapshot and does not pass
 * bfd_session_t storage across the notifier boundary.
 */
void
bfd_vnet_notifier_publish (bfd_listen_event_e event, const vnet_bfd_event_t *payload)
{
  ASSERT (payload);

  if (vlib_get_thread_index () == 0)
    {
      bfd_vnet_notifier_dispatch (event, payload);
    }
  else
    {
      bfd_vnet_notifier_rpc_args_t args = {
	.event = event,
	.payload = *payload,
      };
      vlib_rpc_call_main_thread (bfd_vnet_notifier_publish_rpc_cb, (u8 *) &args, sizeof (args));
    }
}

/**
 * Initialise the notifier during vlib startup.
 */
static clib_error_t *
bfd_vnet_notifier_init (CLIB_UNUSED (vlib_main_t *vm))
{
  bfd_vnet_notifier_init_once ();

  return 0;
}

VLIB_INIT_FUNCTION (bfd_vnet_notifier_init);
