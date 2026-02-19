/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/sfdp/expiry/expiry.h>

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp_funcs.h>

u8 static expiry_is_enabled = 0;

int
sfdp_set_expiry_callbacks (const sfdp_expiry_callbacks_t *callbacks)
{
  sfdp_main_t *sfdp = &sfdp_main;
  if (expiry_is_enabled)
    {
      return -1;
    }
  clib_memcpy (&sfdp->expiry_callbacks, callbacks, sizeof (*callbacks));
  return 0;
}

int
sfdp_init_timeouts (const sfdp_timeout_t *timeouts, u32 n)
{
  sfdp_main_t *sfdp = &sfdp_main;
  if (expiry_is_enabled)
    {
      return -1;
    }
  clib_memset (sfdp->timeouts, 0, sizeof (sfdp->timeouts));
  clib_memcpy (sfdp->timeouts, timeouts, sizeof (*timeouts) * n);
  return 0;
}

void
sfdp_enable_disable_expiry_node (u8 is_disable, int skip_main)
{
  u32 n_vms = vlib_num_workers () + 1;
  for (int i = !!skip_main; i < n_vms; i++)
    {
      vlib_main_t *vm = vlib_get_main_by_index (i);
      vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "sfdp-expire");
      vlib_node_set_state (vm, node->index,
			   is_disable ? VLIB_NODE_STATE_DISABLED :
					VLIB_NODE_STATE_POLLING);
      if (!is_disable)
	vlib_node_set_interrupt_pending (vm, node->index);
    }
}

#include "vnet/flow/flow.h"

static int
sfdp_flow_offload_delete (u32 session_index, u32 hw_if_index)
{
  vnet_main_t *vnm = &vnet_main;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_session_t *session = pool_elt_at_index (sfdp->sessions, session_index);
  int rv = 0;

  if (session->flow_index == ~0)
    {
      clib_warning ("Flow offload unset for session %u", session_index);
      return -1;
    }

  rv = vnet_flow_disable (vnm, session->flow_index, hw_if_index);
  if (rv != 0)
    {
      clib_warning ("Failed to disable flow %u: %d", session->flow_index, rv);
      return rv;
    }

  rv = vnet_flow_del (vnm, session->flow_index);
  if (rv != 0)
    {
      clib_warning ("Failed to delete flow %u: %d", session->flow_index, rv);
      return rv;
    }
  return 0;
}

void
sfdp_enable_disable_expiry (u8 is_disable)
{
  sfdp_main_t *sfdp = &sfdp_main;

  if (!is_disable)
    { /* Init module first */
      expiry_is_enabled = true;
      sfdp->expiry_callbacks.enable ();
    }

  /* Start/stop pre-input node */
  sfdp_enable_disable_expiry_node (is_disable, sfdp->no_main);

  if (is_disable)
    { /* De-init module last */
      sfdp->expiry_callbacks.disable ();
      expiry_is_enabled = false;
    }
}

#define foreach_sfdp_expire_error                                             \
  _ (NODE_CALLED, "node-called", INFO, "node called")                         \
  _ (EXPIRED, "expired", INFO, "session expired")                             \
  _ (REQUESTED_EVICTION, "requested-eviction", INFO, "requested eviction")

typedef enum
{
#define _(sym, name, sev, str) SFDP_EXPIRE_ERROR_##sym,
  foreach_sfdp_expire_error
#undef _
    SFDP_EXPIRE_N_ERROR,
} sfdp_expire_error_t;

static vlib_error_desc_t sfdp_expire_error_descriptors[] = {
#define _(sym, name, sev, str) { name, str, VL_COUNTER_SEVERITY_##sev },
  foreach_sfdp_expire_error
#undef _
};

VLIB_NODE_FN (sfdp_expire_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  sfdp_main_t *sfdp = &sfdp_main;
  if (PREDICT_FALSE (!expiry_is_enabled))
    return 0;
  u32 thread_index = vm->thread_index;
  sfdp_per_thread_data_t *ptd =
    vec_elt_at_index (sfdp->per_thread_data, thread_index);
  u32 *session_index;

  u32 n_remaining_sessions = sfdp_sessions_available_for_this_thread (ptd);
  u32 desired_evictions =
    (n_remaining_sessions < sfdp->eviction_sessions_margin) ?
      (sfdp->eviction_sessions_margin - n_remaining_sessions) :
      0;

  /* Calling callback for expiries or evictions */
  ptd->expired_sessions = sfdp->expiry_callbacks.expire_or_evict_sessions (
    desired_evictions, ptd->expired_sessions);

  vlib_node_increment_counter (vm, node->node_index,
			       SFDP_EXPIRE_ERROR_NODE_CALLED, 1);
  vlib_node_increment_counter (vm, node->node_index,
			       SFDP_EXPIRE_ERROR_REQUESTED_EVICTION,
			       desired_evictions);

  if (vec_len (ptd->expired_sessions) == 0)
    goto done;

  sfdp_notify_deleted_sessions (sfdp, ptd->expired_sessions,
				vec_len (ptd->expired_sessions));

  vec_foreach (session_index, ptd->expired_sessions)
    {
      sfdp_session_t *session = sfdp_session_at_index (*session_index);
      if (session->flow_index != ~0)
	{
	  sfdp_flow_offload_delete (*session_index, session->rx_sw_if_index);
	}
      sfdp_session_remove (sfdp, ptd, session, thread_index, *session_index);
    }

  vlib_node_increment_counter (vm, node->node_index, SFDP_EXPIRE_ERROR_EXPIRED,
			       vec_len (ptd->expired_sessions));
  vec_reset_length (ptd->expired_sessions);

done:
  vlib_node_schedule (vm, node->node_index, 1.0);
  return 0;
}

clib_error_t *
sfdp_set_eviction_sessions_margin (u32 margin)
{
  sfdp_main_t *sfdp = &sfdp_main;
  u32 max = sfdp_num_sessions () / 2;
  if (margin == ~0)
    {
      margin = SFDP_DEFAULT_EVICTION_SESSIONS_MARGIN;
      margin = (margin > max) ? max : margin;
    }

  if (margin > max)
    {
      return clib_error_return (
	0, "Cannot set a margin greater than half the flow table !");
    }

  sfdp->eviction_sessions_margin = margin;
  return 0;
}

VLIB_REGISTER_NODE (sfdp_expire_node) = { .name = "sfdp-expire",
					  .type = VLIB_NODE_TYPE_SCHED,
					  .n_errors = SFDP_EXPIRE_N_ERROR,
					  .error_counters = sfdp_expire_error_descriptors,
					  .state = VLIB_NODE_STATE_DISABLED };
