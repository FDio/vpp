/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/service.h>
#include <vnet/sfdp/timer/timer.h>
#define foreach_sfdp_l4_lifecycle_error _ (DROP, "drop")

typedef enum
{
#define _(sym, str) SFDP_L4_LIFECYCLE_ERROR_##sym,
  foreach_sfdp_l4_lifecycle_error
#undef _
    SFDP_L4_LIFECYCLE_N_ERROR,
} sfdp_l4_lifecycle_error_t;

static char *sfdp_l4_lifecycle_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_l4_lifecycle_error
#undef _
};

typedef struct
{
  u32 flow_id;
  u8 new_state;
} sfdp_l4_lifecycle_trace_t;

static u8 *
format_sfdp_l4_lifecycle_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  sfdp_l4_lifecycle_trace_t *t = va_arg (*args, sfdp_l4_lifecycle_trace_t *);

  s = format (
    s, "sfdp-l4-lifecycle: flow-id %u (session %u, %s) new_state: %U",
    t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward",
    format_sfdp_session_state, t->new_state);
  return s;
}

SFDP_SERVICE_DECLARE (tcp_check)
SFDP_SERVICE_DECLARE (l4_lifecycle)
VLIB_NODE_FN (sfdp_l4_lifecycle_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  sfdp_main_t *sfdp = &sfdp_main;

  u32 thread_index = vm->thread_index;
  sfdp_timer_per_thread_data_t *tptd =
    vec_elt_at_index (sfdp_timer_main.per_thread_data, thread_index);

  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left)
    {
      u32 session_idx = sfdp_session_from_flow_index (b[0]->flow_id);
      sfdp_tenant_index_t tenant_idx = sfdp_buffer (b[0])->tenant_index;
      sfdp_session_t *session = sfdp_session_at_index (session_idx);
      sfdp_tenant_t *tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
      u8 direction = sfdp_direction_from_flow_index (b[0]->flow_id);
      /* TODO: prefetch, 4-loop, remove ifs and do state-transition-timer LUT?
       */
      if (session->proto == IP_PROTOCOL_TCP)
	{
	  session->bitmaps[SFDP_FLOW_FORWARD] &=
	    ~SFDP_SERVICE_MASK (l4_lifecycle);
	  session->bitmaps[SFDP_FLOW_REVERSE] &=
	    ~SFDP_SERVICE_MASK (l4_lifecycle);
	  sfdp_buffer (b[0])->service_bitmap |= SFDP_SERVICE_MASK (tcp_check);
	  session->bitmaps[SFDP_FLOW_FORWARD] |= SFDP_SERVICE_MASK (tcp_check);
	  session->bitmaps[SFDP_FLOW_REVERSE] |= SFDP_SERVICE_MASK (tcp_check);
	}
      else
	{
	  if (session->state == SFDP_SESSION_STATE_FSOL &&
	      direction == SFDP_FLOW_REVERSE)
	    /*Establish the session*/
	    session->state = SFDP_SESSION_STATE_ESTABLISHED;

	  if (session->state == SFDP_SESSION_STATE_ESTABLISHED)
	    {
	      /* TODO: must be configurable per tenant */
	      sfdp_session_timer_update (
		&tptd->wheel, SFDP_SESSION_TIMER (session), tptd->current_time,
		tenant->timeouts[SFDP_TIMEOUT_ESTABLISHED]);
	    }
	}
      sfdp_next (b[0], to_next);

      b++;
      to_next++;
      n_left--;
    }

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      n_left = frame->n_vectors;
      b = bufs;
      for (int i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sfdp_l4_lifecycle_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      u32 session_idx = sfdp_session_from_flow_index (b[0]->flow_id);
	      sfdp_session_t *session = sfdp_session_at_index (session_idx);
	      u16 state = session->state;
	      t->flow_id = b[0]->flow_id;
	      t->new_state = state;
	      b++;
	    }
	  else
	    break;
	}
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (sfdp_l4_lifecycle_node) = {
  .name = "sfdp-l4-lifecycle",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_l4_lifecycle_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_l4_lifecycle_error_strings),
  .error_strings = sfdp_l4_lifecycle_error_strings,
};

SFDP_SERVICE_DEFINE (l4_lifecycle) = {
  .node_name = "sfdp-l4-lifecycle",
  .runs_before = SFDP_SERVICES (0),
  .runs_after = SFDP_SERVICES ("sfdp-drop"),
  .is_terminal = 0
};