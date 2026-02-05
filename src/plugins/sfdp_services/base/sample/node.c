/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/service.h>
#define foreach_sample_terminal_error _ (DROP, "drop")

typedef enum
{
#define _(sym, str) SAMPLE_TERMINAL_ERROR_##sym,
  foreach_sample_terminal_error
#undef _
    SAMPLE_TERMINAL_N_ERROR,
} sample_terminal_error_t;

static char *sample_terminal_error_strings[] = {
#define _(sym, string) string,
  foreach_sample_terminal_error
#undef _
};

#define foreach_sample_terminal_next _ (DROP, "error-drop")

typedef enum
{
#define _(n, x) SAMPLE_TERMINAL_NEXT_##n,
  foreach_sample_terminal_next
#undef _
    SAMPLE_TERMINAL_N_NEXT
} sample_terminal_next_t;

typedef struct
{
  u32 flow_id;
} sample_terminal_trace_t;

static u8 *
format_sample_terminal_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  sample_terminal_trace_t *t = va_arg (*args, sample_terminal_trace_t *);

  s =
    format (s, "sample-terminal-drop: flow-id %u (session %u, %s)", t->flow_id,
	    t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}

VLIB_NODE_FN (sample_terminal_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  vlib_buffer_enqueue_to_single_next (vm, node, from,
				      SAMPLE_TERMINAL_NEXT_DROP, n_left);
  vlib_node_increment_counter (vm, node->node_index,
			       SAMPLE_TERMINAL_ERROR_DROP, n_left);
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      vlib_get_buffers (vm, from, bufs, n_left);
      b = bufs;
      for (i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sample_terminal_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->flow_id = b[0]->flow_id;
	      b++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

#define foreach_sample_non_terminal_error _ (DROP, "drop")

typedef enum
{
#define _(sym, str) SAMPLE_NON_TERMINAL_ERROR_##sym,
  foreach_sample_non_terminal_error
#undef _
    SAMPLE_NON_TERMINAL_N_ERROR,
} sample_non_terminal_error_t;

static char *sample_non_terminal_error_strings[] = {
#define _(sym, string) string,
  foreach_sample_non_terminal_error
#undef _
};

typedef struct
{
  u32 flow_id;
  u8 new_state;
} sample_non_terminal_trace_t;

static u8 *
format_sample_non_terminal_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  sample_non_terminal_trace_t *t =
    va_arg (*args, sample_non_terminal_trace_t *);

  s = format (
    s, "sample-non-terminal: flow-id %u (session %u, %s) new_state: %U",
    t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward",
    format_sfdp_session_state, t->new_state);
  return s;
}

VLIB_NODE_FN (sample_non_terminal_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  sfdp_main_t *sfdp = &sfdp_main;

  u32 thread_index = vm->thread_index;
  sfdp_per_thread_data_t *ptd =
    vec_elt_at_index (sfdp->per_thread_data, thread_index);

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
      CLIB_UNUSED (u8 direction) =
	sfdp_direction_from_flow_index (b[0]->flow_id);
      /* Set the state of the session to established */
      session->state = SFDP_SESSION_STATE_ESTABLISHED;
      /* Rearm the session timeout to
       * tenant->timeouts[SFDP_TIMEOUT_ESTABLISHED] from now */
      sfdp_session_timer_update (&ptd->wheel, &session->timer,
				 ptd->current_time,
				 tenant->timeouts[SFDP_TIMEOUT_ESTABLISHED]);
      /* Next service in chain for this packet */
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
	      sample_non_terminal_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      u32 session_idx = sfdp_session_from_flow_index (b[0]->flow_id);
	      sfdp_session_t *session =
		sfdp_session_at_index (ptd, session_idx);
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

/* This service is a terminal service, i.e., its next nodes are outside
   of sfdp (here for example, error-drop) */

VLIB_REGISTER_NODE (sample_terminal_node) = {
  .name = "sample-terminal",
  .vector_size = sizeof (u32),
  .format_trace = format_sample_terminal_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sample_terminal_error_strings),
  .error_strings = sample_terminal_error_strings,

  .n_next_nodes = SAMPLE_TERMINAL_N_NEXT,
  .next_nodes = {
#define _(n, x) [SAMPLE_TERMINAL_NEXT_##n] = x,
          foreach_sample_terminal_next
#undef _
  }

};

SFDP_SERVICE_DEFINE (sample) = {
  .node_name = "sample-terminal",
  .runs_before = SFDP_SERVICES (0),
  .runs_after = SFDP_SERVICES (0),
  .is_terminal = 1,
};

/* This service is a nonterminal service, i.e., next nodes cannot be specified
 */

VLIB_REGISTER_NODE (sample_non_terminal_node) = {
  .name = "sample-non-terminal",
  .vector_size = sizeof (u32),
  .format_trace = format_sample_non_terminal_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sample_non_terminal_error_strings),
  .error_strings = sample_non_terminal_error_strings,

};

SFDP_SERVICE_DEFINE (sample_non_terminal) = {
  .node_name = "sample-non-terminal",
  .runs_before = SFDP_SERVICES (0),
  .runs_after = SFDP_SERVICES ("sfdp-drop"),
  .is_terminal = 0
};