/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <acl/acl_sample.h>
#include <vnet/sfdp/service.h>
#include <vnet/sfdp/sfdp_funcs.h>

#define foreach_sfdp_acl_sample_error _ (DROP, "drop")

typedef enum
{
#define _(sym, str) SFDP_ACL_SAMPLE_ERROR_##sym,
  foreach_sfdp_acl_sample_error
#undef _
    SFDP_ACL_SAMPLE_N_ERROR,
} sfdp_acl_sample_error_t;

static char *sfdp_acl_sample_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_acl_sample_error
#undef _
};

typedef struct
{
  u32 thread_index;
  u32 flow_id;
  u8 matched;
  u8 action;
} sfdp_acl_sample_trace_t;

static u8 *
format_sfdp_acl_sample_trace (u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg (*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg (*args, vlib_node_t *);
  sfdp_acl_sample_trace_t *t = va_arg (*args, sfdp_acl_sample_trace_t *);
  const char *action_str[] = { "deny", "permit", "permit+reflect" };

  s = format (
    s, "sfdp-acl-sample: flow-id %u (session %u, %s) status: %s, action: %s\n",
    t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward",
    t->matched ? "matched" : "unmatched",
    t->matched ? action_str[t->action] : "<none>");
  return s;
}

SFDP_SERVICE_DECLARE (drop)
SFDP_SERVICE_DECLARE (sfdp_acl_sample)
static_always_inline void
sfdp_acl_sample_process_one (sfdp_acl_main_t *vam, sfdp_session_t *session,
			     u8 dir, u16 *to_next, vlib_buffer_t **b,
			     u8 *matched, u8 *action)
{
  u16 tenant_idx = session->tenant_idx;
  u32 lc_index = vam->lc_by_tenant_idx[tenant_idx];
  fa_5tuple_opaque_t fa_5tuple;
  u32 match_acl_index = ~0;
  u32 match_acl_pos = ~0;
  u32 match_rule_index = ~0;
  u32 trace_bitmap = 0;

  if (lc_index == ~0)
    goto end_of_packet;

  acl_plugin_fill_5tuple_inline (acl_plugin.p_acl_main, lc_index, b[0], 0, 1,
				 0, &fa_5tuple);

  if (acl_plugin_match_5tuple_inline (
	acl_plugin.p_acl_main, lc_index, &fa_5tuple, 0, action, &match_acl_pos,
	&match_acl_index, &match_rule_index, &trace_bitmap))
    {
      matched[0] = 1;
      if (action[0] == 0)
	{
	  /* Drop this flow, in this direction, forever */
	  session->bitmaps[dir] |= SFDP_SERVICE_MASK (drop);
	  sfdp_buffer (b[0])->service_bitmap = SFDP_SERVICE_MASK (drop);
	}
      else if (action[0] == 1)
	/* Allow this packet only */
	;
      else
	{
	  /* Allow this flow and cache the decision in forward and reverse
	   * direction */
	  session->bitmaps[SFDP_FLOW_FORWARD] &=
	    ~SFDP_SERVICE_MASK (sfdp_acl_sample);
	  session->bitmaps[SFDP_FLOW_REVERSE] &=
	    ~SFDP_SERVICE_MASK (sfdp_acl_sample);
	}
    }
  else
    {
      matched[0] = 0;
    }

end_of_packet:
  sfdp_next (b[0], to_next);
  return;
}

static_always_inline u16
sfdp_acl_sample_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame)
{

  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  sfdp_acl_main_t *vam = &sfdp_acl_main;
  u32 thread_index = vlib_get_thread_index ();
  sfdp_session_t *session;
  u32 session_idx;
  u8 dir;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
  u8 matched[VLIB_FRAME_SIZE], action[VLIB_FRAME_SIZE];
  u8 *m = matched;
  u8 *a = action;
  vlib_get_buffers (vm, from, bufs, n_left);
  while (n_left > 0)
    {
      session_idx = sfdp_session_from_flow_index (b[0]->flow_id);
      dir = sfdp_direction_from_flow_index (b[0]->flow_id);
      session = sfdp_session_at_index (session_idx);

      sfdp_acl_sample_process_one (vam, session, dir, to_next, b, m, a);
      n_left -= 1;
      b += 1;
      to_next += 1;
      m += 1;
      a += 1;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      int i;
      b = bufs;
      m = matched;
      a = action;
      n_left = frame->n_vectors;
      for (i = 0; i < n_left; i++)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      sfdp_acl_sample_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->flow_id = b[0]->flow_id;
	      t->thread_index = thread_index;
	      t->matched = m[0];
	      t->action = a[0];
	      b++;
	      m++;
	      a++;
	    }
	  else
	    break;
	}
    }
  return frame->n_vectors;
}

VLIB_NODE_FN (sfdp_acl_sample_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return sfdp_acl_sample_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (sfdp_acl_sample_node) = {
  .name = "sfdp-acl-sample",
  .vector_size = sizeof (u32),
  .format_trace = format_sfdp_acl_sample_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (sfdp_acl_sample_error_strings),
  .error_strings = sfdp_acl_sample_error_strings
};

SFDP_SERVICE_DEFINE (sfdp_acl_sample) = {
  .node_name = "sfdp-acl-sample",
  .runs_before = SFDP_SERVICES ("sfdp-geneve-output", "ip4-lookup"),
  .runs_after = SFDP_SERVICES ("sfdp-drop", "sfdp-l4-lifecycle",
			       "sfdp-tcp-check"),
  .is_terminal = 0
};

SFDP_SERVICE_DEFINE (ip4_lookup) = {
  .node_name = "ip4-lookup",
  .runs_before = SFDP_SERVICES (0),
  .runs_after = SFDP_SERVICES ("sfdp-drop", "sfdp-l4-lifecycle",
			       "sfdp-tcp-check"),
  .is_terminal = 1
};