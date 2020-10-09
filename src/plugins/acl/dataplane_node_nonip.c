/*
 * Copyright (c) 2016-2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stddef.h>
#include <netinet/in.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>


#include <acl/acl.h>
#include <vnet/ip/icmp46_packet.h>

#include <plugins/acl/fa_node.h>
#include <plugins/acl/acl.h>
#include <plugins/acl/lookup_context.h>
#include <plugins/acl/public_inlines.h>
#include <plugins/acl/session_inlines.h>

#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_template.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 lc_index;
  u32 match_acl_in_index;
  u32 match_rule_index;
  u64 packet_info[6];
  u32 trace_bitmap;
  u8 action;
} acl_fa_trace_t;

/* *INDENT-OFF* */
#define foreach_acl_fa_error \
_(ACL_DROP, "ACL deny packets")  \
_(ACL_PERMIT, "ACL permit packets")  \
_(ACL_NEW_SESSION, "new sessions added") \
_(ACL_EXIST_SESSION, "existing session packets") \
_(ACL_CHECK, "checked packets") \
_(ACL_RESTART_SESSION_TIMER, "restart session timer") \
_(ACL_TOO_MANY_SESSIONS, "too many sessions to add new") \
/* end  of errors */

typedef enum
{
#define _(sym,str) ACL_FA_ERROR_##sym,
  foreach_acl_fa_error
#undef _
    ACL_FA_N_ERROR,
} acl_fa_error_t;

/* *INDENT-ON* */

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u16 ethertype;
} nonip_in_out_trace_t;

/* packet trace format function */
static u8 *
format_nonip_in_out_trace (u8 * s, u32 is_output, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nonip_in_out_trace_t *t = va_arg (*args, nonip_in_out_trace_t *);

  s = format (s, "%s: sw_if_index %d next_index %x ethertype %x",
	      is_output ? "OUT-ETHER-WHITELIST" : "IN-ETHER-WHITELIST",
	      t->sw_if_index, t->next_index, t->ethertype);
  return s;
}

static u8 *
format_l2_nonip_in_trace (u8 * s, va_list * args)
{
  return format_nonip_in_out_trace (s, 0, args);
}

static u8 *
format_l2_nonip_out_trace (u8 * s, va_list * args)
{
  return format_nonip_in_out_trace (s, 1, args);
}

#define foreach_nonip_in_error                    \
_(DROP, "dropped inbound non-whitelisted non-ip packets") \
_(PERMIT, "permitted inbound whitelisted non-ip packets") \


#define foreach_nonip_out_error                    \
_(DROP, "dropped outbound non-whitelisted non-ip packets") \
_(PERMIT, "permitted outbound whitelisted non-ip packets") \


/* *INDENT-OFF* */

typedef enum
{
#define _(sym,str) FA_IN_NONIP_ERROR_##sym,
  foreach_nonip_in_error
#undef _
    FA_IN_NONIP_N_ERROR,
} l2_in_feat_arc_error_t;

static char *fa_in_nonip_error_strings[] = {
#define _(sym,string) string,
  foreach_nonip_in_error
#undef _
};

typedef enum
{
#define _(sym,str) FA_OUT_NONIP_ERROR_##sym,
  foreach_nonip_out_error
#undef _
    FA_OUT_NONIP_N_ERROR,
} l2_out_feat_arc_error_t;

static char *fa_out_nonip_error_strings[] = {
#define _(sym,string) string,
  foreach_nonip_out_error
#undef _
};
/* *INDENT-ON* */


always_inline int
is_permitted_ethertype (acl_main_t * am, int sw_if_index0, int is_output,
			u16 ethertype)
{
  u16 **v = is_output
    ? am->output_etype_whitelist_by_sw_if_index
    : am->input_etype_whitelist_by_sw_if_index;
  u16 *whitelist = vec_elt (v, sw_if_index0);
  int i;

  if (vec_len (whitelist) == 0)
    return 1;

  for (i = 0; i < vec_len (whitelist); i++)
    if (whitelist[i] == ethertype)
      return 1;
  return 0;
}

#define get_u16(addr) ( *((u16 *)(addr)) )

always_inline uword
nonip_in_out_node_fn (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame,
		      int is_output)
{
  acl_main_t *am = &acl_main;
  u32 n_left, *from;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vlib_node_runtime_t *error_node;

  from = vlib_frame_vector_args (frame);
  error_node = vlib_node_get_runtime (vm, node->node_index);
  vlib_get_buffers (vm, from, bufs, frame->n_vectors);
  /* set the initial values for the current buffer the next pointers */
  b = bufs;
  next = nexts;

  n_left = frame->n_vectors;
  while (n_left > 0)
    {
      u32 next_index = 0;
      u32 sw_if_index0 =
	vnet_buffer (b[0])->sw_if_index[is_output ? VLIB_TX : VLIB_RX];
      u16 ethertype = 0;

      int error0 = 0;

      ethernet_header_t *h0 = vlib_buffer_get_current (b[0]);
      u8 *l3h0 = (u8 *) h0 + vnet_buffer (b[0])->l2.l2_len;
      ethertype = clib_net_to_host_u16 (get_u16 (l3h0 - 2));

      if (is_permitted_ethertype (am, sw_if_index0, is_output, ethertype))
	vnet_feature_next (&next_index, b[0]);

      next[0] = next_index;

      if (0 == next[0])
	b[0]->error = error_node->errors[error0];

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  nonip_in_out_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->ethertype = ethertype;
	  t->next_index = next[0];
	}
      next[0] = next[0] < node->n_next_nodes ? next[0] : 0;

      next++;
      b++;
      n_left--;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (acl_in_nonip_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  return nonip_in_out_node_fn (vm, node, frame, 0);
}

VLIB_NODE_FN (acl_out_nonip_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return nonip_in_out_node_fn (vm, node, frame, 1);
}


/* *INDENT-OFF* */

VLIB_REGISTER_NODE (acl_in_nonip_node) =
{
  .name = "acl-plugin-in-nonip-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_nonip_in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (fa_in_nonip_error_strings),
  .error_strings = fa_in_nonip_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_in_l2_nonip_fa_feature, static) =
{
  .arc_name = "l2-input-nonip",
  .node_name = "acl-plugin-in-nonip-l2",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};

VLIB_REGISTER_NODE (acl_out_nonip_node) =
{
  .name = "acl-plugin-out-nonip-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_nonip_out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (fa_out_nonip_error_strings),
  .error_strings = fa_out_nonip_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_out_l2_nonip_fa_feature, static) =
{
  .arc_name = "l2-output-nonip",
  .node_name = "acl-plugin-out-nonip-l2",
  .runs_before = VNET_FEATURES ("l2-output-feat-arc-end"),
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
