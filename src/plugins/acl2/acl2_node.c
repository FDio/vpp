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


#include <vnet/ip/icmp46_packet.h>
#include <vnet/match/match_engine.h>
#include <vnet/match/match_set_dp.h>

#include <plugins/acl2/acl2.h>


typedef struct
{
  u32 sw_if_index;
  acl2_result_t result;
  bool match;
} acl2_trace_t;

#define foreach_acl2_error                      \
  _(DROP, "ACL deny packets")                   \
  _(PERMIT, "ACL permit packets")               \
  _(CHECK, "ACL Check")                         \

static char *acl2_error_strings[] = {
#define _(sym,string) string,
  foreach_acl2_error
#undef _
};

typedef enum
{
#define _(sym,str) ACL2_ERROR_##sym,
  foreach_acl2_error
#undef _
    ACL_N_ERROR,
} acl2_error_t;

#define ACL2_N_NEXT 1

always_inline uword
acl_switch_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node,
		   vlib_frame_t * frame,
		   vlib_dir_t dir,
		   vnet_link_t linkt, ip_address_family_t af, int do_counters)
{
  u32 n_left, *from;
  u32 pkts_acl_permit = 0;
  vlib_node_runtime_t *error_node;

  u64 now;
  u32 thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  now = clib_cpu_time_now ();
  thread_index = vm->thread_index;
  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left);

  /* for the delayed counters */
  u32 saved_matched_ace_index = 0;
  u32 saved_packet_count = 0;
  u32 saved_byte_count = 0;

  error_node = vlib_node_get_runtime (vm, node->node_index);

  while (n_left > 0)
    {
      i16 l2_offset, l3_offset;
      const acl2_itf_t *aitf;
      acl2_result_t ar;
      u32 sw_if_index;
      bool match;

      sw_if_index = vnet_buffer (b[0])->sw_if_index[dir];
      aitf = acl2_itf_get (sw_if_index, dir);

      l2_offset = l3_offset = 0;

      /* In the L3 output path the l2 rewrite has already been applied
       * hence the buffer's current data is pointing at l2. */
      if (VNET_LINK_ETHERNET != linkt && VLIB_TX == dir)
	l3_offset = vnet_buffer (b[0])->ip.save_rewrite_length;
      if (VNET_LINK_ETHERNET != linkt && VLIB_RX == dir)
	l2_offset = -vnet_buffer (b[0])->ip.save_rewrite_length;
      if (VNET_LINK_ETHERNET == linkt && VLIB_TX == dir)
	l3_offset = vnet_buffer (b[0])->l2.l2_len;
      if (VNET_LINK_ETHERNET == linkt && VLIB_RX == dir)
	l3_offset = vnet_buffer (b[0])->l2.l2_len;

      match = match_match_one (vm, b[0], l2_offset, l3_offset,
			       &aitf->match_apps[af], now, &ar.ar_u64);

      if (match)
	{
	  if (do_counters)
	    {
	      u32 buf_len = vlib_buffer_length_in_chain (vm, b[0]);

	      if (saved_matched_ace_index != ar.ar_ace)
		{
		  vlib_increment_combined_counter
		    (&ace_counters,
		     thread_index,
		     saved_matched_ace_index,
		     saved_packet_count, saved_byte_count);

		  saved_matched_ace_index = ar.ar_ace;
		  saved_packet_count = 1;
		  saved_byte_count = buf_len;
		  /* prefetch the counter that we are going to increment */
		  vlib_prefetch_combined_counter (&ace_counters,
						  thread_index,
						  saved_matched_ace_index);
		}
	      else
		{
		  saved_packet_count++;
		  saved_byte_count += buf_len;
		}
	    }
	}
      else
	ar.ar_action = ACL2_ACTION_DENY;

      switch (ar.ar_action)
	{
	case ACL2_ACTION_DENY:
	  b[0]->error = error_node->errors[ar.ar_action];
	  next[0] = ACL2_ERROR_DROP;
	  break;

	case ACL2_ACTION_PERMIT:
	  vnet_feature_next_u16 (&next[0], b[0]);
	  pkts_acl_permit++;
	  break;
	}

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  acl2_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = sw_if_index;
	  t->result = ar;
	  t->match = match;
	}

      next++;
      b++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  /*
   * if we were had an acl match then we have a counter to increment.
   * else it is all zeroes, so this will be harmless.
   */
  if (do_counters)
    vlib_increment_combined_counter (&ace_counters,
				     thread_index,
				     saved_matched_ace_index,
				     saved_packet_count, saved_byte_count);

  vlib_node_increment_counter (vm, node->node_index,
			       ACL2_ERROR_CHECK, frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index,
			       ACL2_ERROR_PERMIT, pkts_acl_permit);
  return frame->n_vectors;
}

always_inline uword
acl_switch (vlib_main_t * vm,
	    vlib_node_runtime_t * node,
	    vlib_frame_t * frame,
	    vlib_dir_t dir, vnet_link_t linkt, ip_address_family_t af)
{
  if (acl2_main.counters_enabled)
    return acl_switch_inline (vm, node, frame, dir, linkt, af, true);
  else
    return acl_switch_inline (vm, node, frame, dir, linkt, af, false);
}

static u8 *
format_acl2_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  acl2_trace_t *t = va_arg (*args, acl2_trace_t *);

  s = format (s, "acl2: match:%d sw_if_index:%d action:%U, match-ace:%d",
	      t->match, t->sw_if_index,
	      format_acl2_action, t->result.ar_action, t->result.ar_ace);

  return s;
}

VLIB_NODE_FN (acl_in_l2_ip6_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return acl_switch (vm, node, frame, VLIB_RX, VNET_LINK_ETHERNET, AF_IP6);
}

VLIB_NODE_FN (acl_in_l2_ip4_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return acl_switch (vm, node, frame, VLIB_RX, VNET_LINK_ETHERNET, AF_IP4);
}

VLIB_NODE_FN (acl_out_l2_ip6_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return acl_switch (vm, node, frame, VLIB_TX, VNET_LINK_ETHERNET, AF_IP6);
}

VLIB_NODE_FN (acl_out_l2_ip4_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return acl_switch (vm, node, frame, VLIB_TX, VNET_LINK_ETHERNET, AF_IP4);
}

/**** L3 processing path nodes ****/

VLIB_NODE_FN (acl_in_ip6_node) (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return acl_switch (vm, node, frame, VLIB_RX, VNET_LINK_IP6, AF_IP6);
}

VLIB_NODE_FN (acl_in_ip4_node) (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  return acl_switch (vm, node, frame, VLIB_RX, VNET_LINK_IP4, AF_IP4);
}

VLIB_NODE_FN (acl_out_ip6_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  return acl_switch (vm, node, frame, VLIB_TX, VNET_LINK_IP6, AF_IP6);
}

VLIB_NODE_FN (acl_out_ip4_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  return acl_switch (vm, node, frame, VLIB_TX, VNET_LINK_IP4, AF_IP4);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (acl_in_l2_ip6_node) =
{
  .name = "acl2-in-ip6-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl2_error_strings),
  .error_strings = acl2_error_strings,
  .n_next_nodes = ACL2_N_NEXT,
  .next_nodes = {
    [ACL2_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_in_l2_ip6_feature, static) =
{
  .arc_name = "l2-input-ip6",
  .node_name = "acl2-in-ip6-l2",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};

VLIB_REGISTER_NODE (acl_in_l2_ip4_node) =
{
  .name = "acl2-in-ip4-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl2_error_strings),
  .error_strings = acl2_error_strings,
  .n_next_nodes = ACL2_N_NEXT,
  .next_nodes = {
    [ACL2_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_in_l2_ip4_feature, static) =
{
  .arc_name = "l2-input-ip4",
  .node_name = "acl2-in-ip4-l2",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};

VLIB_REGISTER_NODE (acl_out_l2_ip6_node) =
{
  .name = "acl2-out-ip6-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl2_error_strings),
  .error_strings = acl2_error_strings,
  .n_next_nodes = ACL2_N_NEXT,
  .next_nodes =
  {
    [ACL2_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_out_l2_ip6_feature, static) =
{
  .arc_name = "l2-output-ip6",
  .node_name = "acl2-out-ip6-l2",
  .runs_before = VNET_FEATURES ("l2-output-feat-arc-end"),
};

VLIB_REGISTER_NODE (acl_out_l2_ip4_node) =
{
  .name = "acl2-out-ip4-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl2_error_strings),
  .error_strings = acl2_error_strings,
  .n_next_nodes = ACL2_N_NEXT,
  .next_nodes = {
    [ACL2_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_out_l2_ip4_feature, static) =
{
  .arc_name = "l2-output-ip4",
  .node_name = "acl2-out-ip4-l2",
  .runs_before = VNET_FEATURES ("l2-output-feat-arc-end"),
};

VLIB_REGISTER_NODE (acl_in_ip6_node) =
{
  .name = "acl2-in-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_acl2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl2_error_strings),
  .error_strings = acl2_error_strings,
  .n_next_nodes = ACL2_N_NEXT,
  .next_nodes = {
    [ACL2_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_in_ip6_feature, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "acl2-in-ip6",
  .runs_before = VNET_FEATURES ("ip6-flow-classify"),
};

VLIB_REGISTER_NODE (acl_in_ip4_node) =
{
  .name = "acl2-in-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_acl2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl2_error_strings),
  .error_strings = acl2_error_strings,
  .n_next_nodes = ACL2_N_NEXT,
  .next_nodes = {
    [ACL2_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_in_ip4_feature, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "acl2-in-ip4",
  .runs_before = VNET_FEATURES ("ip4-flow-classify"),
};

VLIB_REGISTER_NODE (acl_out_ip6_node) =
{
  .name = "acl2-out-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_acl2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl2_error_strings),
  .error_strings = acl2_error_strings,
  .n_next_nodes = ACL2_N_NEXT,
  .next_nodes = {
    [ACL2_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_out_ip6_feature, static) =
{
  .arc_name = "ip6-output",
  .node_name = "acl2-out-ip6",
  .runs_before = VNET_FEATURES ("interface-output"),
};

VLIB_REGISTER_NODE (acl_out_ip4_node) =
{
  .name = "acl2-out-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_acl2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl2_error_strings),
  .error_strings = acl2_error_strings,
  .n_next_nodes = ACL2_N_NEXT,
  .next_nodes = {
    [ACL2_ERROR_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (acl_out_ip4_feature, static) =
{
  .arc_name = "ip4-output",
  .node_name = "acl2-out-ip4",
  .runs_before = VNET_FEATURES ("interface-output"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
