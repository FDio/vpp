/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/adj/rewrite.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/adj/adj.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/punt.h>

typedef enum punt_next_t_
{
  PUNT_NEXT_DROP,
  PUNT_N_NEXT,
} punt_next_t;

typedef struct punt_trace_t_
{
  vlib_punt_reason_t pt_reason;
} punt_trace_t;

#define SW_IF_INDEX_PG0 1
#define SW_IF_INDEX_PG1 2

index_t *adjs[FIB_PROTOCOL_IP_MAX];

static vlib_punt_reason_t punt_reason_v4, punt_reason_v6;
static vlib_punt_hdl_t punt_hdl;

static u8 *
format_punt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  punt_trace_t *t = va_arg (*args, punt_trace_t *);

  s = format (s, "punt: %U", format_vlib_punt_reason, t->pt_reason);

  return s;
}

always_inline uword
punt_test_fwd (vlib_main_t * vm,
	       vlib_node_runtime_t * node,
	       vlib_frame_t * frame, fib_protocol_t fproto, u32 sw_if_index)
{
  u32 n_left_from, *from, *to_next, next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  ip_adjacency_t *adj0;
	  vlib_buffer_t *b0;
	  void *ip0;
	  index_t ai0;
	  u32 bi0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index;
	  ai0 = adjs[fproto][sw_if_index];

	  adj0 = adj_get (ai0);
	  ip0 = vlib_buffer_get_current (b0);

	  vlib_buffer_advance (b0, -adj0->rewrite_header.data_bytes);
	  vnet_rewrite_one_header (adj0[0], ip0, sizeof (ethernet_header_t));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0, 0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

always_inline uword
punt_test_pg0_ip4 (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (punt_test_fwd (vm, node, frame, FIB_PROTOCOL_IP4, SW_IF_INDEX_PG0));
}

always_inline uword
punt_test_pg1_ip4 (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (punt_test_fwd (vm, node, frame, FIB_PROTOCOL_IP4, SW_IF_INDEX_PG1));
}

always_inline uword
punt_test_pg0_ip6 (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (punt_test_fwd (vm, node, frame, FIB_PROTOCOL_IP6, SW_IF_INDEX_PG0));
}

always_inline uword
punt_test_pg1_ip6 (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (punt_test_fwd (vm, node, frame, FIB_PROTOCOL_IP6, SW_IF_INDEX_PG1));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (punt_test_pg0_ip4_node) = {
  .function = punt_test_pg0_ip4,
  .name = "punt-test-pg0-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_punt_trace,
};
VLIB_REGISTER_NODE (punt_test_pg1_ip4_node) = {
  .function = punt_test_pg1_ip4,
  .name = "punt-test-pg1-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_punt_trace,
};
VLIB_REGISTER_NODE (punt_test_pg0_ip6_node) = {
  .function = punt_test_pg0_ip6,
  .name = "punt-test-pg0-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_punt_trace,
};
VLIB_REGISTER_NODE (punt_test_pg1_ip6_node) = {
  .function = punt_test_pg1_ip6,
  .name = "punt-test-pg1-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_punt_trace,
};
/* *INDENT-ON* */

typedef struct punt_feat_trace_t_
{
  vlib_punt_reason_t pt_reason;
} punt_feat_trace_t;

always_inline uword
punt_test_feat_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * frame, u8 is_ip4)
{
  u32 n_left_from, *from, *to_next, next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 bi0, next0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  n_left_from -= 1;
	  next0 = 0;

	  b0 = vlib_get_buffer (vm, bi0);

	  if (is_ip4)
	    b0->punt_reason = punt_reason_v4;
	  else
	    b0->punt_reason = punt_reason_v6;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      punt_feat_trace_t *t;

	      b0 = vlib_get_buffer (vm, bi0);

	      t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->pt_reason = b0->punt_reason;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static u8 *
format_punt_feat_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  punt_feat_trace_t *t = va_arg (*args, punt_feat_trace_t *);

  s = format (s, "reason: %U", format_vlib_punt_reason, t->pt_reason);

  return s;
}

always_inline uword
punt_test_feat_ip4 (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (punt_test_feat_inline (vm, node, frame, 1));
}

always_inline uword
punt_test_feat_ip6 (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (punt_test_feat_inline (vm, node, frame, 0));
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (punt_test_feat_ip6_node) = {
  .function = punt_test_feat_ip6,
  .name = "punt-test-feat-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_punt_feat_trace,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "punt-dispatch"
  }
};
VLIB_REGISTER_NODE (punt_test_feat_ip4_node) = {
  .function = punt_test_feat_ip4,
  .name = "punt-test-feat-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_punt_feat_trace,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "punt-dispatch"
  }
};
VNET_FEATURE_INIT (punt_test_feat_ip6_feature, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "punt-test-feat-ip6",
};
VNET_FEATURE_INIT (punt_test_feat_ip4_feature, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "punt-test-feat-ip4",
};
/* *INDENT-ON* */

static clib_error_t *
punt_test (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  ip46_address_t ip46 = ip46_address_initializer;
  fib_protocol_t fproto;
  vnet_main_t *vnm;
  u32 sw_if_index;
  int rc;

  vnm = vnet_get_main ();
  fproto = FIB_PROTOCOL_IP4;

  if (unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      vlib_node_t *from;

      if (unformat (input, "%U", unformat_ip4_address, &ip46.ip4))
	{
	  fproto = FIB_PROTOCOL_IP4;
	}
      else if (unformat (input, "%U", unformat_ip6_address, &ip46.ip6))
	{
	  fproto = FIB_PROTOCOL_IP6;
	}
      else if (unformat (input, "clear"))
	{
	  vnet_feature_enable_disable ("ip4-unicast",
				       "punt-test-feat-ip4",
				       sw_if_index, 0, NULL, 0);
	  vnet_feature_enable_disable ("ip6-unicast",
				       "punt-test-feat-ip6",
				       sw_if_index, 0, NULL, 0);
	  return NULL;
	}
      else
	{
	  /*
	   * allocate a client and a reason
	   */
	  punt_hdl = vlib_punt_client_register ("test");

	  rc = vlib_punt_reason_alloc (
	    punt_hdl, "reason-v4", NULL, NULL, &punt_reason_v4,
	    VNET_PUNT_REASON_F_IP4_PACKET, format_vnet_punt_reason_flags);
	  rc |= vlib_punt_reason_alloc (
	    punt_hdl, "reason-v6", NULL, NULL, &punt_reason_v6,
	    VNET_PUNT_REASON_F_IP6_PACKET, format_vnet_punt_reason_flags);
	  ASSERT (!rc);

	  vnet_feature_enable_disable ("ip4-unicast",
				       "punt-test-feat-ip4",
				       sw_if_index, 1, NULL, 0);
	  vnet_feature_enable_disable ("ip6-unicast",
				       "punt-test-feat-ip6",
				       sw_if_index, 1, NULL, 0);
	  return NULL;
	}

      if (SW_IF_INDEX_PG0 == sw_if_index)
	{
	  if (FIB_PROTOCOL_IP4 == fproto)
	    {
	      /*
	       * register the node that will forward the punted packet
	       */
	      vlib_punt_register (punt_hdl, punt_reason_v4,
				  "punt-test-pg0-ip4");
	      from = vlib_get_node_by_name (vm, (u8 *) "punt-test-pg0-ip4");
	    }
	  else
	    {
	      vlib_punt_register (punt_hdl, punt_reason_v6,
				  "punt-test-pg0-ip6");
	      from = vlib_get_node_by_name (vm, (u8 *) "punt-test-pg0-ip6");
	    }
	}
      else
	{
	  if (FIB_PROTOCOL_IP4 == fproto)
	    {
	      vlib_punt_register (punt_hdl, punt_reason_v4,
				  "punt-test-pg1-ip4");
	      from = vlib_get_node_by_name (vm, (u8 *) "punt-test-pg1-ip4");
	    }
	  else
	    {
	      vlib_punt_register (punt_hdl, punt_reason_v6,
				  "punt-test-pg1-ip6");
	      from = vlib_get_node_by_name (vm, (u8 *) "punt-test-pg1-ip6");
	    }
	}

      vlib_node_add_next (vm, from->index,
			  vnet_tx_node_index_for_sw_interface
			  (vnm, sw_if_index));

      vec_validate (adjs[fproto], sw_if_index);

      adjs[fproto][sw_if_index] = adj_nbr_find (fproto,
						fib_proto_to_link (fproto),
						&ip46, sw_if_index);
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_fib_command, static) =
{
  .path = "test punt",
  .short_help = "punt unit tests - DO NOT RUN ON A LIVE SYSTEM",
  .function = punt_test,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
