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

#include <vnet/punt/punt.h>
#include <vnet/adj/rewrite.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/adj/adj.h>
#include <vnet/ip/ip.h>

typedef enum punt_next_t_
{
  PUNT_NEXT_DROP,
  PUNT_N_NEXT,
} punt_next_t;

typedef struct punt_trace_t_
{
  vnet_punt_reason_t pt_reason;
} punt_trace_t;

/**
 * Per-thread clone vectors
 */
u32 **punt_clones;

#define SW_IF_INDEX_PG0 1
#define SW_IF_INDEX_PG1 2

index_t *adjs[FIB_PROTOCOL_IP_MAX];

static u8 *
format_punt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  punt_trace_t *t = va_arg (*args, punt_trace_t *);

  s = format (s, "punt: %U", format_vnet_punt_reason, t->pt_reason);

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

static clib_error_t *
punt_test (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  ip46_address_t ip46 = ip46_address_initializer;
  vnet_punt_reason_t r1, r2, r3, r4;
  fib_protocol_t fproto;
  vnet_punt_hdl_t h1, h2;
  u32 sw_if_index;
  vnet_main_t *vnm;

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
      else
	return clib_error_return (0, "Need next-hop IP address");

      if (SW_IF_INDEX_PG0 == sw_if_index)
	{
	  h1 = vnet_punt_client_register ("pg0");

	  if (FIB_PROTOCOL_IP4 == fproto)
	    {
	      vnet_punt_register (h1, VNET_PUNT_REASON_IP4_ACL_DENY,
				  "punt-test-pg0-ip4");
	      from = vlib_get_node_by_name (vm, (u8 *) "punt-test-pg0-ip4");
	    }
	  else
	    {
	      vnet_punt_register (h1, VNET_PUNT_REASON_IP6_ACL_DENY,
				  "punt-test-pg0-ip6");
	      from = vlib_get_node_by_name (vm, (u8 *) "punt-test-pg0-ip6");
	    }
	}
      else
	{
	  h1 = vnet_punt_client_register ("pg1");

	  if (FIB_PROTOCOL_IP4 == fproto)
	    {
	      vnet_punt_register (h1, VNET_PUNT_REASON_IP4_ACL_DENY,
				  "punt-test-pg1-ip4");
	      from = vlib_get_node_by_name (vm, (u8 *) "punt-test-pg1-ip4");
	    }
	  else
	    {
	      vnet_punt_register (h1, VNET_PUNT_REASON_IP6_ACL_DENY,
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
  else
    {
      int rc = 0;

      h2 = vnet_punt_client_register ("test2");

      vnet_punt_register (h2, VNET_PUNT_REASON_IP4_ACL_DENY, "mpls-lookup");
      vnet_punt_register (h2, VNET_PUNT_REASON_IP4_ACL_DENY, "ip6-lookup");
      vnet_punt_register (h2, VNET_PUNT_REASON_IP4_ACL_DENY, "ip4-lookup");

      rc |= vnet_punt_reason_alloc (h2, "reason1", &r1);
      rc |= vnet_punt_reason_alloc (h2, "reason2", &r2);
      rc |= vnet_punt_reason_alloc (h2, "reason3", &r3);
      rc |= vnet_punt_reason_alloc (h2, "reason4", &r4);

      ASSERT (rc == 0);

      vnet_punt_register (h2, r1, "ip4-rewrite");
      vnet_punt_register (h2, r2, "ip4-rewrite");
      vnet_punt_register (h2, r3, "ip4-rewrite");
      vnet_punt_register (h2, r1, "ip4-rewrite");
      vnet_punt_register (h2, r4, "ip6-rewrite");
      vnet_punt_unregister (h2, r4, "ip6-rewrite");
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
