/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * ip/ip4_source_check.c: IP v4 check source address (unicast RPF check)
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/ip/ip.h>

typedef struct {
  u8 packet_data[64];
} ip4_source_check_trace_t;

static u8 * format_ip4_source_check_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ip4_source_check_trace_t * t = va_arg (*va, ip4_source_check_trace_t *);

  s = format (s, "%U",
	      format_ip4_header,
	      t->packet_data, sizeof (t->packet_data));

  return s;
}

typedef enum {
  IP4_SOURCE_CHECK_NEXT_DROP,
  IP4_SOURCE_CHECK_N_NEXT,
} ip4_source_check_next_t;

typedef enum {
  IP4_SOURCE_CHECK_REACHABLE_VIA_RX,
  IP4_SOURCE_CHECK_REACHABLE_VIA_ANY,
} ip4_source_check_type_t;

typedef union {
  struct {
    u32 no_default_route : 1;
    u32 fib_index : 31;
  };
  u32 as_u32[1];
} ip4_source_check_config_t;

always_inline uword
ip4_source_check_inline (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * frame,
			 ip4_source_check_type_t source_check_type)
{
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_config_main_t * cm = &lm->rx_config_mains[VNET_UNICAST];
  u32 n_left_from, * from, * to_next;
  u32 next_index;
  vlib_node_runtime_t * error_node = vlib_node_get_runtime (vm, ip4_input_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (ip4_source_check_trace_t));

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t * p0, * p1;
	  ip4_header_t * ip0, * ip1;
	  ip4_fib_mtrie_t * mtrie0, * mtrie1;
	  ip4_fib_mtrie_leaf_t leaf0, leaf1;
	  ip4_source_check_config_t * c0, * c1;
	  ip_adjacency_t * adj0, * adj1;
	  u32 pi0, next0, pass0, adj_index0;
	  u32 pi1, next1, pass1, adj_index1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]), LOAD);
	    CLIB_PREFETCH (p3->data, sizeof (ip1[0]), LOAD);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  c0 = vnet_get_config_data (&cm->config_main,
				     &p0->current_config_index,
				     &next0,
				     sizeof (c0[0]));
	  c1 = vnet_get_config_data (&cm->config_main,
				     &p1->current_config_index,
				     &next1,
				     sizeof (c1[0]));

	  mtrie0 = &vec_elt_at_index (im->fibs, c0->fib_index)->mtrie;
	  mtrie1 = &vec_elt_at_index (im->fibs, c1->fib_index)->mtrie;

	  leaf0 = leaf1 = IP4_FIB_MTRIE_LEAF_ROOT;

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 0);
	  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, &ip1->src_address, 0);

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 1);
	  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, &ip1->src_address, 1);

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 2);
	  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, &ip1->src_address, 2);

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 3);
	  leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, &ip1->src_address, 3);

	  adj_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
	  adj_index1 = ip4_fib_mtrie_leaf_get_adj_index (leaf1);

	  ASSERT (adj_index0 == ip4_fib_lookup_with_table (im, c0->fib_index,
							   &ip0->src_address,
							   c0->no_default_route));
	  ASSERT (adj_index1 == ip4_fib_lookup_with_table (im, c1->fib_index,
							   &ip1->src_address,
							   c1->no_default_route));

	  adj0 = ip_get_adjacency (lm, adj_index0);
	  adj1 = ip_get_adjacency (lm, adj_index1);

	  /* Pass multicast. */
	  pass0 = ip4_address_is_multicast (&ip0->src_address) || ip0->src_address.as_u32 == clib_host_to_net_u32(0xFFFFFFFF);
	  pass1 = ip4_address_is_multicast (&ip1->src_address) || ip1->src_address.as_u32 == clib_host_to_net_u32(0xFFFFFFFF);

	  pass0 |= (adj0->lookup_next_index == IP_LOOKUP_NEXT_REWRITE
		    && (source_check_type == IP4_SOURCE_CHECK_REACHABLE_VIA_ANY
			|| vnet_buffer (p0)->sw_if_index[VLIB_RX] == adj0->rewrite_header.sw_if_index));
	  pass1 |= (adj1->lookup_next_index == IP_LOOKUP_NEXT_REWRITE
		    && (source_check_type == IP4_SOURCE_CHECK_REACHABLE_VIA_ANY
			|| vnet_buffer (p1)->sw_if_index[VLIB_RX] == adj1->rewrite_header.sw_if_index));

	  next0 = (pass0 ? next0 : IP4_SOURCE_CHECK_NEXT_DROP);
	  next1 = (pass1 ? next1 : IP4_SOURCE_CHECK_NEXT_DROP);

	  p0->error = error_node->errors[IP4_ERROR_UNICAST_SOURCE_CHECK_FAILS];
	  p1->error = error_node->errors[IP4_ERROR_UNICAST_SOURCE_CHECK_FAILS];

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}
    
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * p0;
	  ip4_header_t * ip0;
	  ip4_fib_mtrie_t * mtrie0;
	  ip4_fib_mtrie_leaf_t leaf0;
	  ip4_source_check_config_t * c0;
	  ip_adjacency_t * adj0;
	  u32 pi0, next0, pass0, adj_index0;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip0 = vlib_buffer_get_current (p0);

	  c0 = vnet_get_config_data (&cm->config_main,
				     &p0->current_config_index,
				     &next0,
				     sizeof (c0[0]));

	  mtrie0 = &vec_elt_at_index (im->fibs, c0->fib_index)->mtrie;

	  leaf0 = IP4_FIB_MTRIE_LEAF_ROOT;

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 0);

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 1);

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 2);

	  leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, &ip0->src_address, 3);

	  adj_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);

	  ASSERT (adj_index0 == ip4_fib_lookup_with_table (im, c0->fib_index,
							   &ip0->src_address,
							   c0->no_default_route));
	  adj0 = ip_get_adjacency (lm, adj_index0);

	  /* Pass multicast. */
	  pass0 = ip4_address_is_multicast (&ip0->src_address) || ip0->src_address.as_u32 == clib_host_to_net_u32(0xFFFFFFFF);

	  pass0 |= (adj0->lookup_next_index == IP_LOOKUP_NEXT_REWRITE
		    && (source_check_type == IP4_SOURCE_CHECK_REACHABLE_VIA_ANY
			|| vnet_buffer (p0)->sw_if_index[VLIB_RX] == adj0->rewrite_header.sw_if_index));

	  next0 = (pass0 ? next0 : IP4_SOURCE_CHECK_NEXT_DROP);
	  p0->error = error_node->errors[IP4_ERROR_UNICAST_SOURCE_CHECK_FAILS];

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static uword
ip4_source_check_reachable_via_any (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return ip4_source_check_inline (vm, node, frame, IP4_SOURCE_CHECK_REACHABLE_VIA_ANY);
}

static uword
ip4_source_check_reachable_via_rx (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return ip4_source_check_inline (vm, node, frame, IP4_SOURCE_CHECK_REACHABLE_VIA_RX);
}

VLIB_REGISTER_NODE (ip4_check_source_reachable_via_any) = {
  .function = ip4_source_check_reachable_via_any,
  .name = "ip4-source-check-via-any",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP4_SOURCE_CHECK_N_NEXT,
  .next_nodes = {
    [IP4_SOURCE_CHECK_NEXT_DROP] = "error-drop",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_source_check_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_check_source_reachable_via_any,
			      ip4_source_check_reachable_via_any)

VLIB_REGISTER_NODE (ip4_check_source_reachable_via_rx) = {
  .function = ip4_source_check_reachable_via_rx,
  .name = "ip4-source-check-via-rx",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP4_SOURCE_CHECK_N_NEXT,
  .next_nodes = {
    [IP4_SOURCE_CHECK_NEXT_DROP] = "error-drop",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_source_check_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_check_source_reachable_via_rx,
			      ip4_source_check_reachable_via_rx)

static clib_error_t *
set_ip_source_check (vlib_main_t * vm,
		     unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_config_main_t * rx_cm = &lm->rx_config_mains[VNET_UNICAST];
  clib_error_t * error = 0;
  u32 sw_if_index, is_del, ci;
  ip4_source_check_config_t config;
  u32 feature_index;

  sw_if_index = ~0;

  if (! unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  is_del = 0;
  config.no_default_route = 0;
  config.fib_index = im->fib_index_by_sw_if_index[sw_if_index];
  feature_index = im->ip4_unicast_rx_feature_source_reachable_via_rx;
  if (unformat (input, "del"))
    is_del = 1;

  ci = rx_cm->config_index_by_sw_if_index[sw_if_index];
  ci = (is_del
	? vnet_config_del_feature
	: vnet_config_add_feature)
    (vm, &rx_cm->config_main,
     ci,
     feature_index,
     &config,
     sizeof (config));
  rx_cm->config_index_by_sw_if_index[sw_if_index] = ci;

 done:
  return error;
}

VLIB_CLI_COMMAND (set_interface_ip_source_check_command, static) = {
  .path = "set interface ip source-check",
  .function = set_ip_source_check,
  .short_help = "Set IP4/IP6 interface unicast source check",
};

/* Dummy init function to get us linked in. */
clib_error_t * ip4_source_check_init (vlib_main_t * vm)
{ return 0; }

VLIB_INIT_FUNCTION (ip4_source_check_init);
