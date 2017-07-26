/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *	   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_source_and_port_range_check.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>

/**
 * @file
 * @brief IPv4 Source and Port Range Checking.
 *
 * This file contains the source code for IPv4 source and port range
 * checking.
 */


/**
 * @brief The pool of range chack DPOs
 */
static protocol_port_range_dpo_t *ppr_dpo_pool;

/**
 * @brief Dynamically registered DPO type
 */
static dpo_type_t ppr_dpo_type;

vlib_node_registration_t ip4_source_port_and_range_check_rx;
vlib_node_registration_t ip4_source_port_and_range_check_tx;

#define foreach_ip4_source_and_port_range_check_error			\
  _(CHECK_FAIL, "ip4 source and port range check bad packets")	\
  _(CHECK_OK, "ip4 source and port range check good packets")

typedef enum
{
#define _(sym,str) IP4_SOURCE_AND_PORT_RANGE_CHECK_ERROR_##sym,
  foreach_ip4_source_and_port_range_check_error
#undef _
    IP4_SOURCE_AND_PORT_RANGE_CHECK_N_ERROR,
} ip4_source_and_port_range_check_error_t;

static char *ip4_source_and_port_range_check_error_strings[] = {
#define _(sym,string) string,
  foreach_ip4_source_and_port_range_check_error
#undef _
};

typedef struct
{
  u32 pass;
  u32 bypass;
  u32 is_tcp;
  ip4_address_t src_addr;
  u16 port;
  u32 fib_index;
} ip4_source_and_port_range_check_trace_t;

static u8 *
format_ip4_source_and_port_range_check_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ip4_source_and_port_range_check_trace_t *t =
    va_arg (*va, ip4_source_and_port_range_check_trace_t *);

  if (t->bypass)
    s = format (s, "PASS (bypass case)");
  else
    s = format (s, "fib %d src ip %U %s dst port %d: %s",
		t->fib_index, format_ip4_address, &t->src_addr,
		t->is_tcp ? "TCP" : "UDP", (u32) t->port,
		(t->pass == 1) ? "PASS" : "FAIL");
  return s;
}

typedef enum
{
  IP4_SOURCE_AND_PORT_RANGE_CHECK_NEXT_DROP,
  IP4_SOURCE_AND_PORT_RANGE_CHECK_N_NEXT,
} ip4_source_and_port_range_check_next_t;


static inline u32
check_adj_port_range_x1 (const protocol_port_range_dpo_t * ppr_dpo,
			 u16 dst_port, u32 next)
{
  u16x8vec_t key;
  u16x8vec_t diff1;
  u16x8vec_t diff2;
  u16x8vec_t sum, sum_equal_diff2;
  u16 sum_nonzero, sum_equal, winner_mask;
  int i;

  if (NULL == ppr_dpo || dst_port == 0)
    return IP4_SOURCE_AND_PORT_RANGE_CHECK_NEXT_DROP;

  /* Make the obvious screw-case work. A variant also works w/ no MMX */
  if (PREDICT_FALSE (dst_port == 65535))
    {
      int j;

      for (i = 0;
	   i < VLIB_BUFFER_PRE_DATA_SIZE / sizeof (protocol_port_range_t);
	   i++)
	{
	  for (j = 0; j < 8; j++)
	    if (ppr_dpo->blocks[i].low.as_u16[j] == 65535)
	      return next;
	}
      return IP4_SOURCE_AND_PORT_RANGE_CHECK_NEXT_DROP;
    }

  key.as_u16x8 = u16x8_splat (dst_port);

  for (i = 0; i < ppr_dpo->n_used_blocks; i++)
    {
      diff1.as_u16x8 =
	u16x8_sub_saturate (ppr_dpo->blocks[i].low.as_u16x8, key.as_u16x8);
      diff2.as_u16x8 =
	u16x8_sub_saturate (ppr_dpo->blocks[i].hi.as_u16x8, key.as_u16x8);
      sum.as_u16x8 = u16x8_add (diff1.as_u16x8, diff2.as_u16x8);
      sum_equal_diff2.as_u16x8 =
	u16x8_is_equal (sum.as_u16x8, diff2.as_u16x8);
      sum_nonzero = ~u16x8_zero_byte_mask (sum.as_u16x8);
      sum_equal = ~u16x8_zero_byte_mask (sum_equal_diff2.as_u16x8);
      winner_mask = sum_nonzero & sum_equal;
      if (winner_mask)
	return next;
    }
  return IP4_SOURCE_AND_PORT_RANGE_CHECK_NEXT_DROP;
}

always_inline protocol_port_range_dpo_t *
protocol_port_range_dpo_get (index_t index)
{
  return (pool_elt_at_index (ppr_dpo_pool, index));
}

always_inline uword
ip4_source_and_port_range_check_inline (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame, int is_tx)
{
  ip4_main_t *im = &ip4_main;
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  vlib_node_runtime_t *error_node = node;
  u32 good_packets = 0;
  int i;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);


      /*     while (n_left_from >= 4 && n_left_to_next >= 2) */
      /*       { */
      /*         vlib_buffer_t *b0, *b1; */
      /*         ip4_header_t *ip0, *ip1; */
      /*         ip4_fib_mtrie_t *mtrie0, *mtrie1; */
      /*         ip4_fib_mtrie_leaf_t leaf0, leaf1; */
      /*         ip_source_and_port_range_check_config_t *c0, *c1; */
      /*         ip_adjacency_t *adj0 = 0, *adj1 = 0; */
      /*         u32 bi0, next0, adj_index0, pass0, save_next0, fib_index0; */
      /*         u32 bi1, next1, adj_index1, pass1, save_next1, fib_index1; */
      /*         udp_header_t *udp0, *udp1; */

      /*         /\* Prefetch next iteration. *\/ */
      /*         { */
      /*           vlib_buffer_t *p2, *p3; */

      /*           p2 = vlib_get_buffer (vm, from[2]); */
      /*           p3 = vlib_get_buffer (vm, from[3]); */

      /*           vlib_prefetch_buffer_header (p2, LOAD); */
      /*           vlib_prefetch_buffer_header (p3, LOAD); */

      /*           CLIB_PREFETCH (p2->data, sizeof (ip0[0]), LOAD); */
      /*           CLIB_PREFETCH (p3->data, sizeof (ip1[0]), LOAD); */
      /*         } */

      /*         bi0 = to_next[0] = from[0]; */
      /*         bi1 = to_next[1] = from[1]; */
      /*         from += 2; */
      /*         to_next += 2; */
      /*         n_left_from -= 2; */
      /*         n_left_to_next -= 2; */

      /*         b0 = vlib_get_buffer (vm, bi0); */
      /*         b1 = vlib_get_buffer (vm, bi1); */

      /*         fib_index0 = */
      /*           vec_elt (im->fib_index_by_sw_if_index, */
      /*                 vnet_buffer (b0)->sw_if_index[VLIB_RX]); */
      /*         fib_index1 = */
      /*           vec_elt (im->fib_index_by_sw_if_index, */
      /*                 vnet_buffer (b1)->sw_if_index[VLIB_RX]); */

      /*         ip0 = vlib_buffer_get_current (b0); */
      /*         ip1 = vlib_buffer_get_current (b1); */

      /*         if (is_tx) */
      /*           { */
      /*             c0 = vnet_get_config_data (&tx_cm->config_main, */
      /*                                     &b0->current_config_index, */
      /*                                     &next0, sizeof (c0[0])); */
      /*             c1 = vnet_get_config_data (&tx_cm->config_main, */
      /*                                     &b1->current_config_index, */
      /*                                     &next1, sizeof (c1[0])); */
      /*           } */
      /*         else */
      /*           { */
      /*             c0 = vnet_get_config_data (&rx_cm->config_main, */
      /*                                     &b0->current_config_index, */
      /*                                     &next0, sizeof (c0[0])); */
      /*             c1 = vnet_get_config_data (&rx_cm->config_main, */
      /*                                     &b1->current_config_index, */
      /*                                     &next1, sizeof (c1[0])); */
      /*           } */

      /*         /\* we can't use the default VRF here... *\/ */
      /*         for (i = 0; i < IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS; i++) */
      /*           { */
      /*             ASSERT (c0->fib_index[i] && c1->fib_index[i]); */
      /*           } */


      /*         if (is_tx) */
      /*           { */
      /*             if (ip0->protocol == IP_PROTOCOL_UDP) */
      /*            fib_index0 = */
      /*              c0->fib_index */
      /*              [IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_IN]; */
      /*             if (ip0->protocol == IP_PROTOCOL_TCP) */
      /*            fib_index0 = */
      /*              c0->fib_index */
      /*              [IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_IN]; */
      /*           } */
      /*         else */
      /*           { */
      /*             if (ip0->protocol == IP_PROTOCOL_UDP) */
      /*            fib_index0 = */
      /*              c0->fib_index */
      /*              [IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_OUT]; */
      /*             if (ip0->protocol == IP_PROTOCOL_TCP) */
      /*            fib_index0 = */
      /*              c0->fib_index */
      /*              [IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_OUT]; */
      /*           } */

      /*         if (PREDICT_TRUE (fib_index0 != ~0)) */
      /*           { */

      /*             mtrie0 = &vec_elt_at_index (im->fibs, fib_index0)->mtrie; */

      /*             leaf0 = IP4_FIB_MTRIE_LEAF_ROOT; */

      /*             leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, */
      /*                                             &ip0->src_address, 0); */

      /*             leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, */
      /*                                             &ip0->src_address, 1); */

      /*             leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, */
      /*                                             &ip0->src_address, 2); */

      /*             leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, */
      /*                                             &ip0->src_address, 3); */

      /*             adj_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0); */

      /*             ASSERT (adj_index0 == ip4_fib_lookup_with_table (im, fib_index0, */
      /*                                                           &ip0->src_address, */
      /*                                                           0 */
      /*                                                           /\* use dflt rt *\/ */
      /*                  )); */
      /*             adj0 = ip_get_adjacency (lm, adj_index0); */
      /*           } */

      /*         if (is_tx) */
      /*           { */
      /*             if (ip1->protocol == IP_PROTOCOL_UDP) */
      /*            fib_index1 = */
      /*              c1->fib_index */
      /*              [IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_IN]; */
      /*             if (ip1->protocol == IP_PROTOCOL_TCP) */
      /*            fib_index1 = */
      /*              c1->fib_index */
      /*              [IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_IN]; */
      /*           } */
      /*         else */
      /*           { */
      /*             if (ip1->protocol == IP_PROTOCOL_UDP) */
      /*            fib_index1 = */
      /*              c1->fib_index */
      /*              [IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_OUT]; */
      /*             if (ip1->protocol == IP_PROTOCOL_TCP) */
      /*            fib_index1 = */
      /*              c1->fib_index */
      /*              [IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_OUT]; */
      /*           } */

      /*         if (PREDICT_TRUE (fib_index1 != ~0)) */
      /*           { */

      /*             mtrie1 = &vec_elt_at_index (im->fibs, fib_index1)->mtrie; */

      /*             leaf1 = IP4_FIB_MTRIE_LEAF_ROOT; */

      /*             leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, */
      /*                                             &ip1->src_address, 0); */

      /*             leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, */
      /*                                             &ip1->src_address, 1); */

      /*             leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, */
      /*                                             &ip1->src_address, 2); */

      /*             leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, */
      /*                                             &ip1->src_address, 3); */

      /*             adj_index1 = ip4_fib_mtrie_leaf_get_adj_index (leaf1); */

      /*             ASSERT (adj_index1 == ip4_fib_lookup_with_table (im, fib_index1, */
      /*                                                           &ip1->src_address, */
      /*                                                           0)); */
      /*             adj1 = ip_get_adjacency (lm, adj_index1); */
      /*           } */

      /*         pass0 = 0; */
      /*         pass0 |= adj0 == 0; */
      /*         pass0 |= ip4_address_is_multicast (&ip0->src_address); */
      /*         pass0 |= */
      /*           ip0->src_address.as_u32 == clib_host_to_net_u32 (0xFFFFFFFF); */
      /*         pass0 |= (ip0->protocol != IP_PROTOCOL_UDP) */
      /*           && (ip0->protocol != IP_PROTOCOL_TCP); */

      /*         pass1 = 0; */
      /*         pass1 |= adj1 == 0; */
      /*         pass1 |= ip4_address_is_multicast (&ip1->src_address); */
      /*         pass1 |= */
      /*           ip1->src_address.as_u32 == clib_host_to_net_u32 (0xFFFFFFFF); */
      /*         pass1 |= (ip1->protocol != IP_PROTOCOL_UDP) */
      /*           && (ip1->protocol != IP_PROTOCOL_TCP); */

      /*         save_next0 = next0; */
      /*         udp0 = ip4_next_header (ip0); */
      /*         save_next1 = next1; */
      /*         udp1 = ip4_next_header (ip1); */

      /*         if (PREDICT_TRUE (pass0 == 0)) */
      /*           { */
      /*             good_packets++; */
      /*             next0 = check_adj_port_range_x1 */
      /*            (adj0, clib_net_to_host_u16 (udp0->dst_port), next0); */
      /*             good_packets -= (save_next0 != next0); */
      /*             b0->error = error_node->errors */
      /*            [IP4_SOURCE_AND_PORT_RANGE_CHECK_ERROR_CHECK_FAIL]; */
      /*           } */

      /*         if (PREDICT_TRUE (pass1 == 0)) */
      /*           { */
      /*             good_packets++; */
      /*             next1 = check_adj_port_range_x1 */
      /*            (adj1, clib_net_to_host_u16 (udp1->dst_port), next1); */
      /*             good_packets -= (save_next1 != next1); */
      /*             b1->error = error_node->errors */
      /*            [IP4_SOURCE_AND_PORT_RANGE_CHECK_ERROR_CHECK_FAIL]; */
      /*           } */

      /*         if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) */
      /*                         && (b0->flags & VLIB_BUFFER_IS_TRACED))) */
      /*           { */
      /*             ip4_source_and_port_range_check_trace_t *t = */
      /*            vlib_add_trace (vm, node, b0, sizeof (*t)); */
      /*             t->pass = next0 == save_next0; */
      /*             t->bypass = pass0; */
      /*             t->fib_index = fib_index0; */
      /*             t->src_addr.as_u32 = ip0->src_address.as_u32; */
      /*             t->port = (pass0 == 0) ? */
      /*            clib_net_to_host_u16 (udp0->dst_port) : 0; */
      /*             t->is_tcp = ip0->protocol == IP_PROTOCOL_TCP; */
      /*           } */

      /*         if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) */
      /*                         && (b1->flags & VLIB_BUFFER_IS_TRACED))) */
      /*           { */
      /*             ip4_source_and_port_range_check_trace_t *t = */
      /*            vlib_add_trace (vm, node, b1, sizeof (*t)); */
      /*             t->pass = next1 == save_next1; */
      /*             t->bypass = pass1; */
      /*             t->fib_index = fib_index1; */
      /*             t->src_addr.as_u32 = ip1->src_address.as_u32; */
      /*             t->port = (pass1 == 0) ? */
      /*            clib_net_to_host_u16 (udp1->dst_port) : 0; */
      /*             t->is_tcp = ip1->protocol == IP_PROTOCOL_TCP; */
      /*           } */

      /*         vlib_validate_buffer_enqueue_x2 (vm, node, next_index, */
      /*                                       to_next, n_left_to_next, */
      /*                                       bi0, bi1, next0, next1); */
      /*       } */

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  ip4_header_t *ip0;
	  ip_source_and_port_range_check_config_t *c0;
	  u32 bi0, next0, lb_index0, pass0, save_next0, fib_index0;
	  udp_header_t *udp0;
	  const protocol_port_range_dpo_t *ppr_dpo0 = NULL;
	  const dpo_id_t *dpo;
	  u32 sw_if_index0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  fib_index0 = vec_elt (im->fib_index_by_sw_if_index, sw_if_index0);

	  if (is_tx)
	    vlib_buffer_advance (b0, sizeof (ethernet_header_t));

	  ip0 = vlib_buffer_get_current (b0);

	  c0 = vnet_feature_next_with_data (sw_if_index0, &next0,
					    b0, sizeof (c0[0]));

	  /* we can't use the default VRF here... */
	  for (i = 0; i < IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS; i++)
	    {
	      ASSERT (c0->fib_index[i]);
	    }


	  if (is_tx)
	    {
	      if (ip0->protocol == IP_PROTOCOL_UDP)
		fib_index0 =
		  c0->fib_index
		  [IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_IN];
	      if (ip0->protocol == IP_PROTOCOL_TCP)
		fib_index0 =
		  c0->fib_index
		  [IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_IN];
	    }
	  else
	    {
	      if (ip0->protocol == IP_PROTOCOL_UDP)
		fib_index0 =
		  c0->fib_index
		  [IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_OUT];
	      if (ip0->protocol == IP_PROTOCOL_TCP)
		fib_index0 =
		  c0->fib_index
		  [IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_OUT];
	    }

	  if (fib_index0 != ~0)
	    {
	      lb_index0 = ip4_fib_forwarding_lookup (fib_index0,
						     &ip0->src_address);

	      dpo =
		load_balance_get_bucket_i (load_balance_get (lb_index0), 0);

	      if (ppr_dpo_type == dpo->dpoi_type)
		{
		  ppr_dpo0 = protocol_port_range_dpo_get (dpo->dpoi_index);
		}
	      /*
	       * else the lookup hit an enty that was no inserted
	       * by this range checker, which is the default route
	       */
	    }
	  /*
	   * $$$ which (src,dst) categories should we always pass?
	   */
	  pass0 = 0;
	  pass0 |= ip4_address_is_multicast (&ip0->src_address);
	  pass0 |=
	    ip0->src_address.as_u32 == clib_host_to_net_u32 (0xFFFFFFFF);
	  pass0 |= (ip0->protocol != IP_PROTOCOL_UDP)
	    && (ip0->protocol != IP_PROTOCOL_TCP);

	  save_next0 = next0;
	  udp0 = ip4_next_header (ip0);

	  if (PREDICT_TRUE (pass0 == 0))
	    {
	      good_packets++;
	      next0 = check_adj_port_range_x1
		(ppr_dpo0, clib_net_to_host_u16 (udp0->dst_port), next0);
	      good_packets -= (save_next0 != next0);
	      b0->error = error_node->errors
		[IP4_SOURCE_AND_PORT_RANGE_CHECK_ERROR_CHECK_FAIL];
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      ip4_source_and_port_range_check_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->pass = next0 == save_next0;
	      t->bypass = pass0;
	      t->fib_index = fib_index0;
	      t->src_addr.as_u32 = ip0->src_address.as_u32;
	      t->port = (pass0 == 0) ?
		clib_net_to_host_u16 (udp0->dst_port) : 0;
	      t->is_tcp = ip0->protocol == IP_PROTOCOL_TCP;
	    }

	  if (is_tx)
	    vlib_buffer_advance (b0, -sizeof (ethernet_header_t));

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (is_tx)
    vlib_node_increment_counter (vm, ip4_source_port_and_range_check_tx.index,
				 IP4_SOURCE_AND_PORT_RANGE_CHECK_ERROR_CHECK_OK,
				 good_packets);
  else
    vlib_node_increment_counter (vm, ip4_source_port_and_range_check_rx.index,
				 IP4_SOURCE_AND_PORT_RANGE_CHECK_ERROR_CHECK_OK,
				 good_packets);
  return frame->n_vectors;
}

static uword
ip4_source_and_port_range_check_rx (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return ip4_source_and_port_range_check_inline (vm, node, frame,
						 0 /* !is_tx */ );
}

static uword
ip4_source_and_port_range_check_tx (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return ip4_source_and_port_range_check_inline (vm, node, frame,
						 1 /* is_tx */ );
}

/* Note: Calling same function for both RX and TX nodes
   as always checking dst_port, although
   if this changes can easily make new function
*/

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_source_port_and_range_check_rx) = {
  .function = ip4_source_and_port_range_check_rx,
  .name = "ip4-source-and-port-range-check-rx",
  .vector_size = sizeof (u32),

  .n_errors = ARRAY_LEN(ip4_source_and_port_range_check_error_strings),
  .error_strings = ip4_source_and_port_range_check_error_strings,

  .n_next_nodes = IP4_SOURCE_AND_PORT_RANGE_CHECK_N_NEXT,
  .next_nodes = {
    [IP4_SOURCE_AND_PORT_RANGE_CHECK_NEXT_DROP] = "error-drop",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_source_and_port_range_check_trace,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_source_port_and_range_check_tx) = {
  .function = ip4_source_and_port_range_check_tx,
  .name = "ip4-source-and-port-range-check-tx",
  .vector_size = sizeof (u32),

  .n_errors = ARRAY_LEN(ip4_source_and_port_range_check_error_strings),
  .error_strings = ip4_source_and_port_range_check_error_strings,

  .n_next_nodes = IP4_SOURCE_AND_PORT_RANGE_CHECK_N_NEXT,
  .next_nodes = {
    [IP4_SOURCE_AND_PORT_RANGE_CHECK_NEXT_DROP] = "error-drop",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_source_and_port_range_check_trace,
};
/* *INDENT-ON* */

int
set_ip_source_and_port_range_check (vlib_main_t * vm,
				    u32 * fib_index,
				    u32 sw_if_index, u32 is_add)
{
  ip_source_and_port_range_check_config_t config;
  int rv = 0;
  int i;

  for (i = 0; i < IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS; i++)
    {
      config.fib_index[i] = fib_index[i];
    }

  /* For OUT we are in the RX path */
  if ((fib_index[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_OUT] != ~0) ||
      (fib_index[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_OUT] != ~0))
    {
      vnet_feature_enable_disable ("ip4-unicast",
				   "ip4-source-and-port-range-check-rx",
				   sw_if_index, is_add, &config,
				   sizeof (config));
    }

  /* For IN we are in the TX path */
  if ((fib_index[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_IN] != ~0) ||
      (fib_index[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_IN] != ~0))
    {
      vnet_feature_enable_disable ("ip4-output",
				   "ip4-source-and-port-range-check-tx",
				   sw_if_index, is_add, &config,
				   sizeof (config));
    }
  return rv;
}

static clib_error_t *
set_ip_source_and_port_range_check_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  ip4_main_t *im = &ip4_main;
  clib_error_t *error = 0;
  u8 is_add = 1;
  u32 sw_if_index = ~0;
  u32 vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS];
  u32 fib_index[IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS];
  int vrf_set = 0;
  uword *p;
  int rv = 0;
  int i;

  sw_if_index = ~0;
  for (i = 0; i < IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS; i++)
    {
      fib_index[i] = ~0;
      vrf_id[i] = ~0;
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	;
      else
	if (unformat
	    (input, "tcp-out-vrf %d",
	     &vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_OUT]))
	vrf_set = 1;
      else
	if (unformat
	    (input, "udp-out-vrf %d",
	     &vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_OUT]))
	vrf_set = 1;
      else
	if (unformat
	    (input, "tcp-in-vrf %d",
	     &vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_TCP_IN]))
	vrf_set = 1;
      else
	if (unformat
	    (input, "udp-in-vrf %d",
	     &vrf_id[IP_SOURCE_AND_PORT_RANGE_CHECK_PROTOCOL_UDP_IN]))
	vrf_set = 1;
      else if (unformat (input, "del"))
	is_add = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface required but not specified");

  if (!vrf_set)
    return clib_error_return (0,
			      "TCP or UDP VRF ID required but not specified");

  for (i = 0; i < IP_SOURCE_AND_PORT_RANGE_CHECK_N_PROTOCOLS; i++)
    {

      if (vrf_id[i] == 0)
	return clib_error_return (0,
				  "TCP, UDP VRF ID should not be 0 (default). Should be distinct VRF for this purpose. ");

      if (vrf_id[i] != ~0)
	{
	  p = hash_get (im->fib_index_by_table_id, vrf_id[i]);

	  if (p == 0)
	    return clib_error_return (0, "Invalid VRF ID %d", vrf_id[i]);

	  fib_index[i] = p[0];
	}
    }
  rv =
    set_ip_source_and_port_range_check (vm, fib_index, sw_if_index, is_add);

  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return
	(0,
	 "set source and port-range on interface returned an unexpected value: %d",
	 rv);
    }
  return error;
}

/*?
 * Add the 'ip4-source-and-port-range-check-rx' or
 * 'ip4-source-and-port-range-check-tx' graph node for a given
 * interface. 'tcp-out-vrf' and 'udp-out-vrf' will add to
 * the RX path. 'tcp-in-vrf' and 'udp-in-vrf' will add to
 * the TX path. A graph node will be inserted into the chain when
 * the range check is added to the first interface. It will not
 * be removed from when range check is removed from the last
 * interface.
 *
 * By adding the range check graph node to the interface, incoming
 * or outgoing TCP/UDP packets will be validated using the
 * provided IPv4 FIB table (VRF).
 *
 * @note 'ip4-source-and-port-range-check-rx' and
 * 'ip4-source-and-port-range-check-tx' strings are too long, so
 * they are truncated on the 'show vlib graph' output.
 *
 * @todo This content needs to be validated and potentially more detail added.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before range checking is enabled:
 * @cliexstart{show vlib graph ip4-source-and-port-range-check-tx}
 *            Name                      Next                    Previous
 * ip4-source-and-port-range-      error-drop [0]
 * @cliexend
 *
 * Example of how to enable range checking on TX:
 * @cliexcmd{set interface ip source-and-port-range-check GigabitEthernet2/0/0 udp-in-vrf 7}
 *
 * Example of graph node after range checking is enabled:
 * @cliexstart{show vlib graph ip4-source-and-port-range-check-tx}
 *            Name                      Next                    Previous
 * ip4-source-and-port-range-      error-drop [0]              ip4-rewrite
 *                              interface-output [1]
 * @cliexend
 *
 * Example of how to display the features enabed on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 *
 * ipv4 unicast:
 *   ip4-source-and-port-range-check-rx
 *   ip4-lookup
 *
 * ipv4 multicast:
 *   ip4-lookup-multicast
 *
 * ipv4 multicast:
 *   interface-output
 *
 * ipv6 unicast:
 *   ip6-lookup
 *
 * ipv6 multicast:
 *   ip6-lookup
 *
 * ipv6 multicast:
 *   interface-output
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip_source_and_port_range_check_command, static) = {
  .path = "set interface ip source-and-port-range-check",
  .function = set_ip_source_and_port_range_check_fn,
  .short_help = "set interface ip source-and-port-range-check <interface> [tcp-out-vrf <table-id>] [udp-out-vrf <table-id>] [tcp-in-vrf <table-id>] [udp-in-vrf <table-id>] [del]",
};
/* *INDENT-ON* */

static u8 *
format_ppr_dpo (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  protocol_port_range_dpo_t *ppr_dpo;
  int i, j;
  int printed = 0;

  ppr_dpo = protocol_port_range_dpo_get (index);

  s = format (s, "allow ");

  for (i = 0; i < ppr_dpo->n_used_blocks; i++)
    {
      for (j = 0; j < 8; j++)
	{
	  if (ppr_dpo->blocks[i].low.as_u16[j])
	    {
	      if (printed)
		s = format (s, ", ");
	      if (ppr_dpo->blocks[i].hi.as_u16[j] >
		  (ppr_dpo->blocks[i].low.as_u16[j] + 1))
		s =
		  format (s, "%d-%d", (u32) ppr_dpo->blocks[i].low.as_u16[j],
			  (u32) ppr_dpo->blocks[i].hi.as_u16[j] - 1);
	      else
		s = format (s, "%d", ppr_dpo->blocks[i].low.as_u16[j]);
	      printed = 1;
	    }
	}
    }
  return s;
}

static void
ppr_dpo_lock (dpo_id_t * dpo)
{
}

static void
ppr_dpo_unlock (dpo_id_t * dpo)
{
}

const static dpo_vft_t ppr_vft = {
  .dv_lock = ppr_dpo_lock,
  .dv_unlock = ppr_dpo_unlock,
  .dv_format = format_ppr_dpo,
};

const static char *const ppr_ip4_nodes[] = {
  "ip4-source-and-port-range-check-rx",
  NULL,
};

const static char *const *const ppr_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = ppr_ip4_nodes,
};

clib_error_t *
ip4_source_and_port_range_check_init (vlib_main_t * vm)
{
  source_range_check_main_t *srm = &source_range_check_main;

  srm->vlib_main = vm;
  srm->vnet_main = vnet_get_main ();

  ppr_dpo_type = dpo_register_new_type (&ppr_vft, ppr_nodes);

  return 0;
}

VLIB_INIT_FUNCTION (ip4_source_and_port_range_check_init);

protocol_port_range_dpo_t *
protocol_port_range_dpo_alloc (void)
{
  protocol_port_range_dpo_t *ppr_dpo;

  pool_get_aligned (ppr_dpo_pool, ppr_dpo, CLIB_CACHE_LINE_BYTES);
  memset (ppr_dpo, 0, sizeof (*ppr_dpo));

  ppr_dpo->n_free_ranges = N_PORT_RANGES_PER_DPO;

  return (ppr_dpo);
}


static int
add_port_range_adjacency (u32 fib_index,
			  ip4_address_t * address,
			  u32 length, u16 * low_ports, u16 * high_ports)
{
  protocol_port_range_dpo_t *ppr_dpo;
  dpo_id_t dpop = DPO_INVALID;
  int i, j, k;

  fib_node_index_t fei;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = length,
    .fp_addr = {
		.ip4 = *address,
		},
  };

  /*
   * check to see if we have already sourced this prefix
   */
  fei = fib_table_lookup_exact_match (fib_index, &pfx);

  if (FIB_NODE_INDEX_INVALID == fei)
    {
      /*
       * this is a first time add for this prefix.
       */
      ppr_dpo = protocol_port_range_dpo_alloc ();
    }
  else
    {
      /*
       * the prefix is already there.
       * check it was sourced by us, and if so get the ragne DPO from it.
       */
      dpo_id_t dpo = DPO_INVALID;
      const dpo_id_t *bucket;

      if (fib_entry_get_dpo_for_source (fei, FIB_SOURCE_SPECIAL, &dpo))
	{
	  /*
	   * there is existing state. we'll want to add the new ranges to it
	   */
	  bucket =
	    load_balance_get_bucket_i (load_balance_get (dpo.dpoi_index), 0);
	  ppr_dpo = protocol_port_range_dpo_get (bucket->dpoi_index);
	  dpo_reset (&dpo);
	}
      else
	{
	  /*
	   * there is no PPR state associated with this prefix,
	   * so we'll need a new DPO
	   */
	  ppr_dpo = protocol_port_range_dpo_alloc ();
	}
    }

  if (vec_len (low_ports) > ppr_dpo->n_free_ranges)
    return VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY;

  j = k = 0;

  for (i = 0; i < vec_len (low_ports); i++)
    {
      for (; j < N_BLOCKS_PER_DPO; j++)
	{
	  for (; k < 8; k++)
	    {
	      if (ppr_dpo->blocks[j].low.as_u16[k] == 0)
		{
		  ppr_dpo->blocks[j].low.as_u16[k] = low_ports[i];
		  ppr_dpo->blocks[j].hi.as_u16[k] = high_ports[i];
		  goto doublebreak;
		}
	    }
	}
    doublebreak:;
    }
  ppr_dpo->n_used_blocks = j + 1;

  /*
   * add or update the entry in the FIB
   */
  dpo_set (&dpop, ppr_dpo_type, DPO_PROTO_IP4, (ppr_dpo - ppr_dpo_pool));

  if (FIB_NODE_INDEX_INVALID == fei)
    {
      fib_table_entry_special_dpo_add (fib_index,
				       &pfx,
				       FIB_SOURCE_SPECIAL,
				       FIB_ENTRY_FLAG_NONE, &dpop);
    }
  else
    {
      fib_entry_special_update (fei,
				FIB_SOURCE_SPECIAL,
				FIB_ENTRY_FLAG_NONE, &dpop);
    }

  return 0;
}

static int
remove_port_range_adjacency (u32 fib_index,
			     ip4_address_t * address,
			     u32 length, u16 * low_ports, u16 * high_ports)
{
  protocol_port_range_dpo_t *ppr_dpo;
  fib_node_index_t fei;
  int i, j, k;

  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = length,
    .fp_addr = {
		.ip4 = *address,
		},
  };

  /*
   * check to see if we have sourced this prefix
   */
  fei = fib_table_lookup_exact_match (fib_index, &pfx);

  if (FIB_NODE_INDEX_INVALID == fei)
    {
      /*
       * not one of ours
       */
      return VNET_API_ERROR_INCORRECT_ADJACENCY_TYPE;
    }
  else
    {
      /*
       * the prefix is already there.
       * check it was sourced by us
       */
      dpo_id_t dpo = DPO_INVALID;
      const dpo_id_t *bucket;

      if (fib_entry_get_dpo_for_source (fei, FIB_SOURCE_SPECIAL, &dpo))
	{
	  /*
	   * there is existing state. we'll want to add the new ranges to it
	   */
	  bucket =
	    load_balance_get_bucket_i (load_balance_get (dpo.dpoi_index), 0);
	  ppr_dpo = protocol_port_range_dpo_get (bucket->dpoi_index);
	  dpo_reset (&dpo);
	}
      else
	{
	  /*
	   * not one of ours
	   */
	  return VNET_API_ERROR_INCORRECT_ADJACENCY_TYPE;
	}
    }

  for (i = 0; i < vec_len (low_ports); i++)
    {
      for (j = 0; j < N_BLOCKS_PER_DPO; j++)
	{
	  for (k = 0; k < 8; k++)
	    {
	      if (low_ports[i] == ppr_dpo->blocks[j].low.as_u16[k] &&
		  high_ports[i] == ppr_dpo->blocks[j].hi.as_u16[k])
		{
		  ppr_dpo->blocks[j].low.as_u16[k] =
		    ppr_dpo->blocks[j].hi.as_u16[k] = 0;
		  goto doublebreak;
		}
	    }
	}
    doublebreak:;
    }

  ppr_dpo->n_free_ranges = 0;

  /* Have we deleted all ranges yet? */
  for (i = 0; i < N_BLOCKS_PER_DPO; i++)
    {
      for (j = 0; j < 8; j++)
	{
	  if (ppr_dpo->blocks[j].low.as_u16[i] == 0)
	    ppr_dpo->n_free_ranges++;
	}
    }

  if (N_PORT_RANGES_PER_DPO == ppr_dpo->n_free_ranges)
    {
      /* Yes, lose the adjacency... */
      fib_table_entry_special_remove (fib_index, &pfx, FIB_SOURCE_SPECIAL);
    }
  else
    {
      /*
       * compact the ranges down to a contiguous block
       */
      // FIXME. TODO.
    }

  return 0;
}

// This will be moved to another file and implemented post API freeze.
int
ip6_source_and_port_range_check_add_del (ip6_address_t * address,
					 u32 length,
					 u32 vrf_id,
					 u16 * low_ports,
					 u16 * high_ports, int is_add)
{
  uint32_t fib_index;

  fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);

  ASSERT (~0 != fib_index);

  fib_table_unlock (fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_CLASSIFY);

  return 0;
}

int
ip4_source_and_port_range_check_add_del (ip4_address_t * address,
					 u32 length,
					 u32 vrf_id,
					 u16 * low_ports,
					 u16 * high_ports, int is_add)
{
  u32 fib_index;

  fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id,
						 FIB_SOURCE_CLASSIFY);

  if (is_add == 0)
    {
      remove_port_range_adjacency (fib_index, address, length,
				   low_ports, high_ports);
    }
  else
    {
      add_port_range_adjacency (fib_index, address, length,
				low_ports, high_ports);
    }

  return 0;
}

static clib_error_t *
ip_source_and_port_range_check_command_fn (vlib_main_t * vm,
					   unformat_input_t * input,
					   vlib_cli_command_t * cmd)
{
  u16 *low_ports = 0;
  u16 *high_ports = 0;
  u16 this_low;
  u16 this_hi;
  ip4_address_t ip4_addr;
  ip6_address_t ip6_addr;	//This function will be moved to generic impl when v6 done.
  u32 length;
  u32 tmp, tmp2;
  u32 vrf_id = ~0;
  int is_add = 1, ip_ver = ~0;
  int rv;


  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U/%d", unformat_ip4_address, &ip4_addr, &length))
	ip_ver = 4;
      else
	if (unformat
	    (input, "%U/%d", unformat_ip6_address, &ip6_addr, &length))
	ip_ver = 6;
      else if (unformat (input, "vrf %d", &vrf_id))
	;
      else if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "port %d", &tmp))
	{
	  if (tmp == 0 || tmp > 65535)
	    return clib_error_return (0, "port %d out of range", tmp);
	  this_low = tmp;
	  this_hi = this_low + 1;
	  vec_add1 (low_ports, this_low);
	  vec_add1 (high_ports, this_hi);
	}
      else if (unformat (input, "range %d - %d", &tmp, &tmp2))
	{
	  if (tmp > tmp2)
	    return clib_error_return (0, "ports %d and %d out of order",
				      tmp, tmp2);
	  if (tmp == 0 || tmp > 65535)
	    return clib_error_return (0, "low port %d out of range", tmp);
	  if (tmp2 == 0 || tmp2 > 65535)
	    return clib_error_return (0, "high port %d out of range", tmp2);
	  this_low = tmp;
	  this_hi = tmp2 + 1;
	  vec_add1 (low_ports, this_low);
	  vec_add1 (high_ports, this_hi);
	}
      else
	break;
    }

  if (ip_ver == ~0)
    return clib_error_return (0, " <address>/<mask> not specified");

  if (vrf_id == ~0)
    return clib_error_return (0, " VRF ID required, not specified");

  if (vec_len (low_ports) == 0)
    return clib_error_return (0,
			      " Both VRF ID and range/port must be set for a protocol.");

  if (vrf_id == 0)
    return clib_error_return (0, " VRF ID can not be 0 (default).");


  if (ip_ver == 4)
    rv = ip4_source_and_port_range_check_add_del
      (&ip4_addr, length, vrf_id, low_ports, high_ports, is_add);
  else
    return clib_error_return (0, " IPv6 in subsequent patch");

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INCORRECT_ADJACENCY_TYPE:
      return clib_error_return
	(0, " Incorrect adjacency for add/del operation");

    case VNET_API_ERROR_EXCEEDED_NUMBER_OF_PORTS_CAPACITY:
      return clib_error_return (0, " Too many ports in add/del operation");

    case VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY:
      return clib_error_return
	(0, " Too many ranges requested for add operation");

    default:
      return clib_error_return (0, " returned an unexpected value: %d", rv);
    }

  return 0;
}

/*?
 * This command adds an IP Subnet and range of ports to be validated
 * by an IP FIB table (VRF).
 *
 * @todo This is incomplete. This needs a detailed description and a
 * practical example.
 *
 * @cliexpar
 * Example of how to add an IPv4 subnet and single port to an IPv4 FIB table:
 * @cliexcmd{set ip source-and-port-range-check vrf 7 172.16.1.0/24 port 23}
 * Example of how to add an IPv4 subnet and range of ports to an IPv4 FIB table:
 * @cliexcmd{set ip source-and-port-range-check vrf 7 172.16.1.0/24 range 23 - 100}
 * Example of how to delete an IPv4 subnet and single port from an IPv4 FIB table:
 * @cliexcmd{set ip source-and-port-range-check vrf 7 172.16.1.0/24 port 23 del}
 * Example of how to delete an IPv4 subnet and range of ports from an IPv4 FIB table:
 * @cliexcmd{set ip source-and-port-range-check vrf 7 172.16.1.0/24 range 23 - 100 del}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip_source_and_port_range_check_command, static) = {
  .path = "set ip source-and-port-range-check",
  .function = ip_source_and_port_range_check_command_fn,
  .short_help =
  "set ip source-and-port-range-check vrf <table-id> <ip-addr>/<mask> {port nn | range <nn> - <nn>} [del]",
};
/* *INDENT-ON* */


static clib_error_t *
show_source_and_port_range_check_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  protocol_port_range_dpo_t *ppr_dpo;
  u32 fib_index;
  u8 addr_set = 0;
  u32 vrf_id = ~0;
  int rv, i, j;
  u32 port = 0;
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
  };

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_ip4_address, &pfx.fp_addr.ip4))
	addr_set = 1;
      else if (unformat (input, "vrf %d", &vrf_id))
	;
      else if (unformat (input, "port %d", &port))
	;
      else
	break;
    }

  if (addr_set == 0)
    return clib_error_return (0, "<address> not specified");

  if (vrf_id == ~0)
    return clib_error_return (0, "VRF ID required, not specified");

  fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);
  if (~0 == fib_index)
    return clib_error_return (0, "VRF %d not found", vrf_id);

  /*
   * find the longest prefix match on the address requested,
   * check it was sourced by us
   */
  dpo_id_t dpo = DPO_INVALID;
  const dpo_id_t *bucket;

  if (!fib_entry_get_dpo_for_source (fib_table_lookup (fib_index, &pfx),
				     FIB_SOURCE_SPECIAL, &dpo))
    {
      /*
       * not one of ours
       */
      vlib_cli_output (vm, "%U: src address drop", format_ip4_address,
		       &pfx.fp_addr.ip4);
      return 0;
    }

  bucket = load_balance_get_bucket_i (load_balance_get (dpo.dpoi_index), 0);
  ppr_dpo = protocol_port_range_dpo_get (bucket->dpoi_index);
  dpo_reset (&dpo);

  if (port)
    {
      rv = check_adj_port_range_x1 (ppr_dpo, (u16) port, 1234);
      if (rv == 1234)
	vlib_cli_output (vm, "%U port %d PASS", format_ip4_address,
			 &pfx.fp_addr.ip4, port);
      else
	vlib_cli_output (vm, "%U port %d FAIL", format_ip4_address,
			 &pfx.fp_addr.ip4, port);
      return 0;
    }
  else
    {
      u8 *s;

      s = format (0, "%U: ", format_ip4_address, &pfx.fp_addr.ip4);

      for (i = 0; i < N_BLOCKS_PER_DPO; i++)
	{
	  for (j = 0; j < 8; j++)
	    {
	      if (ppr_dpo->blocks[i].low.as_u16[j])
		s = format (s, "%d - %d ",
			    (u32) ppr_dpo->blocks[i].low.as_u16[j],
			    (u32) ppr_dpo->blocks[i].hi.as_u16[j]);
	    }
	}
      vlib_cli_output (vm, "%s", s);
      vec_free (s);
    }

  return 0;
}

/*?
 * Display the range of ports being validated by an IPv4 FIB for a given
 * IP or subnet, or test if a given IP and port are being validated.
 *
 * @todo This is incomplete. This needs a detailed description and a
 * practical example.
 *
 * @cliexpar
 * Example of how to display the set of ports being validated for a given
 * IPv4 subnet:
 * @cliexstart{show ip source-and-port-range-check vrf 7 172.16.2.0}
 * 172.16.2.0: 23 - 101
 * @cliexend
 * Example of how to test to determine of a given Pv4 address and port
 * are being validated:
 * @cliexstart{show ip source-and-port-range-check vrf 7 172.16.2.2 port 23}
 * 172.16.2.2 port 23 PASS
 * @cliexend
 * @cliexstart{show ip source-and-port-range-check vrf 7 172.16.2.2 port 250}
 * 172.16.2.2 port 250 FAIL
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_source_and_port_range_check, static) = {
  .path = "show ip source-and-port-range-check",
  .function = show_source_and_port_range_check_fn,
  .short_help =
  "show ip source-and-port-range-check vrf <table-id> <ip-addr> [port <n>]",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
