/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip6_hop_by_hop_packet.h>
#include <vnet/bonding/node.h>
#include <vnet/bonding/lacp/node.h>

#define foreach_bond_tx_error      \
  _(NONE, "no error")

typedef enum
{
#define _(f,s) BOND_TX_ERROR_##f,
  foreach_bond_tx_error
#undef _
    BOND_TX_N_ERROR,
} bond_tx_error_t;

static char *bond_tx_error_strings[] = {
#define _(n,s) s,
  foreach_bond_tx_error
#undef _
};

static u8 *
format_bond_tx_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");

  return s;
}

u8 *
format_bond_interface_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  bond_main_t *bm = &bond_main;
  bond_if_t *bif = pool_elt_at_index (bm->interfaces, dev_instance);

  s = format (s, "BondEthernet%lu", bif->dev_instance);

  return s;
}

static clib_error_t *
bond_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  bond_main_t *bm = &bond_main;
  bond_if_t *bif = pool_elt_at_index (bm->interfaces, hif->dev_instance);

  bif->admin_up = is_up;
  if (is_up && vec_len (bif->active_slaves))
    vnet_hw_interface_set_flags (vnm, bif->hw_if_index,
				 VNET_HW_INTERFACE_FLAG_LINK_UP);
  return 0;
}

#define foreach_bond_output_error \
  _(NONE, "no error")             \
  _(IF_DOWN, "interface down")    \
  _(NO_SLAVE, "no slave")

typedef enum
{
#define _(f,s) BOND_OUTPUT_ERROR_##f,
  foreach_bond_output_error
#undef _
    BOND_OUTPUT_N_ERROR,
} bond_output_error_t;

static char *bond_output_error_strings[] = {
#define _(n,s) s,
  foreach_bond_output_error
#undef _
};

static u8 *
format_bond_output_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  bond_packet_trace_t *t = va_arg (*args, bond_packet_trace_t *);
  vnet_hw_interface_t *hw, *hw1;
  vnet_main_t *vnm = vnet_get_main ();

  hw = vnet_get_sup_hw_interface (vnm, t->sw_if_index);
  hw1 = vnet_get_sup_hw_interface (vnm, t->bond_sw_if_index);
  s = format (s, "src %U, dst %U, %s -> %s",
	      format_ethernet_address, t->ethernet.src_address,
	      format_ethernet_address, t->ethernet.dst_address,
	      hw->name, hw1->name);

  return s;
}

static uword
bond_tx_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  clib_warning ("NOT IMPLEMENTED");
  return frame->n_vectors;
}

static inline u32
bond_load_balance_broadcast (vlib_main_t * vm, vlib_node_runtime_t * node,
			     bond_if_t * bif, vlib_buffer_t * b0)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_buffer_t *c0;
  int i;
  u32 *to_next = 0;
  u32 sw_if_index;
  vlib_frame_t *f;


  for (i = 1; i < vec_len (bif->active_slaves); i++)
    {
      sw_if_index = *vec_elt_at_index (bif->active_slaves, i);
      f = vnet_get_frame_to_sw_interface (vnm, sw_if_index);
      to_next = vlib_frame_vector_args (f);
      to_next += f->n_vectors;
      c0 = vlib_buffer_copy (vm, b0);
      if (PREDICT_TRUE (c0 != 0))
	{
	  vnet_buffer (c0)->sw_if_index[VLIB_TX] = sw_if_index;
	  to_next[0] = vlib_get_buffer_index (vm, c0);
	  f->n_vectors++;
	  vnet_put_frame_to_sw_interface (vnm, sw_if_index, f);
	}
    }

  return 0;
}

static inline u32
bond_load_balance_l2 (vlib_main_t * vm, vlib_node_runtime_t * node,
		      bond_if_t * bif, vlib_buffer_t * b0)
{
  ethernet_header_t *eth = (ethernet_header_t *) vlib_buffer_get_current (b0);
  u32 a = 0, b = 0, c = 0, t1, t2;
  u16 t11, t22;

  memcpy (&t1, eth->src_address, sizeof (t1));
  memcpy (&t11, &eth->src_address[4], sizeof (t11));
  a = t1 ^ t11;

  memcpy (&t2, eth->dst_address, sizeof (t2));
  memcpy (&t22, &eth->dst_address[4], sizeof (t22));
  b = t2 ^ t22;

  hash_v3_mix32 (a, b, c);
  hash_v3_finalize32 (a, b, c);

  return c % vec_len (bif->active_slaves);
}

static inline u32
bond_load_balance_l23 (vlib_main_t * vm, vlib_node_runtime_t * node,
		       bond_if_t * bif, vlib_buffer_t * b0)
{
  ethernet_header_t *eth = (ethernet_header_t *) vlib_buffer_get_current (b0);
  u8 ip_version;
  ip4_header_t *ip4 = (ip4_header_t *) (eth + 1);

  ip_version = (ip4->ip_version_and_header_length >> 4);
  if ((ip_version != 0x4) && (ip_version != 0x6))
    return (bond_load_balance_l2 (vm, node, bif, b0));

  if (ip_version == 0x4)
    {
      u16 t11, t22;
      u32 a = 0, b = 0, c = 0, t1, t2;

      memcpy (&t1, eth->src_address, sizeof (t1));
      memcpy (&t11, &eth->src_address[4], sizeof (t11));
      a = t1 ^ t11;

      memcpy (&t2, eth->dst_address, sizeof (t2));
      memcpy (&t22, &eth->dst_address[4], sizeof (t22));
      b = t2 ^ t22;

      c = ip4->src_address.data_u32 ^ ip4->dst_address.data_u32;

      hash_v3_mix32 (a, b, c);
      hash_v3_finalize32 (a, b, c);

      return c % vec_len (bif->active_slaves);
    }
  else if (ip_version == 0x6)
    {
      u64 a, b, c;
      u64 t1 = 0, t2 = 0;
      ip6_header_t *ip6 = (ip6_header_t *) (eth + 1);

      memcpy (&t1, eth->src_address, sizeof (eth->src_address));
      memcpy (&t2, eth->dst_address, sizeof (eth->dst_address));
      a = t1 ^ t2;

      b = (ip6->src_address.as_u64[0] ^ ip6->src_address.as_u64[1]);
      c = (ip6->dst_address.as_u64[0] ^ ip6->dst_address.as_u64[1]);

      hash_mix64 (a, b, c);
      return c % vec_len (bif->active_slaves);
    }
  return (bond_load_balance_l2 (vm, node, bif, b0));
}

static inline u32
bond_load_balance_l34 (vlib_main_t * vm, vlib_node_runtime_t * node,
		       bond_if_t * bif, vlib_buffer_t * b0)
{
  ethernet_header_t *eth = (ethernet_header_t *) vlib_buffer_get_current (b0);
  u8 ip_version;
  uword is_tcp_udp = 0;
  ip4_header_t *ip4 = (ip4_header_t *) (eth + 1);

  ip_version = (ip4->ip_version_and_header_length >> 4);

  if (ip_version == 0x4)
    {
      u32 a = 0, b = 0, c = 0, t1, t2;
      tcp_header_t *tcp = (void *) (ip4 + 1);
      is_tcp_udp = (ip4->protocol == IP_PROTOCOL_TCP) ||
	(ip4->protocol == IP_PROTOCOL_UDP);

      a = ip4->src_address.data_u32 ^ ip4->dst_address.data_u32;

      t1 = is_tcp_udp ? tcp->src : 0;
      t2 = is_tcp_udp ? tcp->dst : 0;
      b = t1 + (t2 << 16);

      hash_v3_mix32 (a, b, c);
      hash_v3_finalize32 (a, b, c);

      return c % vec_len (bif->active_slaves);
    }
  else if (ip_version == 0x6)
    {
      u64 a, b, c;
      u64 t1, t2;
      ip6_header_t *ip6 = (ip6_header_t *) (eth + 1);
      tcp_header_t *tcp = (void *) (ip6 + 1);

      if (PREDICT_TRUE ((ip6->protocol == IP_PROTOCOL_TCP) ||
			(ip6->protocol == IP_PROTOCOL_UDP)))
	{
	  is_tcp_udp = 1;
	  tcp = (void *) (ip6 + 1);
	}
      else if (ip6->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	{
	  ip6_hop_by_hop_header_t *hbh =
	    (ip6_hop_by_hop_header_t *) (ip6 + 1);
	  if ((hbh->protocol == IP_PROTOCOL_TCP)
	      || (hbh->protocol == IP_PROTOCOL_UDP))
	    {
	      is_tcp_udp = 1;
	      tcp = (tcp_header_t *) ((u8 *) hbh + ((hbh->length + 1) << 3));
	    }
	}
      a = (ip6->src_address.as_u64[0] ^ ip6->src_address.as_u64[1]);
      b = (ip6->dst_address.as_u64[0] ^ ip6->dst_address.as_u64[1]);

      t1 = is_tcp_udp ? tcp->src : 0;
      t2 = is_tcp_udp ? tcp->dst : 0;
      c = (t2 << 16) | t1;
      hash_mix64 (a, b, c);

      return c % vec_len (bif->active_slaves);
    }

  return (bond_load_balance_l2 (vm, node, bif, b0));
}

static inline u32
bond_load_balance_round_robin (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       bond_if_t * bif, vlib_buffer_t * b0)
{
  bif->lb_rr_last_index++;
  bif->lb_rr_last_index %= vec_len (bif->active_slaves);

  return bif->lb_rr_last_index;
}

static inline u32
bond_load_balance_active_backup (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 bond_if_t * bif, vlib_buffer_t * b0)
{
  /* First interface is the active, the rest is backup */
  return 0;
}

static bond_load_balance_func_t bond_load_balance_table[] = {
#define _(v,f,s, p) { bond_load_balance_##p },
  foreach_bond_lb_algo
#undef _
};

static uword
bond_output_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  bond_main_t *bm = &bond_main;
  bond_if_t *bif;
  u32 bi0;
  vlib_buffer_t *b0;
  u32 next_index;
  u32 *from, *to_next, n_left_from, n_left_to_next;
  ethernet_header_t *eth;
  u32 next0 = 0;
  u32 port;
  u32 sw_if_index;
  bond_packet_trace_t *t0;
  uword n_trace = vlib_get_trace_count (vm, node);
  uword *p;
  u16 thread_index = vlib_get_thread_index ();

  /* Vector of buffer / pkt indices we're supposed to process */
  from = vlib_frame_vector_args (frame);

  /* Number of buffers / pkts */
  n_left_from = frame->n_vectors;

  /* Speculatively send the first buffer to the last disposition we used */
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      /* set up to enqueue to our disposition with index = next_index */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  next0 = 0;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  vnet_feature_next (vnet_buffer (b0)->sw_if_index[VLIB_TX], &next0,
			     b0);
	  sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  // sw_if_index points to the bundle interface
	  p = hash_get (bm->bundle_by_sw_if_index, sw_if_index);
	  if (PREDICT_TRUE (p != 0))
	    {
	      bif = pool_elt_at_index (bm->interfaces, p[0]);

	      if (PREDICT_TRUE (vec_len (bif->active_slaves) >= 1))
		{
		  if (PREDICT_TRUE (bif->admin_up == 1))
		    {
		      port = (bond_load_balance_table[bif->lb]).load_balance
			(vm, node, bif, b0);
		      vnet_buffer (b0)->sw_if_index[VLIB_TX] =
			*vec_elt_at_index (bif->active_slaves, port);

		      vlib_increment_combined_counter
			(vnet_main.interface_main.combined_sw_if_counters
			 + VNET_INTERFACE_COUNTER_TX, thread_index,
			 bif->sw_if_index, 1, b0->current_length);
		    }
		  else
		    {
		      vlib_error_count (vm, node->node_index,
					BOND_OUTPUT_ERROR_IF_DOWN, 1);
		    }
		}
	      else
		{
		  vlib_error_count (vm, node->node_index,
				    BOND_OUTPUT_ERROR_NO_SLAVE, 1);
		}
	    }
	  else
	    {
	      vlib_error_count (vm, node->node_index,
				BOND_OUTPUT_ERROR_NO_SLAVE, 1);
	    }

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      vlib_trace_buffer (vm, node, next0, b0, 0 /* follow_chain */ );
	      vlib_set_trace_count (vm, node, --n_trace);
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      eth = (ethernet_header_t *) vlib_buffer_get_current (b0);
	      t0->ethernet = *eth;
	      t0->sw_if_index = sw_if_index;
	      t0->bond_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, bond_output_node.index,
			       BOND_OUTPUT_ERROR_NONE, frame->n_vectors);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (bond_output_node) = {
  .function = bond_output_fn,
  .name = "bond-output",
  .vector_size = sizeof (u32),
  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_bond_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = BOND_OUTPUT_N_ERROR,
  .error_strings = bond_output_error_strings,
};

VNET_FEATURE_INIT (bond_output_node, static) =
{
  .arc_name = "interface-output",
  .node_name = "bond-output",
  .runs_before = VNET_FEATURES ("interface-tx"),
};

VLIB_NODE_FUNCTION_MULTIARCH (bond_output_node, bond_output_fn)

VNET_DEVICE_CLASS (bond_dev_class) = {
  .name = "bond",
  .tx_function = bond_tx_fn,
  .tx_function_n_errors = BOND_TX_N_ERROR,
  .tx_function_error_strings = bond_tx_error_strings,
  .format_device_name = format_bond_interface_name,
  .admin_up_down_function = bond_interface_admin_up_down,
  .format_tx_trace = format_bond_tx_trace,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH (bond_dev_class, bond_tx_fn)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
