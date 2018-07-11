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
#include <vppinfra/lb_hash_hash.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/arp_packet.h>

#define foreach_bond_tx_error     \
  _(NONE, "no error")             \
  _(IF_DOWN, "interface down")    \
  _(NO_SLAVE, "no slave")

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

u8 *
format_bond_interface_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  bond_main_t *bm = &bond_main;
  bond_if_t *bif = pool_elt_at_index (bm->interfaces, dev_instance);

  s = format (s, "BondEthernet%lu", bif->dev_instance);

  return s;
}

static __clib_unused clib_error_t *
bond_set_l2_mode_function (vnet_main_t * vnm,
			   struct vnet_hw_interface_t *bif_hw,
			   i32 l2_if_adjust)
{
  bond_if_t *bif;
  u32 *sw_if_index;
  struct vnet_hw_interface_t *sif_hw;

  bif = bond_get_master_by_sw_if_index (bif_hw->sw_if_index);
  if (!bif)
    return 0;

  if ((bif_hw->l2_if_count == 1) && (l2_if_adjust == 1))
    {
      /* Just added first L2 interface on this port */
      vec_foreach (sw_if_index, bif->slaves)
      {
	sif_hw = vnet_get_sup_hw_interface (vnm, *sw_if_index);
	ethernet_set_flags (vnm, sif_hw->hw_if_index,
			    ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);

	/* ensure all packets go to ethernet-input */
	ethernet_set_rx_redirect (vnm, sif_hw, 1);
      }
    }

  return 0;
}

static __clib_unused clib_error_t *
bond_subif_add_del_function (vnet_main_t * vnm, u32 hw_if_index,
			     struct vnet_sw_interface_t *st, int is_add)
{
  /* Nothing for now */
  return 0;
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

static_always_inline u32
bond_load_balance_broadcast (vlib_main_t * vm, vlib_node_runtime_t * node,
			     bond_if_t * bif, vlib_buffer_t * b0,
			     uword slave_count)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_buffer_t *c0;
  int port;
  u32 *to_next = 0;
  u32 sw_if_index;
  vlib_frame_t *f;
  u16 thread_index = vm->thread_index;

  for (port = 1; port < slave_count; port++)
    {
      sw_if_index = *vec_elt_at_index (bif->active_slaves, port);
      if (bif->per_thread_info[thread_index].frame[port] == 0)
	bif->per_thread_info[thread_index].frame[port] =
	  vnet_get_frame_to_sw_interface (vnm, sw_if_index);
      f = bif->per_thread_info[thread_index].frame[port];
      to_next = vlib_frame_vector_args (f);
      to_next += f->n_vectors;
      c0 = vlib_buffer_copy (vm, b0);
      if (PREDICT_TRUE (c0 != 0))
	{
	  vnet_buffer (c0)->sw_if_index[VLIB_TX] = sw_if_index;
	  to_next[0] = vlib_get_buffer_index (vm, c0);
	  f->n_vectors++;
	}
    }

  return 0;
}

static_always_inline u32
bond_load_balance_l2 (vlib_main_t * vm, vlib_node_runtime_t * node,
		      bond_if_t * bif, vlib_buffer_t * b0, uword slave_count)
{
  ethernet_header_t *eth = (ethernet_header_t *) vlib_buffer_get_current (b0);
  u32 c;
  u64 *dst = (u64 *) & eth->dst_address[0];
  u64 a = clib_mem_unaligned (dst, u64);
  u32 *src = (u32 *) & eth->src_address[2];
  u32 b = clib_mem_unaligned (src, u32);

  c = lb_hash_hash_2_tuples (a, b);

  if (BOND_MODULO_SHORTCUT (slave_count))
    return (c & (slave_count - 1));
  else
    return c % slave_count;
}

static_always_inline u16 *
bond_locate_ethertype (ethernet_header_t * eth)
{
  u16 *ethertype_p;
  ethernet_vlan_header_t *vlan;

  if (!ethernet_frame_is_tagged (clib_net_to_host_u16 (eth->type)))
    {
      ethertype_p = &eth->type;
    }
  else
    {
      vlan = (void *) (eth + 1);
      ethertype_p = &vlan->type;
      if (*ethertype_p == ntohs (ETHERNET_TYPE_VLAN))
	{
	  vlan++;
	  ethertype_p = &vlan->type;
	}
    }
  return ethertype_p;
}

static_always_inline u32
bond_load_balance_l23 (vlib_main_t * vm, vlib_node_runtime_t * node,
		       bond_if_t * bif, vlib_buffer_t * b0, uword slave_count)
{
  ethernet_header_t *eth = (ethernet_header_t *) vlib_buffer_get_current (b0);
  u8 ip_version;
  ip4_header_t *ip4;
  u16 ethertype, *ethertype_p;
  u32 *mac1, *mac2, *mac3;

  ethertype_p = bond_locate_ethertype (eth);
  ethertype = clib_mem_unaligned (ethertype_p, u16);

  if ((ethertype != htons (ETHERNET_TYPE_IP4)) &&
      (ethertype != htons (ETHERNET_TYPE_IP6)))
    return (bond_load_balance_l2 (vm, node, bif, b0, slave_count));

  ip4 = (ip4_header_t *) (ethertype_p + 1);
  ip_version = (ip4->ip_version_and_header_length >> 4);

  if (ip_version == 0x4)
    {
      u32 a, c;

      mac1 = (u32 *) & eth->dst_address[0];
      mac2 = (u32 *) & eth->dst_address[4];
      mac3 = (u32 *) & eth->src_address[2];

      a = clib_mem_unaligned (mac1, u32) ^ clib_mem_unaligned (mac2, u32) ^
	clib_mem_unaligned (mac3, u32);
      c =
	lb_hash_hash_2_tuples (clib_mem_unaligned (&ip4->address_pair, u64),
			       a);
      if (BOND_MODULO_SHORTCUT (slave_count))
	return (c & (slave_count - 1));
      else
	return c % slave_count;
    }
  else if (ip_version == 0x6)
    {
      u64 a;
      u32 c;
      ip6_header_t *ip6 = (ip6_header_t *) (eth + 1);

      mac1 = (u32 *) & eth->dst_address[0];
      mac2 = (u32 *) & eth->dst_address[4];
      mac3 = (u32 *) & eth->src_address[2];

      a = clib_mem_unaligned (mac1, u32) ^ clib_mem_unaligned (mac2, u32) ^
	clib_mem_unaligned (mac3, u32);
      c =
	lb_hash_hash (clib_mem_unaligned
		      (&ip6->src_address.as_uword[0], uword),
		      clib_mem_unaligned (&ip6->src_address.as_uword[1],
					  uword),
		      clib_mem_unaligned (&ip6->dst_address.as_uword[0],
					  uword),
		      clib_mem_unaligned (&ip6->dst_address.as_uword[1],
					  uword), a);
      if (BOND_MODULO_SHORTCUT (slave_count))
	return (c & (slave_count - 1));
      else
	return c % slave_count;
    }
  return (bond_load_balance_l2 (vm, node, bif, b0, slave_count));
}

static_always_inline u32
bond_load_balance_l34 (vlib_main_t * vm, vlib_node_runtime_t * node,
		       bond_if_t * bif, vlib_buffer_t * b0, uword slave_count)
{
  ethernet_header_t *eth = (ethernet_header_t *) vlib_buffer_get_current (b0);
  u8 ip_version;
  uword is_tcp_udp;
  ip4_header_t *ip4;
  u16 ethertype, *ethertype_p;

  ethertype_p = bond_locate_ethertype (eth);
  ethertype = clib_mem_unaligned (ethertype_p, u16);

  if ((ethertype != htons (ETHERNET_TYPE_IP4)) &&
      (ethertype != htons (ETHERNET_TYPE_IP6)))
    return (bond_load_balance_l2 (vm, node, bif, b0, slave_count));

  ip4 = (ip4_header_t *) (ethertype_p + 1);
  ip_version = (ip4->ip_version_and_header_length >> 4);

  if (ip_version == 0x4)
    {
      u32 a, c, t1, t2;
      tcp_header_t *tcp = (void *) (ip4 + 1);

      is_tcp_udp = (ip4->protocol == IP_PROTOCOL_TCP) ||
	(ip4->protocol == IP_PROTOCOL_UDP);
      t1 = is_tcp_udp ? clib_mem_unaligned (&tcp->src, u16) : 0;
      t2 = is_tcp_udp ? clib_mem_unaligned (&tcp->dst, u16) : 0;
      a = t1 ^ t2;
      c =
	lb_hash_hash_2_tuples (clib_mem_unaligned (&ip4->address_pair, u64),
			       a);
      if (BOND_MODULO_SHORTCUT (slave_count))
	return (c & (slave_count - 1));
      else
	return c % slave_count;
    }
  else if (ip_version == 0x6)
    {
      u64 a;
      u32 c, t1, t2;
      ip6_header_t *ip6 = (ip6_header_t *) (eth + 1);
      tcp_header_t *tcp = (void *) (ip6 + 1);

      is_tcp_udp = 0;
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
      t1 = is_tcp_udp ? clib_mem_unaligned (&tcp->src, u16) : 0;
      t2 = is_tcp_udp ? clib_mem_unaligned (&tcp->dst, u16) : 0;
      a = t1 ^ t2;
      c =
	lb_hash_hash (clib_mem_unaligned
		      (&ip6->src_address.as_uword[0], uword),
		      clib_mem_unaligned (&ip6->src_address.as_uword[1],
					  uword),
		      clib_mem_unaligned (&ip6->dst_address.as_uword[0],
					  uword),
		      clib_mem_unaligned (&ip6->dst_address.as_uword[1],
					  uword), a);
      if (BOND_MODULO_SHORTCUT (slave_count))
	return (c & (slave_count - 1));
      else
	return c % slave_count;
    }

  return (bond_load_balance_l2 (vm, node, bif, b0, slave_count));
}

static_always_inline u32
bond_load_balance_round_robin (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       bond_if_t * bif, vlib_buffer_t * b0,
			       uword slave_count)
{
  bif->lb_rr_last_index++;
  if (BOND_MODULO_SHORTCUT (slave_count))
    bif->lb_rr_last_index &= slave_count - 1;
  else
    bif->lb_rr_last_index %= slave_count;

  return bif->lb_rr_last_index;
}

static_always_inline u32
bond_load_balance_active_backup (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 bond_if_t * bif, vlib_buffer_t * b0,
				 uword slave_count)
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
bond_tx_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  vnet_interface_output_runtime_t *rund = (void *) node->runtime_data;
  bond_main_t *bm = &bond_main;
  bond_if_t *bif = pool_elt_at_index (bm->interfaces, rund->dev_instance);
  u32 bi0, bi1, bi2, bi3;
  vlib_buffer_t *b0, *b1, *b2, *b3;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from;
  ethernet_header_t *eth;
  u32 port;
  u32 sw_if_index, sw_if_index1, sw_if_index2, sw_if_index3;
  bond_packet_trace_t *t0;
  uword n_trace = vlib_get_trace_count (vm, node);
  u16 thread_index = vm->thread_index;
  vnet_main_t *vnm = vnet_get_main ();
  u32 *to_next;
  u32 sif_if_index, sif_if_index1, sif_if_index2, sif_if_index3;
  vlib_frame_t *f;
  uword slave_count;

  if (PREDICT_FALSE (bif->admin_up == 0))
    {
      vlib_buffer_free (vm, vlib_frame_args (frame), frame->n_vectors);
      vlib_increment_simple_counter (vnet_main.interface_main.sw_if_counters +
				     VNET_INTERFACE_COUNTER_DROP,
				     thread_index, bif->sw_if_index,
				     frame->n_vectors);
      vlib_error_count (vm, node->node_index, BOND_TX_ERROR_IF_DOWN,
			frame->n_vectors);
      return frame->n_vectors;
    }

  clib_spinlock_lock_if_init (&bif->lockp);
  slave_count = vec_len (bif->active_slaves);
  if (PREDICT_FALSE (slave_count == 0))
    {
      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      vlib_increment_combined_counter
	(vnet_main.interface_main.combined_sw_if_counters
	 + VNET_INTERFACE_COUNTER_TX, thread_index, bif->sw_if_index,
	 frame->n_vectors, b0->current_length);

      vlib_buffer_free (vm, vlib_frame_args (frame), frame->n_vectors);
      vlib_increment_simple_counter (vnet_main.interface_main.sw_if_counters +
				     VNET_INTERFACE_COUNTER_DROP,
				     thread_index, bif->sw_if_index,
				     frame->n_vectors);
      vlib_error_count (vm, node->node_index, BOND_TX_ERROR_NO_SLAVE,
			frame->n_vectors);
      clib_spinlock_unlock_if_init (&bif->lockp);
      return frame->n_vectors;
    }

  vec_validate_aligned (bif->per_thread_info[thread_index].frame, slave_count,
			CLIB_CACHE_LINE_BYTES);

  /* Number of buffers / pkts */
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      while (n_left_from >= 4)
	{
	  u32 next0 = 0, next1 = 0, next2 = 0, next3 = 0;
	  u32 port0 = 0, port1 = 0, port2 = 0, port3 = 0;

	  // Prefetch next iteration
	  if (n_left_from >= 8)
	    {
	      vlib_buffer_t *p4, *p5, *p6, *p7;

	      p4 = vlib_get_buffer (vm, from[4]);
	      p5 = vlib_get_buffer (vm, from[5]);
	      p6 = vlib_get_buffer (vm, from[6]);
	      p7 = vlib_get_buffer (vm, from[7]);

	      vlib_prefetch_buffer_header (p4, LOAD);
	      vlib_prefetch_buffer_header (p5, LOAD);
	      vlib_prefetch_buffer_header (p6, LOAD);
	      vlib_prefetch_buffer_header (p7, LOAD);

	      CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (p6->data, CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (p7->data, CLIB_CACHE_LINE_BYTES, LOAD);
	    }

	  bi0 = from[0];
	  bi1 = from[1];
	  bi2 = from[2];
	  bi3 = from[3];

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b2);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b3);

	  sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];
	  sw_if_index2 = vnet_buffer (b2)->sw_if_index[VLIB_TX];
	  sw_if_index3 = vnet_buffer (b3)->sw_if_index[VLIB_TX];

	  if (PREDICT_TRUE (slave_count != 1))
	    {
	      port0 =
		(bond_load_balance_table[bif->lb]).load_balance (vm, node,
								 bif, b0,
								 slave_count);
	      port1 =
		(bond_load_balance_table[bif->lb]).load_balance (vm, node,
								 bif, b1,
								 slave_count);
	      port2 =
		(bond_load_balance_table[bif->lb]).load_balance (vm, node,
								 bif, b2,
								 slave_count);
	      port3 =
		(bond_load_balance_table[bif->lb]).load_balance (vm, node,
								 bif, b3,
								 slave_count);
	    }

	  sif_if_index = *vec_elt_at_index (bif->active_slaves, port0);
	  sif_if_index1 = *vec_elt_at_index (bif->active_slaves, port1);
	  sif_if_index2 = *vec_elt_at_index (bif->active_slaves, port2);
	  sif_if_index3 = *vec_elt_at_index (bif->active_slaves, port3);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sif_if_index;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = sif_if_index1;
	  vnet_buffer (b2)->sw_if_index[VLIB_TX] = sif_if_index2;
	  vnet_buffer (b3)->sw_if_index[VLIB_TX] = sif_if_index3;

	  if (PREDICT_FALSE ((bif->per_thread_info[thread_index].frame[port0]
			      == 0)))
	    bif->per_thread_info[thread_index].frame[port0] =
	      vnet_get_frame_to_sw_interface (vnm, sif_if_index);

	  if (PREDICT_FALSE ((bif->per_thread_info[thread_index].frame[port1]
			      == 0)))
	    bif->per_thread_info[thread_index].frame[port1] =
	      vnet_get_frame_to_sw_interface (vnm, sif_if_index1);

	  if (PREDICT_FALSE ((bif->per_thread_info[thread_index].frame[port2]
			      == 0)))
	    bif->per_thread_info[thread_index].frame[port2] =
	      vnet_get_frame_to_sw_interface (vnm, sif_if_index2);

	  if (PREDICT_FALSE ((bif->per_thread_info[thread_index].frame[port3]
			      == 0)))
	    bif->per_thread_info[thread_index].frame[port3] =
	      vnet_get_frame_to_sw_interface (vnm, sif_if_index3);

	  f = bif->per_thread_info[thread_index].frame[port0];
	  to_next = vlib_frame_vector_args (f);
	  to_next += f->n_vectors;
	  to_next[0] = vlib_get_buffer_index (vm, b0);
	  f->n_vectors++;

	  f = bif->per_thread_info[thread_index].frame[port1];
	  to_next = vlib_frame_vector_args (f);
	  to_next += f->n_vectors;
	  to_next[0] = vlib_get_buffer_index (vm, b1);
	  f->n_vectors++;

	  f = bif->per_thread_info[thread_index].frame[port2];
	  to_next = vlib_frame_vector_args (f);
	  to_next += f->n_vectors;
	  to_next[0] = vlib_get_buffer_index (vm, b2);
	  f->n_vectors++;

	  f = bif->per_thread_info[thread_index].frame[port3];
	  to_next = vlib_frame_vector_args (f);
	  to_next += f->n_vectors;
	  to_next[0] = vlib_get_buffer_index (vm, b3);
	  f->n_vectors++;

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      vlib_trace_buffer (vm, node, next0, b0, 0 /* follow_chain */ );
	      vlib_set_trace_count (vm, node, --n_trace);
	      t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
	      eth = (ethernet_header_t *) vlib_buffer_get_current (b0);
	      t0->ethernet = *eth;
	      t0->sw_if_index = sw_if_index;
	      t0->bond_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];

	      if (PREDICT_TRUE (n_trace > 0))
		{
		  vlib_trace_buffer (vm, node, next1, b1,
				     0 /* follow_chain */ );
		  vlib_set_trace_count (vm, node, --n_trace);
		  t0 = vlib_add_trace (vm, node, b1, sizeof (*t0));
		  eth = (ethernet_header_t *) vlib_buffer_get_current (b1);
		  t0->ethernet = *eth;
		  t0->sw_if_index = sw_if_index1;
		  t0->bond_sw_if_index =
		    vnet_buffer (b1)->sw_if_index[VLIB_TX];

		  if (PREDICT_TRUE (n_trace > 0))
		    {
		      vlib_trace_buffer (vm, node, next2, b2,
					 0 /* follow_chain */ );
		      vlib_set_trace_count (vm, node, --n_trace);
		      t0 = vlib_add_trace (vm, node, b2, sizeof (*t0));
		      eth =
			(ethernet_header_t *) vlib_buffer_get_current (b2);
		      t0->ethernet = *eth;
		      t0->sw_if_index = sw_if_index2;
		      t0->bond_sw_if_index =
			vnet_buffer (b2)->sw_if_index[VLIB_TX];

		      if (PREDICT_TRUE (n_trace > 0))
			{
			  vlib_trace_buffer (vm, node, next3, b3,
					     0 /* follow_chain */ );
			  vlib_set_trace_count (vm, node, --n_trace);
			  t0 = vlib_add_trace (vm, node, b3, sizeof (*t0));
			  eth =
			    (ethernet_header_t *)
			    vlib_buffer_get_current (b3);
			  t0->ethernet = *eth;
			  t0->sw_if_index = sw_if_index3;
			  t0->bond_sw_if_index =
			    vnet_buffer (b3)->sw_if_index[VLIB_TX];
			}
		    }
		}
	    }
	  from += 4;
	  n_left_from -= 4;
	}

      while (n_left_from > 0)
	{
	  u32 next0 = 0;
	  u32 port0 = 0;

	  // Prefetch next iteration
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *p2;

	      p2 = vlib_get_buffer (vm, from[1]);
	      vlib_prefetch_buffer_header (p2, LOAD);
	      CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, LOAD);
	    }

	  bi0 = from[0];
	  b0 = vlib_get_buffer (vm, bi0);

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

	  sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];

	  if (PREDICT_TRUE (slave_count != 1))
	    port0 =
	      (bond_load_balance_table[bif->lb]).load_balance (vm, node, bif,
							       b0,
							       slave_count);
	  sif_if_index = *vec_elt_at_index (bif->active_slaves, port0);
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sif_if_index;
	  if (PREDICT_FALSE
	      ((bif->per_thread_info[thread_index].frame[port0] == 0)))
	    bif->per_thread_info[thread_index].frame[port0] =
	      vnet_get_frame_to_sw_interface (vnm, sif_if_index);
	  f = bif->per_thread_info[thread_index].frame[port0];
	  to_next = vlib_frame_vector_args (f);
	  to_next += f->n_vectors;
	  to_next[0] = vlib_get_buffer_index (vm, b0);
	  f->n_vectors++;

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

	  from += 1;
	  n_left_from -= 1;
	}
    }

  for (port = 0; port < slave_count; port++)
    {
      f = bif->per_thread_info[thread_index].frame[port];
      if (f == 0)
	continue;

      sw_if_index = *vec_elt_at_index (bif->active_slaves, port);
      vnet_put_frame_to_sw_interface (vnm, sw_if_index, f);
      bif->per_thread_info[thread_index].frame[port] = 0;
    }

  vlib_increment_simple_counter (vnet_main.interface_main.sw_if_counters
				 + VNET_INTERFACE_COUNTER_TX, thread_index,
				 bif->sw_if_index, frame->n_vectors);

  clib_spinlock_unlock_if_init (&bif->lockp);
  return frame->n_vectors;
}

static walk_rc_t
bond_active_interface_switch_cb (vnet_main_t * vnm, u32 sw_if_index,
				 void *arg)
{
  bond_main_t *bm = &bond_main;

  send_ip4_garp (bm->vlib_main, sw_if_index);
  send_ip6_na (bm->vlib_main, sw_if_index);

  return (WALK_CONTINUE);
}

static uword
bond_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vnet_main_t *vnm = vnet_get_main ();
  uword event_type, *event_data = 0;

  while (1)
    {
      u32 i;
      u32 hw_if_index;

      vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, &event_data);
      ASSERT (event_type == BOND_SEND_GARP_NA);
      for (i = 0; i < vec_len (event_data); i++)
	{
	  hw_if_index = event_data[i];
	  /* walk hw interface to process all subinterfaces */
	  vnet_hw_interface_walk_sw (vnm, hw_if_index,
				     bond_active_interface_switch_cb, 0);
	}
      vec_reset_length (event_data);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (bond_process_node) = {
  .function = bond_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "bond-process",
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (bond_dev_class) = {
  .name = "bond",
  .tx_function = bond_tx_fn,
  .tx_function_n_errors = BOND_TX_N_ERROR,
  .tx_function_error_strings = bond_tx_error_strings,
  .format_device_name = format_bond_interface_name,
  .set_l2_mode_function = bond_set_l2_mode_function,
  .admin_up_down_function = bond_interface_admin_up_down,
  .subif_add_del_function = bond_subif_add_del_function,
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
