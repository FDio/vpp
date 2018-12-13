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

#ifndef CLIB_MARCH_VARIANT
u8 *
format_bond_interface_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  bond_main_t *bm = &bond_main;
  bond_if_t *bif = pool_elt_at_index (bm->interfaces, dev_instance);

  s = format (s, "BondEthernet%lu", bif->id);

  return s;
}
#endif

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
  else if ((bif_hw->l2_if_count == 0) && (l2_if_adjust == -1))
    {
      /* Just removed last L2 subinterface on this port */
      vec_foreach (sw_if_index, bif->slaves)
      {
	sif_hw = vnet_get_sup_hw_interface (vnm, *sw_if_index);

	/* Allow ip packets to go directly to ip4-input etc */
	ethernet_set_rx_redirect (vnm, sif_hw, 0);
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

static_always_inline void
bond_tx_add_to_queue (bond_per_thread_data_t * ptd, u32 port, u32 bi)
{
  u32 idx = ptd->per_port_queue[port].n_buffers++;
  ptd->per_port_queue[port].buffers[idx] = bi;
}

static_always_inline u32
bond_lb_broadcast (vlib_main_t * vm, vlib_node_runtime_t * node,
		   bond_if_t * bif, vlib_buffer_t * b0, uword n_slaves)
{
  bond_main_t *bm = &bond_main;
  vlib_buffer_t *c0;
  int port;
  u32 sw_if_index;
  u16 thread_index = vm->thread_index;
  bond_per_thread_data_t *ptd = vec_elt_at_index (bm->per_thread_data,
						  thread_index);

  for (port = 1; port < n_slaves; port++)
    {
      sw_if_index = *vec_elt_at_index (bif->active_slaves, port);
      c0 = vlib_buffer_copy (vm, b0);
      if (PREDICT_TRUE (c0 != 0))
	{
	  vnet_buffer (c0)->sw_if_index[VLIB_TX] = sw_if_index;
	  bond_tx_add_to_queue (ptd, port, vlib_get_buffer_index (vm, c0));
	}
    }

  return 0;
}

static_always_inline u32
bond_lb_l2 (vlib_main_t * vm, vlib_node_runtime_t * node,
	    bond_if_t * bif, vlib_buffer_t * b0, uword n_slaves)
{
  ethernet_header_t *eth = (ethernet_header_t *) vlib_buffer_get_current (b0);
  u64 *dst = (u64 *) & eth->dst_address[0];
  u64 a = clib_mem_unaligned (dst, u64);
  u32 *src = (u32 *) & eth->src_address[2];
  u32 b = clib_mem_unaligned (src, u32);

  return lb_hash_hash_2_tuples (a, b);
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
bond_lb_l23 (vlib_main_t * vm, vlib_node_runtime_t * node,
	     bond_if_t * bif, vlib_buffer_t * b0, uword n_slaves)
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
    return (bond_lb_l2 (vm, node, bif, b0, n_slaves));

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
      return c;
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
      return c;
    }
  return (bond_lb_l2 (vm, node, bif, b0, n_slaves));
}

static_always_inline u32
bond_lb_l34 (vlib_main_t * vm, vlib_node_runtime_t * node,
	     bond_if_t * bif, vlib_buffer_t * b0, uword n_slaves)
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
    return (bond_lb_l2 (vm, node, bif, b0, n_slaves));

  ip4 = (ip4_header_t *) (ethertype_p + 1);
  ip_version = (ip4->ip_version_and_header_length >> 4);

  if (ip_version == 0x4)
    {
      u32 a, t1, t2;
      tcp_header_t *tcp = (void *) (ip4 + 1);

      is_tcp_udp = (ip4->protocol == IP_PROTOCOL_TCP) ||
	(ip4->protocol == IP_PROTOCOL_UDP);
      t1 = is_tcp_udp ? clib_mem_unaligned (&tcp->src, u16) : 0;
      t2 = is_tcp_udp ? clib_mem_unaligned (&tcp->dst, u16) : 0;
      a = t1 ^ t2;
      return
	lb_hash_hash_2_tuples (clib_mem_unaligned (&ip4->address_pair, u64),
			       a);
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
      return c;
    }

  return (bond_lb_l2 (vm, node, bif, b0, n_slaves));
}

static_always_inline u32
bond_lb_round_robin (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     bond_if_t * bif, vlib_buffer_t * b0, uword n_slaves)
{
  bif->lb_rr_last_index++;
  if (bif->lb_rr_last_index >= n_slaves)
    bif->lb_rr_last_index = 0;

  return bif->lb_rr_last_index;
}

static_always_inline void
bond_tx_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		bond_if_t * bif, vlib_buffer_t ** b,
		u32 * h, u32 n_left, uword n_slaves, u32 lb_alg)
{
  while (n_left >= 4)
    {
      // Prefetch next iteration
      if (n_left >= 8)
	{
	  vlib_buffer_t **pb = b + 4;

	  vlib_prefetch_buffer_header (pb[0], LOAD);
	  vlib_prefetch_buffer_header (pb[1], LOAD);
	  vlib_prefetch_buffer_header (pb[2], LOAD);
	  vlib_prefetch_buffer_header (pb[3], LOAD);

	  CLIB_PREFETCH (pb[0]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (pb[1]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (pb[2]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (pb[3]->data, CLIB_CACHE_LINE_BYTES, LOAD);
	}

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);

      if (lb_alg == BOND_LB_L2)
	{
	  h[0] = bond_lb_l2 (vm, node, bif, b[0], n_slaves);
	  h[1] = bond_lb_l2 (vm, node, bif, b[1], n_slaves);
	  h[2] = bond_lb_l2 (vm, node, bif, b[2], n_slaves);
	  h[3] = bond_lb_l2 (vm, node, bif, b[3], n_slaves);
	}
      else if (lb_alg == BOND_LB_L34)
	{
	  h[0] = bond_lb_l34 (vm, node, bif, b[0], n_slaves);
	  h[1] = bond_lb_l34 (vm, node, bif, b[1], n_slaves);
	  h[2] = bond_lb_l34 (vm, node, bif, b[2], n_slaves);
	  h[3] = bond_lb_l34 (vm, node, bif, b[3], n_slaves);
	}
      else if (lb_alg == BOND_LB_L23)
	{
	  h[0] = bond_lb_l23 (vm, node, bif, b[0], n_slaves);
	  h[1] = bond_lb_l23 (vm, node, bif, b[1], n_slaves);
	  h[2] = bond_lb_l23 (vm, node, bif, b[2], n_slaves);
	  h[3] = bond_lb_l23 (vm, node, bif, b[3], n_slaves);
	}
      else if (lb_alg == BOND_LB_RR)
	{
	  h[0] = bond_lb_round_robin (vm, node, bif, b[0], n_slaves);
	  h[1] = bond_lb_round_robin (vm, node, bif, b[1], n_slaves);
	  h[2] = bond_lb_round_robin (vm, node, bif, b[2], n_slaves);
	  h[3] = bond_lb_round_robin (vm, node, bif, b[3], n_slaves);
	}
      else if (lb_alg == BOND_LB_BC)
	{
	  h[0] = bond_lb_broadcast (vm, node, bif, b[0], n_slaves);
	  h[1] = bond_lb_broadcast (vm, node, bif, b[1], n_slaves);
	  h[2] = bond_lb_broadcast (vm, node, bif, b[2], n_slaves);
	  h[3] = bond_lb_broadcast (vm, node, bif, b[3], n_slaves);
	}
      else
	{
	  ASSERT (0);
	}

      n_left -= 4;
      b += 4;
      h += 4;
    }

  while (n_left > 0)
    {
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);

      if (bif->lb == BOND_LB_L2)
	h[0] = bond_lb_l2 (vm, node, bif, b[0], n_slaves);
      else if (bif->lb == BOND_LB_L34)
	h[0] = bond_lb_l34 (vm, node, bif, b[0], n_slaves);
      else if (bif->lb == BOND_LB_L23)
	h[0] = bond_lb_l23 (vm, node, bif, b[0], n_slaves);
      else if (bif->lb == BOND_LB_RR)
	h[0] = bond_lb_round_robin (vm, node, bif, b[0], n_slaves);
      else if (bif->lb == BOND_LB_BC)
	h[0] = bond_lb_broadcast (vm, node, bif, b[0], n_slaves);
      else
	{
	  ASSERT (0);
	}

      n_left -= 1;
      b += 1;
    }
}

static_always_inline void
bond_hash_to_port (u32 * h, u32 n_left, u32 n_slaves, int use_modulo_shortcut)
{
  u32 mask = n_slaves - 1;

#ifdef CLIB_HAVE_VEC256
  /* only lower 16 bits of hash due to single precision fp arithmetics */
  u32x8 mask8, sc8u, h8a, h8b;
  f32x8 sc8f;

  if (use_modulo_shortcut)
    {
      mask8 = u32x8_splat (mask);
    }
  else
    {
      mask8 = u32x8_splat (0xffff);
      sc8u = u32x8_splat (n_slaves);
      sc8f = f32x8_from_u32x8 (sc8u);
    }

  while (n_left > 16)
    {
      h8a = u32x8_load_unaligned (h) & mask8;
      h8b = u32x8_load_unaligned (h + 8) & mask8;

      if (use_modulo_shortcut == 0)
	{
	  h8a -= sc8u * u32x8_from_f32x8 (f32x8_from_u32x8 (h8a) / sc8f);
	  h8b -= sc8u * u32x8_from_f32x8 (f32x8_from_u32x8 (h8b) / sc8f);
	}

      u32x8_store_unaligned (h8a, h);
      u32x8_store_unaligned (h8b, h + 8);
      n_left -= 16;
      h += 16;
    }
#endif

  while (n_left > 4)
    {
      if (use_modulo_shortcut)
	{
	  h[0] &= mask;
	  h[1] &= mask;
	  h[2] &= mask;
	  h[3] &= mask;
	}
      else
	{
	  h[0] %= n_slaves;
	  h[1] %= n_slaves;
	  h[2] %= n_slaves;
	  h[3] %= n_slaves;
	}
      n_left -= 4;
      h += 4;
    }
  while (n_left)
    {
      if (use_modulo_shortcut)
	h[0] &= mask;
      else
	h[0] %= n_slaves;
      n_left -= 1;
      h += 1;
    }
}

static_always_inline void
bond_update_sw_if_index (bond_per_thread_data_t * ptd, bond_if_t * bif,
			 u32 * bi, vlib_buffer_t ** b, u32 * data, u32 n_left,
			 int single_sw_if_index)
{
  u32 sw_if_index = data[0];
  u32 *h = data;

  while (n_left >= 4)
    {
      // Prefetch next iteration
      if (n_left >= 8)
	{
	  vlib_buffer_t **pb = b + 4;
	  vlib_prefetch_buffer_header (pb[0], LOAD);
	  vlib_prefetch_buffer_header (pb[1], LOAD);
	  vlib_prefetch_buffer_header (pb[2], LOAD);
	  vlib_prefetch_buffer_header (pb[3], LOAD);
	}

      if (PREDICT_FALSE (single_sw_if_index))
	{
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = sw_if_index;
	  vnet_buffer (b[1])->sw_if_index[VLIB_TX] = sw_if_index;
	  vnet_buffer (b[2])->sw_if_index[VLIB_TX] = sw_if_index;
	  vnet_buffer (b[3])->sw_if_index[VLIB_TX] = sw_if_index;

	  bond_tx_add_to_queue (ptd, 0, bi[0]);
	  bond_tx_add_to_queue (ptd, 0, bi[1]);
	  bond_tx_add_to_queue (ptd, 0, bi[2]);
	  bond_tx_add_to_queue (ptd, 0, bi[3]);
	}
      else
	{
	  u32 sw_if_index[4];

	  sw_if_index[0] = *vec_elt_at_index (bif->active_slaves, h[0]);
	  sw_if_index[1] = *vec_elt_at_index (bif->active_slaves, h[1]);
	  sw_if_index[2] = *vec_elt_at_index (bif->active_slaves, h[2]);
	  sw_if_index[3] = *vec_elt_at_index (bif->active_slaves, h[3]);

	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = sw_if_index[0];
	  vnet_buffer (b[1])->sw_if_index[VLIB_TX] = sw_if_index[1];
	  vnet_buffer (b[2])->sw_if_index[VLIB_TX] = sw_if_index[2];
	  vnet_buffer (b[3])->sw_if_index[VLIB_TX] = sw_if_index[3];

	  bond_tx_add_to_queue (ptd, h[0], bi[0]);
	  bond_tx_add_to_queue (ptd, h[1], bi[1]);
	  bond_tx_add_to_queue (ptd, h[2], bi[2]);
	  bond_tx_add_to_queue (ptd, h[3], bi[3]);
	}

      bi += 4;
      h += 4;
      b += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      if (PREDICT_FALSE (single_sw_if_index))
	{
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = sw_if_index;
	  bond_tx_add_to_queue (ptd, 0, bi[0]);
	}
      else
	{
	  u32 sw_if_index0 = *vec_elt_at_index (bif->active_slaves, h[0]);

	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = sw_if_index0;
	  bond_tx_add_to_queue (ptd, h[0], bi[0]);
	}

      bi += 1;
      h += 1;
      b += 1;
      n_left -= 1;
    }
}

static_always_inline void
bond_tx_trace (vlib_main_t * vm, vlib_node_runtime_t * node, bond_if_t * bif,
	       vlib_buffer_t ** b, u32 n_left, u32 * h)
{
  uword n_trace = vlib_get_trace_count (vm, node);

  while (n_trace > 0 && n_left > 0)
    {
      bond_packet_trace_t *t0;
      ethernet_header_t *eth;
      u32 next0 = 0;

      vlib_trace_buffer (vm, node, next0, b[0], 0 /* follow_chain */ );
      vlib_set_trace_count (vm, node, --n_trace);
      t0 = vlib_add_trace (vm, node, b[0], sizeof (*t0));
      eth = (ethernet_header_t *) vlib_buffer_get_current (b[0]);
      t0->ethernet = *eth;
      t0->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
      if (!h)
	{
	  t0->bond_sw_if_index = *vec_elt_at_index (bif->active_slaves, 0);
	}
      else
	{
	  t0->bond_sw_if_index = *vec_elt_at_index (bif->active_slaves, h[0]);
	  h++;
	}
      b++;
      n_left--;
    }
}

VNET_DEVICE_CLASS_TX_FN (bond_dev_class) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
  vnet_interface_output_runtime_t *rund = (void *) node->runtime_data;
  bond_main_t *bm = &bond_main;
  u16 thread_index = vm->thread_index;
  bond_if_t *bif = pool_elt_at_index (bm->interfaces, rund->dev_instance);
  uword n_slaves;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 hashes[VLIB_FRAME_SIZE], *h;
  vnet_main_t *vnm = vnet_get_main ();
  bond_per_thread_data_t *ptd = vec_elt_at_index (bm->per_thread_data,
						  thread_index);
  u32 p, sw_if_index;

  if (PREDICT_FALSE (bif->admin_up == 0))
    {
      vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);
      vlib_increment_simple_counter (vnet_main.interface_main.sw_if_counters +
				     VNET_INTERFACE_COUNTER_DROP,
				     thread_index, bif->sw_if_index,
				     frame->n_vectors);
      vlib_error_count (vm, node->node_index, BOND_TX_ERROR_IF_DOWN,
			frame->n_vectors);
      return frame->n_vectors;
    }

  n_slaves = vec_len (bif->active_slaves);
  if (PREDICT_FALSE (n_slaves == 0))
    {
      vlib_buffer_free (vm, vlib_frame_vector_args (frame), frame->n_vectors);
      vlib_increment_simple_counter (vnet_main.interface_main.sw_if_counters +
				     VNET_INTERFACE_COUNTER_DROP,
				     thread_index, bif->sw_if_index,
				     frame->n_vectors);
      vlib_error_count (vm, node->node_index, BOND_TX_ERROR_NO_SLAVE,
			frame->n_vectors);
      return frame->n_vectors;
    }

  vlib_get_buffers (vm, from, bufs, n_left);

  /* active-backup mode, ship everyting to first sw if index */
  if ((bif->lb == BOND_LB_AB) || PREDICT_FALSE (n_slaves == 1))
    {
      sw_if_index = *vec_elt_at_index (bif->active_slaves, 0);

      bond_tx_trace (vm, node, bif, bufs, frame->n_vectors, 0);
      bond_update_sw_if_index (ptd, bif, from, bufs, &sw_if_index, n_left,
			       /* single_sw_if_index */ 1);
      goto done;
    }

  if (bif->lb == BOND_LB_BC)
    {
      sw_if_index = *vec_elt_at_index (bif->active_slaves, 0);

      bond_tx_inline (vm, node, bif, bufs, hashes, n_left, n_slaves,
		      BOND_LB_BC);
      bond_tx_trace (vm, node, bif, bufs, frame->n_vectors, 0);
      bond_update_sw_if_index (ptd, bif, from, bufs, &sw_if_index, n_left,
			       /* single_sw_if_index */ 1);
      goto done;
    }

  if (bif->lb == BOND_LB_L2)
    bond_tx_inline (vm, node, bif, bufs, hashes, n_left, n_slaves,
		    BOND_LB_L2);
  else if (bif->lb == BOND_LB_L34)
    bond_tx_inline (vm, node, bif, bufs, hashes, n_left, n_slaves,
		    BOND_LB_L34);
  else if (bif->lb == BOND_LB_L23)
    bond_tx_inline (vm, node, bif, bufs, hashes, n_left, n_slaves,
		    BOND_LB_L23);
  else if (bif->lb == BOND_LB_RR)
    bond_tx_inline (vm, node, bif, bufs, hashes, n_left, n_slaves,
		    BOND_LB_RR);
  else
    ASSERT (0);

  /* calculate port out of hash */
  h = hashes;
  if (BOND_MODULO_SHORTCUT (n_slaves))
    bond_hash_to_port (h, frame->n_vectors, n_slaves, 1);
  else
    bond_hash_to_port (h, frame->n_vectors, n_slaves, 0);

  bond_tx_trace (vm, node, bif, bufs, frame->n_vectors, h);

  bond_update_sw_if_index (ptd, bif, from, bufs, hashes, frame->n_vectors,
			   /* single_sw_if_index */ 0);

done:
  for (p = 0; p < n_slaves; p++)
    {
      vlib_frame_t *f;
      u32 *to_next;

      sw_if_index = *vec_elt_at_index (bif->active_slaves, p);
      if (PREDICT_TRUE (ptd->per_port_queue[p].n_buffers))
	{
	  f = vnet_get_frame_to_sw_interface (vnm, sw_if_index);
	  f->n_vectors = ptd->per_port_queue[p].n_buffers;
	  to_next = vlib_frame_vector_args (f);
	  clib_memcpy_fast (to_next, ptd->per_port_queue[p].buffers,
			    f->n_vectors * sizeof (u32));
	  vnet_put_frame_to_sw_interface (vnm, sw_if_index, f);
	  ptd->per_port_queue[p].n_buffers = 0;
	}
    }

  vlib_increment_simple_counter (vnet_main.interface_main.sw_if_counters
				 + VNET_INTERFACE_COUNTER_TX, thread_index,
				 bif->sw_if_index, frame->n_vectors);

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
  .tx_function_n_errors = BOND_TX_N_ERROR,
  .tx_function_error_strings = bond_tx_error_strings,
  .format_device_name = format_bond_interface_name,
  .set_l2_mode_function = bond_set_l2_mode_function,
  .admin_up_down_function = bond_interface_admin_up_down,
  .subif_add_del_function = bond_subif_add_del_function,
  .format_tx_trace = format_bond_tx_trace,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
