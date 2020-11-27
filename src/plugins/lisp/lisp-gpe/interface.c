/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/**
 * @file
 * @brief Common utility functions for LISP-GPE interfaces.
 *
 */

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp_inlines.h>
#include <vnet/ethernet/ethernet.h>
#include <lisp/lisp-gpe/lisp_gpe.h>
#include <lisp/lisp-gpe/lisp_gpe_fwd_entry.h>
#include <lisp/lisp-gpe/lisp_gpe_tenant.h>
#include <lisp/lisp-gpe/lisp_gpe_adjacency.h>
#include <vnet/adj/adj.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <lisp/lisp-cp/lisp_cp_dpo.h>

/**
 * @brief The VLIB node arc/edge from the interface's TX node, to the L2
 * load-balanceing node. Which is where all packets go
 */
static uword l2_arc_to_lb;

#define foreach_lisp_gpe_tx_next        \
  _(DROP, "error-drop")                 \
  _(IP4_LOOKUP, "ip4-lookup")           \
  _(IP6_LOOKUP, "ip6-lookup")

typedef enum
{
#define _(sym,str) LISP_GPE_TX_NEXT_##sym,
  foreach_lisp_gpe_tx_next
#undef _
    LISP_GPE_TX_N_NEXT,
} lisp_gpe_tx_next_t;

typedef struct
{
  u32 tunnel_index;
} lisp_gpe_tx_trace_t;

u8 *
format_lisp_gpe_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lisp_gpe_tx_trace_t *t = va_arg (*args, lisp_gpe_tx_trace_t *);

  s = format (s, "LISP-GPE-TX: tunnel %d", t->tunnel_index);
  return s;
}

#define is_v4_packet(_h) ((*(u8*) _h) & 0xF0) == 0x40

/**
 * @brief LISP-GPE interface TX (encap) function.
 * @node lisp_gpe_interface_tx
 *
 * The LISP-GPE interface TX (encap) function.
 *
 * Looks up the associated tunnel based on the adjacency hit in the SD FIB
 * and if the tunnel is multihomed it uses the flow hash to determine
 * sub-tunnel, and rewrite string, to be used to encapsulate the packet.
 *
 * @param[in]   vm      vlib_main_t corresponding to the current thread.
 * @param[in]   node    vlib_node_runtime_t data for this node.
 * @param[in]   frame   vlib_frame_t whose contents should be dispatched.
 *
 * @return number of vectors in frame.
 */
static uword
lisp_gpe_interface_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  lisp_gpe_main_t *lgm = &lisp_gpe_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, adj_index0, next0;
	  const ip_adjacency_t *adj0;
	  const dpo_id_t *dpo0;
	  vlib_buffer_t *b0;
	  u8 is_v4_0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Fixup the checksum and len fields in the LISP tunnel encap
	   * that was applied at the midchain node */
	  is_v4_0 = is_v4_packet (vlib_buffer_get_current (b0));
	  ip_udp_fixup_one (lgm->vlib_main, b0, is_v4_0);

	  /* Follow the DPO on which the midchain is stacked */
	  adj_index0 = vnet_buffer (b0)->ip.adj_index;
	  adj0 = adj_get (adj_index0);
	  dpo0 = &adj0->sub_type.midchain.next_dpo;
	  next0 = dpo0->dpoi_next_node;
	  vnet_buffer (b0)->ip.adj_index = dpo0->dpoi_index;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      lisp_gpe_tx_trace_t *tr = vlib_add_trace (vm, node, b0,
							sizeof (*tr));
	      tr->tunnel_index = adj_index0;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static u8 *
format_lisp_gpe_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "lisp_gpe%d", dev_instance);
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (lisp_gpe_device_class) = {
  .name = "LISP_GPE",
  .format_device_name = format_lisp_gpe_name,
  .format_tx_trace = format_lisp_gpe_tx_trace,
  .tx_function = lisp_gpe_interface_tx,
};
/* *INDENT-ON* */

u8 *
format_lisp_gpe_header_with_length (u8 * s, va_list * args)
{
  lisp_gpe_header_t *h = va_arg (*args, lisp_gpe_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 header_bytes;

  header_bytes = sizeof (h[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "lisp-gpe header truncated");

  s = format (s, "flags: ");
#define _(n,v) if (h->flags & v) s = format (s, "%s ", #n);
  foreach_lisp_gpe_flag_bit;
#undef _

  s = format (s, "\n  ver_res %d res %d next_protocol %d iid %d(%x)",
	      h->ver_res, h->res, h->next_protocol,
	      clib_net_to_host_u32 (h->iid << 8),
	      clib_net_to_host_u32 (h->iid << 8));
  return s;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (lisp_gpe_hw_class) = {
  .name = "LISP_GPE",
  .format_header = format_lisp_gpe_header_with_length,
  .build_rewrite = lisp_gpe_build_rewrite,
  .update_adjacency = lisp_gpe_update_adjacency,
};
/* *INDENT-ON* */


typedef struct
{
  u32 dpo_index;
} l2_lisp_gpe_tx_trace_t;

static u8 *
format_l2_lisp_gpe_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_lisp_gpe_tx_trace_t *t = va_arg (*args, l2_lisp_gpe_tx_trace_t *);

  s = format (s, "L2-LISP-GPE-TX: load-balance %d", t->dpo_index);
  return s;
}

/**
 * @brief LISP-GPE interface TX (encap) function for L2 overlays.
 * @node l2_lisp_gpe_interface_tx
 *
 * The L2 LISP-GPE interface TX (encap) function.
 *
 * Uses bridge domain index, source and destination ethernet addresses to
 * lookup tunnel. If the tunnel is multihomed a flow has is used to determine
 * the sub-tunnel and therefore the rewrite string to be used to encapsulate
 * the packets.
 *
 * @param[in]   vm        vlib_main_t corresponding to the current thread.
 * @param[in]   node      vlib_node_runtime_t data for this node.
 * @param[in]   frame     vlib_frame_t whose contents should be dispatched.
 *
 * @return number of vectors in frame.
 */
static uword
l2_lisp_gpe_interface_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  lisp_gpe_main_t *lgm = &lisp_gpe_main;
  u32 thread_index = vm->thread_index;
  vlib_combined_counter_main_t *cm = &load_balance_main.lbm_to_counters;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 bi0, lbi0;
	  ethernet_header_t *e0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  e0 = vlib_buffer_get_current (b0);

	  vnet_buffer (b0)->lisp.overlay_afi = LISP_AFI_MAC;

	  /* lookup dst + src mac */
	  lbi0 = lisp_l2_fib_lookup (lgm, vnet_buffer (b0)->l2.bd_index,
				     e0->src_address, e0->dst_address);
	  vnet_buffer (b0)->ip.adj_index = lbi0;

	  vlib_increment_combined_counter (cm, thread_index, lbi0, 1,
					   vlib_buffer_length_in_chain (vm,
									b0));
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      l2_lisp_gpe_tx_trace_t *tr = vlib_add_trace (vm, node, b0,
							   sizeof (*tr));
	      tr->dpo_index = lbi0;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, l2_arc_to_lb);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static u8 *
format_l2_lisp_gpe_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "l2_lisp_gpe%d", dev_instance);
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (l2_lisp_gpe_device_class,static) = {
  .name = "L2_LISP_GPE",
  .format_device_name = format_l2_lisp_gpe_name,
  .format_tx_trace = format_l2_lisp_gpe_tx_trace,
  .tx_function = l2_lisp_gpe_interface_tx,
};
/* *INDENT-ON* */

typedef struct
{
  u32 dpo_index;
} nsh_lisp_gpe_tx_trace_t;

u8 *
format_nsh_lisp_gpe_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nsh_lisp_gpe_tx_trace_t *t = va_arg (*args, nsh_lisp_gpe_tx_trace_t *);

  s = format (s, "NSH-GPE-TX: tunnel %d", t->dpo_index);
  return s;
}

/**
 * @brief LISP-GPE interface TX for NSH overlays.
 * @node nsh_lisp_gpe_interface_tx
 *
 * The NSH LISP-GPE interface TX function.
 *
 * @param[in]   vm        vlib_main_t corresponding to the current thread.
 * @param[in]   node      vlib_node_runtime_t data for this node.
 * @param[in]   frame     vlib_frame_t whose contents should be dispatched.
 *
 * @return number of vectors in frame.
 */
static uword
nsh_lisp_gpe_interface_tx (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, *from, *to_next;
  lisp_gpe_main_t *lgm = &lisp_gpe_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 bi0;
	  u32 *nsh0, next0;
	  const dpo_id_t *dpo0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  nsh0 = vlib_buffer_get_current (b0);

	  vnet_buffer (b0)->lisp.overlay_afi = LISP_AFI_LCAF;

	  /* lookup SPI + SI (second word of the NSH header).
	   * NB: Load balancing was done by the control plane */
	  dpo0 = lisp_nsh_fib_lookup (lgm, nsh0[1]);

	  next0 = dpo0->dpoi_next_node;
	  vnet_buffer (b0)->ip.adj_index = dpo0->dpoi_index;

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      nsh_lisp_gpe_tx_trace_t *tr = vlib_add_trace (vm, node, b0,
							    sizeof (*tr));
	      tr->dpo_index = dpo0->dpoi_index;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static u8 *
format_nsh_lisp_gpe_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "nsh_lisp_gpe%d", dev_instance);
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (nsh_lisp_gpe_device_class,static) = {
  .name = "NSH_LISP_GPE",
  .format_device_name = format_nsh_lisp_gpe_name,
  .format_tx_trace = format_nsh_lisp_gpe_tx_trace,
  .tx_function = nsh_lisp_gpe_interface_tx,
};
/* *INDENT-ON* */

static vnet_hw_interface_t *
lisp_gpe_create_iface (lisp_gpe_main_t * lgm, u32 vni, u32 dp_table,
		       vnet_device_class_t * dev_class,
		       tunnel_lookup_t * tuns)
{
  u32 flen;
  u32 hw_if_index = ~0;
  u8 *new_name;
  vnet_hw_interface_t *hi;
  vnet_main_t *vnm = lgm->vnet_main;

  /* create hw lisp_gpeX iface if needed, otherwise reuse existing */
  flen = vec_len (lgm->free_tunnel_hw_if_indices);
  if (flen > 0)
    {
      hw_if_index = lgm->free_tunnel_hw_if_indices[flen - 1];
      _vec_len (lgm->free_tunnel_hw_if_indices) -= 1;

      hi = vnet_get_hw_interface (vnm, hw_if_index);

      /* rename interface */
      new_name = format (0, "%U", dev_class->format_device_name, vni);

      vec_add1 (new_name, 0);
      vnet_rename_interface (vnm, hw_if_index, (char *) new_name);
      vec_free (new_name);

      /* clear old stats of freed interface before reuse */
      vnet_interface_main_t *im = &vnm->interface_main;
      vnet_interface_counter_lock (im);
      vlib_zero_combined_counter (&im->combined_sw_if_counters
				  [VNET_INTERFACE_COUNTER_TX],
				  hi->sw_if_index);
      vlib_zero_combined_counter (&im->combined_sw_if_counters
				  [VNET_INTERFACE_COUNTER_RX],
				  hi->sw_if_index);
      vlib_zero_simple_counter (&im->sw_if_counters
				[VNET_INTERFACE_COUNTER_DROP],
				hi->sw_if_index);
      vnet_interface_counter_unlock (im);
    }
  else
    {
      hw_if_index = vnet_register_interface (vnm, dev_class->index, vni,
					     lisp_gpe_hw_class.index, 0);
      hi = vnet_get_hw_interface (vnm, hw_if_index);
    }

  hash_set (tuns->hw_if_index_by_dp_table, dp_table, hw_if_index);

  /* set tunnel termination: post decap, packets are tagged as having been
   * originated by lisp-gpe interface */
  hash_set (tuns->sw_if_index_by_vni, vni, hi->sw_if_index);
  hash_set (tuns->vni_by_sw_if_index, hi->sw_if_index, vni);

  return hi;
}

static void
lisp_gpe_remove_iface (lisp_gpe_main_t * lgm, u32 hi_index, u32 dp_table,
		       tunnel_lookup_t * tuns)
{
  vnet_main_t *vnm = lgm->vnet_main;
  vnet_hw_interface_t *hi;
  uword *vnip;

  hi = vnet_get_hw_interface (vnm, hi_index);

  /* disable interface */
  vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 0 /* down */ );
  vnet_hw_interface_set_flags (vnm, hi->hw_if_index, 0 /* down */ );
  hash_unset (tuns->hw_if_index_by_dp_table, dp_table);
  vec_add1 (lgm->free_tunnel_hw_if_indices, hi->hw_if_index);

  /* clean tunnel termination and vni to sw_if_index binding */
  vnip = hash_get (tuns->vni_by_sw_if_index, hi->sw_if_index);
  if (0 == vnip)
    {
      clib_warning ("No vni associated to interface %d", hi->sw_if_index);
      return;
    }
  hash_unset (tuns->sw_if_index_by_vni, vnip[0]);
  hash_unset (tuns->vni_by_sw_if_index, hi->sw_if_index);
}

static void
lisp_gpe_iface_set_table (u32 sw_if_index, u32 table_id)
{
  fib_node_index_t fib_index;

  fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, table_id,
						 FIB_SOURCE_LISP);
  vec_validate (ip4_main.fib_index_by_sw_if_index, sw_if_index);
  ip4_main.fib_index_by_sw_if_index[sw_if_index] = fib_index;
  ip4_sw_interface_enable_disable (sw_if_index, 1);

  fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6, table_id,
						 FIB_SOURCE_LISP);
  vec_validate (ip6_main.fib_index_by_sw_if_index, sw_if_index);
  ip6_main.fib_index_by_sw_if_index[sw_if_index] = fib_index;
  ip6_sw_interface_enable_disable (sw_if_index, 1);
}

static void
lisp_gpe_tenant_del_default_routes (u32 table_id)
{
  fib_protocol_t proto;

  FOR_EACH_FIB_IP_PROTOCOL (proto)
  {
    fib_prefix_t prefix = {
      .fp_proto = proto,
    };
    u32 fib_index;

    fib_index = fib_table_find (prefix.fp_proto, table_id);
    fib_table_entry_special_remove (fib_index, &prefix, FIB_SOURCE_LISP);
    fib_table_unlock (fib_index, prefix.fp_proto, FIB_SOURCE_LISP);
  }
}

static void
lisp_gpe_tenant_add_default_routes (u32 table_id)
{
  fib_protocol_t proto;

  FOR_EACH_FIB_IP_PROTOCOL (proto)
  {
    fib_prefix_t prefix = {
      .fp_proto = proto,
    };
    u32 fib_index;

    /*
     * Add a deafult route that results in a control plane punt DPO
     */
    fib_index = fib_table_find_or_create_and_lock (prefix.fp_proto, table_id,
						   FIB_SOURCE_LISP);
    fib_table_entry_special_dpo_add (fib_index, &prefix, FIB_SOURCE_LISP,
				     FIB_ENTRY_FLAG_EXCLUSIVE,
				     lisp_cp_dpo_get (fib_proto_to_dpo
						      (proto)));
  }
}


/**
 * @brief Add/del LISP-GPE L3 interface.
 *
 * Creates LISP-GPE interface, sets ingress arcs from lisp_gpeX_lookup,
 * installs default routes that attract all traffic with no more specific
 * routes to lgpe-ipx-lookup, set egress arcs to ipx-lookup, sets
 * the interface in the right vrf and enables it.
 *
 * @param[in]   lgm     Reference to @ref lisp_gpe_main_t.
 * @param[in]   a       Parameters to create interface.
 *
 * @return number of vectors in frame.
 */
u32
lisp_gpe_add_l3_iface (lisp_gpe_main_t * lgm, u32 vni, u32 table_id,
		       u8 with_default_routes)
{
  vnet_main_t *vnm = lgm->vnet_main;
  tunnel_lookup_t *l3_ifaces = &lgm->l3_ifaces;
  vnet_hw_interface_t *hi;
  uword *hip, *si;

  hip = hash_get (l3_ifaces->hw_if_index_by_dp_table, table_id);

  if (hip)
    {
      clib_warning ("vrf %d already mapped to a vni", table_id);
      return ~0;
    }

  si = hash_get (l3_ifaces->sw_if_index_by_vni, vni);

  if (si)
    {
      clib_warning ("Interface for vni %d already exists", vni);
    }

  /* create lisp iface and populate tunnel tables */
  hi = lisp_gpe_create_iface (lgm, vni, table_id,
			      &lisp_gpe_device_class, l3_ifaces);

  /* insert default routes that point to lisp-cp lookup */
  lisp_gpe_iface_set_table (hi->sw_if_index, table_id);
  if (with_default_routes)
    lisp_gpe_tenant_add_default_routes (table_id);

  /* enable interface */
  vnet_sw_interface_set_flags (vnm, hi->sw_if_index,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  vnet_hw_interface_set_flags (vnm, hi->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);

  return (hi->sw_if_index);
}

void
lisp_gpe_del_l3_iface (lisp_gpe_main_t * lgm, u32 vni, u32 table_id)
{
  vnet_main_t *vnm = lgm->vnet_main;
  tunnel_lookup_t *l3_ifaces = &lgm->l3_ifaces;
  vnet_hw_interface_t *hi;
  uword *hip;

  hip = hash_get (l3_ifaces->hw_if_index_by_dp_table, table_id);

  if (hip == 0)
    {
      clib_warning ("The interface for vrf %d doesn't exist", table_id);
      return;
    }

  hi = vnet_get_hw_interface (vnm, hip[0]);

  lisp_gpe_remove_iface (lgm, hip[0], table_id, &lgm->l3_ifaces);

  /* unset default routes */
  ip4_sw_interface_enable_disable (hi->sw_if_index, 0);
  ip6_sw_interface_enable_disable (hi->sw_if_index, 0);
  lisp_gpe_tenant_del_default_routes (table_id);
}

/**
 * @brief Add/del LISP-GPE L2 interface.
 *
 * Creates LISP-GPE interface, sets it in L2 mode in the appropriate
 * bridge domain, sets egress arcs and enables it.
 *
 * @param[in]   lgm     Reference to @ref lisp_gpe_main_t.
 * @param[in]   a       Parameters to create interface.
 *
 * @return number of vectors in frame.
 */
u32
lisp_gpe_add_l2_iface (lisp_gpe_main_t * lgm, u32 vni, u32 bd_id)
{
  vnet_main_t *vnm = lgm->vnet_main;
  tunnel_lookup_t *l2_ifaces = &lgm->l2_ifaces;
  vnet_hw_interface_t *hi;
  uword *hip, *si;
  u16 bd_index;

  if (bd_id > L2_BD_ID_MAX)
    {
      clib_warning ("bridge domain ID %d exceed 16M limit", bd_id);
      return ~0;
    }

  bd_index = bd_find_or_add_bd_index (&bd_main, bd_id);
  hip = hash_get (l2_ifaces->hw_if_index_by_dp_table, bd_index);

  if (hip)
    {
      clib_warning ("bridge domain %d already mapped to a vni", bd_id);
      return ~0;
    }

  si = hash_get (l2_ifaces->sw_if_index_by_vni, vni);
  if (si)
    {
      clib_warning ("Interface for vni %d already exists", vni);
      return ~0;
    }

  /* create lisp iface and populate tunnel tables */
  hi = lisp_gpe_create_iface (lgm, vni, bd_index,
			      &l2_lisp_gpe_device_class, &lgm->l2_ifaces);

  /* enable interface */
  vnet_sw_interface_set_flags (vnm, hi->sw_if_index,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  vnet_hw_interface_set_flags (vnm, hi->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);

  l2_arc_to_lb = vlib_node_add_named_next (vlib_get_main (),
					   hi->tx_node_index,
					   "l2-load-balance");

  /* we're ready. add iface to l2 bridge domain */
  set_int_l2_mode (lgm->vlib_main, vnm, MODE_L2_BRIDGE, hi->sw_if_index,
		   bd_index, L2_BD_PORT_TYPE_NORMAL, 0, 0);

  return (hi->sw_if_index);
}

/**
 * @brief Add/del LISP-GPE L2 interface.
 *
 * Creates LISP-GPE interface, sets it in L2 mode in the appropriate
 * bridge domain, sets egress arcs and enables it.
 *
 * @param[in]   lgm     Reference to @ref lisp_gpe_main_t.
 * @param[in]   a       Parameters to create interface.
 *
 * @return number of vectors in frame.
 */
void
lisp_gpe_del_l2_iface (lisp_gpe_main_t * lgm, u32 vni, u32 bd_id)
{
  tunnel_lookup_t *l2_ifaces = &lgm->l2_ifaces;
  vnet_hw_interface_t *hi;

  u32 bd_index = bd_find_index (&bd_main, bd_id);
  ASSERT (bd_index != ~0);
  uword *hip = hash_get (l2_ifaces->hw_if_index_by_dp_table, bd_index);

  if (hip == 0)
    {
      clib_warning ("The interface for bridge domain %d doesn't exist",
		    bd_id);
      return;
    }

  /* Remove interface from bridge .. by enabling L3 mode */
  hi = vnet_get_hw_interface (lgm->vnet_main, hip[0]);
  set_int_l2_mode (lgm->vlib_main, lgm->vnet_main, MODE_L3, hi->sw_if_index,
		   0, L2_BD_PORT_TYPE_NORMAL, 0, 0);
  lisp_gpe_remove_iface (lgm, hip[0], bd_index, &lgm->l2_ifaces);
}

/**
 * @brief Add LISP-GPE NSH interface.
 *
 * Creates LISP-GPE interface, sets it in L3 mode.
 *
 * @param[in]   lgm     Reference to @ref lisp_gpe_main_t.
 * @param[in]   a       Parameters to create interface.
 *
 * @return sw_if_index.
 */
u32
vnet_lisp_gpe_add_nsh_iface (lisp_gpe_main_t * lgm)
{
  vnet_main_t *vnm = lgm->vnet_main;
  tunnel_lookup_t *nsh_ifaces = &lgm->nsh_ifaces;
  vnet_hw_interface_t *hi;
  uword *hip, *si;

  hip = hash_get (nsh_ifaces->hw_if_index_by_dp_table, 0);

  if (hip)
    {
      clib_warning ("NSH interface 0 already exists");
      return ~0;
    }

  si = hash_get (nsh_ifaces->sw_if_index_by_vni, 0);
  if (si)
    {
      clib_warning ("NSH interface already exists");
      return ~0;
    }

  /* create lisp iface and populate tunnel tables */
  hi = lisp_gpe_create_iface (lgm, 0, 0,
			      &nsh_lisp_gpe_device_class, &lgm->nsh_ifaces);

  /* enable interface */
  vnet_sw_interface_set_flags (vnm, hi->sw_if_index,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  vnet_hw_interface_set_flags (vnm, hi->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);

  return (hi->sw_if_index);
}

/**
 * @brief Del LISP-GPE NSH interface.
 *
 */
void
vnet_lisp_gpe_del_nsh_iface (lisp_gpe_main_t * lgm)
{
  tunnel_lookup_t *nsh_ifaces = &lgm->nsh_ifaces;
  uword *hip;

  hip = hash_get (nsh_ifaces->hw_if_index_by_dp_table, 0);

  if (hip == 0)
    {
      clib_warning ("The NSH 0 interface doesn't exist");
      return;
    }
  lisp_gpe_remove_iface (lgm, hip[0], 0, &lgm->nsh_ifaces);
}

static clib_error_t *
lisp_gpe_add_del_iface_command_fn (vlib_main_t * vm, unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 table_id, vni, bd_id;
  u8 vni_is_set = 0, vrf_is_set = 0, bd_index_is_set = 0;
  u8 nsh_iface = 0;
  clib_error_t *error = NULL;

  if (vnet_lisp_gpe_enable_disable_status () == 0)
    {
      return clib_error_return (0, "LISP is disabled");
    }

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "vrf %d", &table_id))
	{
	  vrf_is_set = 1;
	}
      else if (unformat (line_input, "vni %d", &vni))
	{
	  vni_is_set = 1;
	}
      else if (unformat (line_input, "bd %d", &bd_id))
	{
	  bd_index_is_set = 1;
	}
      else if (unformat (line_input, "nsh"))
	{
	  nsh_iface = 1;
	}
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (nsh_iface)
    {
      if (is_add)
	{
	  if (~0 == vnet_lisp_gpe_add_nsh_iface (&lisp_gpe_main))
	    {
	      error = clib_error_return (0, "NSH interface not created");
	      goto done;
	    }
	}
      else
	{
	  vnet_lisp_gpe_del_nsh_iface (&lisp_gpe_main);
	}
      goto done;
    }

  if (vrf_is_set && bd_index_is_set)
    {
      error = clib_error_return
	(0, "Cannot set both vrf and brdige domain index!");
      goto done;
    }

  if (!vni_is_set)
    {
      error = clib_error_return (0, "vni must be set!");
      goto done;
    }

  if (!vrf_is_set && !bd_index_is_set)
    {
      error =
	clib_error_return (0, "vrf or bridge domain index must be set!");
      goto done;
    }

  if (bd_index_is_set)
    {
      if (is_add)
	{
	  if (~0 == lisp_gpe_tenant_l2_iface_add_or_lock (vni, bd_id))
	    {
	      error = clib_error_return (0, "L2 interface not created");
	      goto done;
	    }
	}
      else
	lisp_gpe_tenant_l2_iface_unlock (vni);
    }
  else
    {
      if (is_add)
	{
	  if (~0 == lisp_gpe_tenant_l3_iface_add_or_lock (vni, table_id, 1
							  /* with_default_route */
	      ))
	    {
	      error = clib_error_return (0, "L3 interface not created");
	      goto done;
	    }
	}
      else
	lisp_gpe_tenant_l3_iface_unlock (vni);
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (add_del_lisp_gpe_iface_command, static) = {
  .path = "gpe iface",
  .short_help = "gpe iface add/del vni <vni> vrf <vrf>",
  .function = lisp_gpe_add_del_iface_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
