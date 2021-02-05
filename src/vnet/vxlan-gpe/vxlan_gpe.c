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
/**
 *  @file
 *  @brief Common utility functions for IPv4 and IPv6 VXLAN GPE tunnels
 *
*/
#include <vnet/vxlan-gpe/vxlan_gpe.h>
#include <vnet/fib/fib.h>
#include <vnet/ip/format.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/interface.h>
#include <vnet/udp/udp_local.h>
#include <vlib/vlib.h>

/**
 * @file
 * @brief VXLAN-GPE.
 *
 * VXLAN-GPE provides the features needed to allow L2 bridge domains (BDs)
 * to span multiple servers. This is done by building an L2 overlay on
 * top of an L3 network underlay using VXLAN-GPE tunnels.
 *
 * This makes it possible for servers to be co-located in the same data
 * center or be separated geographically as long as they are reachable
 * through the underlay L3 network.
 *
 * You can refer to this kind of L2 overlay bridge domain as a VXLAN-GPE segment.
 */

vxlan_gpe_main_t vxlan_gpe_main;

static u8 *
format_decap_next (u8 * s, va_list * args)
{
  vxlan_gpe_tunnel_t *t = va_arg (*args, vxlan_gpe_tunnel_t *);

  switch (t->protocol)
    {
    case VXLAN_GPE_PROTOCOL_IP4:
      s = format (s, "protocol ip4 fib-idx %d", t->decap_fib_index);
      break;
    case VXLAN_GPE_PROTOCOL_IP6:
      s = format (s, "protocol ip6 fib-idx %d", t->decap_fib_index);
      break;
    case VXLAN_GPE_PROTOCOL_ETHERNET:
      s = format (s, "protocol ethernet");
      break;
    case VXLAN_GPE_PROTOCOL_NSH:
      s = format (s, "protocol nsh");
      break;
    default:
      s = format (s, "protocol unknown %d", t->protocol);
    }

  return s;
}

/**
 * @brief Format function for VXLAN GPE tunnel
 *
 * @param *s formatting string
 * @param *args
 *
 * @return *s formatted string
 *
 */
u8 *
format_vxlan_gpe_tunnel (u8 * s, va_list * args)
{
  vxlan_gpe_tunnel_t *t = va_arg (*args, vxlan_gpe_tunnel_t *);
  vxlan_gpe_main_t *ngm = &vxlan_gpe_main;

  s = format (s,
	      "[%d] lcl %U rmt %U lcl_port %d rmt_port %d vni %d "
	      "fib-idx %d sw-if-idx %d ",
	      t - ngm->tunnels, format_ip46_address, &t->local, IP46_TYPE_ANY,
	      format_ip46_address, &t->remote, IP46_TYPE_ANY, t->local_port,
	      t->remote_port, t->vni, t->encap_fib_index, t->sw_if_index);

#if 0
  /* next_dpo not yet used by vxlan-gpe-encap node */
  s = format (s, "encap-dpo-idx %d ", t->next_dpo.dpoi_index);
  */
#endif
    s = format (s, "decap-next-%U ", format_decap_next, t);

  if (PREDICT_FALSE (ip46_address_is_multicast (&t->remote)))
    s = format (s, "mcast-sw-if-idx %d ", t->mcast_sw_if_index);

  return s;
}

/**
 * @brief Naming for VXLAN GPE tunnel
 *
 * @param *s formatting string
 * @param *args
 *
 * @return *s formatted string
 *
 */
static u8 *
format_vxlan_gpe_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "vxlan_gpe_tunnel%d", dev_instance);
}

/**
 * @brief CLI function for VXLAN GPE admin up/down
 *
 * @param *vnm
 * @param hw_if_index
 * @param flag
 *
 * @return *rc
 *
 */
static clib_error_t *
vxlan_gpe_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				   u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (vxlan_gpe_device_class,static) = {
  .name = "VXLAN_GPE",
  .format_device_name = format_vxlan_gpe_name,
  .format_tx_trace = format_vxlan_gpe_encap_trace,
  .admin_up_down_function = vxlan_gpe_interface_admin_up_down,
};
/* *INDENT-ON* */


/**
 * @brief Formatting function for tracing VXLAN GPE with length
 *
 * @param *s
 * @param *args
 *
 * @return *s
 *
 */
static u8 *
format_vxlan_gpe_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (vxlan_gpe_hw_class) = {
  .name = "VXLAN_GPE",
  .format_header = format_vxlan_gpe_header_with_length,
  .build_rewrite = default_build_rewrite,
};
/* *INDENT-ON* */

static void
vxlan_gpe_tunnel_restack_dpo (vxlan_gpe_tunnel_t * t)
{
  dpo_id_t dpo = DPO_INVALID;
  u32 encap_index = vxlan_gpe_encap_node.index;
  fib_forward_chain_type_t forw_type = ip46_address_is_ip4 (&t->remote) ?
    FIB_FORW_CHAIN_TYPE_UNICAST_IP4 : FIB_FORW_CHAIN_TYPE_UNICAST_IP6;

  fib_entry_contribute_forwarding (t->fib_entry_index, forw_type, &dpo);
  dpo_stack_from_node (encap_index, &t->next_dpo, &dpo);
  dpo_reset (&dpo);
}

static vxlan_gpe_tunnel_t *
vxlan_gpe_tunnel_from_fib_node (fib_node_t * node)
{
  ASSERT (FIB_NODE_TYPE_VXLAN_GPE_TUNNEL == node->fn_type);
  return ((vxlan_gpe_tunnel_t *) (((char *) node) -
				  STRUCT_OFFSET_OF (vxlan_gpe_tunnel_t,
						    node)));
}

/**
 * Function definition to backwalk a FIB node -
 * Here we will restack the new dpo of VXLAN_GPE DIP to encap node.
 */
static fib_node_back_walk_rc_t
vxlan_gpe_tunnel_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  vxlan_gpe_tunnel_restack_dpo (vxlan_gpe_tunnel_from_fib_node (node));
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
vxlan_gpe_tunnel_fib_node_get (fib_node_index_t index)
{
  vxlan_gpe_tunnel_t *t;
  vxlan_gpe_main_t *ngm = &vxlan_gpe_main;

  t = pool_elt_at_index (ngm->tunnels, index);

  return (&t->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
vxlan_gpe_tunnel_last_lock_gone (fib_node_t * node)
{
  /*
   * The VXLAN_GPE tunnel is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

/*
 * Virtual function table registered by VXLAN_GPE tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t vxlan_gpe_vft = {
  .fnv_get = vxlan_gpe_tunnel_fib_node_get,
  .fnv_last_lock = vxlan_gpe_tunnel_last_lock_gone,
  .fnv_back_walk = vxlan_gpe_tunnel_back_walk,
};

#define foreach_gpe_copy_field                                                \
  _ (vni)                                                                     \
  _ (protocol)                                                                \
  _ (mcast_sw_if_index)                                                       \
  _ (encap_fib_index)                                                         \
  _ (decap_fib_index)                                                         \
  _ (local_port)                                                              \
  _ (remote_port)

#define foreach_copy_ipv4 {                     \
  _(local.ip4.as_u32)                           \
  _(remote.ip4.as_u32)                          \
}

#define foreach_copy_ipv6 {                     \
  _(local.ip6.as_u64[0])                        \
  _(local.ip6.as_u64[1])                        \
  _(remote.ip6.as_u64[0])                       \
  _(remote.ip6.as_u64[1])                       \
}


/**
 * @brief Calculate IPv4 VXLAN GPE rewrite header
 *
 * @param *t
 *
 * @return rc
 *
 */
int
vxlan4_gpe_rewrite (vxlan_gpe_tunnel_t * t, u32 extension_size,
		    u8 protocol_override, uword encap_next_node)
{
  u8 *rw = 0;
  ip4_header_t *ip0;
  ip4_vxlan_gpe_header_t *h0;
  int len;

  len = sizeof (*h0) + extension_size;

  vec_free (t->rewrite);
  vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip4_vxlan_gpe_header_t *) rw;

  /* Fixed portion of the (outer) ip4 header */
  ip0 = &h0->ip4;
  ip0->ip_version_and_header_length = 0x45;
  ip0->ttl = 254;
  ip0->protocol = IP_PROTOCOL_UDP;

  /* we fix up the ip4 header length and checksum after-the-fact */
  ip0->src_address.as_u32 = t->local.ip4.as_u32;
  ip0->dst_address.as_u32 = t->remote.ip4.as_u32;
  ip0->checksum = ip4_header_checksum (ip0);

  /* UDP header, randomize src port on something, maybe? */
  h0->udp.src_port = clib_host_to_net_u16 (t->local_port);
  h0->udp.dst_port = clib_host_to_net_u16 (t->remote_port);

  /* VXLAN header. Are we having fun yet? */
  h0->vxlan.flags = VXLAN_GPE_FLAGS_I | VXLAN_GPE_FLAGS_P;
  h0->vxlan.ver_res = VXLAN_GPE_VERSION;
  if (protocol_override)
    {
      h0->vxlan.protocol = protocol_override;
    }
  else
    {
      h0->vxlan.protocol = t->protocol;
    }
  t->rewrite_size = sizeof (ip4_vxlan_gpe_header_t) + extension_size;
  h0->vxlan.vni_res = clib_host_to_net_u32 (t->vni << 8);

  t->rewrite = rw;
  t->encap_next_node = encap_next_node;
  return (0);
}

/**
 * @brief Calculate IPv6 VXLAN GPE rewrite header
 *
 * @param *t
 *
 * @return rc
 *
 */
int
vxlan6_gpe_rewrite (vxlan_gpe_tunnel_t * t, u32 extension_size,
		    u8 protocol_override, uword encap_next_node)
{
  u8 *rw = 0;
  ip6_header_t *ip0;
  ip6_vxlan_gpe_header_t *h0;
  int len;

  len = sizeof (*h0) + extension_size;

  vec_free (t->rewrite);
  vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

  h0 = (ip6_vxlan_gpe_header_t *) rw;

  /* Fixed portion of the (outer) ip4 header */
  ip0 = &h0->ip6;
  ip0->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (6 << 28);
  ip0->hop_limit = 255;
  ip0->protocol = IP_PROTOCOL_UDP;

  ip0->src_address.as_u64[0] = t->local.ip6.as_u64[0];
  ip0->src_address.as_u64[1] = t->local.ip6.as_u64[1];
  ip0->dst_address.as_u64[0] = t->remote.ip6.as_u64[0];
  ip0->dst_address.as_u64[1] = t->remote.ip6.as_u64[1];

  /* UDP header, randomize src port on something, maybe? */
  h0->udp.src_port = clib_host_to_net_u16 (t->local_port);
  h0->udp.dst_port = clib_host_to_net_u16 (t->remote_port);

  /* VXLAN header. Are we having fun yet? */
  h0->vxlan.flags = VXLAN_GPE_FLAGS_I | VXLAN_GPE_FLAGS_P;
  h0->vxlan.ver_res = VXLAN_GPE_VERSION;
  if (protocol_override)
    {
      h0->vxlan.protocol = t->protocol;
    }
  else
    {
      h0->vxlan.protocol = protocol_override;
    }
  t->rewrite_size = sizeof (ip4_vxlan_gpe_header_t) + extension_size;
  h0->vxlan.vni_res = clib_host_to_net_u32 (t->vni << 8);

  t->rewrite = rw;
  t->encap_next_node = encap_next_node;
  return (0);
}

/* *INDENT-OFF* */
typedef CLIB_PACKED(union {
  struct {
    fib_node_index_t mfib_entry_index;
    adj_index_t mcast_adj_index;
  };
  u64 as_u64;
}) mcast_shared_t;
/* *INDENT-ON* */

static inline mcast_shared_t
mcast_shared_get (ip46_address_t * ip)
{
  ASSERT (ip46_address_is_multicast (ip));
  uword *p = hash_get_mem (vxlan_gpe_main.mcast_shared, ip);
  ALWAYS_ASSERT (p);
  return (mcast_shared_t)
  {
  .as_u64 = *p};
}

static inline void
mcast_shared_add (ip46_address_t * remote,
		  fib_node_index_t mfei, adj_index_t ai)
{
  mcast_shared_t new_ep = {
    .mcast_adj_index = ai,
    .mfib_entry_index = mfei,
  };

  hash_set_mem_alloc (&vxlan_gpe_main.mcast_shared, remote, new_ep.as_u64);
}

static inline void
mcast_shared_remove (ip46_address_t * remote)
{
  mcast_shared_t ep = mcast_shared_get (remote);

  adj_unlock (ep.mcast_adj_index);
  mfib_table_entry_delete_index (ep.mfib_entry_index, MFIB_SOURCE_VXLAN_GPE);

  hash_unset_mem_free (&vxlan_gpe_main.mcast_shared, remote);
}

/**
 * @brief Add or Del a VXLAN GPE tunnel
 *
 * @param *a
 * @param *sw_if_index
 *
 * @return rc
 *
 */
int vnet_vxlan_gpe_add_del_tunnel
  (vnet_vxlan_gpe_add_del_tunnel_args_t * a, u32 * sw_if_indexp)
{
  vxlan_gpe_main_t *ngm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t = 0;
  vnet_main_t *vnm = ngm->vnet_main;
  vnet_hw_interface_t *hi;
  uword *p;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  int rv;
  vxlan4_gpe_tunnel_key_t key4, *key4_copy;
  vxlan6_gpe_tunnel_key_t key6, *key6_copy;
  u32 is_ip6 = a->is_ip6;

  /* Set udp-ports */
  if (a->local_port == 0)
    a->local_port = is_ip6 ? UDP_DST_PORT_VXLAN6_GPE : UDP_DST_PORT_VXLAN_GPE;

  if (a->remote_port == 0)
    a->remote_port = is_ip6 ? UDP_DST_PORT_VXLAN6_GPE : UDP_DST_PORT_VXLAN_GPE;

  if (!is_ip6)
    {
      key4.local = a->local.ip4.as_u32;
      key4.remote = a->remote.ip4.as_u32;
      key4.vni = clib_host_to_net_u32 (a->vni << 8);
      key4.port = (u32) clib_host_to_net_u16 (a->local_port);

      p = hash_get_mem (ngm->vxlan4_gpe_tunnel_by_key, &key4);
    }
  else
    {
      key6.local.as_u64[0] = a->local.ip6.as_u64[0];
      key6.local.as_u64[1] = a->local.ip6.as_u64[1];
      key6.remote.as_u64[0] = a->remote.ip6.as_u64[0];
      key6.remote.as_u64[1] = a->remote.ip6.as_u64[1];
      key6.vni = clib_host_to_net_u32 (a->vni << 8);
      key6.port = (u32) clib_host_to_net_u16 (a->local_port);

      p = hash_get_mem (ngm->vxlan6_gpe_tunnel_by_key, &key6);
    }

  if (a->is_add)
    {
      l2input_main_t *l2im = &l2input_main;

      /* adding a tunnel: tunnel must not already exist */
      if (p)
	return VNET_API_ERROR_TUNNEL_EXIST;

      pool_get_aligned (ngm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      clib_memset (t, 0, sizeof (*t));

      /* copy from arg structure */
/* *INDENT-OFF* */
#define _(x) t->x = a->x;
      foreach_gpe_copy_field;
      if (!a->is_ip6)
	foreach_copy_ipv4
      else
	foreach_copy_ipv6
#undef _
/* *INDENT-ON* */

      if (!a->is_ip6)
	t->flags |= VXLAN_GPE_TUNNEL_IS_IPV4;

      if (!a->is_ip6)
	{
	  rv = vxlan4_gpe_rewrite (t, 0, 0, VXLAN_GPE_ENCAP_NEXT_IP4_LOOKUP);
	}
      else
	{
	  rv = vxlan6_gpe_rewrite (t, 0, 0, VXLAN_GPE_ENCAP_NEXT_IP6_LOOKUP);
	}

      if (rv)
	{
	  pool_put (ngm->tunnels, t);
	  return rv;
	}

      if (!is_ip6)
	{
	  key4_copy = clib_mem_alloc (sizeof (*key4_copy));
	  clib_memcpy_fast (key4_copy, &key4, sizeof (*key4_copy));
	  hash_set_mem (ngm->vxlan4_gpe_tunnel_by_key, key4_copy,
			t - ngm->tunnels);
	}
      else
	{
	  key6_copy = clib_mem_alloc (sizeof (*key6_copy));
	  clib_memcpy_fast (key6_copy, &key6, sizeof (*key6_copy));
	  hash_set_mem (ngm->vxlan6_gpe_tunnel_by_key, key6_copy,
			t - ngm->tunnels);
	}

      if (vec_len (ngm->free_vxlan_gpe_tunnel_hw_if_indices) > 0)
	{
	  vnet_interface_main_t *im = &vnm->interface_main;
	  hw_if_index = ngm->free_vxlan_gpe_tunnel_hw_if_indices
	    [vec_len (ngm->free_vxlan_gpe_tunnel_hw_if_indices) - 1];
	  _vec_len (ngm->free_vxlan_gpe_tunnel_hw_if_indices) -= 1;

	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  hi->dev_instance = t - ngm->tunnels;
	  hi->hw_instance = hi->dev_instance;
	  /* clear old stats of freed tunnel before reuse */
	  sw_if_index = hi->sw_if_index;
	  vnet_interface_counter_lock (im);
	  vlib_zero_combined_counter
	    (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX],
	     sw_if_index);
	  vlib_zero_combined_counter (&im->combined_sw_if_counters
				      [VNET_INTERFACE_COUNTER_RX],
				      sw_if_index);
	  vlib_zero_simple_counter (&im->sw_if_counters
				    [VNET_INTERFACE_COUNTER_DROP],
				    sw_if_index);
	  vnet_interface_counter_unlock (im);
	}
      else
	{
	  hw_if_index = vnet_register_interface
	    (vnm, vxlan_gpe_device_class.index, t - ngm->tunnels,
	     vxlan_gpe_hw_class.index, t - ngm->tunnels);
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	}

      /* Set vxlan-gpe tunnel output node */
      u32 encap_index = vxlan_gpe_encap_node.index;
      vnet_set_interface_output_node (vnm, hw_if_index, encap_index);

      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index = hi->sw_if_index;
      vec_validate_init_empty (ngm->tunnel_index_by_sw_if_index, sw_if_index,
			       ~0);
      ngm->tunnel_index_by_sw_if_index[sw_if_index] = t - ngm->tunnels;

      /* setup l2 input config with l2 feature and bd 0 to drop packet */
      vec_validate (l2im->configs, sw_if_index);
      l2im->configs[sw_if_index].feature_bitmap = L2INPUT_FEAT_DROP;
      l2im->configs[sw_if_index].bd_index = 0;

      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
      si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
      fib_node_init (&t->node, FIB_NODE_TYPE_VXLAN_GPE_TUNNEL);
      fib_prefix_t tun_remote_pfx;
      vnet_flood_class_t flood_class = VNET_FLOOD_CLASS_TUNNEL_NORMAL;

      fib_prefix_from_ip46_addr (&t->remote, &tun_remote_pfx);
      if (!ip46_address_is_multicast (&t->remote))
	{
	  /* Unicast tunnel -
	   * source the FIB entry for the tunnel's destination
	   * and become a child thereof. The tunnel will then get poked
	   * when the forwarding for the entry updates, and the tunnel can
	   * re-stack accordingly
	   */
	  vtep_addr_ref (&ngm->vtep_table, t->encap_fib_index, &t->local);
	  t->fib_entry_index = fib_entry_track (t->encap_fib_index,
						&tun_remote_pfx,
						FIB_NODE_TYPE_VXLAN_GPE_TUNNEL,
						t - ngm->tunnels,
						&t->sibling_index);
	  vxlan_gpe_tunnel_restack_dpo (t);
	}
      else
	{
	  /* Multicast tunnel -
	   * as the same mcast group can be used for multiple mcast tunnels
	   * with different VNIs, create the output fib adjacency only if
	   * it does not already exist
	   */
	  fib_protocol_t fp = fib_ip_proto (is_ip6);

	  if (vtep_addr_ref (&ngm->vtep_table,
			     t->encap_fib_index, &t->remote) == 1)
	    {
	      fib_node_index_t mfei;
	      adj_index_t ai;
	      fib_route_path_t path = {
		.frp_proto = fib_proto_to_dpo (fp),
		.frp_addr = zero_addr,
		.frp_sw_if_index = 0xffffffff,
		.frp_fib_index = ~0,
		.frp_weight = 1,
		.frp_flags = FIB_ROUTE_PATH_LOCAL,
		.frp_mitf_flags = MFIB_ITF_FLAG_FORWARD,
	      };
	      const mfib_prefix_t mpfx = {
		.fp_proto = fp,
		.fp_len = (is_ip6 ? 128 : 32),
		.fp_grp_addr = tun_remote_pfx.fp_addr,
	      };

	      /*
	       * Setup the (*,G) to receive traffic on the mcast group
	       *  - the forwarding interface is for-us
	       *  - the accepting interface is that from the API
	       */
	      mfib_table_entry_path_update (t->encap_fib_index,
					    &mpfx,
					    MFIB_SOURCE_VXLAN_GPE, &path);

	      path.frp_sw_if_index = a->mcast_sw_if_index;
	      path.frp_flags = FIB_ROUTE_PATH_FLAG_NONE;
	      path.frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT;
	      mfei = mfib_table_entry_path_update (t->encap_fib_index,
						   &mpfx,
						   MFIB_SOURCE_VXLAN_GPE,
						   &path);

	      /*
	       * Create the mcast adjacency to send traffic to the group
	       */
	      ai = adj_mcast_add_or_lock (fp,
					  fib_proto_to_link (fp),
					  a->mcast_sw_if_index);

	      /*
	       * create a new end-point
	       */
	      mcast_shared_add (&t->remote, mfei, ai);
	    }

	  dpo_id_t dpo = DPO_INVALID;
	  mcast_shared_t ep = mcast_shared_get (&t->remote);

	  /* Stack shared mcast remote mac addr rewrite on encap */
	  dpo_set (&dpo, DPO_ADJACENCY_MCAST,
		   fib_proto_to_dpo (fp), ep.mcast_adj_index);

	  dpo_stack_from_node (encap_index, &t->next_dpo, &dpo);
	  dpo_reset (&dpo);
	  flood_class = VNET_FLOOD_CLASS_TUNNEL_MASTER;
	}

      vnet_get_sw_interface (vnet_get_main (), sw_if_index)->flood_class =
	flood_class;
    }
  else
    {
      /* deleting a tunnel: tunnel must exist */
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (ngm->tunnels, p[0]);

      sw_if_index = t->sw_if_index;
      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */ );
      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, t->sw_if_index);
      si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;
      set_int_l2_mode (ngm->vlib_main, vnm, MODE_L3, t->sw_if_index, 0,
		       L2_BD_PORT_TYPE_NORMAL, 0, 0);
      vec_add1 (ngm->free_vxlan_gpe_tunnel_hw_if_indices, t->hw_if_index);

      ngm->tunnel_index_by_sw_if_index[t->sw_if_index] = ~0;

      if (!is_ip6)
	hash_unset (ngm->vxlan4_gpe_tunnel_by_key, key4.as_u64);
      else
	hash_unset_mem_free (&ngm->vxlan6_gpe_tunnel_by_key, &key6);

      if (!ip46_address_is_multicast (&t->remote))
	{
	  vtep_addr_unref (&ngm->vtep_table, t->encap_fib_index, &t->local);
	  fib_entry_untrack (t->fib_entry_index, t->sibling_index);
	}
      else if (vtep_addr_unref (&ngm->vtep_table,
				t->encap_fib_index, &t->remote) == 0)
	{
	  mcast_shared_remove (&t->remote);
	}

      fib_node_deinit (&t->node);
      vec_free (t->rewrite);
      pool_put (ngm->tunnels, t);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  if (a->is_add)
    {
      /* register udp ports */
      if (!is_ip6 && !udp_is_valid_dst_port (a->local_port, 1))
	udp_register_dst_port (ngm->vlib_main, a->local_port,
			       vxlan4_gpe_input_node.index, 1 /* is_ip4 */);
      if (is_ip6 && !udp_is_valid_dst_port (a->remote_port, 0))
	udp_register_dst_port (ngm->vlib_main, a->remote_port,
			       vxlan6_gpe_input_node.index, 0 /* is_ip4 */);
    }

  return 0;
}

static clib_error_t *
vxlan_gpe_add_del_tunnel_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  ip46_address_t local, remote;
  u8 local_set = 0;
  u8 remote_set = 0;
  u8 grp_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u32 mcast_sw_if_index = ~0;
  u32 encap_fib_index = 0;
  u32 decap_fib_index = 0;
  u8 protocol = VXLAN_GPE_PROTOCOL_IP4;
  u32 vni;
  u8 vni_set = 0;
  u32 local_port = 0;
  u32 remote_port = 0;
  int rv;
  u32 tmp;
  vnet_vxlan_gpe_add_del_tunnel_args_t _a, *a = &_a;
  u32 sw_if_index;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "local %U",
			 unformat_ip4_address, &local.ip4))
	{
	  local_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "remote %U",
			 unformat_ip4_address, &remote.ip4))
	{
	  remote_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "local %U",
			 unformat_ip6_address, &local.ip6))
	{
	  local_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "remote %U",
			 unformat_ip6_address, &remote.ip6))
	{
	  remote_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "group %U %U",
			 unformat_ip4_address, &remote.ip4,
			 unformat_vnet_sw_interface,
			 vnet_get_main (), &mcast_sw_if_index))
	{
	  grp_set = remote_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "group %U %U",
			 unformat_ip6_address, &remote.ip6,
			 unformat_vnet_sw_interface,
			 vnet_get_main (), &mcast_sw_if_index))
	{
	  grp_set = remote_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "encap-vrf-id %d", &tmp))
	{
	  if (ipv6_set)
	    encap_fib_index = fib_table_find (FIB_PROTOCOL_IP6, tmp);
	  else
	    encap_fib_index = fib_table_find (FIB_PROTOCOL_IP4, tmp);

	  if (encap_fib_index == ~0)
	    {
	      error =
		clib_error_return (0, "nonexistent encap fib id %d", tmp);
	      goto done;
	    }
	}
      else if (unformat (line_input, "decap-vrf-id %d", &tmp))
	{
	  if (ipv6_set)
	    decap_fib_index = fib_table_find (FIB_PROTOCOL_IP6, tmp);
	  else
	    decap_fib_index = fib_table_find (FIB_PROTOCOL_IP4, tmp);

	  if (decap_fib_index == ~0)
	    {
	      error =
		clib_error_return (0, "nonexistent decap fib id %d", tmp);
	      goto done;
	    }
	}
      else if (unformat (line_input, "vni %d", &vni))
	vni_set = 1;
      else if (unformat (line_input, "local_port %d", &local_port))
	;
      else if (unformat (line_input, "remote_port %d", &remote_port))
	;
      else if (unformat (line_input, "next-ip4"))
	protocol = VXLAN_GPE_PROTOCOL_IP4;
      else if (unformat (line_input, "next-ip6"))
	protocol = VXLAN_GPE_PROTOCOL_IP6;
      else if (unformat (line_input, "next-ethernet"))
	protocol = VXLAN_GPE_PROTOCOL_ETHERNET;
      else if (unformat (line_input, "next-nsh"))
	protocol = VXLAN_GPE_PROTOCOL_NSH;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (local_set == 0)
    {
      error = clib_error_return (0, "tunnel local address not specified");
      goto done;
    }

  if (remote_set == 0)
    {
      error = clib_error_return (0, "tunnel remote address not specified");
      goto done;
    }

  if (grp_set && !ip46_address_is_multicast (&remote))
    {
      error = clib_error_return (0, "tunnel group address not multicast");
      goto done;
    }

  if (grp_set == 0 && ip46_address_is_multicast (&remote))
    {
      error = clib_error_return (0, "remote address must be unicast");
      goto done;
    }

  if (grp_set && mcast_sw_if_index == ~0)
    {
      error = clib_error_return (0, "tunnel nonexistent multicast device");
      goto done;
    }
  if (ipv4_set && ipv6_set)
    {
      error = clib_error_return (0, "both IPv4 and IPv6 addresses specified");
      goto done;
    }

  if ((ipv4_set && memcmp (&local.ip4, &remote.ip4, sizeof (local.ip4)) == 0)
      || (ipv6_set
	  && memcmp (&local.ip6, &remote.ip6, sizeof (local.ip6)) == 0))
    {
      error = clib_error_return (0, "src and remote addresses are identical");
      goto done;
    }

  if (vni_set == 0)
    {
      error = clib_error_return (0, "vni not specified");
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));

  a->is_add = is_add;
  a->is_ip6 = ipv6_set;

/* *INDENT-OFF* */
#define _(x) a->x = x;
  foreach_gpe_copy_field;
  if (ipv4_set)
    foreach_copy_ipv4
  else
    foreach_copy_ipv6
#undef _
/* *INDENT-ON* */

  rv = vnet_vxlan_gpe_add_del_tunnel (a, &sw_if_index);

  switch (rv)
    {
    case 0:
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);
      break;
    case VNET_API_ERROR_INVALID_DECAP_NEXT:
      error = clib_error_return (0, "invalid decap-next...");
      goto done;

    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "tunnel already exists...");
      goto done;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "tunnel does not exist...");
      goto done;

    default:
      error = clib_error_return
	(0, "vnet_vxlan_gpe_add_del_tunnel returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Add or delete a VXLAN-GPE Tunnel.
 *
 * VXLAN-GPE provides the features needed to allow L2 bridge domains (BDs)
 * to span multiple servers. This is done by building an L2 overlay on
 * top of an L3 network underlay using VXLAN-GPE tunnels.
 *
 * This makes it possible for servers to be co-located in the same data
 * center or be separated geographically as long as they are reachable
 * through the underlay L3 network.
 *
 * You can refer to this kind of L2 overlay bridge domain as a VXLAN-GPE segment.
 *
 * @cliexpar
 * Example of how to create a VXLAN-GPE Tunnel:
 * @cliexcmd{create vxlan-gpe tunnel local 10.0.3.1 remote 10.0.3.3 vni 13 encap-vrf-id 7}
 * Example of how to delete a VXLAN-GPE Tunnel:
 * @cliexcmd{create vxlan-gpe tunnel local 10.0.3.1 remote 10.0.3.3 vni 13 del}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_vxlan_gpe_tunnel_command, static) = {
  .path = "create vxlan-gpe tunnel",
  .short_help =
  "create vxlan-gpe tunnel local <local-addr> "
  " {remote <remote-addr>|group <mcast-addr> <intf-name>}"
  " vni <nn> [next-ip4][next-ip6][next-ethernet][next-nsh]"
  " [encap-vrf-id <nn>] [decap-vrf-id <nn>] [del]\n",
  .function = vxlan_gpe_add_del_tunnel_command_fn,
};
/* *INDENT-ON* */

/**
 * @brief CLI function for showing VXLAN GPE tunnels
 *
 * @param *vm
 * @param *input
 * @param *cmd
 *
 * @return error
 *
 */
static clib_error_t *
show_vxlan_gpe_tunnel_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  vxlan_gpe_main_t *ngm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t;

  if (pool_elts (ngm->tunnels) == 0)
    vlib_cli_output (vm, "No vxlan-gpe tunnels configured.");

  /* *INDENT-OFF* */
  pool_foreach (t, ngm->tunnels)
   {
    vlib_cli_output (vm, "%U", format_vxlan_gpe_tunnel, t);
  }
  /* *INDENT-ON* */

  return 0;
}

/*?
 * Display all the VXLAN-GPE Tunnel entries.
 *
 * @cliexpar
 * Example of how to display the VXLAN-GPE Tunnel entries:
 * @cliexstart{show vxlan-gpe tunnel}
 * [0] local 10.0.3.1 remote 10.0.3.3 vni 13 encap_fib_index 0 sw_if_index 5 decap_next l2
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_vxlan_gpe_tunnel_command, static) = {
    .path = "show vxlan-gpe",
    .function = show_vxlan_gpe_tunnel_command_fn,
};
/* *INDENT-ON* */

void
vnet_int_vxlan_gpe_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable)
{
  if (is_ip6)
    vnet_feature_enable_disable ("ip6-unicast", "ip6-vxlan-gpe-bypass",
				 sw_if_index, is_enable, 0, 0);
  else
    vnet_feature_enable_disable ("ip4-unicast", "ip4-vxlan-gpe-bypass",
				 sw_if_index, is_enable, 0, 0);
}


static clib_error_t *
set_ip_vxlan_gpe_bypass (u32 is_ip6,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index, is_enable;

  sw_if_index = ~0;
  is_enable = 1;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_user
	  (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_enable = 0;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (~0 == sw_if_index)
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  vnet_int_vxlan_gpe_bypass_mode (sw_if_index, is_ip6, is_enable);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
set_ip4_vxlan_gpe_bypass (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return set_ip_vxlan_gpe_bypass (0, input, cmd);
}

/*?
 * This command adds the 'ip4-vxlan-gpe-bypass' graph node for a given interface.
 * By adding the IPv4 vxlan-gpe-bypass graph node to an interface, the node checks
 *  for and validate input vxlan_gpe packet and bypass ip4-lookup, ip4-local,
 * ip4-udp-lookup nodes to speedup vxlan_gpe packet forwarding. This node will
 * cause extra overhead to for non-vxlan_gpe packets which is kept at a minimum.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before ip4-vxlan-gpe-bypass is enabled:
 * @cliexstart{show vlib graph ip4-vxlan-gpe-bypass}
 *            Name                      Next                    Previous
 * ip4-vxlan-gpe-bypass                error-drop [0]
 *                                vxlan4-gpe-input [1]
 *                                 ip4-lookup [2]
 * @cliexend
 *
 * Example of how to enable ip4-vxlan-gpe-bypass on an interface:
 * @cliexcmd{set interface ip vxlan-gpe-bypass GigabitEthernet2/0/0}
 *
 * Example of graph node after ip4-vxlan-gpe-bypass is enabled:
 * @cliexstart{show vlib graph ip4-vxlan-gpe-bypass}
 *            Name                      Next                    Previous
 * ip4-vxlan-gpe-bypass                error-drop [0]               ip4-input
 *                                vxlan4-gpe-input [1]        ip4-input-no-checksum
 *                                 ip4-lookup [2]
 * @cliexend
 *
 * Example of how to display the feature enabled on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 * ...
 * ipv4 unicast:
 *   ip4-vxlan-gpe-bypass
 *   ip4-lookup
 * ...
 * @cliexend
 *
 * Example of how to disable ip4-vxlan-gpe-bypass on an interface:
 * @cliexcmd{set interface ip vxlan-gpe-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip_vxlan_gpe_bypass_command, static) = {
  .path = "set interface ip vxlan-gpe-bypass",
  .function = set_ip4_vxlan_gpe_bypass,
  .short_help = "set interface ip vxlan-gpe-bypass <interface> [del]",
};
/* *INDENT-ON* */

static clib_error_t *
set_ip6_vxlan_gpe_bypass (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return set_ip_vxlan_gpe_bypass (1, input, cmd);
}

/*?
 * This command adds the 'ip6-vxlan-gpe-bypass' graph node for a given interface.
 * By adding the IPv6 vxlan-gpe-bypass graph node to an interface, the node checks
 *  for and validate input vxlan_gpe packet and bypass ip6-lookup, ip6-local,
 * ip6-udp-lookup nodes to speedup vxlan_gpe packet forwarding. This node will
 * cause extra overhead to for non-vxlan_gpe packets which is kept at a minimum.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before ip6-vxlan-gpe-bypass is enabled:
 * @cliexstart{show vlib graph ip6-vxlan-gpe-bypass}
 *            Name                      Next                    Previous
 * ip6-vxlan-gpe-bypass                error-drop [0]
 *                                vxlan6-gpe-input [1]
 *                                 ip6-lookup [2]
 * @cliexend
 *
 * Example of how to enable ip6-vxlan-gpe-bypass on an interface:
 * @cliexcmd{set interface ip6 vxlan-gpe-bypass GigabitEthernet2/0/0}
 *
 * Example of graph node after ip6-vxlan-gpe-bypass is enabled:
 * @cliexstart{show vlib graph ip6-vxlan-gpe-bypass}
 *            Name                      Next                    Previous
 * ip6-vxlan-gpe-bypass                error-drop [0]               ip6-input
 *                                vxlan6-gpe-input [1]        ip4-input-no-checksum
 *                                 ip6-lookup [2]
 * @cliexend
 *
 * Example of how to display the feature enabled on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 * ...
 * ipv6 unicast:
 *   ip6-vxlan-gpe-bypass
 *   ip6-lookup
 * ...
 * @cliexend
 *
 * Example of how to disable ip6-vxlan-gpe-bypass on an interface:
 * @cliexcmd{set interface ip6 vxlan-gpe-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip6_vxlan_gpe_bypass_command, static) = {
  .path = "set interface ip6 vxlan-gpe-bypass",
  .function = set_ip6_vxlan_gpe_bypass,
  .short_help = "set interface ip6 vxlan-gpe-bypass <interface> [del]",
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_vxlan_gpe_bypass, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "ip4-vxlan-gpe-bypass",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (ip6_vxlan_gpe_bypass, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "ip6-vxlan-gpe-bypass",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
/* *INDENT-ON* */

/**
 * @brief Feature init function for VXLAN GPE
 *
 * @param *vm
 *
 * @return error
 *
 */
clib_error_t *
vxlan_gpe_init (vlib_main_t * vm)
{
  vxlan_gpe_main_t *ngm = &vxlan_gpe_main;

  ngm->vnet_main = vnet_get_main ();
  ngm->vlib_main = vm;

  ngm->vxlan4_gpe_tunnel_by_key
    = hash_create_mem (0, sizeof (vxlan4_gpe_tunnel_key_t), sizeof (uword));

  ngm->vxlan6_gpe_tunnel_by_key
    = hash_create_mem (0, sizeof (vxlan6_gpe_tunnel_key_t), sizeof (uword));


  ngm->mcast_shared = hash_create_mem (0,
				       sizeof (ip46_address_t),
				       sizeof (mcast_shared_t));
  ngm->vtep_table = vtep_table_create ();

  /* Register the list of standard decap protocols supported */
  vxlan_gpe_register_decap_protocol (VXLAN_GPE_PROTOCOL_IP4,
				     VXLAN_GPE_INPUT_NEXT_IP4_INPUT);
  vxlan_gpe_register_decap_protocol (VXLAN_GPE_PROTOCOL_IP6,
				     VXLAN_GPE_INPUT_NEXT_IP6_INPUT);
  vxlan_gpe_register_decap_protocol (VXLAN_GPE_PROTOCOL_ETHERNET,
				     VXLAN_GPE_INPUT_NEXT_L2_INPUT);

  fib_node_register_type (FIB_NODE_TYPE_VXLAN_GPE_TUNNEL, &vxlan_gpe_vft);

  return 0;
}

VLIB_INIT_FUNCTION (vxlan_gpe_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
