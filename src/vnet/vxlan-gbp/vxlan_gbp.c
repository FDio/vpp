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
#include <vnet/vxlan-gbp/vxlan_gbp.h>
#include <vnet/ip/format.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/adj/rewrite.h>
#include <vnet/interface.h>
#include <vlib/vlib.h>

/**
 * @file
 * @brief VXLAN GBP.
 *
 * VXLAN GBP provides the features of vxlan and carry group policy id.
 */
static vlib_punt_hdl_t punt_hdl;

vxlan_gbp_main_t vxlan_gbp_main;

u8 *
format_vxlan_gbp_tunnel_mode (u8 * s, va_list * args)
{
  vxlan_gbp_tunnel_mode_t mode = va_arg (*args, vxlan_gbp_tunnel_mode_t);

  switch (mode)
    {
    case VXLAN_GBP_TUNNEL_MODE_L2:
      s = format (s, "L2");
      break;
    case VXLAN_GBP_TUNNEL_MODE_L3:
      s = format (s, "L3");
      break;
    }
  return (s);
}

u8 *
format_vxlan_gbp_tunnel (u8 * s, va_list * args)
{
  vxlan_gbp_tunnel_t *t = va_arg (*args, vxlan_gbp_tunnel_t *);

  s = format (s,
	      "[%d] instance %d src %U dst %U vni %d fib-idx %d"
	      " sw-if-idx %d mode %U ",
	      t->dev_instance, t->user_instance,
	      format_ip46_address, &t->src, IP46_TYPE_ANY,
	      format_ip46_address, &t->dst, IP46_TYPE_ANY,
	      t->vni, t->encap_fib_index, t->sw_if_index,
	      format_vxlan_gbp_tunnel_mode, t->mode);

  s = format (s, "encap-dpo-idx %d ", t->next_dpo.dpoi_index);

  if (PREDICT_FALSE (ip46_address_is_multicast (&t->dst)))
    s = format (s, "mcast-sw-if-idx %d ", t->mcast_sw_if_index);

  return s;
}

static u8 *
format_vxlan_gbp_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;
  vxlan_gbp_tunnel_t *t;

  if (dev_instance == ~0)
    return format (s, "<cached-unused>");

  if (dev_instance >= vec_len (vxm->tunnels))
    return format (s, "<improperly-referenced>");

  t = pool_elt_at_index (vxm->tunnels, dev_instance);

  return format (s, "vxlan_gbp_tunnel%d", t->user_instance);
}

static clib_error_t *
vxlan_gbp_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index,
				   u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (vxlan_gbp_device_class, static) = {
  .name = "VXLAN-GBP",
  .format_device_name = format_vxlan_gbp_name,
  .format_tx_trace = format_vxlan_gbp_encap_trace,
  .admin_up_down_function = vxlan_gbp_interface_admin_up_down,
};
/* *INDENT-ON* */

static u8 *
format_vxlan_gbp_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (vxlan_gbp_hw_class) = {
  .name = "VXLAN-GBP",
  .format_header = format_vxlan_gbp_header_with_length,
  .build_rewrite = default_build_rewrite,
};
/* *INDENT-ON* */

static void
vxlan_gbp_tunnel_restack_dpo (vxlan_gbp_tunnel_t * t)
{
  u8 is_ip4 = ip46_address_is_ip4 (&t->dst);
  dpo_id_t dpo = DPO_INVALID;
  fib_forward_chain_type_t forw_type = is_ip4 ?
    FIB_FORW_CHAIN_TYPE_UNICAST_IP4 : FIB_FORW_CHAIN_TYPE_UNICAST_IP6;

  fib_entry_contribute_forwarding (t->fib_entry_index, forw_type, &dpo);

  /* vxlan_gbp uses the payload hash as the udp source port
   * hence the packet's hash is unknown
   * skip single bucket load balance dpo's */
  while (DPO_LOAD_BALANCE == dpo.dpoi_type)
    {
      load_balance_t *lb = load_balance_get (dpo.dpoi_index);
      if (lb->lb_n_buckets > 1)
	break;

      dpo_copy (&dpo, load_balance_get_bucket_i (lb, 0));
    }

  u32 encap_index = is_ip4 ?
    vxlan4_gbp_encap_node.index : vxlan6_gbp_encap_node.index;
  dpo_stack_from_node (encap_index, &t->next_dpo, &dpo);
  dpo_reset (&dpo);
}

static vxlan_gbp_tunnel_t *
vxlan_gbp_tunnel_from_fib_node (fib_node_t * node)
{
  ASSERT (FIB_NODE_TYPE_VXLAN_GBP_TUNNEL == node->fn_type);
  return ((vxlan_gbp_tunnel_t *) (((char *) node) -
				  STRUCT_OFFSET_OF (vxlan_gbp_tunnel_t,
						    node)));
}

/**
 * Function definition to backwalk a FIB node -
 * Here we will restack the new dpo of VXLAN DIP to encap node.
 */
static fib_node_back_walk_rc_t
vxlan_gbp_tunnel_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  vxlan_gbp_tunnel_restack_dpo (vxlan_gbp_tunnel_from_fib_node (node));
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
vxlan_gbp_tunnel_fib_node_get (fib_node_index_t index)
{
  vxlan_gbp_tunnel_t *t;
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;

  t = pool_elt_at_index (vxm->tunnels, index);

  return (&t->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
vxlan_gbp_tunnel_last_lock_gone (fib_node_t * node)
{
  /*
   * The VXLAN GBP tunnel is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

/*
 * Virtual function table registered by VXLAN GBP tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t vxlan_gbp_vft = {
  .fnv_get = vxlan_gbp_tunnel_fib_node_get,
  .fnv_last_lock = vxlan_gbp_tunnel_last_lock_gone,
  .fnv_back_walk = vxlan_gbp_tunnel_back_walk,
};


#define foreach_copy_field                      \
_(vni)                                          \
_(mode)                                         \
_(mcast_sw_if_index)                            \
_(encap_fib_index)                              \
_(src)                                          \
_(dst)

static void
vxlan_gbp_rewrite (vxlan_gbp_tunnel_t * t, bool is_ip6)
{
  union
  {
    ip4_vxlan_gbp_header_t h4;
    ip6_vxlan_gbp_header_t h6;
  } h;
  int len = is_ip6 ? sizeof h.h6 : sizeof h.h4;

  udp_header_t *udp;
  vxlan_gbp_header_t *vxlan_gbp;
  /* Fixed portion of the (outer) ip header */

  clib_memset (&h, 0, sizeof (h));
  if (!is_ip6)
    {
      ip4_header_t *ip = &h.h4.ip4;
      udp = &h.h4.udp, vxlan_gbp = &h.h4.vxlan_gbp;
      ip->ip_version_and_header_length = 0x45;
      ip->ttl = 254;
      ip->protocol = IP_PROTOCOL_UDP;

      ip->src_address = t->src.ip4;
      ip->dst_address = t->dst.ip4;

      /* we fix up the ip4 header length and checksum after-the-fact */
      ip->checksum = ip4_header_checksum (ip);
    }
  else
    {
      ip6_header_t *ip = &h.h6.ip6;
      udp = &h.h6.udp, vxlan_gbp = &h.h6.vxlan_gbp;
      ip->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (6 << 28);
      ip->hop_limit = 255;
      ip->protocol = IP_PROTOCOL_UDP;

      ip->src_address = t->src.ip6;
      ip->dst_address = t->dst.ip6;
    }

  /* UDP header, randomize src port on something, maybe? */
  udp->src_port = clib_host_to_net_u16 (47789);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_vxlan_gbp);

  /* VXLAN header */
  vxlan_gbp_set_header (vxlan_gbp, t->vni);
  vnet_rewrite_set_data (*t, &h, len);
}

static uword
vtep_addr_ref (ip46_address_t * ip)
{
  uword *vtep = ip46_address_is_ip4 (ip) ?
    hash_get (vxlan_gbp_main.vtep4, ip->ip4.as_u32) :
    hash_get_mem (vxlan_gbp_main.vtep6, &ip->ip6);
  if (vtep)
    return ++(*vtep);
  ip46_address_is_ip4 (ip) ?
    hash_set (vxlan_gbp_main.vtep4, ip->ip4.as_u32, 1) :
    hash_set_mem_alloc (&vxlan_gbp_main.vtep6, &ip->ip6, 1);
  return 1;
}

static uword
vtep_addr_unref (ip46_address_t * ip)
{
  uword *vtep = ip46_address_is_ip4 (ip) ?
    hash_get (vxlan_gbp_main.vtep4, ip->ip4.as_u32) :
    hash_get_mem (vxlan_gbp_main.vtep6, &ip->ip6);
  ASSERT (vtep);
  if (--(*vtep) != 0)
    return *vtep;
  ip46_address_is_ip4 (ip) ?
    hash_unset (vxlan_gbp_main.vtep4, ip->ip4.as_u32) :
    hash_unset_mem_free (&vxlan_gbp_main.vtep6, &ip->ip6);
  return 0;
}

/* *INDENT-OFF* */
typedef CLIB_PACKED(union
{
  struct
  {
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
  uword *p = hash_get_mem (vxlan_gbp_main.mcast_shared, ip);
  ASSERT (p);
  mcast_shared_t ret = {.as_u64 = *p };
  return ret;
}

static inline void
mcast_shared_add (ip46_address_t * dst, fib_node_index_t mfei, adj_index_t ai)
{
  mcast_shared_t new_ep = {
    .mcast_adj_index = ai,
    .mfib_entry_index = mfei,
  };

  hash_set_mem_alloc (&vxlan_gbp_main.mcast_shared, dst, new_ep.as_u64);
}

static inline void
mcast_shared_remove (ip46_address_t * dst)
{
  mcast_shared_t ep = mcast_shared_get (dst);

  adj_unlock (ep.mcast_adj_index);
  mfib_table_entry_delete_index (ep.mfib_entry_index, MFIB_SOURCE_VXLAN_GBP);

  hash_unset_mem_free (&vxlan_gbp_main.mcast_shared, dst);
}

inline void
vxlan_gbp_register_udp_ports (void)
{
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;

  if (vxm->udp_ports_registered == 0)
    {
      udp_register_dst_port (vxm->vlib_main, UDP_DST_PORT_vxlan_gbp,
			     vxlan4_gbp_input_node.index, /* is_ip4 */ 1);
      udp_register_dst_port (vxm->vlib_main, UDP_DST_PORT_vxlan6_gbp,
			     vxlan6_gbp_input_node.index, /* is_ip4 */ 0);
    }
  /*
   * Counts the number of vxlan_gbp tunnels
   */
  vxm->udp_ports_registered += 1;
}

inline void
vxlan_gbp_unregister_udp_ports (void)
{
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;

  ASSERT (vxm->udp_ports_registered != 0);

  if (vxm->udp_ports_registered == 1)
    {
      udp_unregister_dst_port (vxm->vlib_main, UDP_DST_PORT_vxlan_gbp,
			       /* is_ip4 */ 1);
      udp_unregister_dst_port (vxm->vlib_main, UDP_DST_PORT_vxlan6_gbp,
			       /* is_ip4 */ 0);
    }

  vxm->udp_ports_registered -= 1;
}

int vnet_vxlan_gbp_tunnel_add_del
  (vnet_vxlan_gbp_tunnel_add_del_args_t * a, u32 * sw_if_indexp)
{
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;
  vxlan_gbp_tunnel_t *t = 0;
  vnet_main_t *vnm = vxm->vnet_main;
  u64 *p;
  u32 sw_if_index = ~0;
  vxlan4_gbp_tunnel_key_t key4;
  vxlan6_gbp_tunnel_key_t key6;
  u32 is_ip6 = a->is_ip6;

  int not_found;
  if (!is_ip6)
    {
      key4.key[0] = ip46_address_is_multicast (&a->dst) ?
	a->dst.ip4.as_u32 :
	a->dst.ip4.as_u32 | (((u64) a->src.ip4.as_u32) << 32);
      key4.key[1] = (((u64) a->encap_fib_index) << 32)
	| clib_host_to_net_u32 (a->vni << 8);
      not_found =
	clib_bihash_search_inline_16_8 (&vxm->vxlan4_gbp_tunnel_by_key,
					&key4);
      p = &key4.value;
    }
  else
    {
      key6.key[0] = a->dst.ip6.as_u64[0];
      key6.key[1] = a->dst.ip6.as_u64[1];
      key6.key[2] = (((u64) a->encap_fib_index) << 32)
	| clib_host_to_net_u32 (a->vni << 8);
      not_found =
	clib_bihash_search_inline_24_8 (&vxm->vxlan6_gbp_tunnel_by_key,
					&key6);
      p = &key6.value;
    }

  if (not_found)
    p = 0;

  if (a->is_add)
    {
      l2input_main_t *l2im = &l2input_main;
      u32 dev_instance;		/* real dev instance tunnel index */
      u32 user_instance;	/* request and actual instance number */

      /* adding a tunnel: tunnel must not already exist */
      if (p)
	{
	  t = pool_elt_at_index (vxm->tunnels, *p);
	  *sw_if_indexp = t->sw_if_index;
	  return VNET_API_ERROR_TUNNEL_EXIST;
	}
      pool_get_aligned (vxm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      clib_memset (t, 0, sizeof (*t));
      dev_instance = t - vxm->tunnels;

      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _

      vxlan_gbp_rewrite (t, is_ip6);
      /*
       * Reconcile the real dev_instance and a possible requested instance.
       */
      user_instance = a->instance;
      if (user_instance == ~0)
	user_instance = dev_instance;
      if (hash_get (vxm->instance_used, user_instance))
	{
	  pool_put (vxm->tunnels, t);
	  return VNET_API_ERROR_INSTANCE_IN_USE;
	}
      hash_set (vxm->instance_used, user_instance, 1);

      t->dev_instance = dev_instance;	/* actual */
      t->user_instance = user_instance;	/* name */

      /* copy the key */
      int add_failed;
      if (is_ip6)
	{
	  key6.value = (u64) dev_instance;
	  add_failed =
	    clib_bihash_add_del_24_8 (&vxm->vxlan6_gbp_tunnel_by_key, &key6,
				      1 /*add */ );
	}
      else
	{
	  key4.value = (u64) dev_instance;
	  add_failed =
	    clib_bihash_add_del_16_8 (&vxm->vxlan4_gbp_tunnel_by_key, &key4,
				      1 /*add */ );
	}

      if (add_failed)
	{
	  pool_put (vxm->tunnels, t);
	  return VNET_API_ERROR_INVALID_REGISTRATION;
	}

      vxlan_gbp_register_udp_ports ();

      t->hw_if_index = vnet_register_interface
	(vnm, vxlan_gbp_device_class.index, dev_instance,
	 vxlan_gbp_hw_class.index, dev_instance);
      vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, t->hw_if_index);

      /* Set vxlan_gbp tunnel output node */
      u32 encap_index = !is_ip6 ?
	vxlan4_gbp_encap_node.index : vxlan6_gbp_encap_node.index;
      vnet_set_interface_output_node (vnm, t->hw_if_index, encap_index);

      t->sw_if_index = sw_if_index = hi->sw_if_index;

      if (VXLAN_GBP_TUNNEL_MODE_L3 == t->mode)
	{
	  ip4_sw_interface_enable_disable (t->sw_if_index, 1);
	  ip6_sw_interface_enable_disable (t->sw_if_index, 1);
	}

      vec_validate_init_empty (vxm->tunnel_index_by_sw_if_index, sw_if_index,
			       ~0);
      vxm->tunnel_index_by_sw_if_index[sw_if_index] = dev_instance;

      /* setup l2 input config with l2 feature and bd 0 to drop packet */
      vec_validate (l2im->configs, sw_if_index);
      l2im->configs[sw_if_index].feature_bitmap = L2INPUT_FEAT_DROP;
      l2im->configs[sw_if_index].bd_index = 0;

      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
      si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
      vnet_sw_interface_set_flags (vnm, sw_if_index,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);

      fib_node_init (&t->node, FIB_NODE_TYPE_VXLAN_GBP_TUNNEL);
      fib_prefix_t tun_dst_pfx;
      vnet_flood_class_t flood_class = VNET_FLOOD_CLASS_TUNNEL_NORMAL;

      fib_prefix_from_ip46_addr (&t->dst, &tun_dst_pfx);
      if (!ip46_address_is_multicast (&t->dst))
	{
	  /* Unicast tunnel -
	   * source the FIB entry for the tunnel's destination
	   * and become a child thereof. The tunnel will then get poked
	   * when the forwarding for the entry updates, and the tunnel can
	   * re-stack accordingly
	   */
	  vtep_addr_ref (&t->src);
	  t->fib_entry_index = fib_table_entry_special_add
	    (t->encap_fib_index, &tun_dst_pfx, FIB_SOURCE_RR,
	     FIB_ENTRY_FLAG_NONE);
	  t->sibling_index = fib_entry_child_add
	    (t->fib_entry_index, FIB_NODE_TYPE_VXLAN_GBP_TUNNEL,
	     dev_instance);
	  vxlan_gbp_tunnel_restack_dpo (t);
	}
      else
	{
	  /* Multicast tunnel -
	   * as the same mcast group can be used for multiple mcast tunnels
	   * with different VNIs, create the output fib adjacency only if
	   * it does not already exist
	   */
	  fib_protocol_t fp = fib_ip_proto (is_ip6);

	  if (vtep_addr_ref (&t->dst) == 1)
	    {
	      fib_node_index_t mfei;
	      adj_index_t ai;
	      fib_route_path_t path = {
		.frp_proto = fib_proto_to_dpo (fp),
		.frp_addr = zero_addr,
		.frp_sw_if_index = 0xffffffff,
		.frp_fib_index = ~0,
		.frp_weight = 0,
		.frp_flags = FIB_ROUTE_PATH_LOCAL,
	      };
	      const mfib_prefix_t mpfx = {
		.fp_proto = fp,
		.fp_len = (is_ip6 ? 128 : 32),
		.fp_grp_addr = tun_dst_pfx.fp_addr,
	      };

	      /*
	       * Setup the (*,G) to receive traffic on the mcast group
	       *  - the forwarding interface is for-us
	       *  - the accepting interface is that from the API
	       */
	      mfib_table_entry_path_update (t->encap_fib_index,
					    &mpfx,
					    MFIB_SOURCE_VXLAN_GBP,
					    &path, MFIB_ITF_FLAG_FORWARD);

	      path.frp_sw_if_index = a->mcast_sw_if_index;
	      path.frp_flags = FIB_ROUTE_PATH_FLAG_NONE;
	      mfei = mfib_table_entry_path_update (t->encap_fib_index,
						   &mpfx,
						   MFIB_SOURCE_VXLAN_GBP,
						   &path,
						   MFIB_ITF_FLAG_ACCEPT);

	      /*
	       * Create the mcast adjacency to send traffic to the group
	       */
	      ai = adj_mcast_add_or_lock (fp,
					  fib_proto_to_link (fp),
					  a->mcast_sw_if_index);

	      /*
	       * create a new end-point
	       */
	      mcast_shared_add (&t->dst, mfei, ai);
	    }

	  dpo_id_t dpo = DPO_INVALID;
	  mcast_shared_t ep = mcast_shared_get (&t->dst);

	  /* Stack shared mcast dst mac addr rewrite on encap */
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

      u32 instance = p[0];
      t = pool_elt_at_index (vxm->tunnels, instance);

      sw_if_index = t->sw_if_index;
      vnet_sw_interface_set_flags (vnm, sw_if_index, 0 /* down */ );

      if (VXLAN_GBP_TUNNEL_MODE_L3 == t->mode)
	{
	  ip4_sw_interface_enable_disable (t->sw_if_index, 0);
	  ip6_sw_interface_enable_disable (t->sw_if_index, 0);
	}

      vxm->tunnel_index_by_sw_if_index[sw_if_index] = ~0;

      if (!is_ip6)
	clib_bihash_add_del_16_8 (&vxm->vxlan4_gbp_tunnel_by_key, &key4,
				  0 /*del */ );
      else
	clib_bihash_add_del_24_8 (&vxm->vxlan6_gbp_tunnel_by_key, &key6,
				  0 /*del */ );

      if (!ip46_address_is_multicast (&t->dst))
	{
	  vtep_addr_unref (&t->src);
	  fib_entry_child_remove (t->fib_entry_index, t->sibling_index);
	  fib_table_entry_delete_index (t->fib_entry_index, FIB_SOURCE_RR);
	}
      else if (vtep_addr_unref (&t->dst) == 0)
	{
	  mcast_shared_remove (&t->dst);
	}

      vxlan_gbp_unregister_udp_ports ();
      vnet_delete_hw_interface (vnm, t->hw_if_index);
      hash_unset (vxm->instance_used, t->user_instance);

      fib_node_deinit (&t->node);
      pool_put (vxm->tunnels, t);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}

int
vnet_vxlan_gbp_tunnel_del (u32 sw_if_index)
{
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;
  vxlan_gbp_tunnel_t *t = 0;
  u32 ti;

  if (sw_if_index >= vec_len (vxm->tunnel_index_by_sw_if_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  ti = vxm->tunnel_index_by_sw_if_index[sw_if_index];
  if (~0 != ti)
    {
      t = pool_elt_at_index (vxm->tunnels, ti);

      vnet_vxlan_gbp_tunnel_add_del_args_t args = {
	.is_add = 0,
	.is_ip6 = !ip46_address_is_ip4 (&t->src),
	.vni = t->vni,
	.src = t->src,
	.dst = t->dst,
	.instance = ~0,
      };

      return (vnet_vxlan_gbp_tunnel_add_del (&args, NULL));
    }

  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

static uword
get_decap_next_for_node (u32 node_index, u32 ipv4_set)
{
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;
  vlib_main_t *vm = vxm->vlib_main;
  uword input_node = (ipv4_set) ? vxlan4_gbp_input_node.index :
    vxlan6_gbp_input_node.index;

  return vlib_node_add_next (vm, input_node, node_index);
}

static uword
unformat_decap_next (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 ipv4_set = va_arg (*args, int);
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;
  vlib_main_t *vm = vxm->vlib_main;
  u32 node_index;
  u32 tmp;

  if (unformat (input, "l2"))
    *result = VXLAN_GBP_INPUT_NEXT_L2_INPUT;
  else if (unformat (input, "node %U", unformat_vlib_node, vm, &node_index))
    *result = get_decap_next_for_node (node_index, ipv4_set);
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static clib_error_t *
vxlan_gbp_tunnel_add_del_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t src = ip46_address_initializer, dst =
    ip46_address_initializer;
  vxlan_gbp_tunnel_mode_t mode = VXLAN_GBP_TUNNEL_MODE_L2;
  u8 is_add = 1;
  u8 src_set = 0;
  u8 dst_set = 0;
  u8 grp_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u32 instance = ~0;
  u32 encap_fib_index = 0;
  u32 mcast_sw_if_index = ~0;
  u32 decap_next_index = VXLAN_GBP_INPUT_NEXT_L2_INPUT;
  u32 vni = 0;
  u32 table_id;
  clib_error_t *parse_error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (line_input, "instance %d", &instance))
	;
      else if (unformat (line_input, "src %U",
			 unformat_ip46_address, &src, IP46_TYPE_ANY))
	{
	  src_set = 1;
	  ip46_address_is_ip4 (&src) ? (ipv4_set = 1) : (ipv6_set = 1);
	}
      else if (unformat (line_input, "dst %U",
			 unformat_ip46_address, &dst, IP46_TYPE_ANY))
	{
	  dst_set = 1;
	  ip46_address_is_ip4 (&dst) ? (ipv4_set = 1) : (ipv6_set = 1);
	}
      else if (unformat (line_input, "group %U %U",
			 unformat_ip46_address, &dst, IP46_TYPE_ANY,
			 unformat_vnet_sw_interface,
			 vnet_get_main (), &mcast_sw_if_index))
	{
	  grp_set = dst_set = 1;
	  ip46_address_is_ip4 (&dst) ? (ipv4_set = 1) : (ipv6_set = 1);
	}
      else if (unformat (line_input, "encap-vrf-id %d", &table_id))
	{
	  encap_fib_index =
	    fib_table_find (fib_ip_proto (ipv6_set), table_id);
	}
      else if (unformat (line_input, "decap-next %U", unformat_decap_next,
			 &decap_next_index, ipv4_set))
	;
      else if (unformat (line_input, "vni %d", &vni))
	;
      else
	{
	  parse_error = clib_error_return (0, "parse error: '%U'",
					   format_unformat_error, line_input);
	  break;
	}
    }

  unformat_free (line_input);

  if (parse_error)
    return parse_error;

  if (encap_fib_index == ~0)
    return clib_error_return (0, "nonexistent encap-vrf-id %d", table_id);

  if (src_set == 0)
    return clib_error_return (0, "tunnel src address not specified");

  if (dst_set == 0)
    return clib_error_return (0, "tunnel dst address not specified");

  if (grp_set && !ip46_address_is_multicast (&dst))
    return clib_error_return (0, "tunnel group address not multicast");

  if (grp_set == 0 && ip46_address_is_multicast (&dst))
    return clib_error_return (0, "dst address must be unicast");

  if (grp_set && mcast_sw_if_index == ~0)
    return clib_error_return (0, "tunnel nonexistent multicast device");

  if (ipv4_set && ipv6_set)
    return clib_error_return (0, "both IPv4 and IPv6 addresses specified");

  if (ip46_address_cmp (&src, &dst) == 0)
    return clib_error_return (0, "src and dst addresses are identical");

  if (decap_next_index == ~0)
    return clib_error_return (0, "next node not found");

  if (vni == 0)
    return clib_error_return (0, "vni not specified");

  if (vni >> 24)
    return clib_error_return (0, "vni %d out of range", vni);

  vnet_vxlan_gbp_tunnel_add_del_args_t a = {
    .is_add = is_add,
    .is_ip6 = ipv6_set,
    .instance = instance,
#define _(x) .x = x,
    foreach_copy_field
#undef _
  };

  u32 tunnel_sw_if_index;
  int rv = vnet_vxlan_gbp_tunnel_add_del (&a, &tunnel_sw_if_index);

  switch (rv)
    {
    case 0:
      if (is_add)
	vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
			 vnet_get_main (), tunnel_sw_if_index);
      break;

    case VNET_API_ERROR_TUNNEL_EXIST:
      return clib_error_return (0, "tunnel already exists...");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "tunnel does not exist...");

    case VNET_API_ERROR_INSTANCE_IN_USE:
      return clib_error_return (0, "Instance is in use");

    default:
      return clib_error_return
	(0, "vnet_vxlan_gbp_tunnel_add_del returned %d", rv);
    }

  return 0;
}

/*?
 * Add or delete a VXLAN Tunnel.
 *
 * VXLAN provides the features needed to allow L2 bridge domains (BDs)
 * to span multiple servers. This is done by building an L2 overlay on
 * top of an L3 network underlay using VXLAN tunnels.
 *
 * This makes it possible for servers to be co-located in the same data
 * center or be separated geographically as long as they are reachable
 * through the underlay L3 network.
 *
 * You can refer to this kind of L2 overlay bridge domain as a VXLAN
 * (Virtual eXtensible VLAN) segment.
 *
 * @cliexpar
 * Example of how to create a VXLAN Tunnel:
 * @cliexcmd{create vxlan_gbp tunnel src 10.0.3.1 dst 10.0.3.3 vni 13 encap-vrf-id 7}
 * Example of how to create a VXLAN Tunnel with a known name, vxlan_gbp_tunnel42:
 * @cliexcmd{create vxlan_gbp tunnel src 10.0.3.1 dst 10.0.3.3 instance 42}
 * Example of how to create a multicast VXLAN Tunnel with a known name, vxlan_gbp_tunnel23:
 * @cliexcmd{create vxlan_gbp tunnel src 10.0.3.1 group 239.1.1.1 GigabitEthernet0/8/0 instance 23}
 * Example of how to delete a VXLAN Tunnel:
 * @cliexcmd{create vxlan_gbp tunnel src 10.0.3.1 dst 10.0.3.3 vni 13 del}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_vxlan_gbp_tunnel_command, static) = {
  .path = "create vxlan-gbp tunnel",
  .short_help =
  "create vxlan-gbp tunnel src <local-vtep-addr>"
  " {dst <remote-vtep-addr>|group <mcast-vtep-addr> <intf-name>} vni <nn>"
  " [instance <id>]"
  " [encap-vrf-id <nn>] [decap-next [l2|node <name>]] [del]",
  .function = vxlan_gbp_tunnel_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_vxlan_gbp_tunnel_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;
  vxlan_gbp_tunnel_t *t;
  int raw = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "raw"))
	raw = 1;
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, input);
    }

  if (pool_elts (vxm->tunnels) == 0)
    vlib_cli_output (vm, "No vxlan-gbp tunnels configured...");

/* *INDENT-OFF* */
  pool_foreach (t, vxm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_vxlan_gbp_tunnel, t);
  }));
/* *INDENT-ON* */

  if (raw)
    {
      vlib_cli_output (vm, "Raw IPv4 Hash Table:\n%U\n",
		       format_bihash_16_8, &vxm->vxlan4_gbp_tunnel_by_key,
		       1 /* verbose */ );
      vlib_cli_output (vm, "Raw IPv6 Hash Table:\n%U\n",
		       format_bihash_24_8, &vxm->vxlan6_gbp_tunnel_by_key,
		       1 /* verbose */ );
    }

  return 0;
}

/*?
 * Display all the VXLAN Tunnel entries.
 *
 * @cliexpar
 * Example of how to display the VXLAN Tunnel entries:
 * @cliexstart{show vxlan_gbp tunnel}
 * [0] src 10.0.3.1 dst 10.0.3.3 vni 13 encap_fib_index 0 sw_if_index 5 decap_next l2
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_vxlan_gbp_tunnel_command, static) = {
    .path = "show vxlan-gbp tunnel",
    .short_help = "show vxlan-gbp tunnel [raw]",
    .function = show_vxlan_gbp_tunnel_command_fn,
};
/* *INDENT-ON* */


void
vnet_int_vxlan_gbp_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable)
{
  if (is_ip6)
    vnet_feature_enable_disable ("ip6-unicast", "ip6-vxlan-gbp-bypass",
				 sw_if_index, is_enable, 0, 0);
  else
    vnet_feature_enable_disable ("ip4-unicast", "ip4-vxlan-gbp-bypass",
				 sw_if_index, is_enable, 0, 0);
}


static clib_error_t *
set_ip_vxlan_gbp_bypass (u32 is_ip6,
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

  vnet_int_vxlan_gbp_bypass_mode (sw_if_index, is_ip6, is_enable);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
set_ip4_vxlan_gbp_bypass (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return set_ip_vxlan_gbp_bypass (0, input, cmd);
}

/*?
 * This command adds the 'ip4-vxlan-gbp-bypass' graph node for a given interface.
 * By adding the IPv4 vxlan_gbp-bypass graph node to an interface, the node checks
 *  for and validate input vxlan_gbp packet and bypass ip4-lookup, ip4-local,
 * ip4-udp-lookup nodes to speedup vxlan_gbp packet forwarding. This node will
 * cause extra overhead to for non-vxlan_gbp packets which is kept at a minimum.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before ip4-vxlan_gbp-bypass is enabled:
 * @cliexstart{show vlib graph ip4-vxlan_gbp-bypass}
 *            Name                      Next                    Previous
 * ip4-vxlan-gbp-bypass              error-drop [0]
 *                                vxlan4-gbp-input [1]
 *                                   ip4-lookup [2]
 * @cliexend
 *
 * Example of how to enable ip4-vxlan-gbp-bypass on an interface:
 * @cliexcmd{set interface ip vxlan-gbp-bypass GigabitEthernet2/0/0}
 *
 * Example of graph node after ip4-vxlan-gbp-bypass is enabled:
 * @cliexstart{show vlib graph ip4-vxlan-gbp-bypass}
 *            Name                      Next                    Previous
 * ip4-vxlan-gbp-bypass              error-drop [0]               ip4-input
 *                                vxlan4-gbp-input [1]        ip4-input-no-checksum
 *                                   ip4-lookup [2]
 * @cliexend
 *
 * Example of how to display the feature enabled on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 * ...
 * ipv4 unicast:
 *   ip4-vxlan-gbp-bypass
 *   ip4-lookup
 * ...
 * @cliexend
 *
 * Example of how to disable ip4-vxlan-gbp-bypass on an interface:
 * @cliexcmd{set interface ip vxlan-gbp-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip_vxlan_gbp_bypass_command, static) = {
  .path = "set interface ip vxlan-gbp-bypass",
  .function = set_ip4_vxlan_gbp_bypass,
  .short_help = "set interface ip vxlan-gbp-bypass <interface> [del]",
};
/* *INDENT-ON* */

static clib_error_t *
set_ip6_vxlan_gbp_bypass (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return set_ip_vxlan_gbp_bypass (1, input, cmd);
}

/*?
 * This command adds the 'ip6-vxlan-gbp-bypass' graph node for a given interface.
 * By adding the IPv6 vxlan-gbp-bypass graph node to an interface, the node checks
 *  for and validate input vxlan_gbp packet and bypass ip6-lookup, ip6-local,
 * ip6-udp-lookup nodes to speedup vxlan_gbp packet forwarding. This node will
 * cause extra overhead to for non-vxlan packets which is kept at a minimum.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before ip6-vxlan-gbp-bypass is enabled:
 * @cliexstart{show vlib graph ip6-vxlan-gbp-bypass}
 *            Name                      Next                    Previous
 * ip6-vxlan-gbp-bypass              error-drop [0]
 *                                vxlan6-gbp-input [1]
 *                                   ip6-lookup [2]
 * @cliexend
 *
 * Example of how to enable ip6-vxlan-gbp-bypass on an interface:
 * @cliexcmd{set interface ip6 vxlan-gbp-bypass GigabitEthernet2/0/0}
 *
 * Example of graph node after ip6-vxlan-gbp-bypass is enabled:
 * @cliexstart{show vlib graph ip6-vxlan-gbp-bypass}
 *            Name                      Next                    Previous
 * ip6-vxlan-gbp-bypass              error-drop [0]               ip6-input
 *                                vxlan6-gbp-input [1]        ip4-input-no-checksum
 *                                   ip6-lookup [2]
 * @cliexend
 *
 * Example of how to display the feature enabled on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 * ...
 * ipv6 unicast:
 *   ip6-vxlan-gbp-bypass
 *   ip6-lookup
 * ...
 * @cliexend
 *
 * Example of how to disable ip6-vxlan-gbp-bypass on an interface:
 * @cliexcmd{set interface ip6 vxlan-gbp-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip6_vxlan_gbp_bypass_command, static) = {
  .path = "set interface ip6 vxlan-gbp-bypass",
  .function = set_ip6_vxlan_gbp_bypass,
  .short_help = "set interface ip vxlan-gbp-bypass <interface> [del]",
};
/* *INDENT-ON* */

#define VXLAN_GBP_HASH_NUM_BUCKETS (2 * 1024)
#define VXLAN_GBP_HASH_MEMORY_SIZE (1 << 20)

clib_error_t *
vxlan_gbp_init (vlib_main_t * vm)
{
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;
  clib_error_t *error;

  vxm->vnet_main = vnet_get_main ();
  vxm->vlib_main = vm;

  if ((error = vlib_call_init_function (vm, punt_init)))
    return (error);

  /* initialize the ip6 hash */
  clib_bihash_init_16_8 (&vxm->vxlan4_gbp_tunnel_by_key, "vxlan4-gbp",
			 VXLAN_GBP_HASH_NUM_BUCKETS,
			 VXLAN_GBP_HASH_MEMORY_SIZE);
  clib_bihash_init_24_8 (&vxm->vxlan6_gbp_tunnel_by_key, "vxlan6-gbp",
			 VXLAN_GBP_HASH_NUM_BUCKETS,
			 VXLAN_GBP_HASH_MEMORY_SIZE);
  vxm->vtep6 = hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));
  vxm->mcast_shared = hash_create_mem (0,
				       sizeof (ip46_address_t),
				       sizeof (mcast_shared_t));

  fib_node_register_type (FIB_NODE_TYPE_VXLAN_GBP_TUNNEL, &vxlan_gbp_vft);

  punt_hdl = vlib_punt_client_register ("vxlan-gbp");

  vlib_punt_reason_alloc (punt_hdl,
			  "VXLAN-GBP-no-such-v4-tunnel",
			  &vxm->punt_no_such_tunnel[FIB_PROTOCOL_IP4]);
  vlib_punt_reason_alloc (punt_hdl,
			  "VXLAN-GBP-no-such-v6-tunnel",
			  &vxm->punt_no_such_tunnel[FIB_PROTOCOL_IP6]);

  return (error);
}

VLIB_INIT_FUNCTION (vxlan_gbp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
