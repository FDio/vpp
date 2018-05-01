/*
 * Copyright (c) 2017 SUSE LLC.
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
#include <vnet/geneve/geneve.h>
#include <vnet/ip/format.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/interface.h>
#include <vlib/vlib.h>

/**
 * @file
 * @brief GENEVE.
 *
 * GENEVE provides the features needed to allow L2 bridge domains (BDs)
 * to span multiple servers. This is done by building an L2 overlay on
 * top of an L3 network underlay using GENEVE tunnels.
 *
 * This makes it possible for servers to be co-located in the same data
 * center or be separated geographically as long as they are reachable
 * through the underlay L3 network.
 */


geneve_main_t geneve_main;

static u8 *
format_decap_next (u8 * s, va_list * args)
{
  u32 next_index = va_arg (*args, u32);

  switch (next_index)
    {
    case GENEVE_INPUT_NEXT_DROP:
      return format (s, "drop");
    case GENEVE_INPUT_NEXT_L2_INPUT:
      return format (s, "l2");
    default:
      return format (s, "index %d", next_index);
    }
  return s;
}

u8 *
format_geneve_tunnel (u8 * s, va_list * args)
{
  geneve_tunnel_t *t = va_arg (*args, geneve_tunnel_t *);
  geneve_main_t *ngm = &geneve_main;

  s = format (s, "[%d] lcl %U rmt %U vni %d fib-idx %d sw-if-idx %d ",
	      t - ngm->tunnels,
	      format_ip46_address, &t->local, IP46_TYPE_ANY,
	      format_ip46_address, &t->remote, IP46_TYPE_ANY,
	      t->vni, t->encap_fib_index, t->sw_if_index);

  s = format (s, "encap-dpo-idx %d ", t->next_dpo.dpoi_index);
  s = format (s, "decap-next-%U ", format_decap_next, t->decap_next_index);

  if (PREDICT_FALSE (ip46_address_is_multicast (&t->remote)))
    s = format (s, "mcast-sw-if-idx %d ", t->mcast_sw_if_index);

  return s;
}

static u8 *
format_geneve_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "geneve_tunnel%d", dev_instance);
}

static clib_error_t *
geneve_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (geneve_device_class, static) = {
  .name = "GENEVE",
  .format_device_name = format_geneve_name,
  .format_tx_trace = format_geneve_encap_trace,
  .admin_up_down_function = geneve_interface_admin_up_down,
};
/* *INDENT-ON* */

static u8 *
format_geneve_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (geneve_hw_class) = {
  .name = "GENEVE",
  .format_header = format_geneve_header_with_length,
  .build_rewrite = default_build_rewrite,
};
/* *INDENT-ON* */

static void
geneve_tunnel_restack_dpo (geneve_tunnel_t * t)
{
  dpo_id_t dpo = DPO_INVALID;
  u32 encap_index = ip46_address_is_ip4 (&t->remote) ?
    geneve4_encap_node.index : geneve6_encap_node.index;
  fib_forward_chain_type_t forw_type = ip46_address_is_ip4 (&t->remote) ?
    FIB_FORW_CHAIN_TYPE_UNICAST_IP4 : FIB_FORW_CHAIN_TYPE_UNICAST_IP6;

  fib_entry_contribute_forwarding (t->fib_entry_index, forw_type, &dpo);
  dpo_stack_from_node (encap_index, &t->next_dpo, &dpo);
  dpo_reset (&dpo);
}

static geneve_tunnel_t *
geneve_tunnel_from_fib_node (fib_node_t * node)
{
  ASSERT (FIB_NODE_TYPE_GENEVE_TUNNEL == node->fn_type);
  return ((geneve_tunnel_t *) (((char *) node) -
			       STRUCT_OFFSET_OF (geneve_tunnel_t, node)));
}

/**
 * Function definition to backwalk a FIB node -
 * Here we will restack the new dpo of GENEVE DIP to encap node.
 */
static fib_node_back_walk_rc_t
geneve_tunnel_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  geneve_tunnel_restack_dpo (geneve_tunnel_from_fib_node (node));
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
geneve_tunnel_fib_node_get (fib_node_index_t index)
{
  geneve_tunnel_t *t;
  geneve_main_t *vxm = &geneve_main;

  t = pool_elt_at_index (vxm->tunnels, index);

  return (&t->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
geneve_tunnel_last_lock_gone (fib_node_t * node)
{
  /*
   * The GENEVE tunnel is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

/*
 * Virtual function table registered by GENEVE tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t geneve_vft = {
  .fnv_get = geneve_tunnel_fib_node_get,
  .fnv_last_lock = geneve_tunnel_last_lock_gone,
  .fnv_back_walk = geneve_tunnel_back_walk,
};


#define foreach_copy_field                      \
_(vni)                                          \
_(mcast_sw_if_index)                            \
_(encap_fib_index)                              \
_(decap_next_index)                             \
_(local)                                          \
_(remote)

static int
geneve_rewrite (geneve_tunnel_t * t, bool is_ip6)
{
  union
  {
    ip4_geneve_header_t *h4;
    ip6_geneve_header_t *h6;
    u8 *rw;
  } r =
  {
  .rw = 0};
  int len = is_ip6 ? sizeof *r.h6 : sizeof *r.h4;
#if SUPPORT_OPTIONS_HEADER==1
  len += t->options_len;
#endif

  vec_validate_aligned (r.rw, len - 1, CLIB_CACHE_LINE_BYTES);

  udp_header_t *udp;
  geneve_header_t *geneve;
  /* Fixed portion of the (outer) ip header */
  if (!is_ip6)
    {
      ip4_header_t *ip = &r.h4->ip4;
      udp = &r.h4->udp, geneve = &r.h4->geneve;
      ip->ip_version_and_header_length = 0x45;
      ip->ttl = 254;
      ip->protocol = IP_PROTOCOL_UDP;

      ip->src_address = t->local.ip4;
      ip->dst_address = t->remote.ip4;

      /* we fix up the ip4 header length and checksum after-the-fact */
      ip->checksum = ip4_header_checksum (ip);
    }
  else
    {
      ip6_header_t *ip = &r.h6->ip6;
      udp = &r.h6->udp, geneve = &r.h6->geneve;
      ip->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (6 << 28);
      ip->hop_limit = 255;
      ip->protocol = IP_PROTOCOL_UDP;

      ip->src_address = t->local.ip6;
      ip->dst_address = t->remote.ip6;
    }

  /* UDP header, randomize local port on something, maybe? */
  udp->src_port = clib_host_to_net_u16 (5251);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_geneve);

  /* GENEVE header */
  vnet_set_geneve_version (geneve, GENEVE_VERSION);
#if SUPPORT_OPTIONS_HEADER==1
  vnet_set_geneve_options_len (geneve, t->options_len);
#else
  vnet_set_geneve_options_len (geneve, 0);
#endif
  vnet_set_geneve_oamframe_bit (geneve, 0);
  vnet_set_geneve_critical_bit (geneve, 0);
  vnet_set_geneve_protocol (geneve, GENEVE_ETH_PROTOCOL);

  vnet_geneve_hdr_1word_hton (geneve);

  vnet_set_geneve_vni (geneve, t->vni);

  t->rewrite = r.rw;
  return (0);
}

static bool
geneve_decap_next_is_valid (geneve_main_t * vxm, u32 is_ip6,
			    u32 decap_next_index)
{
  vlib_main_t *vm = vxm->vlib_main;
  u32 input_idx =
    (!is_ip6) ? geneve4_input_node.index : geneve6_input_node.index;
  vlib_node_runtime_t *r = vlib_node_get_runtime (vm, input_idx);

  return decap_next_index < r->n_next_nodes;
}

static uword
vtep_addr_ref (ip46_address_t * ip)
{
  uword *vtep = ip46_address_is_ip4 (ip) ?
    hash_get (geneve_main.vtep4, ip->ip4.as_u32) :
    hash_get_mem (geneve_main.vtep6, &ip->ip6);
  if (vtep)
    return ++(*vtep);
  ip46_address_is_ip4 (ip) ?
    hash_set (geneve_main.vtep4, ip->ip4.as_u32, 1) :
    hash_set_mem_alloc (&geneve_main.vtep6, &ip->ip6, 1);
  return 1;
}

static uword
vtep_addr_unref (ip46_address_t * ip)
{
  uword *vtep = ip46_address_is_ip4 (ip) ?
    hash_get (geneve_main.vtep4, ip->ip4.as_u32) :
    hash_get_mem (geneve_main.vtep6, &ip->ip6);
  ASSERT (vtep);
  if (--(*vtep) != 0)
    return *vtep;
  ip46_address_is_ip4 (ip) ?
    hash_unset (geneve_main.vtep4, ip->ip4.as_u32) :
    hash_unset_mem_free (&geneve_main.vtep6, &ip->ip6);
  return 0;
}

typedef CLIB_PACKED (union
		     {
		     struct
		     {
		     fib_node_index_t mfib_entry_index;
		     adj_index_t mcast_adj_index;
		     }; u64 as_u64;
		     }) mcast_shared_t;

static inline mcast_shared_t
mcast_shared_get (ip46_address_t * ip)
{
  ASSERT (ip46_address_is_multicast (ip));
  uword *p = hash_get_mem (geneve_main.mcast_shared, ip);
  ASSERT (p);
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

  hash_set_mem_alloc (&geneve_main.mcast_shared, remote, new_ep.as_u64);
}

static inline void
mcast_shared_remove (ip46_address_t * remote)
{
  mcast_shared_t ep = mcast_shared_get (remote);

  adj_unlock (ep.mcast_adj_index);
  mfib_table_entry_delete_index (ep.mfib_entry_index, MFIB_SOURCE_GENEVE);

  hash_unset_mem_free (&geneve_main.mcast_shared, remote);
}

int vnet_geneve_add_del_tunnel
  (vnet_geneve_add_del_tunnel_args_t * a, u32 * sw_if_indexp)
{
  geneve_main_t *vxm = &geneve_main;
  geneve_tunnel_t *t = 0;
  vnet_main_t *vnm = vxm->vnet_main;
  uword *p;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  int rv;
  geneve4_tunnel_key_t key4;
  geneve6_tunnel_key_t key6;
  u32 is_ip6 = a->is_ip6;

  if (!is_ip6)
    {
      key4.remote = a->remote.ip4.as_u32;
      key4.vni =
	clib_host_to_net_u32 ((a->vni << GENEVE_VNI_SHIFT) & GENEVE_VNI_MASK);
      p = hash_get (vxm->geneve4_tunnel_by_key, key4.as_u64);
    }
  else
    {
      key6.remote = a->remote.ip6;
      key6.vni =
	clib_host_to_net_u32 ((a->vni << GENEVE_VNI_SHIFT) & GENEVE_VNI_MASK);
      p = hash_get_mem (vxm->geneve6_tunnel_by_key, &key6);
    }

  if (a->is_add)
    {
      l2input_main_t *l2im = &l2input_main;

      /* adding a tunnel: tunnel must not already exist */
      if (p)
	return VNET_API_ERROR_TUNNEL_EXIST;

      /*if not set explicitly, default to l2 */
      if (a->decap_next_index == ~0)
	a->decap_next_index = GENEVE_INPUT_NEXT_L2_INPUT;
      if (!geneve_decap_next_is_valid (vxm, is_ip6, a->decap_next_index))
	return VNET_API_ERROR_INVALID_DECAP_NEXT;

      pool_get_aligned (vxm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      clib_memset (t, 0, sizeof (*t));

      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _

      rv = geneve_rewrite (t, is_ip6);
      if (rv)
	{
	  pool_put (vxm->tunnels, t);
	  return rv;
	}

      /* copy the key */
      if (is_ip6)
	hash_set_mem_alloc (&vxm->geneve6_tunnel_by_key, &key6,
			    t - vxm->tunnels);
      else
	hash_set (vxm->geneve4_tunnel_by_key, key4.as_u64, t - vxm->tunnels);

      vnet_hw_interface_t *hi;
      if (vec_len (vxm->free_geneve_tunnel_hw_if_indices) > 0)
	{
	  vnet_interface_main_t *im = &vnm->interface_main;
	  hw_if_index = vxm->free_geneve_tunnel_hw_if_indices
	    [vec_len (vxm->free_geneve_tunnel_hw_if_indices) - 1];
	  _vec_len (vxm->free_geneve_tunnel_hw_if_indices) -= 1;

	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  hi->dev_instance = t - vxm->tunnels;
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
	    (vnm, geneve_device_class.index, t - vxm->tunnels,
	     geneve_hw_class.index, t - vxm->tunnels);
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	}

      /* Set geneve tunnel output node */
      u32 encap_index = !is_ip6 ?
	geneve4_encap_node.index : geneve6_encap_node.index;
      vnet_set_interface_output_node (vnm, hw_if_index, encap_index);

      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index = hi->sw_if_index;

      vec_validate_init_empty (vxm->tunnel_index_by_sw_if_index, sw_if_index,
			       ~0);
      vxm->tunnel_index_by_sw_if_index[sw_if_index] = t - vxm->tunnels;

      /* setup l2 input config with l2 feature and bd 0 to drop packet */
      vec_validate (l2im->configs, sw_if_index);
      l2im->configs[sw_if_index].feature_bitmap = L2INPUT_FEAT_DROP;
      l2im->configs[sw_if_index].bd_index = 0;

      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
      si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
      vnet_sw_interface_set_flags (vnm, sw_if_index,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);

      fib_node_init (&t->node, FIB_NODE_TYPE_GENEVE_TUNNEL);
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
	  vtep_addr_ref (&t->local);
	  t->fib_entry_index = fib_table_entry_special_add
	    (t->encap_fib_index, &tun_remote_pfx, FIB_SOURCE_RR,
	     FIB_ENTRY_FLAG_NONE);
	  t->sibling_index = fib_entry_child_add
	    (t->fib_entry_index, FIB_NODE_TYPE_GENEVE_TUNNEL,
	     t - vxm->tunnels);
	  geneve_tunnel_restack_dpo (t);
	}
      else
	{
	  /* Multicast tunnel -
	   * as the same mcast group can be used for mutiple mcast tunnels
	   * with different VNIs, create the output fib adjecency only if
	   * it does not already exist
	   */
	  fib_protocol_t fp = fib_ip_proto (is_ip6);

	  if (vtep_addr_ref (&t->remote) == 1)
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
					    &mpfx, MFIB_SOURCE_GENEVE, &path);

	      path.frp_sw_if_index = a->mcast_sw_if_index;
	      path.frp_flags = FIB_ROUTE_PATH_FLAG_NONE;
	      path.frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT;
	      mfei = mfib_table_entry_path_update (t->encap_fib_index,
						   &mpfx,
						   MFIB_SOURCE_GENEVE, &path);

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

      t = pool_elt_at_index (vxm->tunnels, p[0]);

      sw_if_index = t->sw_if_index;
      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */ );
      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, t->sw_if_index);
      si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

      /* make sure tunnel is removed from l2 bd or xconnect */
      set_int_l2_mode (vxm->vlib_main, vnm, MODE_L3, t->sw_if_index, 0,
		       L2_BD_PORT_TYPE_NORMAL, 0, 0);
      vec_add1 (vxm->free_geneve_tunnel_hw_if_indices, t->hw_if_index);

      vxm->tunnel_index_by_sw_if_index[t->sw_if_index] = ~0;

      if (!is_ip6)
	hash_unset (vxm->geneve4_tunnel_by_key, key4.as_u64);
      else
	hash_unset_mem_free (&vxm->geneve6_tunnel_by_key, &key6);

      if (!ip46_address_is_multicast (&t->remote))
	{
	  vtep_addr_unref (&t->local);
	  fib_entry_child_remove (t->fib_entry_index, t->sibling_index);
	  fib_table_entry_delete_index (t->fib_entry_index, FIB_SOURCE_RR);
	}
      else if (vtep_addr_unref (&t->remote) == 0)
	{
	  mcast_shared_remove (&t->remote);
	}

      fib_node_deinit (&t->node);
      vec_free (t->rewrite);
      pool_put (vxm->tunnels, t);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}

static uword
get_decap_next_for_node (u32 node_index, u32 ipv4_set)
{
  geneve_main_t *vxm = &geneve_main;
  vlib_main_t *vm = vxm->vlib_main;
  uword input_node = (ipv4_set) ? geneve4_input_node.index :
    geneve6_input_node.index;

  return vlib_node_add_next (vm, input_node, node_index);
}

static uword
unformat_decap_next (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 ipv4_set = va_arg (*args, int);
  geneve_main_t *vxm = &geneve_main;
  vlib_main_t *vm = vxm->vlib_main;
  u32 node_index;
  u32 tmp;

  if (unformat (input, "l2"))
    *result = GENEVE_INPUT_NEXT_L2_INPUT;
  else if (unformat (input, "node %U", unformat_vlib_node, vm, &node_index))
    *result = get_decap_next_for_node (node_index, ipv4_set);
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;
  return 1;
}

static clib_error_t *
geneve_add_del_tunnel_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t local, remote;
  u8 is_add = 1;
  u8 local_set = 0;
  u8 remote_set = 0;
  u8 grp_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u32 encap_fib_index = 0;
  u32 mcast_sw_if_index = ~0;
  u32 decap_next_index = GENEVE_INPUT_NEXT_L2_INPUT;
  u32 vni = 0;
  u32 tmp;
  int rv;
  vnet_geneve_add_del_tunnel_args_t _a, *a = &_a;
  u32 tunnel_sw_if_index;
  clib_error_t *error = NULL;

  /* Cant "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&local, 0, sizeof local);
  clib_memset (&remote, 0, sizeof remote);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
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
	  encap_fib_index = fib_table_find (fib_ip_proto (ipv6_set), tmp);
	  if (encap_fib_index == ~0)
	    {
	      error =
		clib_error_return (0, "nonexistent encap-vrf-id %d", tmp);
	      goto done;
	    }
	}
      else if (unformat (line_input, "decap-next %U", unformat_decap_next,
			 &decap_next_index, ipv4_set))
	;
      else if (unformat (line_input, "vni %d", &vni))
	{
	  if (vni >> 24)
	    {
	      error = clib_error_return (0, "vni %d out of range", vni);
	      goto done;
	    }
	}
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

  if (ip46_address_cmp (&local, &remote) == 0)
    {
      error =
	clib_error_return (0, "local and remote addresses are identical");
      goto done;
    }

  if (decap_next_index == ~0)
    {
      error = clib_error_return (0, "next node not found");
      goto done;
    }

  if (vni == 0)
    {
      error = clib_error_return (0, "vni not specified");
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));

  a->is_add = is_add;
  a->is_ip6 = ipv6_set;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _

  rv = vnet_geneve_add_del_tunnel (a, &tunnel_sw_if_index);

  switch (rv)
    {
    case 0:
      if (is_add)
	vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
			 vnet_get_main (), tunnel_sw_if_index);
      break;

    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "tunnel already exists...");
      goto done;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "tunnel does not exist...");
      goto done;

    default:
      error = clib_error_return
	(0, "vnet_geneve_add_del_tunnel returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Add or delete a GENEVE Tunnel.
 *
 * GENEVE provides the features needed to allow L2 bridge domains (BDs)
 * to span multiple servers. This is done by building an L2 overlay on
 * top of an L3 network underlay using GENEVE tunnels.
 *
 * This makes it possible for servers to be co-located in the same data
 * center or be separated geographically as long as they are reachable
 * through the underlay L3 network.
 *
 * You can refer to this kind of L2 overlay bridge domain as a GENEVE
 * segment.
 *
 * @cliexpar
 * Example of how to create a GENEVE Tunnel:
 * @cliexcmd{create geneve tunnel local 10.0.3.1 remote 10.0.3.3 vni 13 encap-vrf-id 7}
 * Example of how to delete a GENEVE Tunnel:
 * @cliexcmd{create geneve tunnel local 10.0.3.1 remote 10.0.3.3 vni 13 del}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_geneve_tunnel_command, static) = {
  .path = "create geneve tunnel",
  .short_help =
  "create geneve tunnel local <local-vtep-addr>"
  " {remote <remote-vtep-addr>|group <mcast-vtep-addr> <intf-name>} vni <nn>"
  " [encap-vrf-id <nn>] [decap-next [l2|node <name>]] [del]",
  .function = geneve_add_del_tunnel_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_geneve_tunnel_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  geneve_main_t *vxm = &geneve_main;
  geneve_tunnel_t *t;

  if (pool_elts (vxm->tunnels) == 0)
    vlib_cli_output (vm, "No geneve tunnels configured...");

  pool_foreach (t, vxm->tunnels, (
				   {
				   vlib_cli_output (vm, "%U",
						    format_geneve_tunnel, t);
				   }
		));

  return 0;
}

/*?
 * Display all the GENEVE Tunnel entries.
 *
 * @cliexpar
 * Example of how to display the GENEVE Tunnel entries:
 * @cliexstart{show geneve tunnel}
 * [0] local 10.0.3.1 remote 10.0.3.3 vni 13 encap_fib_index 0 sw_if_index 5 decap_next l2
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_geneve_tunnel_command, static) = {
    .path = "show geneve tunnel",
    .short_help = "show geneve tunnel",
    .function = show_geneve_tunnel_command_fn,
};
/* *INDENT-ON* */


void
vnet_int_geneve_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable)
{
  if (is_ip6)
    vnet_feature_enable_disable ("ip6-unicast", "ip6-geneve-bypass",
				 sw_if_index, is_enable, 0, 0);
  else
    vnet_feature_enable_disable ("ip4-unicast", "ip4-geneve-bypass",
				 sw_if_index, is_enable, 0, 0);
}


static clib_error_t *
set_ip_geneve_bypass (u32 is_ip6,
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

  vnet_int_geneve_bypass_mode (sw_if_index, is_ip6, is_enable);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
set_ip4_geneve_bypass (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return set_ip_geneve_bypass (0, input, cmd);
}

/*?
 * This command adds the 'ip4-geneve-bypass' graph node for a given interface.
 * By adding the IPv4 geneve-bypass graph node to an interface, the node checks
 *  for and validate input geneve packet and bypass ip4-lookup, ip4-local,
 * ip4-udp-lookup nodes to speedup geneve packet forwarding. This node will
 * cause extra overhead to for non-geneve packets which is kept at a minimum.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before ip4-geneve-bypass is enabled:
 * @cliexstart{show vlib graph ip4-geneve-bypass}
 *            Name                      Next                    Previous
 * ip4-geneve-bypass                error-drop [0]
 *                                geneve4-input [1]
 *                                 ip4-lookup [2]
 * @cliexend
 *
 * Example of how to enable ip4-geneve-bypass on an interface:
 * @cliexcmd{set interface ip geneve-bypass GigabitEthernet2/0/0}
 *
 * Example of graph node after ip4-geneve-bypass is enabled:
 * @cliexstart{show vlib graph ip4-geneve-bypass}
 *            Name                      Next                    Previous
 * ip4-geneve-bypass                error-drop [0]               ip4-input
 *                                geneve4-input [1]        ip4-input-no-checksum
 *                                 ip4-lookup [2]
 * @cliexend
 *
 * Example of how to display the feature enabed on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 * ...
 * ipv4 unicast:
 *   ip4-geneve-bypass
 *   ip4-lookup
 * ...
 * @cliexend
 *
 * Example of how to disable ip4-geneve-bypass on an interface:
 * @cliexcmd{set interface ip geneve-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip_geneve_bypass_command, static) = {
  .path = "set interface ip geneve-bypass",
  .function = set_ip4_geneve_bypass,
  .short_help = "set interface ip geneve-bypass <interface> [del]",
};
/* *INDENT-ON* */

static clib_error_t *
set_ip6_geneve_bypass (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return set_ip_geneve_bypass (1, input, cmd);
}

/*?
 * This command adds the 'ip6-geneve-bypass' graph node for a given interface.
 * By adding the IPv6 geneve-bypass graph node to an interface, the node checks
 *  for and validate input geneve packet and bypass ip6-lookup, ip6-local,
 * ip6-udp-lookup nodes to speedup geneve packet forwarding. This node will
 * cause extra overhead to for non-geneve packets which is kept at a minimum.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before ip6-geneve-bypass is enabled:
 * @cliexstart{show vlib graph ip6-geneve-bypass}
 *            Name                      Next                    Previous
 * ip6-geneve-bypass                error-drop [0]
 *                                geneve6-input [1]
 *                                 ip6-lookup [2]
 * @cliexend
 *
 * Example of how to enable ip6-geneve-bypass on an interface:
 * @cliexcmd{set interface ip6 geneve-bypass GigabitEthernet2/0/0}
 *
 * Example of graph node after ip6-geneve-bypass is enabled:
 * @cliexstart{show vlib graph ip6-geneve-bypass}
 *            Name                      Next                    Previous
 * ip6-geneve-bypass                error-drop [0]               ip6-input
 *                                geneve6-input [1]        ip4-input-no-checksum
 *                                 ip6-lookup [2]
 * @cliexend
 *
 * Example of how to display the feature enabed on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 * ...
 * ipv6 unicast:
 *   ip6-geneve-bypass
 *   ip6-lookup
 * ...
 * @cliexend
 *
 * Example of how to disable ip6-geneve-bypass on an interface:
 * @cliexcmd{set interface ip6 geneve-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip6_geneve_bypass_command, static) = {
  .path = "set interface ip6 geneve-bypass",
  .function = set_ip6_geneve_bypass,
  .short_help = "set interface ip geneve-bypass <interface> [del]",
};
/* *INDENT-ON* */

clib_error_t *
geneve_init (vlib_main_t * vm)
{
  geneve_main_t *vxm = &geneve_main;

  vxm->vnet_main = vnet_get_main ();
  vxm->vlib_main = vm;

  /* initialize the ip6 hash */
  vxm->geneve6_tunnel_by_key = hash_create_mem (0,
						sizeof (geneve6_tunnel_key_t),
						sizeof (uword));
  vxm->vtep6 = hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));
  vxm->mcast_shared = hash_create_mem (0,
				       sizeof (ip46_address_t),
				       sizeof (mcast_shared_t));

  udp_register_dst_port (vm, UDP_DST_PORT_geneve,
			 geneve4_input_node.index, /* is_ip4 */ 1);
  udp_register_dst_port (vm, UDP_DST_PORT_geneve6,
			 geneve6_input_node.index, /* is_ip4 */ 0);

  fib_node_register_type (FIB_NODE_TYPE_GENEVE_TUNNEL, &geneve_vft);

  return 0;
}

VLIB_INIT_FUNCTION (geneve_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
