/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
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
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/dpo/dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <gtpu/gtpu.h>
#include <vnet/flow/flow.h>

gtpu_main_t gtpu_main;

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_gtpu_bypass, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ip4-gtpu-bypass",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (ip6_gtpu_bypass, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ip6-gtpu-bypass",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
/* *INDENT-on* */

u8 * format_gtpu_encap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gtpu_encap_trace_t * t
      = va_arg (*args, gtpu_encap_trace_t *);

  s = format (s, "GTPU encap to gtpu_tunnel%d tteid %u ", t->tunnel_index,
	      t->tteid);

  if (t->pdu_extension)
    s = format (s, "pdu-extension qfi %d ", t->qfi);
  else
    s = format (s, "no-pdu-extension ");
  return s;
}

static u8 *
format_decap_next (u8 * s, va_list * args)
{
  u32 next_index = va_arg (*args, u32);

  switch (next_index)
    {
    case GTPU_INPUT_NEXT_DROP:
      return format (s, "drop");
    case GTPU_INPUT_NEXT_L2_INPUT:
      return format (s, "l2");
    case GTPU_INPUT_NEXT_IP4_INPUT:
      return format (s, "ip4");
    case GTPU_INPUT_NEXT_IP6_INPUT:
      return format (s, "ip6");
    default:
      return format (s, "index %d", next_index);
    }
  return s;
}

u8 *
format_gtpu_tunnel (u8 * s, va_list * args)
{
  gtpu_tunnel_t *t = va_arg (*args, gtpu_tunnel_t *);
  gtpu_main_t *ngm = &gtpu_main;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !ip46_address_is_ip4 (&t->dst);

  u32 encap_vrf_id =
    is_ipv6 ? im6->fibs[t->encap_fib_index].ft_table_id :
    im4->fibs[t->encap_fib_index].ft_table_id;

  s = format (s,
	      "[%d] src %U dst %U teid %u tteid %u "
	      "encap-vrf-id %d sw-if-idx %d ",
	      t - ngm->tunnels, format_ip46_address, &t->src, IP46_TYPE_ANY,
	      format_ip46_address, &t->dst, IP46_TYPE_ANY, t->teid, t->tteid,
	      encap_vrf_id, t->sw_if_index);

  s = format (s, "encap-dpo-idx %d ", t->next_dpo.dpoi_index);
  s = format (s, "decap-next-%U ", format_decap_next, t->decap_next_index);

  if (t->is_forwarding)
    {
      switch (t->forwarding_type)
	{
	case GTPU_FORWARD_BAD_HEADER:
	  s = format (s, "forwarding bad-header ");
	  break;
	case GTPU_FORWARD_UNKNOWN_TEID:
	  s = format (s, "forwarding unknown-teid ");
	  break;
	case GTPU_FORWARD_UNKNOWN_TYPE:
	  s = format (s, "forwarding unknown-type ");
	  break;
	}
      return s;
    }
  if (t->pdu_extension != 0)
    s = format (s, "pdu-enabled qfi %d ", t->qfi);
  else
    s = format (s, "pdu-disabled ");

  if (PREDICT_FALSE (ip46_address_is_multicast (&t->dst)))
    s = format (s, "mcast-sw-if-idx %d ", t->mcast_sw_if_index);

  return s;
}

static u8 *
format_gtpu_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "gtpu_tunnel%d", dev_instance);
}

static clib_error_t *
gtpu_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (gtpu_device_class,static) = {
  .name = "GTPU",
  .format_device_name = format_gtpu_name,
  .format_tx_trace = format_gtpu_encap_trace,
  .admin_up_down_function = gtpu_interface_admin_up_down,
};
/* *INDENT-ON* */

static u8 *
format_gtpu_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (gtpu_hw_class) =
{
  .name = "GTPU",
  .format_header = format_gtpu_header_with_length,
  .build_rewrite = default_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

static void
gtpu_tunnel_restack_dpo (gtpu_tunnel_t * t)
{
  dpo_id_t dpo = DPO_INVALID;
  u32 encap_index = ip46_address_is_ip4 (&t->dst) ?
    gtpu4_encap_node.index : gtpu6_encap_node.index;
  fib_forward_chain_type_t forw_type = ip46_address_is_ip4 (&t->dst) ?
    FIB_FORW_CHAIN_TYPE_UNICAST_IP4 : FIB_FORW_CHAIN_TYPE_UNICAST_IP6;

  fib_entry_contribute_forwarding (t->fib_entry_index, forw_type, &dpo);
  dpo_stack_from_node (encap_index, &t->next_dpo, &dpo);
  dpo_reset (&dpo);
}

static gtpu_tunnel_t *
gtpu_tunnel_from_fib_node (fib_node_t * node)
{
  return ((gtpu_tunnel_t *) (((char *) node) -
			     STRUCT_OFFSET_OF (gtpu_tunnel_t, node)));
}

/**
 * Function definition to backwalk a FIB node -
 * Here we will restack the new dpo of GTPU DIP to encap node.
 */
static fib_node_back_walk_rc_t
gtpu_tunnel_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  gtpu_tunnel_restack_dpo (gtpu_tunnel_from_fib_node (node));
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
gtpu_tunnel_fib_node_get (fib_node_index_t index)
{
  gtpu_tunnel_t *t;
  gtpu_main_t *gtm = &gtpu_main;

  t = pool_elt_at_index (gtm->tunnels, index);

  return (&t->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
gtpu_tunnel_last_lock_gone (fib_node_t * node)
{
  /*
   * The GTPU tunnel is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

/*
 * Virtual function table registered by GTPU tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t gtpu_vft = {
  .fnv_get = gtpu_tunnel_fib_node_get,
  .fnv_last_lock = gtpu_tunnel_last_lock_gone,
  .fnv_back_walk = gtpu_tunnel_back_walk,
};

#define foreach_copy_field                                                    \
  _ (teid)                                                                    \
  _ (tteid)                                                                   \
  _ (mcast_sw_if_index)                                                       \
  _ (encap_fib_index)                                                         \
  _ (decap_next_index)                                                        \
  _ (src)                                                                     \
  _ (dst)                                                                     \
  _ (pdu_extension)                                                           \
  _ (qfi)                                                                     \
  _ (is_forwarding)                                                           \
  _ (forwarding_type)

static void
ip_udp_gtpu_rewrite (gtpu_tunnel_t * t, bool is_ip6)
{
  union
  {
    ip4_gtpu_header_t *h4;
    ip6_gtpu_header_t *h6;
    u8 *rw;
  } r =
  {
  .rw = 0};
  int len = is_ip6 ? sizeof *r.h6 : sizeof *r.h4;

  vec_validate_aligned (r.rw, len - 1, CLIB_CACHE_LINE_BYTES);

  udp_header_t *udp;
  gtpu_header_t *gtpu;
  gtpu_ext_with_pdu_session_header_t *gtpu_ext_pdu;
  i64 length_adjustment = 0;
  /* Fixed portion of the (outer) ip header */
  if (!is_ip6)
    {
      ip4_header_t *ip = &r.h4->ip4;
      udp = &r.h4->udp;
      gtpu = &r.h4->gtpu;
      gtpu_ext_pdu = &r.h4->gtpu_ext;
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
      ip6_header_t *ip = &r.h6->ip6;
      udp = &r.h6->udp;
      gtpu = &r.h6->gtpu;
      gtpu_ext_pdu = &r.h6->gtpu_ext;
      ip->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (6 << 28);
      ip->hop_limit = 255;
      ip->protocol = IP_PROTOCOL_UDP;

      ip->src_address = t->src.ip6;
      ip->dst_address = t->dst.ip6;
    }

  /* UDP header, randomize src port on something, maybe? */
  udp->src_port = clib_host_to_net_u16 (2152);
  udp->dst_port = clib_host_to_net_u16 (UDP_DST_PORT_GTPU);

  /* GTPU header */
  gtpu->ver_flags = GTPU_V1_VER | GTPU_PT_GTP;
  gtpu->type = GTPU_TYPE_GTPU;
  gtpu->teid = clib_host_to_net_u32 (t->tteid);

  if (t->pdu_extension)
    {
      gtpu->ver_flags = GTPU_V1_VER | GTPU_PT_GTP | GTPU_E_BIT;
      gtpu->next_ext_type = GTPU_EXT_HDR_PDU_SESSION_CONTAINER;
      gtpu_ext_pdu->len = 1;
      gtpu_ext_pdu->pdu.oct0 = GTPU_PDU_DL_SESSION_TYPE;
      gtpu_ext_pdu->pdu.oct1 = t->qfi;
      gtpu_ext_pdu->next_header = 0;
    }
  else
    {
      // Remove the size of the PDU session header and the optional fields
      length_adjustment = -sizeof (gtpu_ext_with_pdu_session_header_t) - 4;
    }

  t->rewrite = r.rw;
  /* Now only support 8-byte gtpu header or 12+4-byte header. TBD */
  if (!is_ip6)
    vec_set_len (t->rewrite, sizeof (ip4_gtpu_header_t) + length_adjustment);
  else
    vec_set_len (t->rewrite, sizeof (ip6_gtpu_header_t) + length_adjustment);

  return;
}

static bool
gtpu_decap_next_is_valid (gtpu_main_t * gtm, u32 is_ip6, u32 decap_next_index)
{
  vlib_main_t *vm = gtm->vlib_main;
  u32 input_idx = (!is_ip6) ? gtpu4_input_node.index : gtpu6_input_node.index;
  vlib_node_runtime_t *r = vlib_node_get_runtime (vm, input_idx);

  return decap_next_index < r->n_next_nodes;
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
  uword *p = hash_get_mem (gtpu_main.mcast_shared, ip);
  ALWAYS_ASSERT (p);
  return (mcast_shared_t)
  {
  .as_u64 = *p};
}

static inline void
mcast_shared_add (ip46_address_t * dst, fib_node_index_t mfei, adj_index_t ai)
{
  mcast_shared_t new_ep = {
    .mcast_adj_index = ai,
    .mfib_entry_index = mfei,
  };

  hash_set_mem_alloc (&gtpu_main.mcast_shared, dst, new_ep.as_u64);
}

static inline void
mcast_shared_remove (ip46_address_t * dst)
{
  mcast_shared_t ep = mcast_shared_get (dst);

  adj_unlock (ep.mcast_adj_index);
  mfib_table_entry_delete_index (ep.mfib_entry_index, MFIB_SOURCE_GTPU);

  hash_unset_mem_free (&gtpu_main.mcast_shared, dst);
}

int
vnet_gtpu_add_del_forwarding (vnet_gtpu_add_mod_del_tunnel_args_t *a,
			      u32 *sw_if_indexp)
{
  gtpu_main_t *gtm = &gtpu_main;
  bool is_add;
  u32 current_index_value, current_index_value_ipv6;
  u32 address_tabel_ipv4;
  ip6_address_t address_tabel_ipv6;
  u32 sw_if_index = ~0;
  bool is_ip6 = !ip46_address_is_ip4 (&a->dst);
  int rv;
  /* Check for errors */
  if (!a->is_forwarding)
    {
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  switch (a->opn)
    {
    case GTPU_ADD_TUNNEL:
      is_add = 1;
      break;
    case GTPU_DEL_TUNNEL:
      is_add = 0;
      break;
    default:
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  /* Check if the operation is valid, and get the current state if it is.
   * Handling multiple flags at once is not supported yet. */
  switch (a->forwarding_type)
    {
    case GTPU_FORWARD_BAD_HEADER:
      current_index_value = gtm->bad_header_forward_tunnel_index_ipv4;
      current_index_value_ipv6 = gtm->bad_header_forward_tunnel_index_ipv6;
      address_tabel_ipv4 = GTPU_FORWARD_BAD_HEADER_ADDRESS_IPV4;
      /* ipv6 is TBD */
      ip6_address_t address_tabel_ipv6_ = GTPU_FORWARD_BAD_HEADER_ADDRESS_IPV6;
      address_tabel_ipv6 = address_tabel_ipv6_;
      break;
    case GTPU_FORWARD_UNKNOWN_TEID:
      current_index_value = gtm->unknown_teid_forward_tunnel_index_ipv4;
      current_index_value_ipv6 = gtm->unknown_teid_forward_tunnel_index_ipv6;
      address_tabel_ipv4 = GTPU_FORWARD_UNKNOWN_TEID_ADDRESS_IPV4;
      ip6_address_t address_tabel_ipv6__ =
	GTPU_FORWARD_UNKNOWN_TEID_ADDRESS_IPV6;
      address_tabel_ipv6 = address_tabel_ipv6__;
      break;
    case GTPU_FORWARD_UNKNOWN_TYPE:
      current_index_value = gtm->unknown_type_forward_tunnel_index_ipv4;
      current_index_value_ipv6 = gtm->unknown_type_forward_tunnel_index_ipv6;
      address_tabel_ipv4 = GTPU_FORWARD_UNKNOWN_TYPE_ADDRESS_IPV4;
      ip6_address_t address_tabel_ipv6___ =
	GTPU_FORWARD_UNKNOWN_TYPE_ADDRESS_IPV6;
      address_tabel_ipv6 = address_tabel_ipv6___;
      break;
    default:
      return VNET_API_ERROR_INVALID_ARGUMENT;
    }

  if (is_ip6)
    current_index_value = current_index_value_ipv6;

  /* Check if the existing forwarding rule state conflicts with this operation
   */
  if ((is_add) && (current_index_value != ~0))
    {
      return VNET_API_ERROR_TUNNEL_EXIST;
    }
  if (!is_add)
    {
      if (current_index_value == ~0)
	return VNET_API_ERROR_NO_SUCH_ENTRY;
      /* Clear the tunnel index before deleting the tunnel itself */
      switch (a->forwarding_type)
	{
	case GTPU_FORWARD_BAD_HEADER:
	  gtm->bad_header_forward_tunnel_index_ipv4 = ~0;
	  break;
	case GTPU_FORWARD_UNKNOWN_TEID:
	  gtm->unknown_teid_forward_tunnel_index_ipv4 = ~0;
	  break;
	case GTPU_FORWARD_UNKNOWN_TYPE:
	  gtm->unknown_type_forward_tunnel_index_ipv4 = ~0;
	  break;
	}
    }

  /* src is the tunnel lookup key, so it is fixed.
   * dst is used for the new target */
  a->src = a->dst;
  if (is_ip6)
    a->dst.ip6 = address_tabel_ipv6;
  else
    a->dst.ip4.as_u32 = address_tabel_ipv4;
  rv = vnet_gtpu_add_mod_del_tunnel (a, &sw_if_index);

  // Forward only if not nil
  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  if (rv != 0)
    return rv;

  /* Update the forwarding tunnel index */
  u32 tunnel_index = is_add ? vnet_gtpu_get_tunnel_index (sw_if_index) : ~0;
  switch (a->forwarding_type)
    {
    case GTPU_FORWARD_BAD_HEADER:
      if (is_ip6)
	gtm->bad_header_forward_tunnel_index_ipv6 = tunnel_index;
      else
	gtm->bad_header_forward_tunnel_index_ipv4 = tunnel_index;

      break;
    case GTPU_FORWARD_UNKNOWN_TEID:
      if (is_ip6)
	gtm->unknown_teid_forward_tunnel_index_ipv6 = tunnel_index;
      else
	gtm->unknown_teid_forward_tunnel_index_ipv4 = tunnel_index;
      break;
    case GTPU_FORWARD_UNKNOWN_TYPE:
      if (is_ip6)
	gtm->unknown_type_forward_tunnel_index_ipv6 = tunnel_index;
      else
	gtm->unknown_type_forward_tunnel_index_ipv4 = tunnel_index;
      break;
    }
  return 0;
}

int vnet_gtpu_add_mod_del_tunnel
  (vnet_gtpu_add_mod_del_tunnel_args_t * a, u32 * sw_if_indexp)
{
  gtpu_main_t *gtm = &gtpu_main;
  gtpu_tunnel_t *t = 0;
  vnet_main_t *vnm = gtm->vnet_main;
  uword *p;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  gtpu4_tunnel_key_t key4;
  gtpu6_tunnel_key_t key6;
  bool is_ip6 = !ip46_address_is_ip4 (&a->dst);

  if (!is_ip6)
    {
      key4.src = a->dst.ip4.as_u32;	/* decap src in key is encap dst in config */
      key4.teid = clib_host_to_net_u32 (a->teid);
      p = hash_get (gtm->gtpu4_tunnel_by_key, key4.as_u64);
    }
  else
    {
      key6.src = a->dst.ip6;
      key6.teid = clib_host_to_net_u32 (a->teid);
      p = hash_get_mem (gtm->gtpu6_tunnel_by_key, &key6);
    }

  if (a->opn == GTPU_ADD_TUNNEL)
    {
      l2input_main_t *l2im = &l2input_main;

      /* adding a tunnel: tunnel must not already exist */
      if (p)
	return VNET_API_ERROR_TUNNEL_EXIST;

      /*if not set explicitly, default to l2 */
      if (a->decap_next_index == ~0)
	a->decap_next_index = GTPU_INPUT_NEXT_L2_INPUT;
      if (!gtpu_decap_next_is_valid (gtm, is_ip6, a->decap_next_index))
	return VNET_API_ERROR_INVALID_DECAP_NEXT;

      pool_get_aligned (gtm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      clib_memset (t, 0, sizeof (*t));

      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _

      /* default to same as local rx teid */
      if (t->tteid == 0)
	t->tteid = t->teid;

      ip_udp_gtpu_rewrite (t, is_ip6);

      /* clear the flow index */
      t->flow_index = ~0;

      /* copy the key */
      if (is_ip6)
	hash_set_mem_alloc (&gtm->gtpu6_tunnel_by_key, &key6,
			    t - gtm->tunnels);
      else
	hash_set (gtm->gtpu4_tunnel_by_key, key4.as_u64, t - gtm->tunnels);

      vnet_hw_interface_t *hi;
      if (vec_len (gtm->free_gtpu_tunnel_hw_if_indices) > 0)
	{
	  vnet_interface_main_t *im = &vnm->interface_main;
	  hw_if_index = gtm->free_gtpu_tunnel_hw_if_indices
	    [vec_len (gtm->free_gtpu_tunnel_hw_if_indices) - 1];
	  vec_dec_len (gtm->free_gtpu_tunnel_hw_if_indices, 1);

	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  hi->dev_instance = t - gtm->tunnels;
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
	    (vnm, gtpu_device_class.index, t - gtm->tunnels,
	     gtpu_hw_class.index, t - gtm->tunnels);
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	}

      /* Set gtpu tunnel output node */
      u32 encap_index = !is_ip6 ?
	gtpu4_encap_node.index : gtpu6_encap_node.index;
      vnet_set_interface_output_node (vnm, hw_if_index, encap_index);

      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index = hi->sw_if_index;

      vec_validate_init_empty (gtm->tunnel_index_by_sw_if_index, sw_if_index,
			       ~0);
      gtm->tunnel_index_by_sw_if_index[sw_if_index] = t - gtm->tunnels;

      /* setup l2 input config with l2 feature and bd 0 to drop packet */
      vec_validate (l2im->configs, sw_if_index);
      l2im->configs[sw_if_index].feature_bitmap = L2INPUT_FEAT_DROP;
      l2im->configs[sw_if_index].bd_index = 0;

      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
      si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
      vnet_sw_interface_set_flags (vnm, sw_if_index,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);

      fib_node_init (&t->node, gtm->fib_node_type);
      fib_prefix_t tun_dst_pfx;
      vnet_flood_class_t flood_class = VNET_FLOOD_CLASS_TUNNEL_NORMAL;

      fib_protocol_t fp = fib_ip_proto (is_ip6);
      fib_prefix_from_ip46_addr (fp, &t->dst, &tun_dst_pfx);
      if (!ip46_address_is_multicast (&t->dst))
	{
	  /* Unicast tunnel -
	   * Track the FIB entry for the tunnel's destination.
	   * The tunnel will then get poked
	   * when the forwarding for the entry updates, and the tunnel can
	   * re-stack accordingly
	   */
	  vtep_addr_ref (&gtm->vtep_table, t->encap_fib_index, &t->src);
	  t->fib_entry_index = fib_entry_track (t->encap_fib_index,
						&tun_dst_pfx,
						gtm->fib_node_type,
						t - gtm->tunnels,
						&t->sibling_index);
	  gtpu_tunnel_restack_dpo (t);
	}
      else
	{
	  /* Multicast tunnel -
	   * as the same mcast group can be used for multiple mcast tunnels
	   * with different VNIs, create the output adjacency only if
	   * it does not already exist
	   */
	  if (vtep_addr_ref (&gtm->vtep_table,
			     t->encap_fib_index, &t->dst) == 1)
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
		.fp_grp_addr = tun_dst_pfx.fp_addr,
	      };

	      /*
	       * Setup the (*,G) to receive traffic on the mcast group
	       *  - the forwarding interface is for-us
	       *  - the accepting interface is that from the API
	       */
	      mfib_table_entry_path_update (t->encap_fib_index, &mpfx,
					    MFIB_SOURCE_GTPU,
					    MFIB_ENTRY_FLAG_NONE, &path);

	      path.frp_sw_if_index = a->mcast_sw_if_index;
	      path.frp_flags = FIB_ROUTE_PATH_FLAG_NONE;
	      path.frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT;
	      mfei = mfib_table_entry_path_update (
		t->encap_fib_index, &mpfx, MFIB_SOURCE_GTPU,
		MFIB_ENTRY_FLAG_NONE, &path);

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
      /* mod-tteid or deleting a tunnel: tunnel must exist */
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (gtm->tunnels, p[0]);
      sw_if_index = t->sw_if_index;

      if (a->opn == GTPU_UPD_TTEID)
	{
	  if (a->tteid == 0)
	    return VNET_API_ERROR_INVALID_VALUE;
	  t->tteid = a->tteid;
	  vec_free (t->rewrite);
	  ip_udp_gtpu_rewrite (t, is_ip6);
	  return 0;
	}

      /* delete tunnel */
      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */ );
      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, t->sw_if_index);
      si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

      /* make sure tunnel is removed from l2 bd or xconnect */
      set_int_l2_mode (gtm->vlib_main, vnm, MODE_L3, t->sw_if_index, 0,
		       L2_BD_PORT_TYPE_NORMAL, 0, 0);
      vec_add1 (gtm->free_gtpu_tunnel_hw_if_indices, t->hw_if_index);

      gtm->tunnel_index_by_sw_if_index[t->sw_if_index] = ~0;

      if (!is_ip6)
	hash_unset (gtm->gtpu4_tunnel_by_key, key4.as_u64);
      else
	hash_unset_mem_free (&gtm->gtpu6_tunnel_by_key, &key6);

      if (!ip46_address_is_multicast (&t->dst))
	{
	  if (t->flow_index != ~0)
	    vnet_flow_del (vnm, t->flow_index);

	  vtep_addr_unref (&gtm->vtep_table, t->encap_fib_index, &t->src);
	  fib_entry_untrack (t->fib_entry_index, t->sibling_index);
	}
      else if (vtep_addr_unref (&gtm->vtep_table,
				t->encap_fib_index, &t->dst) == 0)
	{
	  mcast_shared_remove (&t->dst);
	}

      fib_node_deinit (&t->node);
      vec_free (t->rewrite);
      pool_put (gtm->tunnels, t);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  if (a->opn == GTPU_ADD_TUNNEL)
    {
      /* register udp ports */
      if (!is_ip6 && !udp_is_valid_dst_port (UDP_DST_PORT_GTPU, 1))
	udp_register_dst_port (gtm->vlib_main, UDP_DST_PORT_GTPU,
			       gtpu4_input_node.index, /* is_ip4 */ 1);
      if (is_ip6 && !udp_is_valid_dst_port (UDP_DST_PORT_GTPU6, 0))
	udp_register_dst_port (gtm->vlib_main, UDP_DST_PORT_GTPU6,
			       gtpu6_input_node.index, /* is_ip4 */ 0);
    }

  return 0;
}

int
get_combined_counters (u32 sw_if_index, vlib_counter_t *result_rx,
		       vlib_counter_t *result_tx)
{
  gtpu_main_t *gtm = &gtpu_main;
  vnet_main_t *vnm = gtm->vnet_main;
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_get_combined_counter (im->combined_sw_if_counters +
			       VNET_INTERFACE_COUNTER_RX,
			     sw_if_index, result_rx);
  vlib_get_combined_counter (im->combined_sw_if_counters +
			       VNET_INTERFACE_COUNTER_TX,
			     sw_if_index, result_tx);
  return 0;
}

static uword
get_decap_next_for_node (u32 node_index, u32 ipv4_set)
{
  gtpu_main_t *gtm = &gtpu_main;
  vlib_main_t *vm = gtm->vlib_main;
  uword input_node = (ipv4_set) ? gtpu4_input_node.index :
    gtpu6_input_node.index;

  return vlib_node_add_next (vm, input_node, node_index);
}

static uword
unformat_decap_next (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 ipv4_set = va_arg (*args, int);
  gtpu_main_t *gtm = &gtpu_main;
  vlib_main_t *vm = gtm->vlib_main;
  u32 node_index;
  u32 tmp;

  if (unformat (input, "l2"))
    *result = GTPU_INPUT_NEXT_L2_INPUT;
  else if (unformat (input, "ip4"))
    *result = GTPU_INPUT_NEXT_IP4_INPUT;
  else if (unformat (input, "ip6"))
    *result = GTPU_INPUT_NEXT_IP6_INPUT;
  else if (unformat (input, "node %U", unformat_vlib_node, vm, &node_index))
    *result = get_decap_next_for_node (node_index, ipv4_set);
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;

  return 1;
}

static clib_error_t *
gtpu_add_del_tunnel_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t src, dst;
  u8 opn = GTPU_ADD_TUNNEL;
  u8 src_set = 0;
  u8 dst_set = 0;
  u8 grp_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u32 encap_fib_index = 0;
  u32 mcast_sw_if_index = ~0;
  u32 decap_next_index = GTPU_INPUT_NEXT_L2_INPUT;
  u32 teid = 0, tteid = 0;
  u32 tmp;
  /* PDU is disabled by default */
  u8 pdu_extension = 0;
  u32 qfi = ~0;
  u8 is_forwarding = 0;
  u8 forwarding_type = 0;
  int rv;
  vnet_gtpu_add_mod_del_tunnel_args_t _a, *a = &_a;
  u32 tunnel_sw_if_index;
  clib_error_t *error = NULL;

  /* Cant "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&src, 0, sizeof src);
  clib_memset (&dst, 0, sizeof dst);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  opn = GTPU_DEL_TUNNEL;
	}
      else if (unformat (line_input, "src %U",
			 unformat_ip4_address, &src.ip4))
	{
	  src_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "dst %U",
			 unformat_ip4_address, &dst.ip4))
	{
	  dst_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "src %U",
			 unformat_ip6_address, &src.ip6))
	{
	  src_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "dst %U",
			 unformat_ip6_address, &dst.ip6))
	{
	  dst_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "group %U %U",
			 unformat_ip4_address, &dst.ip4,
			 unformat_vnet_sw_interface,
			 vnet_get_main (), &mcast_sw_if_index))
	{
	  grp_set = dst_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "group %U %U",
			 unformat_ip6_address, &dst.ip6,
			 unformat_vnet_sw_interface,
			 vnet_get_main (), &mcast_sw_if_index))
	{
	  grp_set = dst_set = 1;
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
      else if (unformat (line_input, "teid %d", &teid))
	;
      else if (unformat (line_input, "tteid %d", &tteid))
	;
      else if (unformat (line_input, "upd-tteid %d", &tteid))
	opn = GTPU_UPD_TTEID;
      else if (unformat (line_input, "qfi %d", &qfi))
	pdu_extension = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (teid == 0)
    {
      error = clib_error_return (0, "tunnel teid specified");
      goto done;
    }

  if (src_set == 0 && opn == GTPU_ADD_TUNNEL)
    {
      error = clib_error_return (0, "tunnel src address not specified");
      goto done;
    }

  if (dst_set == 0)
    {
      error = clib_error_return (0, "tunnel dst address not specified");
      goto done;
    }

  if (grp_set && !ip46_address_is_multicast (&dst))
    {
      error = clib_error_return (0, "tunnel group address not multicast");
      goto done;
    }

  if (grp_set == 0 && ip46_address_is_multicast (&dst))
    {
      error = clib_error_return (0, "dst address must be unicast");
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

  if (ip46_address_cmp (&src, &dst) == 0)
    {
      error = clib_error_return (0, "src and dst addresses are identical");
      goto done;
    }

  if (decap_next_index == ~0)
    {
      error = clib_error_return (0, "next node not found");
      goto done;
    }
  if (pdu_extension == 1 && qfi > 31)
    {
      error = clib_error_return (0, "qfi max value is 31");
      goto done;
    }
  clib_memset (a, 0, sizeof (*a));

  a->opn = opn;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _

  rv = vnet_gtpu_add_mod_del_tunnel (a, &tunnel_sw_if_index);

  switch (rv)
    {
    case 0:
      if (opn == GTPU_ADD_TUNNEL)
	vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
			 vnet_get_main (), tunnel_sw_if_index);
      break;

    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "tunnel already exists...");
      goto done;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "tunnel does not exist...");
      goto done;

    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "tx teid not specified...");
      goto done;

    default:
      error = clib_error_return
	(0, "vnet_gtpu_add_del_tunnel returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Add or delete a GTPU Tunnel.
 *
 * GTPU can be used to transport Ethernet packets as its PDU type to
 * provides allow L2 network or bridge domains (BDs)
 * to span multiple servers. This is done by building an L2 overlay on
 * top of an L3 network underlay using GTPU tunnels.
 *
 * GTPU can also be used to transport IP packets as its PDU type to
 * allow IP forwarding over underlay network, e.g. between RAN and UPF
 * for mobility deployments.
 *
 * @cliexpar
 * Example of how to create a GTPU Tunnel:
 * @cliexcmd{create gtpu tunnel src 10.0.3.1 dst 10.0.3.3 teid 13 tteid 55
 * encap-vrf-id 7}
 * Example of how to delete a GTPU Tunnel:
 * @cliexcmd{create gtpu tunnel src 10.0.3.1 dst 10.0.3.3 teid 13 encap-vrf-id
 * 7 del}
 * Example of how to update tx TEID of a GTPU Tunnel:
 * @cliexcmd{create gtpu tunnel src 10.0.3.1 dst 10.0.3.3 encap-vrf-id 7
 * upd-tteid 55}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_gtpu_tunnel_command, static) = {
  .path = "create gtpu tunnel",
  .short_help =
    "create gtpu tunnel src <local-tep-addr>"
    " {dst <remote-tep-addr>|group <mcast-addr> <intf-name>}"
    " teid <nn> [tteid <nn>] [encap-vrf-id <nn>]"
    " [decap-next [l2|ip4|ip6|node <name>]] [qfi <nn>] [del | upd-tteid <nn>]",
  .function = gtpu_add_del_tunnel_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_gtpu_tunnel_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  gtpu_main_t *gtm = &gtpu_main;
  gtpu_tunnel_t *t;

  if (pool_elts (gtm->tunnels) == 0)
    vlib_cli_output (vm, "No gtpu tunnels configured...");

  pool_foreach (t, gtm->tunnels)
  {
    vlib_cli_output (vm, "%U", format_gtpu_tunnel, t);
  }

  return 0;
}

/*?
 * Display all the GTPU Tunnel entries.
 *
 * @cliexpar
 * Example of how to display the GTPU Tunnel entries:
 * @cliexstart{show gtpu tunnel}
 * [0] src 10.0.3.1 dst 10.0.3.3 teid 13 tx-teid 55 encap_fib_index 0
 sw_if_index 5 decap_next l2 pdu-disabled
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_gtpu_tunnel_command, static) = {
    .path = "show gtpu tunnel",
    .short_help = "show gtpu tunnel",
    .function = show_gtpu_tunnel_command_fn,
};
/* *INDENT-ON* */

void
vnet_int_gtpu_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable)
{
  if (is_ip6)
    vnet_feature_enable_disable ("ip6-unicast", "ip6-gtpu-bypass",
				 sw_if_index, is_enable, 0, 0);
  else
    vnet_feature_enable_disable ("ip4-unicast", "ip4-gtpu-bypass",
				 sw_if_index, is_enable, 0, 0);
}

static clib_error_t *
set_ip_gtpu_bypass (u32 is_ip6,
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

  vnet_int_gtpu_bypass_mode (sw_if_index, is_ip6, is_enable);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
set_ip4_gtpu_bypass (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return set_ip_gtpu_bypass (0, input, cmd);
}

/*?
 * This command adds the 'ip4-gtpu-bypass' graph node for a given interface.
 * By adding the IPv4 gtpu-bypass graph node to an interface, the node checks
 * for and validate input gtpu packet and bypass ip4-lookup, ip4-local,
 * ip4-udp-lookup nodes to speedup gtpu packet forwarding. This node will
 * cause extra overhead to for non-gtpu packets which is kept at a minimum.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before ip4-gtpu-bypass is enabled:
 * @cliexstart{show vlib graph ip4-gtpu-bypass}
 *            Name                      Next                    Previous
 * ip4-gtpu-bypass                error-drop [0]
 *                                gtpu4-input [1]
 *                                 ip4-lookup [2]
 * @cliexend
 *
 * Example of how to enable ip4-gtpu-bypass on an interface:
 * @cliexcmd{set interface ip gtpu-bypass GigabitEthernet2/0/0}
 *
 * Example of graph node after ip4-gtpu-bypass is enabled:
 * @cliexstart{show vlib graph ip4-gtpu-bypass}
 *            Name                      Next                    Previous
 * ip4-gtpu-bypass                error-drop [0]               ip4-input
 *                                gtpu4-input [1]        ip4-input-no-checksum
 *                                 ip4-lookup [2]
 * @cliexend
 *
 * Example of how to display the feature enabled on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 * ...
 * ipv4 unicast:
 *   ip4-gtpu-bypass
 *   ip4-lookup
 * ...
 * @cliexend
 *
 * Example of how to disable ip4-gtpu-bypass on an interface:
 * @cliexcmd{set interface ip gtpu-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip_gtpu_bypass_command, static) = {
  .path = "set interface ip gtpu-bypass",
  .function = set_ip4_gtpu_bypass,
  .short_help = "set interface ip gtpu-bypass <interface> [del]",
};
/* *INDENT-ON* */

static clib_error_t *
set_ip6_gtpu_bypass (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return set_ip_gtpu_bypass (1, input, cmd);
}

/*?
 * This command adds the 'ip6-gtpu-bypass' graph node for a given interface.
 * By adding the IPv6 gtpu-bypass graph node to an interface, the node checks
 * for and validate input gtpu packet and bypass ip6-lookup, ip6-local,
 * ip6-udp-lookup nodes to speedup gtpu packet forwarding. This node will
 * cause extra overhead to for non-gtpu packets which is kept at a minimum.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before ip6-gtpu-bypass is enabled:
 * @cliexstart{show vlib graph ip6-gtpu-bypass}
 *            Name                      Next                    Previous
 * ip6-gtpu-bypass                error-drop [0]
 *                                gtpu6-input [1]
 *                                 ip6-lookup [2]
 * @cliexend
 *
 * Example of how to enable ip6-gtpu-bypass on an interface:
 * @cliexcmd{set interface ip6 gtpu-bypass GigabitEthernet2/0/0}
 *
 * Example of graph node after ip6-gtpu-bypass is enabled:
 * @cliexstart{show vlib graph ip6-gtpu-bypass}
 *            Name                      Next                    Previous
 * ip6-gtpu-bypass                error-drop [0]               ip6-input
 *                                gtpu6-input [1]        ip4-input-no-checksum
 *                                 ip6-lookup [2]
 * @cliexend
 *
 * Example of how to display the feature enabled on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 * ...
 * ipv6 unicast:
 *   ip6-gtpu-bypass
 *   ip6-lookup
 * ...
 * @cliexend
 *
 * Example of how to disable ip6-gtpu-bypass on an interface:
 * @cliexcmd{set interface ip6 gtpu-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip6_gtpu_bypass_command, static) = {
  .path = "set interface ip6 gtpu-bypass",
  .function = set_ip6_gtpu_bypass,
  .short_help = "set interface ip6 gtpu-bypass <interface> [del]",
};
/* *INDENT-ON* */

int
vnet_gtpu_add_del_rx_flow (u32 hw_if_index, u32 t_index, int is_add)
{
  gtpu_main_t *gtm = &gtpu_main;
  gtpu_tunnel_t *t = pool_elt_at_index (gtm->tunnels, t_index);
  vnet_main_t *vnm = vnet_get_main ();
  if (is_add)
    {
      if (t->flow_index == ~0)
	{
	  vnet_flow_t flow = {
	    .actions =
	      VNET_FLOW_ACTION_REDIRECT_TO_NODE | VNET_FLOW_ACTION_MARK |
	      VNET_FLOW_ACTION_BUFFER_ADVANCE,
	    .mark_flow_id = t_index + gtm->flow_id_start,
	    .redirect_node_index = gtpu4_flow_input_node.index,
	    .buffer_advance = sizeof (ethernet_header_t)
	      + sizeof (ip4_header_t) + sizeof (udp_header_t),
	    .type = VNET_FLOW_TYPE_IP4_GTPU,
	    .ip4_gtpu = {
			 .protocol.prot = IP_PROTOCOL_UDP,
			 .src_addr.addr = t->dst.ip4,
			 .src_addr.mask.as_u32 = ~0,
			 .dst_addr.addr = t->src.ip4,
			 .dst_addr.mask.as_u32 = ~0,
			 .teid = t->teid,
			 }
	    ,
	  };
	  vnet_flow_add (vnm, &flow, &t->flow_index);
	}

      return vnet_flow_enable (vnm, t->flow_index, hw_if_index);
    }

  /* flow index is removed when the tunnel is deleted */
  return vnet_flow_disable (vnm, t->flow_index, hw_if_index);
}

u32
vnet_gtpu_get_tunnel_index (u32 sw_if_index)
{
  gtpu_main_t *gtm = &gtpu_main;

  if (sw_if_index >= vec_len (gtm->tunnel_index_by_sw_if_index))
    return ~0;
  return gtm->tunnel_index_by_sw_if_index[sw_if_index];
}

static clib_error_t *
gtpu_offload_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  vnet_main_t *vnm = vnet_get_main ();
  u32 rx_sw_if_index = ~0;
  u32 hw_if_index = ~0;
  int is_add = 1;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "hw %U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	continue;
      if (unformat (line_input, "rx %U", unformat_vnet_sw_interface, vnm,
		    &rx_sw_if_index))
	continue;
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	  continue;
	}
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, line_input);
    }

  if (rx_sw_if_index == ~0)
    return clib_error_return (0, "missing rx interface");
  if (hw_if_index == ~0)
    return clib_error_return (0, "missing hw interface");

  u32 t_index = vnet_gtpu_get_tunnel_index (rx_sw_if_index);;
  if (t_index == ~0)
    return clib_error_return (0, "%U is not a gtpu tunnel",
			      format_vnet_sw_if_index_name, vnm,
			      rx_sw_if_index);

  gtpu_main_t *gtm = &gtpu_main;
  gtpu_tunnel_t *t = pool_elt_at_index (gtm->tunnels, t_index);

  /* first support ipv4 hw offload */
  if (!ip46_address_is_ip4 (&t->dst))
    return clib_error_return (0, "currently only IPV4 tunnels are supported");

  /* inner protocol should be IPv4/IPv6 */
  if ((t->decap_next_index != GTPU_INPUT_NEXT_IP4_INPUT) &&
      (t->decap_next_index != GTPU_INPUT_NEXT_IP6_INPUT))
    return clib_error_return (0,
			      "currently only inner IPv4/IPv6 protocol is supported");

  vnet_hw_interface_t *hw_if = vnet_get_hw_interface (vnm, hw_if_index);
  ip4_main_t *im = &ip4_main;
  u32 rx_fib_index =
    vec_elt (im->fib_index_by_sw_if_index, hw_if->sw_if_index);

  if (t->encap_fib_index != rx_fib_index)
    return clib_error_return (0, "interface/tunnel fib mismatch");

  if (vnet_gtpu_add_del_rx_flow (hw_if_index, t_index, is_add))
    return clib_error_return (0, "error %s flow",
			      is_add ? "enabling" : "disabling");

  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gtpu_offload_command, static) = {
    .path = "set flow-offload gtpu",
    .short_help =
    "set flow-offload gtpu hw <inerface-name> rx <tunnel-name> [del]",
    .function = gtpu_offload_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
gtpu_forward_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  u32 tunnel_sw_if_index;
  clib_error_t *error = NULL;

  u32 decap_next_index = GTPU_INPUT_NEXT_L2_INPUT;

  int is_add = 1;
  u8 dst_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  ip46_address_t src, dst;
  u32 encap_fib_index = 0;
  u32 mcast_sw_if_index = ~0;
  u32 teid = 0, tteid = 0;
  u32 tmp;
  /* PDU is disabled by default */
  u8 pdu_extension = 0;
  u32 qfi = ~0;
  u8 is_forwarding = 1;
  u8 forwarding_type = 0;
  int rv;
  vnet_gtpu_add_mod_del_tunnel_args_t _a, *a = &_a;

  /* Cant "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&src, 0, sizeof src);
  clib_memset (&dst, 0, sizeof dst);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "dst %U", unformat_ip4_address, &dst.ip4))
	{
	  dst_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "dst %U", unformat_ip6_address, &dst.ip6))
	{
	  dst_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "decap-next %U", unformat_decap_next,
			 &decap_next_index, ipv4_set))
	;
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
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "bad-header"))
	forwarding_type |= GTPU_FORWARD_BAD_HEADER;
      else if (unformat (line_input, "unknown-teid"))
	forwarding_type |= GTPU_FORWARD_UNKNOWN_TEID;
      else if (unformat (line_input, "unknown-type"))
	forwarding_type |= GTPU_FORWARD_UNKNOWN_TYPE;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!dst_set)
    {
      error = clib_error_return (0, "dst must be set to a valid IP address");
      goto done;
    }

  a->opn = is_add ? GTPU_ADD_TUNNEL : GTPU_DEL_TUNNEL;
#define _(x) a->x = x;
  foreach_copy_field;
#undef _

  rv = vnet_gtpu_add_del_forwarding (a, &tunnel_sw_if_index);

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

    case VNET_API_ERROR_INVALID_ARGUMENT:
      error =
	clib_error_return (0, "one and only one of unknown-teid, unknown-type "
			      "or bad-header must be specified");
      goto done;

    default:
      error =
	clib_error_return (0, "vnet_gtpu_add_del_tunnel returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (gtpu_forward_command, static) = {
  .path = "create gtpu forward",
  .short_help =
    "create gtpu forward dst <local-tep-addr> "
    "{unknown-teid|unknown-type|bad-header} "
    "[decap-next [l2|ip4|ip6|node <name>]] [encap-vrf-id <nn>] [del]",
  .function = gtpu_forward_command_fn,
};

clib_error_t *
gtpu_init (vlib_main_t * vm)
{
  gtpu_main_t *gtm = &gtpu_main;

  gtm->vnet_main = vnet_get_main ();
  gtm->vlib_main = vm;

  vnet_flow_get_range (gtm->vnet_main, "gtpu", 1024 * 1024,
		       &gtm->flow_id_start);

  /* initialize the ip6 hash */
  gtm->gtpu6_tunnel_by_key = hash_create_mem (0,
					      sizeof (gtpu6_tunnel_key_t),
					      sizeof (uword));
  gtm->vtep_table = vtep_table_create ();
  gtm->mcast_shared = hash_create_mem (0,
				       sizeof (ip46_address_t),
				       sizeof (mcast_shared_t));

  gtm->fib_node_type = fib_node_register_new_type ("gtpu", &gtpu_vft);

  /* Clear forward tunnels */
  gtm->bad_header_forward_tunnel_index_ipv4 = ~0;
  gtm->unknown_teid_forward_tunnel_index_ipv4 = ~0;
  gtm->unknown_type_forward_tunnel_index_ipv4 = ~0;
  gtm->bad_header_forward_tunnel_index_ipv6 = ~0;
  gtm->unknown_teid_forward_tunnel_index_ipv6 = ~0;
  gtm->unknown_type_forward_tunnel_index_ipv6 = ~0;

  return 0;
}

VLIB_INIT_FUNCTION (gtpu_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "GPRS Tunnelling Protocol, User Data (GTPv1-U)",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
