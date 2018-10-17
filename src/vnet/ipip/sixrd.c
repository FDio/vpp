/*
 * sixrd.c - 6RD specific functions (RFC5969)
 *
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

/**
 * This code supports the following sixrd modes:
 *
 * 32 EA bits (Complete IPv4 address is embedded):
 *   ea_bits_len = 32
 * IPv4 suffix is embedded:
 *   ea_bits_len = < 32
 * No embedded address bits (1:1 mode):
 *   ea_bits_len = 0
 */

#include "ipip.h"
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_delegate.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/plugin/plugin.h>

extern vlib_node_registration_t ip4_sixrd_node;

/**
 * Adj delegate data
 */
typedef struct sixrd_adj_delegate_t_
{
  u32 adj_index;
  fib_node_t sixrd_node;
  fib_node_index_t sixrd_fib_entry_index;
  u32 sixrd_sibling;
} sixrd_adj_delegate_t;

/**
 * Pool of delegate structs
 */
static sixrd_adj_delegate_t *sixrd_adj_delegate_pool;

/**
 * Adj delegate registered type
 */
static adj_delegate_type_t sixrd_adj_delegate_type;

/**
 * FIB node registered type
 */
static fib_node_type_t sixrd_fib_node_type;

static inline sixrd_adj_delegate_t *
sixrd_adj_from_base (adj_delegate_t * ad)
{
  if (ad == NULL)
    return (NULL);
  return (pool_elt_at_index (sixrd_adj_delegate_pool, ad->ad_index));
}

static inline const sixrd_adj_delegate_t *
sixrd_adj_from_const_base (const adj_delegate_t * ad)
{
  if (ad == NULL)
    {
      return (NULL);
    }
  return (pool_elt_at_index (sixrd_adj_delegate_pool, ad->ad_index));
}

static void
sixrd_fixup (vlib_main_t * vm, ip_adjacency_t * adj, vlib_buffer_t * b0,
	     const void *data)
{
  ip4_header_t *ip4 = vlib_buffer_get_current (b0);
  ip6_header_t *ip6 = vlib_buffer_get_current (b0) + sizeof (ip4_header_t);
  const ipip_tunnel_t *t = data;

  ip4->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  ip4->dst_address.as_u32 =
    sixrd_get_addr_net (t, ip6->dst_address.as_u64[0]);
  ip4->checksum = ip4_header_checksum (ip4);
}

static void
ip6ip_fixup (vlib_main_t * vm, ip_adjacency_t * adj, vlib_buffer_t * b0,
	     const void *data)
{
  const ipip_tunnel_t *t = data;
  ip4_header_t *ip4 = vlib_buffer_get_current (b0);
  ip4->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  ip4->dst_address.as_u32 =
    sixrd_get_addr_net (t, adj->sub_type.nbr.next_hop.as_u64[0]);
  ip4->checksum = ip4_header_checksum (ip4);
}

static u8 *
sixrd_build_rewrite (vnet_main_t * vnm, u32 sw_if_index,
		     vnet_link_t link_type, const void *dst_address)
{
  u8 *rewrite = NULL;
  ipip_tunnel_t *t;

  t = ipip_tunnel_db_find_by_sw_if_index (sw_if_index);
  if (!t)
    return 0;

  vec_validate (rewrite, sizeof (ip4_header_t) - 1);
  ip4_header_t *ip4 = (ip4_header_t *) rewrite;
  ip4->ip_version_and_header_length = 0x45;
  ip4->ttl = 64;
  ip4->protocol = IP_PROTOCOL_IPV6;
  /* fixup ip4 header length and checksum after-the-fact */
  ip4->src_address.as_u32 = t->tunnel_src.ip4.as_u32;
  ip4->dst_address.as_u32 = 0;
  ip4->checksum = ip4_header_checksum (ip4);

  return rewrite;
}

static void
ip6ip_tunnel_stack (adj_index_t ai, u32 fib_entry_index)
{
  ip_adjacency_t *adj = adj_get (ai);
  ipip_tunnel_t *t;
  u32 sw_if_index = adj->rewrite_header.sw_if_index;

  t = ipip_tunnel_db_find_by_sw_if_index (sw_if_index);
  if (!t)
    return;

  /*
   * find the adjacency that is contributed by the FIB entry
   * that this tunnel resolves via, and use it as the next adj
   * in the midchain
   */
  if (vnet_hw_interface_get_flags (vnet_get_main (), t->hw_if_index) &
      VNET_HW_INTERFACE_FLAG_LINK_UP)
    {
      adj_nbr_midchain_stack (ai,
			      fib_entry_contribute_ip_forwarding
			      (fib_entry_index));
    }
  else
    {
      adj_nbr_midchain_unstack (ai);
    }
}

static void
sixrd_tunnel_stack (adj_index_t ai, u32 fib_index)
{
  dpo_id_t dpo = DPO_INVALID;
  ip_adjacency_t *adj = adj_get (ai);
  u32 sw_if_index = adj->rewrite_header.sw_if_index;

  ipip_tunnel_t *t = ipip_tunnel_db_find_by_sw_if_index (sw_if_index);
  if (!t)
    return;

  lookup_dpo_add_or_lock_w_fib_index (fib_index, DPO_PROTO_IP4,
				      LOOKUP_UNICAST, LOOKUP_INPUT_DST_ADDR,
				      LOOKUP_TABLE_FROM_CONFIG, &dpo);
  adj_nbr_midchain_stack (ai, &dpo);
  dpo_reset (&dpo);
}

static void
sixrd_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  ip_adjacency_t *adj = adj_get (ai);
  ipip_tunnel_t *t = ipip_tunnel_db_find_by_sw_if_index (sw_if_index);

  /* Not our tunnel */
  if (!t)
    return;
  if (IP_LOOKUP_NEXT_BCAST == adj->lookup_next_index)
    {
      adj_nbr_midchain_update_rewrite (ai, sixrd_fixup, t, ADJ_FLAG_NONE,
				       sixrd_build_rewrite (vnm, sw_if_index,
							    adj_get_link_type
							    (ai), NULL));
      sixrd_tunnel_stack (ai, t->fib_index);
    }
  else
    {
      sixrd_adj_delegate_t *sixrd_ad;
      ip4_address_t da4;

      da4.as_u32 =
	sixrd_get_addr_net (t, adj->sub_type.nbr.next_hop.as_u64[0]);

      fib_prefix_t pfx = {
	.fp_proto = FIB_PROTOCOL_IP4,
	.fp_len = 32,
	.fp_addr = {
		    .ip4 = da4,
		    }
	,
      };

      adj_nbr_midchain_update_rewrite (ai, ip6ip_fixup, t, ADJ_FLAG_NONE,
				       sixrd_build_rewrite (vnm, sw_if_index,
							    adj_get_link_type
							    (ai), NULL));

      sixrd_ad =
	sixrd_adj_from_base (adj_delegate_get (adj, sixrd_adj_delegate_type));
      if (sixrd_ad == NULL)
	{
	  pool_get (sixrd_adj_delegate_pool, sixrd_ad);
	  fib_node_init (&sixrd_ad->sixrd_node, sixrd_fib_node_type);
	  sixrd_ad->adj_index = ai;
	  sixrd_ad->sixrd_fib_entry_index =
	    fib_table_entry_special_add (t->fib_index, &pfx, FIB_SOURCE_RR,
					 FIB_ENTRY_FLAG_NONE);
	  sixrd_ad->sixrd_sibling =
	    fib_entry_child_add (sixrd_ad->sixrd_fib_entry_index,
				 sixrd_fib_node_type,
				 sixrd_ad - sixrd_adj_delegate_pool);

	  adj_delegate_add (adj, sixrd_adj_delegate_type,
			    sixrd_ad - sixrd_adj_delegate_pool);

	  ip6ip_tunnel_stack (ai, sixrd_ad->sixrd_fib_entry_index);
	}
    }
}

clib_error_t *
sixrd_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  /* Always up */
  vnet_hw_interface_set_flags (vnm, hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS(sixrd_hw_interface_class) = {
    .name = "ip6ip-6rd",
    .build_rewrite = sixrd_build_rewrite,
    .update_adjacency = sixrd_update_adj,
};

VNET_DEVICE_CLASS(sixrd_device_class) = {
    .name = "ip6ip-6rd",
    .admin_up_down_function = sixrd_interface_admin_up_down,
#ifdef SOON
    .clear counter = 0;
#endif
}
;
/* *INDENT-ON* */

int
sixrd_add_tunnel (ip6_address_t * ip6_prefix, u8 ip6_prefix_len,
		  ip4_address_t * ip4_prefix, u8 ip4_prefix_len,
		  ip4_address_t * ip4_src, bool security_check,
		  u32 ip4_fib_index, u32 ip6_fib_index, u32 * sw_if_index)
{
  ipip_main_t *gm = &ipip_main;
  ipip_tunnel_t *t;

  if ((ip6_prefix_len + 32 - ip4_prefix_len) > 64)
    return VNET_API_ERROR_INVALID_VALUE;

  /* Tunnel already configured */
  ip46_address_t src = ip46_address_initializer, dst =
    ip46_address_initializer;
  ip_set (&src, ip4_src, true);
  ipip_tunnel_key_t key = {
    .transport = IPIP_TRANSPORT_IP4,
    .fib_index = ip4_fib_index,
    .src = src,
    .dst = dst
  };

  t = ipip_tunnel_db_find (&key);
  if (t)
    return VNET_API_ERROR_IF_ALREADY_EXISTS;

  /* Get tunnel index */
  pool_get_aligned (gm->tunnels, t, CLIB_CACHE_LINE_BYTES);
  clib_memset (t, 0, sizeof (*t));
  u32 t_idx = t - gm->tunnels;	/* tunnel index (or instance) */

  /* Init tunnel struct */
  t->mode = IPIP_MODE_6RD;
  t->sixrd.ip4_prefix.as_u32 = ip4_prefix->as_u32;
  t->sixrd.ip4_prefix_len = ip4_prefix_len;
  t->sixrd.ip6_prefix = *ip6_prefix;
  t->sixrd.ip6_prefix_len = ip6_prefix_len;
  t->sixrd.ip6_fib_index = ip6_fib_index;
  t->tunnel_src = src;
  t->sixrd.security_check = security_check;
  t->sixrd.shift =
    (ip4_prefix_len < 32) ? 64 - ip6_prefix_len - (32 - ip4_prefix_len) : 0;

  /* Create interface */
  u32 hw_if_index =
    vnet_register_interface (vnet_get_main (), sixrd_device_class.index,
			     t_idx,
			     sixrd_hw_interface_class.index, t_idx);

  /* Default the interface to up and enable IPv6 (payload) */
  vnet_hw_interface_t *hi =
    vnet_get_hw_interface (vnet_get_main (), hw_if_index);
  t->hw_if_index = hw_if_index;
  t->fib_index = ip4_fib_index;
  t->sw_if_index = hi->sw_if_index;
  t->dev_instance = t_idx;
  t->user_instance = t_idx;

  vnet_sw_interface_set_mtu (vnet_get_main (), t->sw_if_index, 1480);

  ipip_tunnel_db_add (t, &key);

  vec_validate_init_empty (gm->tunnel_index_by_sw_if_index, hi->sw_if_index,
			   ~0);
  gm->tunnel_index_by_sw_if_index[hi->sw_if_index] = t_idx;

  vnet_hw_interface_set_flags (vnet_get_main (), hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  vnet_sw_interface_set_flags (vnet_get_main (), hi->sw_if_index,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  ip6_sw_interface_enable_disable (t->sw_if_index, true);

  /* Create IPv6 route/adjacency */
  /* *INDENT-OFF* */
  fib_prefix_t pfx6 = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = t->sixrd.ip6_prefix_len,
    .fp_addr = {
      .ip6 = t->sixrd.ip6_prefix,
    },
  };
  /* *INDENT-ON* */

  fib_table_lock (ip6_fib_index, FIB_PROTOCOL_IP6, FIB_SOURCE_6RD);
  fib_table_entry_update_one_path (ip6_fib_index, &pfx6, FIB_SOURCE_6RD,
				   FIB_ENTRY_FLAG_ATTACHED, DPO_PROTO_IP6,
				   &ADJ_BCAST_ADDR, t->sw_if_index, ~0, 1,
				   NULL, FIB_ROUTE_PATH_FLAG_NONE);

  *sw_if_index = t->sw_if_index;

  if (!gm->ip4_protocol_registered)
    {
      vlib_node_t *ipip4_input =
	vlib_get_node_by_name (gm->vlib_main, (u8 *) "ipip4-input");
      ASSERT (ipip4_input);
      ip4_register_protocol (IP_PROTOCOL_IPV6, ipip4_input->index);
    }
  return 0;
}

/*
 * sixrd_del_tunnel
 */
int
sixrd_del_tunnel (u32 sw_if_index)
{
  ipip_main_t *gm = &ipip_main;
  ipip_tunnel_t *t = ipip_tunnel_db_find_by_sw_if_index (sw_if_index);

  if (!t)
    {
      clib_warning ("SIXRD tunnel delete: tunnel does not exist: %d",
		    sw_if_index);
      return -1;
    }

  /* *INDENT-OFF* */
  fib_prefix_t pfx6 = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = t->sixrd.ip6_prefix_len,
    .fp_addr = {
      .ip6 = t->sixrd.ip6_prefix,
    },
  };
  /* *INDENT-ON* */

  fib_table_entry_path_remove (t->sixrd.ip6_fib_index, &pfx6,
			       FIB_SOURCE_6RD,
			       DPO_PROTO_IP6,
			       &ADJ_BCAST_ADDR, t->sw_if_index, ~0, 1,
			       FIB_ROUTE_PATH_FLAG_NONE);
  fib_table_unlock (t->sixrd.ip6_fib_index, FIB_PROTOCOL_IP6, FIB_SOURCE_6RD);

  vnet_sw_interface_set_flags (vnet_get_main (), t->sw_if_index,
			       0 /* down */ );
  ip6_sw_interface_enable_disable (t->sw_if_index, false);
  gm->tunnel_index_by_sw_if_index[t->sw_if_index] = ~0;

  vnet_delete_hw_interface (vnet_get_main (), t->hw_if_index);
  ipip_tunnel_db_remove (t);
  pool_put (gm->tunnels, t);

  return 0;
}

static void
sixrd_adj_delegate_adj_deleted (adj_delegate_t * aed)
{
  sixrd_adj_delegate_t *sixrd_ad;

  sixrd_ad = sixrd_adj_from_base (aed);
  fib_entry_child_remove (sixrd_ad->sixrd_fib_entry_index,
			  sixrd_ad->sixrd_sibling);
  fib_table_entry_delete_index (sixrd_ad->sixrd_fib_entry_index,
				FIB_SOURCE_RR);
  pool_put (sixrd_adj_delegate_pool, sixrd_ad);
}

static u8 *
sixrd_adj_delegate_format (const adj_delegate_t * aed, u8 * s)
{
  const sixrd_adj_delegate_t *sixrd_ad;

  sixrd_ad = sixrd_adj_from_const_base (aed);
  s = format (s, "SIXRD:[fib-entry:%d]", sixrd_ad->sixrd_fib_entry_index);

  return (s);
}

static void
sixrd_fib_node_last_lock_gone (fib_node_t * node)
{
  /* top of the dependency tree, locks not managed here. */
}

static sixrd_adj_delegate_t *
sixrd_adj_delegate_from_fib_node (fib_node_t * node)
{
  return ((sixrd_adj_delegate_t *) (((char *) node) -
				    STRUCT_OFFSET_OF (sixrd_adj_delegate_t,
						      sixrd_node)));
}

static fib_node_back_walk_rc_t
sixrd_fib_node_back_walk_notify (fib_node_t * node,
				 fib_node_back_walk_ctx_t * ctx)
{
  sixrd_adj_delegate_t *sixrd_ad;

  sixrd_ad = sixrd_adj_delegate_from_fib_node (node);
  ip6ip_tunnel_stack (sixrd_ad->adj_index, sixrd_ad->sixrd_fib_entry_index);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
sixrd_fib_node_get (fib_node_index_t index)
{
  sixrd_adj_delegate_t *sixrd_ad;

  sixrd_ad = pool_elt_at_index (sixrd_adj_delegate_pool, index);

  return (&sixrd_ad->sixrd_node);
}

/**
 * VFT registered with the adjacency delegate
 */
const static adj_delegate_vft_t sixrd_adj_delegate_vft = {
  .adv_adj_deleted = sixrd_adj_delegate_adj_deleted,
  .adv_format = sixrd_adj_delegate_format,
};

/**
 * VFT registered with the FIB node for the adj delegate
 */
const static fib_node_vft_t sixrd_fib_node_vft = {
  .fnv_get = sixrd_fib_node_get,
  .fnv_last_lock = sixrd_fib_node_last_lock_gone,
  .fnv_back_walk = sixrd_fib_node_back_walk_notify,
};

static clib_error_t *
sixrd_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  /* Make sure the IPIP tunnel subsystem is initialised */
  error = vlib_call_init_function (vm, ipip_init);

  sixrd_adj_delegate_type =
    adj_delegate_register_new_type (&sixrd_adj_delegate_vft);
  sixrd_fib_node_type = fib_node_register_new_type (&sixrd_fib_node_vft);

  return error;
}

VLIB_INIT_FUNCTION (sixrd_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
