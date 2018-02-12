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

#include "sixrd.h"
#include <vnet/plugin/plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/adj/adj.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_delegate.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vpp/app/version.h>	// Really needed?

/* define message IDs */
#include "sixrd_msg_enum.h"

/* define message structures */
#define vl_typedefs
#include "sixrd_all_api_h.h"
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include "sixrd_all_api_h.h"
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output(handle, __VA_ARGS__)
#define vl_printfun
#include "sixrd_all_api_h.h"
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n, v) static u32 api_version = (v);
#include "sixrd_all_api_h.h"
#undef vl_api_version

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

extern vlib_node_registration_t ip4_sixrd_node;

/**
 * Adj delegate data
 */
typedef struct sixrd_adj_delegate_t_
{
    /**
     * linkage to the adj
     */
  adj_delegate_t sixrd_link;

    /**
     * Linnkage to the FIB node graph
     */
  fib_node_t sixrd_node;

    /**
     * tracking of the IPv4 next-hop
     */
  fib_node_index_t sixrd_fib_entry_index;

    /**
     * sibling on the fib-entry
     */
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
 * FIN node registered type
 */
static fib_node_type_t sixrd_fib_node_type;

static inline sixrd_adj_delegate_t *
sixrd_adj_from_base (adj_delegate_t * ad)
{
  if (NULL == ad)
    {
      return (NULL);
    }
  return ((sixrd_adj_delegate_t *) ((char *) ad -
				    STRUCT_OFFSET_OF (sixrd_adj_delegate_t,
						      sixrd_link)));
}

static inline const sixrd_adj_delegate_t *
sixrd_adj_from_const_base (const adj_delegate_t * ad)
{
  if (NULL == ad)
    {
      return (NULL);
    }
  return ((const sixrd_adj_delegate_t *) ((char *) ad -
					  STRUCT_OFFSET_OF
					  (sixrd_adj_delegate_t,
					   sixrd_link)));
}

sixrd_main_t sixrd_main;

static void
sixrd_fixup (vlib_main_t * vm,
	     ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  ip4_header_t *ip4 = vlib_buffer_get_current (b0);
  ip6_header_t *ip6 = vlib_buffer_get_current (b0) + sizeof (ip4_header_t);
  const sixrd_tunnel_t *t = data;

  ip4->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  ip4->dst_address.as_u32 = sixrd_get_addr (t, ip6->dst_address.as_u64[0]);
  ip4->checksum = ip4_header_checksum (ip4);
}

static void
ip6ip_fixup (vlib_main_t * vm,
	     ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  const sixrd_tunnel_t *t = data;
  ip4_header_t *ip4 = vlib_buffer_get_current (b0);
  ip4->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  ip4->dst_address.as_u32 =
    sixrd_get_addr (t, adj->sub_type.nbr.next_hop.as_u64[0]);
  ip4->checksum = ip4_header_checksum (ip4);
}

static sixrd_tunnel_t *
find_tunnel_by_sw_if_index (u32 sw_if_index)
{
  sixrd_main_t *sm = &sixrd_main;
  u32 ti = sm->tunnel_index_by_sw_if_index[sw_if_index];
  if (ti == ~0)
    {
      clib_warning ("Not our tunnel\n");
      return (0);
    }
  return pool_elt_at_index (sm->tunnels, ti);
}

static sixrd_tunnel_t *
find_tunnel (ip6_address_t * ip6_prefix)
{
  sixrd_main_t *sm = &sixrd_main;
  sixrd_tunnel_t *d;

  /* *INDENT-OFF* */
  pool_foreach (d, sm->tunnels,
  ({
    if (!memcmp (&d->ip6_prefix, ip6_prefix, 16))
      return d;
  }));
  /* *INDENT-ON* */
  return 0;
}


static u8 *
sixrd_build_rewrite (vnet_main_t * vnm,
		     u32 sw_if_index,
		     vnet_link_t link_type, const void *dst_address)
{
  u8 *rewrite = NULL;
  sixrd_tunnel_t *t;

  t = find_tunnel_by_sw_if_index (sw_if_index);
  if (!t)
    {
      return 0;
    }

  vec_validate (rewrite, sizeof (ip4_header_t) - 1);
  ip4_header_t *ip4 = (ip4_header_t *) rewrite;
  ip4->ip_version_and_header_length = 0x45;
  ip4->ttl = 64;
  ip4->protocol = IP_PROTOCOL_IPV6;
  /* fixup ip4 header length and checksum after-the-fact */
  ip4->src_address.as_u32 = t->ip4_src.as_u32;
  ip4->dst_address.as_u32 = 0;
  ip4->checksum = ip4_header_checksum (ip4);

  return rewrite;
}

static void
ip6ip_tunnel_stack (adj_index_t ai, u32 fib_entry_index)
{
  sixrd_main_t *sm = &sixrd_main;
  ip_adjacency_t *adj = adj_get (ai);
  sixrd_tunnel_t *t;
  u32 sw_if_index = adj->rewrite_header.sw_if_index;

  if ((vec_len (sm->tunnel_index_by_sw_if_index) < sw_if_index) ||
      (~0 == sm->tunnel_index_by_sw_if_index[sw_if_index]))
    return;

  t =
    pool_elt_at_index (sm->tunnels,
		       sm->tunnel_index_by_sw_if_index[sw_if_index]);

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
  sixrd_main_t *sm = &sixrd_main;
  ip_adjacency_t *adj = adj_get (ai);
  u32 sw_if_index = adj->rewrite_header.sw_if_index;

  if ((vec_len (sm->tunnel_index_by_sw_if_index) < sw_if_index) ||
      (~0 == sm->tunnel_index_by_sw_if_index[sw_if_index]))
    return;

  if ((vec_len (sm->tunnel_index_by_sw_if_index) < sw_if_index) ||
      (sm->tunnel_index_by_sw_if_index[sw_if_index] == ~0))
    return;

  lookup_dpo_add_or_lock_w_fib_index (fib_index, DPO_PROTO_IP4,
				      LOOKUP_UNICAST, LOOKUP_INPUT_DST_ADDR,
				      LOOKUP_TABLE_FROM_CONFIG, &dpo);
  adj_nbr_midchain_stack (ai, &dpo);
}


static void
sixrd_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  ip_adjacency_t *adj = adj_get (ai);
  sixrd_tunnel_t *t = find_tunnel_by_sw_if_index (sw_if_index);

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_GLEAN:
      adj_nbr_midchain_update_rewrite (ai, sixrd_fixup, t, ADJ_FLAG_NONE,
				       sixrd_build_rewrite (vnm, sw_if_index,
							    adj_get_link_type
							    (ai), NULL));
      sixrd_tunnel_stack (ai, t->fib_index);
      break;
    default:
      {
	/* P2P */
	sixrd_adj_delegate_t *sixrd_ad;
	ip4_address_t da4;

	da4.as_u32 = sixrd_get_addr (t, adj->sub_type.nbr.next_hop.as_u64[0]);

	fib_prefix_t pfx = {
	  .fp_proto = FIB_PROTOCOL_IP4,
	  .fp_len = 32,
	  .fp_addr = {.ip4 = da4,}
	  ,
	};

	adj_nbr_midchain_update_rewrite
	  (ai, ip6ip_fixup, t,
	   ADJ_FLAG_NONE,
	   sixrd_build_rewrite (vnm, sw_if_index,
				adj_get_link_type (ai), NULL));

	sixrd_ad =
	  sixrd_adj_from_base (adj_delegate_get
			       (adj, sixrd_adj_delegate_type));

	if (NULL == sixrd_ad)
	  {
	    pool_get (sixrd_adj_delegate_pool, sixrd_ad);

	    sixrd_ad->sixrd_fib_entry_index =
	      fib_table_entry_special_add (t->fib_index, &pfx,
					   FIB_SOURCE_RR,
					   FIB_ENTRY_FLAG_NONE);
	    sixrd_ad->sixrd_sibling = fib_entry_child_add (t->fib_index,
							   FIB_NODE_TYPE_ADJ,
							   ai);

	    adj_delegate_add (adj,
			      sixrd_adj_delegate_type, &sixrd_ad->sixrd_link);

	    ip6ip_tunnel_stack (ai, sixrd_ad->sixrd_fib_entry_index);
	    break;
	  }
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
VNET_HW_INTERFACE_CLASS (sixrd_hw_interface_class) =
{
  .name = "ip6ip-6rd",
  .build_rewrite = sixrd_build_rewrite,
  .update_adjacency = sixrd_update_adj,
};

VNET_DEVICE_CLASS (sixrd_device_class) =
{
  .name = "ip6ip-6rd",
  .admin_up_down_function = sixrd_interface_admin_up_down,
#ifdef SOON
  .clear counter = 0;
#endif
};
/* *INDENT-ON* */

static int
sixrd_create_tunnel (ip6_address_t * ip6_prefix, u8 ip6_prefix_len,
		     ip4_address_t * ip4_prefix, u8 ip4_prefix_len,
		     ip4_address_t * ip4_src, u16 mtu, u32 fib_index,
		     u32 * sixrd_tunnel_index)
{
  sixrd_main_t *sm = &sixrd_main;
  sixrd_tunnel_t *t;

  if (fib_index == ~0)
    return VNET_API_ERROR_NO_SUCH_FIB;

  if ((ip6_prefix_len + 32 - ip4_prefix_len) > 64)
    return VNET_API_ERROR_INVALID_VALUE;

  /* Tunnel already configured */
  if (find_tunnel (ip6_prefix))
    return VNET_API_ERROR_INVALID_VALUE;
  /* Tunnel already configured */
  if (find_tunnel_by_ip4_address (ip4_src))
    return VNET_API_ERROR_INVALID_VALUE;

  /* Get tunnel index */
  pool_get_aligned (sm->tunnels, t, CLIB_CACHE_LINE_BYTES);
  memset (t, 0, sizeof (*t));
  t->tunnel_index = t - sm->tunnels;

  /* Init tunnel struct */
  t->ip4_prefix.as_u32 = ip4_prefix->as_u32;
  t->ip4_prefix_len = ip4_prefix_len;
  t->ip6_prefix = *ip6_prefix;
  t->ip6_prefix_len = ip6_prefix_len;
  t->ip4_src = *ip4_src;
  t->mtu = mtu;

  if (ip4_prefix_len < 32)
    t->shift = 64 - ip6_prefix_len + (32 - ip4_prefix_len);


  /* Create interface */
  u32 hw_if_index = vnet_register_interface (vnet_get_main (),
					     sixrd_device_class.index,
					     0,
					     sixrd_hw_interface_class.index,
					     0);

  /* Default the interface to up and enable IPv6 (payload) */
  vnet_hw_interface_t *hi =
    vnet_get_hw_interface (vnet_get_main (), hw_if_index);
  t->hw_if_index = hw_if_index;
  t->fib_index = fib_index;
  t->sw_if_index = hi->sw_if_index;

  vec_validate_init_empty (sm->tunnel_index_by_sw_if_index, hi->sw_if_index,
			   ~0);
  sm->tunnel_index_by_sw_if_index[hi->sw_if_index] = t->tunnel_index;

  hash_set (sm->tunnel_by_ip, ip4_src->as_u32, t->tunnel_index);

  /* Create IPv6 route/adjacency */
  fib_prefix_t pfx6 = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = t->ip6_prefix_len,
    .fp_addr = {.ip6 = t->ip6_prefix,}
    ,
  };

  fib_table_entry_update_one_path (fib_index, &pfx6,
				   FIB_SOURCE_CLI, FIB_ENTRY_FLAG_ATTACHED,
				   DPO_PROTO_IP6, NULL, hi->sw_if_index,
				   ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);

  *sixrd_tunnel_index = t->tunnel_index;

  ip4_register_protocol (IP_PROTOCOL_IPV6, ip4_sixrd_node.index);

  return 0;
}

/*
 * sixrd_delete_tunnel
 */
int
sixrd_delete_tunnel (u32 sixrd_tunnel_index)
{
  sixrd_main_t *sm = &sixrd_main;
  sixrd_tunnel_t *t;

  if (pool_is_free_index (sm->tunnels, sixrd_tunnel_index))
    {
      clib_warning ("SIXRD tunnel delete: tunnel does not exist: %d",
		    sixrd_tunnel_index);
      return -1;
    }

  t = pool_elt_at_index (sm->tunnels, sixrd_tunnel_index);

  fib_prefix_t pfx6 = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = t->ip6_prefix_len,
    .fp_addr = {.ip6 = t->ip6_prefix,}
    ,
  };
  fib_table_entry_special_remove (0, &pfx6, FIB_SOURCE_CLI);
  vnet_sw_interface_set_flags (vnet_get_main (), t->sw_if_index,
			       0 /* down */ );

  sm->tunnel_index_by_sw_if_index[t->sw_if_index] = ~0;

  hash_unset (sm->tunnel_by_ip, t->ip4_src.as_u32);

  pool_put (sm->tunnels, t);

  return 0;
}

static clib_error_t *
sixrd_add_del_tunnel_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t ip4_prefix;
  ip6_address_t ip6_prefix;
  ip4_address_t ip4_src;
  u32 ip6_prefix_len = 0, ip4_prefix_len = 0, sixrd_tunnel_index;
  u32 num_m_args = 0;
  /* Optional arguments */
  u32 mtu = 0;
  u32 fib_index = 0;
  clib_error_t *error = 0;
  bool is_add = true;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = false;
      else
	if (unformat
	    (line_input, "ip6-pfx %U/%d", unformat_ip6_address, &ip6_prefix,
	     &ip6_prefix_len))
	num_m_args++;
      else if (unformat (line_input, "ip4-pfx %U/%d", unformat_ip4_address,
			 &ip4_prefix, &ip4_prefix_len))
	num_m_args++;
      else
	if (unformat
	    (line_input, "ip4-src %U", unformat_ip4_address, &ip4_src))
	num_m_args++;
      else if (unformat (line_input, "mtu %d", &mtu))
	num_m_args++;
      else if (unformat (line_input, "fib-id %d", &fib_index))
	;
      else
	{
	  error =
	    clib_error_return (0, "unknown input `%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  if (num_m_args < 3)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      goto done;
    }
  if (is_add)
    {
      sixrd_create_tunnel (&ip6_prefix, ip6_prefix_len, &ip4_prefix,
			   ip4_prefix_len, &ip4_src, mtu, fib_index,
			   &sixrd_tunnel_index);
    }
  else
    {
      sixrd_tunnel_t *t = find_tunnel (&ip6_prefix);
      if (t)
	{
	  sixrd_delete_tunnel (t->tunnel_index);
	}
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (sixrd_add_del_tunnel_command, static) =
{
  .path = "create 6rd tunnel",
  .short_help = "create 6rd tunnel ip6-pfx <ip6-pfx> ip4-pfx <ip4-pfx> "
  "ip4-src <ip4-addr> [del]",
  .function = sixrd_add_del_tunnel_command_fn,
};
/* *INDENT-ON* */

static void
vl_api_sixrd_add_tunnel_t_handler (vl_api_sixrd_add_tunnel_t * mp)
{
  sixrd_main_t *sm = &sixrd_main;
  vl_api_sixrd_add_tunnel_reply_t *rmp;
  u32 sixrd_tunnel_index;
  u16 mtu = 0;

  int rv = sixrd_create_tunnel ((ip6_address_t *) & mp->ip6_prefix,
				mp->ip6_prefix_len,
				(ip4_address_t *) & mp->ip4_prefix,
				mp->ip4_prefix_len,
				(ip4_address_t *) & mp->ip4_src, mtu,
				ntohl (mp->fib_index),
				&sixrd_tunnel_index);

  REPLY_MACRO (VL_API_SIXRD_ADD_TUNNEL_REPLY);
}

static void
vl_api_sixrd_del_tunnel_t_handler (vl_api_sixrd_del_tunnel_t * mp)
{
  sixrd_main_t *sm = &sixrd_main;
  vl_api_sixrd_del_tunnel_reply_t *rmp;

  int rv = sixrd_delete_tunnel (mp->index);

  REPLY_MACRO (VL_API_SIXRD_DEL_TUNNEL_REPLY);
}

/* List of message types that this plugin understands */

#define foreach_sixrd_plugin_api_msg		\
_(SIXRD_ADD_TUNNEL, sixrd_add_tunnel)		\
_(SIXRD_DEL_TUNNEL, sixrd_del_tunnel)

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER() = {
    .version = VPP_BUILD_VER,
    .description = "IPv6 Rapid Deployment on IPv4 Infrastructure (RFC5969)",
};
/* *INDENT-ON* */

/**
 * @brief Set up the API message handling tables.
 */
static clib_error_t *
sixrd_plugin_api_hookup (vlib_main_t * vm)
{
  sixrd_main_t *sm = &sixrd_main;

#define _(N, n)                                                                \
  vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base), #n,                  \
                          vl_api_##n##_t_handler, vl_noop_handler,             \
                          vl_api_##n##_t_endian, vl_api_##n##_t_print,         \
                          sizeof(vl_api_##n##_t), 1);
  foreach_sixrd_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include "sixrd_all_api_h.h"
#undef vl_msg_name_crc_list

static void
setup_message_id_table (sixrd_main_t * sm, api_main_t * am)
{
#define _(id, n, crc)                                                          \
  vl_msg_api_add_msg_name_crc(am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_sixrd;
#undef _
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
  // top of the dependency tree, locks not managed here.
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

  ip6ip_tunnel_stack (sixrd_ad->sixrd_link.ad_adj_index,
		      sixrd_ad->sixrd_fib_entry_index);

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
  sixrd_main_t *sm = &sixrd_main;
  clib_error_t *error = 0;
  u8 *name;

  name = format (0, "sixrd_%08x%c", api_version, 0);

  sm->msg_id_base =
    vl_msg_api_get_msg_ids ((char *) name, VL_MSG_FIRST_AVAILABLE);
  vec_free (name);
  error = sixrd_plugin_api_hookup (vm);

  setup_message_id_table (sm, &api_main);

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
