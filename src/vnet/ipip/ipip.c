/*
 * ipip.c: ipip
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or aipiped to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/ipip/ipip.h>
#include <vnet/vnet.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/format.h>
#include <vnet/ipip/ipip.h>

ipip_main_t ipip_main;

/* Packet trace structure */
typedef struct
{
  u32 tunnel_id;
  u32 length;
  ip46_address_t src;
  ip46_address_t dst;
} ipip_tx_trace_t;

u8 *
format_ipip_tx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipip_tx_trace_t *t = va_arg (*args, ipip_tx_trace_t *);

  s =
    format (s, "IPIP: tunnel %d len %d src %U dst %U", t->tunnel_id,
	    t->length, format_ip46_address, &t->src, IP46_TYPE_ANY,
	    format_ip46_address, &t->dst, IP46_TYPE_ANY);
  return s;
}

static u8 *
ipip_build_rewrite (vnet_main_t * vnm, u32 sw_if_index,
		    vnet_link_t link_type, const void *dst_address)
{
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  u8 *rewrite = NULL;
  ipip_tunnel_t *t = ipip_tunnel_db_find_by_sw_if_index (sw_if_index);

  if (!t)
    /* not one of ours */
    return (0);

  switch (t->transport)
    {
    case IPIP_TRANSPORT_IP4:
      vec_validate (rewrite, sizeof (*ip4) - 1);
      ip4 = (ip4_header_t *) rewrite;
      ip4->ip_version_and_header_length = 0x45;
      ip4->ttl = 64;
      /* fixup ip4 header length, protocol and checksum after-the-fact */
      ip4->src_address.as_u32 = t->tunnel_src.ip4.as_u32;
      ip4->dst_address.as_u32 = t->tunnel_dst.ip4.as_u32;
      ip4->checksum = ip4_header_checksum (ip4);
      if (t->tc_tos != 0xFF)
	ip4->tos = t->tc_tos;
      break;

    case IPIP_TRANSPORT_IP6:
      vec_validate (rewrite, sizeof (*ip6) - 1);
      ip6 = (ip6_header_t *) rewrite;
      ip6->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (6 << 28);
      if (t->tc_tos != 0xFF)
	ip6_set_traffic_class_network_order (ip6, t->tc_tos);
      ip6->hop_limit = 64;
      /* fixup ip6 header length and protocol after-the-fact */
      ip6->src_address.as_u64[0] = t->tunnel_src.ip6.as_u64[0];
      ip6->src_address.as_u64[1] = t->tunnel_src.ip6.as_u64[1];
      ip6->dst_address.as_u64[0] = t->tunnel_dst.ip6.as_u64[0];
      ip6->dst_address.as_u64[1] = t->tunnel_dst.ip6.as_u64[1];
      break;

    default:
      /* pass through */
      ;
    }
  return (rewrite);
}

static void
ipip4_fixup (vlib_main_t * vm, ip_adjacency_t * adj, vlib_buffer_t * b,
	     const void *data)
{
  ip4_header_t *ip4;
  const ipip_tunnel_t *t = data;

  ip4 = vlib_buffer_get_current (b);
  ip4->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b));
  switch (adj->ia_link)
    {
    case VNET_LINK_IP6:
      ip4->protocol = IP_PROTOCOL_IPV6;
      if (t->tc_tos == 0xFF)
	ip4->tos =
	  ip6_traffic_class_network_order ((const ip6_header_t *) (ip4 + 1));
      break;

    case VNET_LINK_IP4:
      ip4->protocol = IP_PROTOCOL_IP_IN_IP;
      if (t->tc_tos == 0xFF)
	ip4->tos = ((ip4_header_t *) (ip4 + 1))->tos;
      break;

    default:
      break;
    }

  ip4->checksum = ip4_header_checksum (ip4);
}

static void
ipip6_fixup (vlib_main_t * vm, ip_adjacency_t * adj, vlib_buffer_t * b,
	     const void *data)
{
  ip6_header_t *ip6;
  const ipip_tunnel_t *t = data;

  /* Must set locally originated otherwise we're not allowed to
     fragment the packet later */
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  ip6 = vlib_buffer_get_current (b);
  ip6->payload_length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b) -
			  sizeof (*ip6));
  switch (adj->ia_link)
    {
    case VNET_LINK_IP6:
      ip6->protocol = IP_PROTOCOL_IPV6;
      if (t->tc_tos == 0xFF)
	ip6_set_traffic_class_network_order (ip6,
					     ip6_traffic_class_network_order ((const ip6_header_t *) (ip6 + 1)));
      break;

    case VNET_LINK_IP4:
      ip6->protocol = IP_PROTOCOL_IP_IN_IP;
      if (t->tc_tos == 0xFF)
	ip6_set_traffic_class_network_order (ip6,
					     ((ip4_header_t *) (ip6 +
								1))->tos);
      break;

    default:
      break;
    }
}

static void
ipip_tunnel_stack (adj_index_t ai)
{
  ip_adjacency_t *adj;
  ipip_tunnel_t *t;
  u32 sw_if_index;

  adj = adj_get (ai);
  sw_if_index = adj->rewrite_header.sw_if_index;

  t = ipip_tunnel_db_find_by_sw_if_index (sw_if_index);
  if (!t)
    return;

  if ((vnet_hw_interface_get_flags (vnet_get_main (), t->hw_if_index) &
       VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)
    {
      adj_midchain_delegate_unstack (ai);
    }
  else
    {
      /* *INDENT-OFF* */
      fib_prefix_t dst = {
        .fp_len = t->transport == IPIP_TRANSPORT_IP6 ? 128 : 32,
        .fp_proto = (t->transport == IPIP_TRANSPORT_IP6 ?
                     FIB_PROTOCOL_IP6 :
                     FIB_PROTOCOL_IP4),
        .fp_addr = t->tunnel_dst
      };
      /* *INDENT-ON* */

      adj_midchain_delegate_stack (ai, t->fib_index, &dst);
    }
}

static adj_walk_rc_t
ipip_adj_walk_cb (adj_index_t ai, void *ctx)
{
  ipip_tunnel_stack (ai);

  return (ADJ_WALK_RC_CONTINUE);
}

static void
ipip_tunnel_restack (ipip_tunnel_t * gt)
{
  fib_protocol_t proto;

  /*
   * walk all the adjacencies on th IPIP interface and restack them
   */
  FOR_EACH_FIB_IP_PROTOCOL (proto)
  {
    adj_nbr_walk (gt->sw_if_index, proto, ipip_adj_walk_cb, NULL);
  }
}

void
ipip_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  adj_midchain_fixup_t f;
  ipip_tunnel_t *t;
  adj_flags_t af;

  t = ipip_tunnel_db_find_by_sw_if_index (sw_if_index);
  if (!t)
    return;

  f = t->transport == IPIP_TRANSPORT_IP6 ? ipip6_fixup : ipip4_fixup;
  af = ADJ_FLAG_MIDCHAIN_IP_STACK;
  if (VNET_LINK_ETHERNET == adj_get_link_type (ai))
    af |= ADJ_FLAG_MIDCHAIN_NO_COUNT;

  adj_nbr_midchain_update_rewrite (ai, f, t, af,
				   ipip_build_rewrite (vnm,
						       sw_if_index,
						       adj_get_link_type
						       (ai), NULL));
  ipip_tunnel_stack (ai);
}

static u8 *
format_ipip_tunnel_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  ipip_main_t *gm = &ipip_main;
  ipip_tunnel_t *t;

  if (dev_instance >= vec_len (gm->tunnels))
    return format (s, "<improperly-referenced>");

  t = pool_elt_at_index (gm->tunnels, dev_instance);
  return format (s, "ipip%d", t->user_instance);
}

static u8 *
format_ipip_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);

  s = format (s, "IPIP tunnel: id %d\n", dev_instance);
  return s;
}

static clib_error_t *
ipip_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi;
  ipip_tunnel_t *t;

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  t = ipip_tunnel_db_find_by_sw_if_index (hi->sw_if_index);
  if (!t)
    return 0;

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    vnet_hw_interface_set_flags (vnm, hw_if_index,
				 VNET_HW_INTERFACE_FLAG_LINK_UP);
  else
    vnet_hw_interface_set_flags (vnm, hw_if_index, 0 /* down */ );

  ipip_tunnel_restack (t);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS(ipip_device_class) = {
    .name = "IPIP tunnel device",
    .format_device_name = format_ipip_tunnel_name,
    .format_device = format_ipip_device,
    .format_tx_trace = format_ipip_tx_trace,
    .admin_up_down_function = ipip_interface_admin_up_down,
#ifdef SOON
    .clear counter = 0;
#endif
};

VNET_HW_INTERFACE_CLASS(ipip_hw_interface_class) = {
    .name = "IPIP",
    //.format_header = format_ipip_header_with_length,
    //.unformat_header = unformat_ipip_header,
    .build_rewrite = ipip_build_rewrite,
    .update_adjacency = ipip_update_adj,
    .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

ipip_tunnel_t *
ipip_tunnel_db_find (ipip_tunnel_key_t * key)
{
  ipip_main_t *gm = &ipip_main;
  uword *p;

  p = hash_get_mem (gm->tunnel_by_key, key);
  if (!p)
    return (NULL);
  return (pool_elt_at_index (gm->tunnels, p[0]));
}

ipip_tunnel_t *
ipip_tunnel_db_find_by_sw_if_index (u32 sw_if_index)
{
  ipip_main_t *gm = &ipip_main;
  if (vec_len (gm->tunnel_index_by_sw_if_index) <= sw_if_index)
    return NULL;
  u32 ti = gm->tunnel_index_by_sw_if_index[sw_if_index];
  if (ti == ~0)
    return NULL;
  return pool_elt_at_index (gm->tunnels, ti);
}

void
ipip_tunnel_db_add (ipip_tunnel_t * t, ipip_tunnel_key_t * key)
{
  ipip_main_t *gm = &ipip_main;

  t->key = clib_mem_alloc (sizeof (*t->key));
  clib_memcpy (t->key, key, sizeof (*key));
  hash_set_mem (gm->tunnel_by_key, t->key, t->dev_instance);
}

void
ipip_tunnel_db_remove (ipip_tunnel_t * t)
{
  ipip_main_t *gm = &ipip_main;

  hash_unset_mem (gm->tunnel_by_key, t->key);
  clib_mem_free (t->key);
  t->key = NULL;
}

int
ipip_add_tunnel (ipip_transport_t transport,
		 u32 instance, ip46_address_t * src, ip46_address_t * dst,
		 u32 fib_index, u8 tc_tos, u32 * sw_if_indexp)
{
  ipip_main_t *gm = &ipip_main;
  vnet_main_t *vnm = gm->vnet_main;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  ipip_tunnel_t *t;
  vnet_hw_interface_t *hi;
  u32 hw_if_index, sw_if_index;
  ipip_tunnel_key_t key = {.transport = transport,
    .fib_index = fib_index,
    .src = *src,
    .dst = *dst
  };
  t = ipip_tunnel_db_find (&key);
  if (t)
    return VNET_API_ERROR_IF_ALREADY_EXISTS;

  pool_get_aligned (gm->tunnels, t, CLIB_CACHE_LINE_BYTES);
  clib_memset (t, 0, sizeof (*t));

  /* Reconcile the real dev_instance and a possible requested instance */
  u32 t_idx = t - gm->tunnels;	/* tunnel index (or instance) */
  u32 u_idx = instance;		/* user specified instance */
  if (u_idx == ~0)
    u_idx = t_idx;
  if (hash_get (gm->instance_used, u_idx))
    {
      pool_put (gm->tunnels, t);
      return VNET_API_ERROR_INSTANCE_IN_USE;
    }
  hash_set (gm->instance_used, u_idx, 1);

  t->dev_instance = t_idx;	/* actual */
  t->user_instance = u_idx;	/* name */

  hw_if_index = vnet_register_interface (vnm, ipip_device_class.index, t_idx,
					 ipip_hw_interface_class.index,
					 t_idx);

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  sw_if_index = hi->sw_if_index;

  t->hw_if_index = hw_if_index;
  t->fib_index = fib_index;
  t->sw_if_index = sw_if_index;
  t->tc_tos = tc_tos;

  t->transport = transport;
  vec_validate_init_empty (gm->tunnel_index_by_sw_if_index, sw_if_index, ~0);
  gm->tunnel_index_by_sw_if_index[sw_if_index] = t_idx;

  if (t->transport == IPIP_TRANSPORT_IP4)
    {
      vec_validate (im4->fib_index_by_sw_if_index, sw_if_index);
      hi->min_packet_bytes = 64 + sizeof (ip4_header_t);
    }
  else
    {
      vec_validate (im6->fib_index_by_sw_if_index, sw_if_index);
      hi->min_packet_bytes = 64 + sizeof (ip6_header_t);
    }

  /* Standard default ipip MTU. */
  vnet_sw_interface_set_mtu (vnm, sw_if_index, 9000);

  t->tunnel_src = *src;
  t->tunnel_dst = *dst;

  ipip_tunnel_db_add (t, &key);

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  if (t->transport == IPIP_TRANSPORT_IP6 && !gm->ip6_protocol_registered)
    {
      ip6_register_protocol (IP_PROTOCOL_IP_IN_IP, ipip6_input_node.index);
      ip6_register_protocol (IP_PROTOCOL_IPV6, ipip6_input_node.index);
      gm->ip6_protocol_registered = true;
    }
  else if (t->transport == IPIP_TRANSPORT_IP4 && !gm->ip4_protocol_registered)
    {
      ip4_register_protocol (IP_PROTOCOL_IP_IN_IP, ipip4_input_node.index);
      ip4_register_protocol (IP_PROTOCOL_IPV6, ipip4_input_node.index);
      gm->ip4_protocol_registered = true;
    }
  return 0;
}

int
ipip_del_tunnel (u32 sw_if_index)
{
  ipip_main_t *gm = &ipip_main;
  vnet_main_t *vnm = gm->vnet_main;
  ipip_tunnel_t *t;


  t = ipip_tunnel_db_find_by_sw_if_index (sw_if_index);
  if (t == NULL)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vnet_sw_interface_set_flags (vnm, sw_if_index, 0 /* down */ );
  gm->tunnel_index_by_sw_if_index[sw_if_index] = ~0;
  vnet_delete_hw_interface (vnm, t->hw_if_index);
  hash_unset (gm->instance_used, t->user_instance);
  ipip_tunnel_db_remove (t);
  pool_put (gm->tunnels, t);

  return 0;
}

static clib_error_t *
ipip_init (vlib_main_t * vm)
{
  ipip_main_t *gm = &ipip_main;

  clib_memset (gm, 0, sizeof (gm[0]));
  gm->vlib_main = vm;
  gm->vnet_main = vnet_get_main ();
  gm->tunnel_by_key =
    hash_create_mem (0, sizeof (ipip_tunnel_key_t), sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION (ipip_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
