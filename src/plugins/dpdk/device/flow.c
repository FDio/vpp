/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>
#include <assert.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/vxlan/vxlan.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <vppinfra/error.h>

#define FLOW_IS_ETHERNET_CLASS(f) \
  (f->type == VNET_FLOW_TYPE_ETHERNET)

#define FLOW_IS_IPV4_CLASS(f) \
  ((f->type == VNET_FLOW_TYPE_IP4) || \
    (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) || \
    (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) || \
    (f->type == VNET_FLOW_TYPE_IP4_VXLAN) || \
    (f->type == VNET_FLOW_TYPE_IP4_GTPC) || \
    (f->type == VNET_FLOW_TYPE_IP4_GTPU) || \
    (f->type == VNET_FLOW_TYPE_IP4_L2TPV3OIP) || \
    (f->type == VNET_FLOW_TYPE_IP4_IPSEC_ESP) || \
    (f->type == VNET_FLOW_TYPE_IP4_IPSEC_AH))

#define FLOW_IS_IPV6_CLASS(f) \
  ((f->type == VNET_FLOW_TYPE_IP6) || \
    (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE) || \
    (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED) || \
    (f->type == VNET_FLOW_TYPE_IP6_VXLAN))

/* check if flow is VLAN sensitive */
#define FLOW_HAS_VLAN_TAG(f) \
  ((f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) || \
    (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED))

/* check if flow is L3 type */
#define FLOW_IS_L3_TYPE(f) \
  ((f->type == VNET_FLOW_TYPE_IP4) || \
    (f->type == VNET_FLOW_TYPE_IP6))

/* check if flow is L4 type */
#define FLOW_IS_L4_TYPE(f) \
  ((f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) || \
    (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE) || \
    (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) || \
    (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED))

/* check if flow is L4 tunnel type */
#define FLOW_IS_L4_TUNNEL_TYPE(f) \
  ((f->type == VNET_FLOW_TYPE_IP4_VXLAN) || \
    (f->type == VNET_FLOW_TYPE_IP6_VXLAN) || \
    (f->type == VNET_FLOW_TYPE_IP4_GTPC) || \
    (f->type == VNET_FLOW_TYPE_IP4_GTPU))

/* constant structs */
static const struct rte_flow_attr ingress = {.ingress = 1 };

static inline bool
mac_address_is_all_zero (const u8 addr[6])
{
  int i = 0;

  for (i = 0; i < 6; i++)
    if (addr[i] != 0)
      return false;

  return true;
}

static inline void
dpdk_flow_convert_rss_types (u64 type, u64 * dpdk_rss_type)
{
#define BIT_IS_SET(v, b) \
  ((v) & (u64)1<<(b))

  *dpdk_rss_type = 0;

#undef _
#define _(n, f, s) \
      if (n != -1 && BIT_IS_SET(type, n)) \
        *dpdk_rss_type |= f;

  foreach_dpdk_rss_hf
#undef _
    return;
}

static inline enum rte_eth_hash_function
dpdk_flow_convert_rss_func (vnet_rss_function_t func)
{
  enum rte_eth_hash_function rss_func;

  switch (func)
    {
    case VNET_RSS_FUNC_DEFAULT:
      rss_func = RTE_ETH_HASH_FUNCTION_DEFAULT;
      break;
    case VNET_RSS_FUNC_TOEPLITZ:
      rss_func = RTE_ETH_HASH_FUNCTION_TOEPLITZ;
      break;
    case VNET_RSS_FUNC_SIMPLE_XOR:
      rss_func = RTE_ETH_HASH_FUNCTION_SIMPLE_XOR;
      break;
    case VNET_RSS_FUNC_SYMMETRIC_TOEPLITZ:
      rss_func = RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ;
      break;
    default:
      rss_func = RTE_ETH_HASH_FUNCTION_MAX;
      break;
    }

  return rss_func;
}

static int
dpdk_flow_add (dpdk_device_t * xd, vnet_flow_t * f, dpdk_flow_entry_t * fe)
{
  struct rte_flow_item_eth eth[2] = { };
  struct rte_flow_item_ipv4 ip4[2] = { };
  struct rte_flow_item_ipv6 ip6[2] = { };
  struct rte_flow_item_udp udp[2] = { };
  struct rte_flow_item_tcp tcp[2] = { };
  struct rte_flow_item_gtp gtp[2] = { };
  struct rte_flow_item_l2tpv3oip l2tp[2] = { };
  struct rte_flow_item_esp esp[2] = { };
  struct rte_flow_item_ah ah[2] = { };
  struct rte_flow_item_raw generic[2] = { };
  struct rte_flow_action_mark mark = { 0 };
  struct rte_flow_action_queue queue = { 0 };
  struct rte_flow_action_rss rss = { 0 };
  struct rte_flow_item *item, *items = 0;
  struct rte_flow_action *action, *actions = 0;
  bool fate = false;

  enum
  {
    vxlan_hdr_sz = sizeof (vxlan_header_t),
    raw_sz = sizeof (struct rte_flow_item_raw)
  };

  union
  {
    struct rte_flow_item_raw item;
    u8 val[raw_sz + vxlan_hdr_sz];
  } raw[2];

  u16 src_port = 0, dst_port = 0, src_port_mask = 0, dst_port_mask = 0;
  u8 protocol = IP_PROTOCOL_RESERVED;
  int rv = 0;

  /* Handle generic flow first */
  if (f->type == VNET_FLOW_TYPE_GENERIC)
    {
      generic[0].pattern = f->generic.pattern.spec;
      generic[1].pattern = f->generic.pattern.mask;

      vec_add2 (items, item, 1);
      item->type = RTE_FLOW_ITEM_TYPE_RAW;
      item->spec = generic;
      item->mask = generic + 1;

      goto pattern_end;
    }

  enum
  {
    FLOW_UNKNOWN_CLASS,
    FLOW_ETHERNET_CLASS,
    FLOW_IPV4_CLASS,
    FLOW_IPV6_CLASS,
  } flow_class = FLOW_UNKNOWN_CLASS;

  if (FLOW_IS_ETHERNET_CLASS (f))
    flow_class = FLOW_ETHERNET_CLASS;
  else if (FLOW_IS_IPV4_CLASS (f))
    flow_class = FLOW_IPV4_CLASS;
  else if (FLOW_IS_IPV6_CLASS (f))
    flow_class = FLOW_IPV6_CLASS;
  else
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  if (f->actions & (~xd->supported_flow_actions))
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  /* Match items */
  /* Layer 2, Ethernet */
  vec_add2 (items, item, 1);
  item->type = RTE_FLOW_ITEM_TYPE_ETH;

  if (flow_class == FLOW_ETHERNET_CLASS)
    {
      vnet_flow_ethernet_t *te = &f->ethernet;

      clib_memset (&eth[0], 0, sizeof (eth[0]));
      clib_memset (&eth[1], 0, sizeof (eth[1]));

      /* check if SMAC/DMAC/Ether_type assigned */
      if (!mac_address_is_all_zero (te->eth_hdr.dst_address))
	{
	  clib_memcpy_fast (&eth[0].dst, &te->eth_hdr.dst_address,
			    sizeof (eth[0].dst));
	  clib_memset (&eth[1].dst, 0xFF, sizeof (eth[1].dst));
	}

      if (!mac_address_is_all_zero (te->eth_hdr.src_address))
	{
	  clib_memcpy_fast (&eth[0].src, &te->eth_hdr.src_address,
			    sizeof (eth[0].src));
	  clib_memset (&eth[1].src, 0xFF, sizeof (eth[1].src));
	}

      if (te->eth_hdr.type)
	{
	  eth[0].type = clib_host_to_net_u16 (te->eth_hdr.type);
	  eth[1].type = clib_host_to_net_u16 (0xFFFF);
	}

      item->spec = eth;
      item->mask = eth + 1;
    }
  else
    {
      item->spec = NULL;
      item->mask = NULL;
    }

  /* currently only single empty vlan tag is supported */
  if (FLOW_HAS_VLAN_TAG (f))
    {
      vec_add2 (items, item, 1);
      item->type = RTE_FLOW_ITEM_TYPE_VLAN;
      item->spec = NULL;
      item->mask = NULL;
    }

  if (FLOW_IS_ETHERNET_CLASS (f))
    goto pattern_end;

  /* Layer 3, IP */
  vec_add2 (items, item, 1);
  if (flow_class == FLOW_IPV4_CLASS)
    {
      vnet_flow_ip4_t *ip4_ptr = &f->ip4;

      item->type = RTE_FLOW_ITEM_TYPE_IPV4;
      if ((!ip4_ptr->src_addr.mask.as_u32) &&
	  (!ip4_ptr->dst_addr.mask.as_u32) && (!ip4_ptr->protocol.mask))
	{
	  item->spec = NULL;
	  item->mask = NULL;
	}
      else
	{
	  ip4[0].hdr.src_addr = ip4_ptr->src_addr.addr.as_u32;
	  ip4[1].hdr.src_addr = ip4_ptr->src_addr.mask.as_u32;
	  ip4[0].hdr.dst_addr = ip4_ptr->dst_addr.addr.as_u32;
	  ip4[1].hdr.dst_addr = ip4_ptr->dst_addr.mask.as_u32;
	  ip4[0].hdr.next_proto_id = ip4_ptr->protocol.prot;
	  ip4[1].hdr.next_proto_id = ip4_ptr->protocol.mask;

	  item->spec = ip4;
	  item->mask = ip4 + 1;
	}

      if (FLOW_IS_L4_TYPE (f) || FLOW_IS_L4_TUNNEL_TYPE (f))
	{
	  vnet_flow_ip4_n_tuple_t *ip4_n_ptr = &f->ip4_n_tuple;

	  src_port = ip4_n_ptr->src_port.port;
	  dst_port = ip4_n_ptr->dst_port.port;
	  src_port_mask = ip4_n_ptr->src_port.mask;
	  dst_port_mask = ip4_n_ptr->dst_port.mask;
	}

      protocol = ip4_ptr->protocol.prot;
    }
  else if (flow_class == FLOW_IPV6_CLASS)
    {
      vnet_flow_ip6_t *ip6_ptr = &f->ip6;

      item->type = RTE_FLOW_ITEM_TYPE_IPV6;

      if ((ip6_ptr->src_addr.mask.as_u64[0] == 0) &&
	  (ip6_ptr->src_addr.mask.as_u64[1] == 0) &&
	  (!ip6_ptr->protocol.mask))
	{
	  item->spec = NULL;
	  item->mask = NULL;
	}
      else
	{
	  clib_memcpy (ip6[0].hdr.src_addr, &ip6_ptr->src_addr.addr,
		       ARRAY_LEN (ip6_ptr->src_addr.addr.as_u8));
	  clib_memcpy (ip6[1].hdr.src_addr, &ip6_ptr->src_addr.mask,
		       ARRAY_LEN (ip6_ptr->src_addr.mask.as_u8));
	  clib_memcpy (ip6[0].hdr.dst_addr, &ip6_ptr->dst_addr.addr,
		       ARRAY_LEN (ip6_ptr->dst_addr.addr.as_u8));
	  clib_memcpy (ip6[1].hdr.dst_addr, &ip6_ptr->dst_addr.mask,
		       ARRAY_LEN (ip6_ptr->dst_addr.mask.as_u8));
	  ip6[0].hdr.proto = ip6_ptr->protocol.prot;
	  ip6[1].hdr.proto = ip6_ptr->protocol.mask;

	  item->spec = ip6;
	  item->mask = ip6 + 1;
	}

      if (FLOW_IS_L4_TYPE (f) || FLOW_IS_L4_TUNNEL_TYPE (f))
	{
	  vnet_flow_ip6_n_tuple_t *ip6_n_ptr = &f->ip6_n_tuple;

	  src_port = ip6_n_ptr->src_port.port;
	  dst_port = ip6_n_ptr->dst_port.port;
	  src_port_mask = ip6_n_ptr->src_port.mask;
	  dst_port_mask = ip6_n_ptr->dst_port.mask;
	}

      protocol = ip6_ptr->protocol.prot;
    }

  if (FLOW_IS_L3_TYPE (f))
    goto pattern_end;

  /* Layer 3, IP */
  vec_add2 (items, item, 1);
  switch (protocol)
    {
    case IP_PROTOCOL_L2TP:
      item->type = RTE_FLOW_ITEM_TYPE_L2TPV3OIP;
      l2tp[0].session_id = clib_host_to_net_u32 (f->ip4_l2tpv3oip.session_id);
      l2tp[1].session_id = ~0;

      item->spec = l2tp;
      item->mask = l2tp + 1;
      break;

    case IP_PROTOCOL_IPSEC_ESP:
      item->type = RTE_FLOW_ITEM_TYPE_ESP;
      esp[0].hdr.spi = clib_host_to_net_u32 (f->ip4_ipsec_esp.spi);
      esp[1].hdr.spi = ~0;

      item->spec = esp;
      item->mask = esp + 1;
      break;

    case IP_PROTOCOL_IPSEC_AH:
      item->type = RTE_FLOW_ITEM_TYPE_AH;
      ah[0].spi = clib_host_to_net_u32 (f->ip4_ipsec_ah.spi);
      ah[1].spi = ~0;

      item->spec = ah;
      item->mask = ah + 1;
      break;
    case IP_PROTOCOL_TCP:
      item->type = RTE_FLOW_ITEM_TYPE_TCP;
      if ((src_port_mask == 0) && (dst_port_mask == 0))
	{
	  item->spec = NULL;
	  item->mask = NULL;
	}
      else
	{
	  tcp[0].hdr.src_port = clib_host_to_net_u16 (src_port);
	  tcp[1].hdr.src_port = clib_host_to_net_u16 (src_port_mask);
	  tcp[0].hdr.dst_port = clib_host_to_net_u16 (dst_port);
	  tcp[1].hdr.dst_port = clib_host_to_net_u16 (dst_port_mask);
	  item->spec = tcp;
	  item->mask = tcp + 1;
	}
      break;

    case IP_PROTOCOL_UDP:
      item->type = RTE_FLOW_ITEM_TYPE_UDP;
      if ((src_port_mask == 0) && (dst_port_mask == 0))
	{
	  item->spec = NULL;
	  item->mask = NULL;
	}
      else
	{
	  udp[0].hdr.src_port = clib_host_to_net_u16 (src_port);
	  udp[1].hdr.src_port = clib_host_to_net_u16 (src_port_mask);
	  udp[0].hdr.dst_port = clib_host_to_net_u16 (dst_port);
	  udp[1].hdr.dst_port = clib_host_to_net_u16 (dst_port_mask);
	  item->spec = udp;
	  item->mask = udp + 1;
	}

      /* handle the UDP tunnels */
      if (f->type == VNET_FLOW_TYPE_IP4_GTPC)
	{
	  gtp[0].teid = clib_host_to_net_u32 (f->ip4_gtpc.teid);
	  gtp[1].teid = ~0;

	  vec_add2 (items, item, 1);
	  item->type = RTE_FLOW_ITEM_TYPE_GTPC;
	  item->spec = gtp;
	  item->mask = gtp + 1;
	}
      else if (f->type == VNET_FLOW_TYPE_IP4_GTPU)
	{
	  gtp[0].teid = clib_host_to_net_u32 (f->ip4_gtpu.teid);
	  gtp[1].teid = ~0;

	  vec_add2 (items, item, 1);
	  item->type = RTE_FLOW_ITEM_TYPE_GTPU;
	  item->spec = gtp;
	  item->mask = gtp + 1;
	}
      else if (f->type == VNET_FLOW_TYPE_IP4_VXLAN)
	{
	  u32 vni = f->ip4_vxlan.vni;

	  vxlan_header_t spec_hdr = {
	    .flags = VXLAN_FLAGS_I,
	    .vni_reserved = clib_host_to_net_u32 (vni << 8)
	  };
	  vxlan_header_t mask_hdr = {
	    .flags = 0xff,
	    .vni_reserved = clib_host_to_net_u32 (((u32) - 1) << 8)
	  };

	  clib_memset (raw, 0, sizeof raw);
	  raw[0].item.relative = 1;
	  raw[0].item.length = vxlan_hdr_sz;

	  clib_memcpy_fast (raw[0].val + raw_sz, &spec_hdr, vxlan_hdr_sz);
	  raw[0].item.pattern = raw[0].val + raw_sz;
	  clib_memcpy_fast (raw[1].val + raw_sz, &mask_hdr, vxlan_hdr_sz);
	  raw[1].item.pattern = raw[1].val + raw_sz;

	  vec_add2 (items, item, 1);
	  item->type = RTE_FLOW_ITEM_TYPE_RAW;
	  item->spec = raw;
	  item->mask = raw + 1;
	}
      break;

    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

pattern_end:
  if ((f->actions & VNET_FLOW_ACTION_RSS) &&
      (f->rss_types & (1ULL << VNET_FLOW_RSS_TYPES_ESP)))
    {

      vec_add2 (items, item, 1);
      item->type = RTE_FLOW_ITEM_TYPE_ESP;
    }

  vec_add2 (items, item, 1);
  item->type = RTE_FLOW_ITEM_TYPE_END;

  /* Actions */
  /* Only one 'fate' can be assigned */
  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      vec_add2 (actions, action, 1);
      queue.index = f->redirect_queue;
      action->type = RTE_FLOW_ACTION_TYPE_QUEUE;
      action->conf = &queue;
      fate = true;
    }

  if (f->actions & VNET_FLOW_ACTION_DROP)
    {
      vec_add2 (actions, action, 1);
      action->type = RTE_FLOW_ACTION_TYPE_DROP;
      if (fate == true)
	{
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	fate = true;
    }

  if (f->actions & VNET_FLOW_ACTION_RSS)
    {
      u64 rss_type = 0;

      vec_add2 (actions, action, 1);
      action->type = RTE_FLOW_ACTION_TYPE_RSS;
      action->conf = &rss;

      /* convert types to DPDK rss bitmask */
      dpdk_flow_convert_rss_types (f->rss_types, &rss_type);

      rss.types = rss_type;
      if ((rss.func = dpdk_flow_convert_rss_func (f->rss_fun)) ==
	  RTE_ETH_HASH_FUNCTION_MAX)
	{
	  rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
	  goto done;
	}

      if (fate == true)
	{
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	fate = true;
    }

  if (fate == false)
    {
      vec_add2 (actions, action, 1);
      action->type = RTE_FLOW_ACTION_TYPE_PASSTHRU;
    }

  if (f->actions & VNET_FLOW_ACTION_MARK)
    {
      vec_add2 (actions, action, 1);
      mark.id = fe->mark;
      action->type = RTE_FLOW_ACTION_TYPE_MARK;
      action->conf = &mark;
    }

  vec_add2 (actions, action, 1);
  action->type = RTE_FLOW_ACTION_TYPE_END;

  rv = rte_flow_validate (xd->device_index, &ingress, items, actions,
			  &xd->last_flow_error);

  if (rv)
    {
      if (rv == -EINVAL)
	rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      else if (rv == -EEXIST)
	rv = VNET_FLOW_ERROR_ALREADY_EXISTS;
      else
	rv = VNET_FLOW_ERROR_INTERNAL;

      goto done;
    }

  fe->handle = rte_flow_create (xd->device_index, &ingress, items, actions,
				&xd->last_flow_error);

  if (!fe->handle)
    rv = VNET_FLOW_ERROR_NOT_SUPPORTED;

done:
  vec_free (items);
  vec_free (actions);
  return rv;
}

int
dpdk_flow_ops_fn (vnet_main_t * vnm, vnet_flow_dev_op_t op, u32 dev_instance,
		  u32 flow_index, uword * private_data)
{
  vlib_main_t *vm = vlib_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  vnet_flow_t *flow = vnet_get_flow (flow_index);
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_entry_t *fe;
  dpdk_flow_lookup_entry_t *fle = 0;
  int rv;

  /* recycle old flow lookup entries only after the main loop counter
     increases - i.e. previously DMA'ed packets were handled */
  if (vec_len (xd->parked_lookup_indexes) > 0 &&
      xd->parked_loop_count != vm->main_loop_count)
    {
      u32 *fl_index;

      vec_foreach (fl_index, xd->parked_lookup_indexes)
	pool_put_index (xd->flow_lookup_entries, *fl_index);
      vec_reset_length (xd->parked_lookup_indexes);
    }

  if (op == VNET_FLOW_DEV_OP_DEL_FLOW)
    {
      fe = vec_elt_at_index (xd->flow_entries, *private_data);

      if ((rv = rte_flow_destroy (xd->device_index, fe->handle,
				  &xd->last_flow_error)))
	return VNET_FLOW_ERROR_INTERNAL;

      if (fe->mark)
	{
	  /* make sure no action is taken for in-flight (marked) packets */
	  fle = pool_elt_at_index (xd->flow_lookup_entries, fe->mark);
	  clib_memset (fle, -1, sizeof (*fle));
	  vec_add1 (xd->parked_lookup_indexes, fe->mark);
	  xd->parked_loop_count = vm->main_loop_count;
	}

      clib_memset (fe, 0, sizeof (*fe));
      pool_put (xd->flow_entries, fe);

      goto disable_rx_offload;
    }

  if (op != VNET_FLOW_DEV_OP_ADD_FLOW)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  pool_get (xd->flow_entries, fe);
  fe->flow_index = flow->index;

  if (flow->actions == 0)
    {
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  /* if we need to mark packets, assign one mark */
  if (flow->actions & (VNET_FLOW_ACTION_MARK |
		       VNET_FLOW_ACTION_REDIRECT_TO_NODE |
		       VNET_FLOW_ACTION_BUFFER_ADVANCE))
    {
      /* reserve slot 0 */
      if (xd->flow_lookup_entries == 0)
	pool_get_aligned (xd->flow_lookup_entries, fle,
			  CLIB_CACHE_LINE_BYTES);
      pool_get_aligned (xd->flow_lookup_entries, fle, CLIB_CACHE_LINE_BYTES);
      fe->mark = fle - xd->flow_lookup_entries;

      /* install entry in the lookup table */
      clib_memset (fle, -1, sizeof (*fle));
      if (flow->actions & VNET_FLOW_ACTION_MARK)
	fle->flow_id = flow->mark_flow_id;
      if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
	fle->next_index = flow->redirect_device_input_next_index;
      if (flow->actions & VNET_FLOW_ACTION_BUFFER_ADVANCE)
	fle->buffer_advance = flow->buffer_advance;
    }
  else
    fe->mark = 0;

  if ((xd->flags & DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD) == 0)
    {
      xd->flags |= DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;
      dpdk_device_setup (xd);
    }

  switch (flow->type)
    {
    case VNET_FLOW_TYPE_ETHERNET:
    case VNET_FLOW_TYPE_IP4:
    case VNET_FLOW_TYPE_IP6:
    case VNET_FLOW_TYPE_IP4_N_TUPLE:
    case VNET_FLOW_TYPE_IP6_N_TUPLE:
    case VNET_FLOW_TYPE_IP4_VXLAN:
    case VNET_FLOW_TYPE_IP4_GTPC:
    case VNET_FLOW_TYPE_IP4_GTPU:
    case VNET_FLOW_TYPE_IP4_L2TPV3OIP:
    case VNET_FLOW_TYPE_IP4_IPSEC_ESP:
    case VNET_FLOW_TYPE_IP4_IPSEC_AH:
    case VNET_FLOW_TYPE_GENERIC:
      if ((rv = dpdk_flow_add (xd, flow, fe)))
	goto done;
      break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  *private_data = fe - xd->flow_entries;

done:
  if (rv)
    {
      clib_memset (fe, 0, sizeof (*fe));
      pool_put (xd->flow_entries, fe);
      if (fle)
	{
	  clib_memset (fle, -1, sizeof (*fle));
	  pool_put (xd->flow_lookup_entries, fle);
	}
    }
disable_rx_offload:
  if ((xd->flags & DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD) != 0
      && pool_elts (xd->flow_entries) == 0)
    {
      xd->flags &= ~DPDK_DEVICE_FLAG_RX_FLOW_OFFLOAD;
      dpdk_device_setup (xd);
    }

  return rv;
}

u8 *
format_dpdk_flow (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  u32 flow_index = va_arg (*args, u32);
  uword private_data = va_arg (*args, uword);
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = vec_elt_at_index (dm->devices, dev_instance);
  dpdk_flow_entry_t *fe;

  if (flow_index == ~0)
    {
      s = format (s, "%-25s: %U\n", "supported flow actions",
		  format_flow_actions, xd->supported_flow_actions);
      s = format (s, "%-25s: %d\n", "last DPDK error type",
		  xd->last_flow_error.type);
      s = format (s, "%-25s: %s\n", "last DPDK error message",
		  xd->last_flow_error.message ? xd->last_flow_error.message :
		  "n/a");
      return s;
    }

  if (private_data >= vec_len (xd->flow_entries))
    return format (s, "unknown flow");

  fe = vec_elt_at_index (xd->flow_entries, private_data);
  s = format (s, "mark %u", fe->mark);
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
