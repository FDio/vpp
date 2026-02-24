/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/flow_items.h>
#include <dpdk/device/flow_actions.h>
#include <dpdk/device/flow_gen.h>

#define foreach_ip_ip                                                                              \
  _ (4, 4)                                                                                         \
  _ (4, 6)                                                                                         \
  _ (6, 4)                                                                                         \
  _ (6, 6)

/*
 * Populate template function pointer arrays based on flow type.
 * Called once at template creation time.
 * Returns 0 on success, sets n_item_fns=0 to fallback to generic path.
 */
void
dpdk_flow_template_populate_fns (vnet_flow_t *t, dpdk_flow_template_entry_t *fte)
{
  u8 n_items = 0;
  u8 n_actions = 0;
  u8 protocol = 0;

  fte->n_item_fns = 0;
  fte->n_action_fns = 0;

  /* Handle Ethernet class */
  if (FLOW_IS_ETHERNET_CLASS (t))
    fte->item_fns[n_items++] = dpdk_fill_item_eth;

  /* Handle VLAN tagged flows */
  if (FLOW_HAS_VLAN_TAG (t))
    fte->item_fns[n_items++] = dpdk_fill_item_vlan;

  if (FLOW_IS_ETHERNET_CLASS (t))
    goto done_items;

  /* Handle IPv4 class */
  if (FLOW_IS_IPV4_CLASS (t))
    {
      fte->item_fns[n_items++] = dpdk_fill_item_ipv4;
      protocol = t->ip4.protocol.prot;

      /* L3-only type - no L4 */
      if (FLOW_IS_L3_TYPE (t))
	goto done_items;

      /* L4 protocol handling */
      switch (protocol)
	{
	case IP_PROTOCOL_TCP:
	  fte->item_fns[n_items++] = dpdk_fill_item_tcp4;
	  break;
	case IP_PROTOCOL_UDP:
	  fte->item_fns[n_items++] = dpdk_fill_item_udp4;
	  /* Handle UDP tunnels */
	  if (t->type == VNET_FLOW_TYPE_IP4_GTPC)
	    fte->item_fns[n_items++] = dpdk_fill_item_gtpc;
	  else if (t->type == VNET_FLOW_TYPE_IP4_GTPU)
	    fte->item_fns[n_items++] = dpdk_fill_item_gtpu;
	  else if (t->type == VNET_FLOW_TYPE_IP4_VXLAN)
	    goto fallback; /* VXLAN uses RAW item, complex */
	  break;
	case IP_PROTOCOL_L2TP:
	  fte->item_fns[n_items++] = dpdk_fill_item_l2tp;
	  break;
	case IP_PROTOCOL_IPSEC_ESP:
	  fte->item_fns[n_items++] = dpdk_fill_item_esp;
	  break;
	case IP_PROTOCOL_IPSEC_AH:
	  fte->item_fns[n_items++] = dpdk_fill_item_ah;
	  break;
	case IP_PROTOCOL_IPV6:
	case IP_PROTOCOL_IP_IN_IP:
	  /* IP-in-IP tunnels - complex, fallback */
	  goto fallback;
	default:
	  goto fallback;
	}
      goto done_items;
    }

  /* Handle IPv6 class */
  if (FLOW_IS_IPV6_CLASS (t))
    {
      fte->item_fns[n_items++] = dpdk_fill_item_ipv6;
      protocol = t->ip6.protocol.prot;

      /* L3-only type - no L4 */
      if (FLOW_IS_L3_TYPE (t))
	goto done_items;

      /* L4 protocol handling */
      switch (protocol)
	{
	case IP_PROTOCOL_TCP:
	  fte->item_fns[n_items++] = dpdk_fill_item_tcp6;
	  break;
	case IP_PROTOCOL_UDP:
	  fte->item_fns[n_items++] = dpdk_fill_item_udp6;
	  break;
	case IP_PROTOCOL_IPV6:
	case IP_PROTOCOL_IP_IN_IP:
	  /* IP-in-IP tunnels - complex, fallback */
	  goto fallback;
	default:
	  goto fallback;
	}
      goto done_items;
    }

  /* Unknown flow class */
  goto fallback;

done_items:
  fte->item_fns[n_items++] = dpdk_fill_item_end;
  fte->n_item_fns = n_items;

  /* Determine action fill functions based on actions bitmap */
  /* Only one fate action allowed */
  if (t->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    fte->action_fns[n_actions++] = dpdk_fill_action_queue;
  else if (t->actions & VNET_FLOW_ACTION_DROP)
    fte->action_fns[n_actions++] = dpdk_fill_action_drop;
  else if (t->actions & VNET_FLOW_ACTION_RSS)
    fte->action_fns[n_actions++] = dpdk_fill_action_rss;
  else
    fte->action_fns[n_actions++] = dpdk_fill_action_passthru;

  if (t->actions & VNET_FLOW_ACTION_MARK)
    fte->action_fns[n_actions++] = dpdk_fill_action_mark;

  fte->action_fns[n_actions++] = dpdk_fill_action_end;
  fte->n_action_fns = n_actions;
  return;

fallback:
  /* Complex cases - use generic fill functions */
  fte->n_item_fns = 0;
  fte->n_action_fns = 0;
}

int
dpdk_flow_fill_items (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe,
		      struct rte_flow_item *items)
{
  int n = 0;
  u8 protocol = IP_PROTOCOL_RESERVED;

  if (f->actions & (~xd->supported_flow_actions))
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  /* Handle generic flow first */
  if (f->type == VNET_FLOW_TYPE_GENERIC)
    {
      dpdk_fill_item_generic (f, &items[n++]);
      dpdk_fill_item_end (f, &items[n]);
      return 0;
    }

  /* Layer 2: Ethernet */
  if (FLOW_IS_ETHERNET_CLASS (f))
    dpdk_fill_item_eth (f, &items[n++]);

  if (FLOW_HAS_VLAN_TAG (f))
    dpdk_fill_item_vlan (f, &items[n++]);

  if (FLOW_IS_ETHERNET_CLASS (f))
    goto pattern_end;

  /* Layer 3: IPv4 */
  if (FLOW_IS_IPV4_CLASS (f))
    {
      dpdk_fill_item_ipv4 (f, &items[n++]);
      protocol = f->ip4.protocol.prot;

      if (FLOW_IS_L3_TYPE (f))
	goto pattern_end;

      /* Layer 4 */
      switch (protocol)
	{
	case IP_PROTOCOL_TCP:
	  dpdk_fill_item_tcp4 (f, &items[n++]);
	  break;
	case IP_PROTOCOL_UDP:
	  dpdk_fill_item_udp4 (f, &items[n++]);
	  if (f->type == VNET_FLOW_TYPE_IP4_GTPC)
	    dpdk_fill_item_gtpc (f, &items[n++]);
	  else if (f->type == VNET_FLOW_TYPE_IP4_GTPU)
	    dpdk_fill_item_gtpu (f, &items[n++]);
	  else if (f->type == VNET_FLOW_TYPE_IP4_VXLAN)
	    dpdk_fill_item_vxlan (f, &items[n++]);
	  break;
	case IP_PROTOCOL_L2TP:
	  dpdk_fill_item_l2tp (f, &items[n++]);
	  break;
	case IP_PROTOCOL_IPSEC_ESP:
	  dpdk_fill_item_esp (f, &items[n++]);
	  break;
	case IP_PROTOCOL_IPSEC_AH:
	  dpdk_fill_item_ah (f, &items[n++]);
	  break;
	case IP_PROTOCOL_IPV6:
	  dpdk_fill_item_inner_ipv6 (f, &items[n++]);
	  break;
	case IP_PROTOCOL_IP_IN_IP:
	  dpdk_fill_item_inner_ipv4 (f, &items[n++]);
	  break;
	default:
	  return VNET_FLOW_ERROR_NOT_SUPPORTED;
	}
    }

  /* Layer 3: IPv6 */
  else if (FLOW_IS_IPV6_CLASS (f))
    {
      dpdk_fill_item_ipv6 (f, &items[n++]);
      protocol = f->ip6.protocol.prot;

      if (FLOW_IS_L3_TYPE (f))
	goto pattern_end;

      /* Layer 4 */
      switch (protocol)
	{
	case IP_PROTOCOL_TCP:
	  dpdk_fill_item_tcp6 (f, &items[n++]);
	  break;
	case IP_PROTOCOL_UDP:
	  dpdk_fill_item_udp6 (f, &items[n++]);
	  break;
	case IP_PROTOCOL_IPV6:
	  dpdk_fill_item_inner_ipv6 (f, &items[n++]);
	  break;
	case IP_PROTOCOL_IP_IN_IP:
	  dpdk_fill_item_inner_ipv4 (f, &items[n++]);
	  break;
	default:
	  return VNET_FLOW_ERROR_NOT_SUPPORTED;
	}
    }

  /* Handle inner N-tuple for IP-in-IP tunnels */
  if (FLOW_HAS_INNER_N_TUPLE (f))
    {
      /* Inner TCP/UDP based on inner protocol */
      u8 in_proto = 0;
      if (0)
	;
#define _(_inner, _outer)                                                                          \
  else if (f->type == VNET_FLOW_TYPE_IP##_outer##_IP##_inner##_N_TUPLE) in_proto =                 \
    f->ip##_outer##_ip##_inner##_n_tuple.in_protocol.prot;
      foreach_ip_ip
#undef _

	u16 src_port = 0,
	    dst_port = 0, src_mask = 0, dst_mask = 0;
      if (0)
	;
#define _(_inner, _outer)                                                                          \
  else if (f->type == VNET_FLOW_TYPE_IP##_outer##_IP##_inner##_N_TUPLE)                            \
  {                                                                                                \
    src_port = f->ip##_outer##_ip##_inner##_n_tuple.in_src_port.port;                              \
    dst_port = f->ip##_outer##_ip##_inner##_n_tuple.in_dst_port.port;                              \
    src_mask = f->ip##_outer##_ip##_inner##_n_tuple.in_src_port.mask;                              \
    dst_mask = f->ip##_outer##_ip##_inner##_n_tuple.in_dst_port.mask;                              \
  }
      foreach_ip_ip
#undef _

	items[n]
	  .spec = NULL;
      items[n].mask = NULL;
      items[n].last = NULL;

      if (in_proto == IP_PROTOCOL_TCP)
	{
	  /* Use generic inner TCP fill - reuse tcp4 structure */
	  static struct rte_flow_item_tcp spec, mask;
	  items[n].type = RTE_FLOW_ITEM_TYPE_TCP;

	  if (src_mask || dst_mask)
	    {
	      spec.hdr.src_port = clib_host_to_net_u16 (src_port);
	      spec.hdr.dst_port = clib_host_to_net_u16 (dst_port);
	      mask.hdr.src_port = clib_host_to_net_u16 (src_mask);
	      mask.hdr.dst_port = clib_host_to_net_u16 (dst_mask);
	      items[n].spec = &spec;
	      items[n].mask = &mask;
	    }
	  n++;
	}
      else if (in_proto == IP_PROTOCOL_UDP)
	{
	  static struct rte_flow_item_udp spec, mask;
	  items[n].type = RTE_FLOW_ITEM_TYPE_UDP;

	  if (src_mask || dst_mask)
	    {
	      spec.hdr.src_port = clib_host_to_net_u16 (src_port);
	      spec.hdr.dst_port = clib_host_to_net_u16 (dst_port);
	      mask.hdr.src_port = clib_host_to_net_u16 (src_mask);
	      mask.hdr.dst_port = clib_host_to_net_u16 (dst_mask);
	      items[n].spec = &spec;
	      items[n].mask = &mask;
	    }
	  n++;
	}
    }

pattern_end:
  /* RSS ESP item */
  if ((f->actions & VNET_FLOW_ACTION_RSS) && (f->rss_types & (1ULL << VNET_FLOW_RSS_TYPES_ESP)))
    dpdk_fill_item_esp_empty (f, &items[n++]);

  dpdk_fill_item_end (f, &items[n]);
  return 0;
}

int
dpdk_flow_fill_actions (dpdk_device_t *xd, vnet_flow_t *f, dpdk_flow_entry_t *fe,
			struct rte_flow_action *actions)
{
  int n = 0;
  bool fate = false;

  /* Only one 'fate' action is allowed */
  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      dpdk_fill_action_queue (f, &actions[n++]);
      fate = true;
    }

  if (f->actions & VNET_FLOW_ACTION_DROP)
    {
      if (fate)
	return VNET_FLOW_ERROR_INTERNAL;
      dpdk_fill_action_drop (f, &actions[n++]);
      fate = true;
    }

  if (f->actions & VNET_FLOW_ACTION_RSS)
    {
      if (fate)
	return VNET_FLOW_ERROR_INTERNAL;
      if (dpdk_fill_action_rss_validated (f, &actions[n++]))
	return VNET_FLOW_ERROR_NOT_SUPPORTED;
      fate = true;
    }

  if (!fate)
    dpdk_fill_action_passthru (f, &actions[n++]);

  if (FLOW_NEEDS_MARK (f))
    dpdk_fill_action_mark_with_id (f, &actions[n++], fe->mark);

  dpdk_fill_action_end (f, &actions[n]);
  return 0;
}

int
dpdk_flow_fill_items_template (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte,
			       struct rte_flow_item *items)
{
  struct rte_flow_item *item;
  int rv;

  // HACK: flow_entry is not used in fill_items
  if ((rv = dpdk_flow_fill_items (xd, t, NULL, items)))
    return rv;

  FOREACH_FLOW_ITEM (items, item) { item->spec = NULL; }

  return 0;
}

int
dpdk_flow_fill_actions_template (dpdk_device_t *xd, vnet_flow_t *t, dpdk_flow_template_entry_t *fte,
				 struct rte_flow_action *actions, struct rte_flow_action *masks)
{
  int action_counter = 0;
  bool fate = false;
  int rv;

#define add_action_type(_type)                                                                     \
  {                                                                                                \
    actions[action_counter].type = RTE_FLOW_ACTION_TYPE_##_type;                                   \
    masks[action_counter].type = RTE_FLOW_ACTION_TYPE_##_type;                                     \
    action_counter++;                                                                              \
  }

  /* Only one 'fate' can be assigned */
  if (t->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      add_action_type (QUEUE);
      fate = true;
    }

  if (t->actions & VNET_FLOW_ACTION_DROP)
    {
      if (fate)
	{
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	fate = true;

      add_action_type (DROP);
    }

  if (t->actions & VNET_FLOW_ACTION_RSS)
    {
      if (fate)
	{
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	fate = true;

      add_action_type (RSS);
    }

  if (!fate)
    add_action_type (PASSTHRU);

  if (t->actions & VNET_FLOW_ACTION_MARK)
    add_action_type (MARK);

  add_action_type (END);
  return 0;

done:
  return rv;
#undef add_action_type
}
