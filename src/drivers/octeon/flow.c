/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <octeon.h>
#include <base/roc_npc_priv.h>

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "flow",
};

#define FLOW_IS_ETHERNET_CLASS(f) (f->type == VNET_FLOW_TYPE_ETHERNET)

#define FLOW_IS_IPV4_CLASS(f)                                                 \
  ((f->type == VNET_FLOW_TYPE_IP4) ||                                         \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) ||                          \
   (f->type == VNET_FLOW_TYPE_IP4_VXLAN) ||                                   \
   (f->type == VNET_FLOW_TYPE_IP4_GTPC) ||                                    \
   (f->type == VNET_FLOW_TYPE_IP4_GTPU) ||                                    \
   (f->type == VNET_FLOW_TYPE_IP4_L2TPV3OIP) ||                               \
   (f->type == VNET_FLOW_TYPE_IP4_IPSEC_ESP) ||                               \
   (f->type == VNET_FLOW_TYPE_IP4_IPSEC_AH))

#define FLOW_IS_IPV6_CLASS(f)                                                 \
  ((f->type == VNET_FLOW_TYPE_IP6) ||                                         \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED) ||                          \
   (f->type == VNET_FLOW_TYPE_IP6_VXLAN))

#define FLOW_IS_L3_TYPE(f)                                                    \
  ((f->type == VNET_FLOW_TYPE_IP4) || (f->type == VNET_FLOW_TYPE_IP6))

#define FLOW_IS_L4_TYPE(f)                                                    \
  ((f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) ||                          \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED))

#define FLOW_IS_L4_TUNNEL_TYPE(f)                                             \
  ((f->type == VNET_FLOW_TYPE_IP4_VXLAN) ||                                   \
   (f->type == VNET_FLOW_TYPE_IP6_VXLAN) ||                                   \
   (f->type == VNET_FLOW_TYPE_IP4_GTPC) ||                                    \
   (f->type == VNET_FLOW_TYPE_IP4_GTPU))

#define FLOW_IS_GENERIC_TYPE(f) (f->type == VNET_FLOW_TYPE_GENERIC)

#define OCT_FLOW_UNSUPPORTED_ACTIONS(f)                                       \
  ((f->actions == VNET_FLOW_ACTION_BUFFER_ADVANCE) ||                         \
   (f->actions == VNET_FLOW_ACTION_REDIRECT_TO_NODE))

/* Keep values in sync with vnet/flow.h */
#define foreach_oct_flow_rss_types                                            \
  _ (1, FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_TCP, "ipv4-tcp")                   \
  _ (2, FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_UDP, "ipv4-udp")                   \
  _ (3, FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_SCTP, "ipv4-sctp")                 \
  _ (5, FLOW_KEY_TYPE_IPV4, "ipv4")                                           \
  _ (9, FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP, "ipv6-tcp")                   \
  _ (10, FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_UDP, "ipv6-udp")                  \
  _ (11, FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_SCTP, "ipv6-sctp")                \
  _ (13, FLOW_KEY_TYPE_IPV6_EXT, "ipv6-ex")                                   \
  _ (14, FLOW_KEY_TYPE_IPV6, "ipv6")                                          \
  _ (16, FLOW_KEY_TYPE_PORT, "port")                                          \
  _ (17, FLOW_KEY_TYPE_VXLAN, "vxlan")                                        \
  _ (18, FLOW_KEY_TYPE_GENEVE, "geneve")                                      \
  _ (19, FLOW_KEY_TYPE_NVGRE, "nvgre")                                        \
  _ (20, FLOW_KEY_TYPE_GTPU, "gtpu")                                          \
  _ (60, FLOW_KEY_TYPE_L4_DST, "l4-dst-only")                                 \
  _ (61, FLOW_KEY_TYPE_L4_SRC, "l4-src-only")                                 \
  _ (62, FLOW_KEY_TYPE_L3_DST, "l3-dst-only")                                 \
  _ (63, FLOW_KEY_TYPE_L3_SRC, "l3-src-only")

#define GTPU_PORT  2152
#define VXLAN_PORT 4789

typedef struct
{
  u16 src_port;
  u16 dst_port;
  u32 verification_tag;
  u32 cksum;
} sctp_header_t;

typedef struct
{
  u8 ver_flags;
  u8 type;
  u16 length;
  u32 teid;
} gtpu_header_t;

typedef struct
{
  u8 layer;
  u16 nxt_proto;
  vnet_dev_port_t *port;
  struct roc_npc_item_info *items;
  struct
  {
    u8 *spec;
    u8 *mask;
    u16 off;
  } oct_drv;
  struct
  {
    u8 *spec;
    u8 *mask;
    u16 off;
    u16 len;
  } generic;
} oct_flow_parse_state;

static void
oct_flow_convert_rss_types (u64 *key, u64 rss_types)
{
#define _(a, b, c)                                                            \
  if (rss_types & (1UL << a))                                                 \
    *key |= b;

  foreach_oct_flow_rss_types
#undef _

    return;
}

vnet_dev_rv_t
oct_flow_validate_params (vlib_main_t *vm, vnet_dev_port_t *port,
			  vnet_dev_port_cfg_type_t type, u32 flow_index,
			  uword *priv_data)
{
  vnet_dev_port_interfaces_t *ifs = port->interfaces;
  vnet_flow_t *flow = vnet_get_flow (flow_index);
  u32 last_queue;
  u32 qid;

  if (type == VNET_DEV_PORT_CFG_GET_RX_FLOW_COUNTER ||
      type == VNET_DEV_PORT_CFG_RESET_RX_FLOW_COUNTER)
    {
      log_err (port->dev, "Unsupported request type");
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  if (OCT_FLOW_UNSUPPORTED_ACTIONS (flow))
    {
      log_err (port->dev, "Unsupported flow action");
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      qid = flow->redirect_queue;
      if (qid > ifs->num_rx_queues - 1 || qid < 0)
	{
	  log_err (port->dev,
		   "Given Q(%d) is invalid, supported range is %d-%d", qid, 0,
		   ifs->num_rx_queues - 1);
	  return VNET_DEV_ERR_NOT_SUPPORTED;
	}
    }

  if (flow->actions & VNET_FLOW_ACTION_RSS)
    {
      last_queue = flow->queue_index + flow->queue_num;
      if (last_queue > ifs->num_rx_queues - 1)
	{
	  log_err (port->dev,
		   "Given Q range(%d-%d) is invalid, supported range is %d-%d",
		   flow->queue_index, flow->queue_index + flow->queue_num, 0,
		   ifs->num_rx_queues - 1);
	  return VNET_DEV_ERR_NOT_SUPPORTED;
	}
    }
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
oct_flow_rule_create (vnet_dev_port_t *port, struct roc_npc_action *actions,
		      struct roc_npc_item_info *item_info, vnet_flow_t *flow,
		      uword *private_data)
{
  oct_port_t *oct_port = vnet_dev_get_port_data (port);
  struct roc_npc_attr attr = { .priority = 1 };
  struct roc_npc_flow *npc_flow;
  oct_flow_entry_t *flow_entry;
  u64 npc_default_action = 0;
  struct roc_npc *npc;
  int rv = 0;

  if (flow->group)
    log_warn (port->dev, "Flow[%d] Group is non zero, but octeon driver does not support it",
	      flow->index);
  switch (flow->dir)
    {
    case VNET_FLOW_DIRECTION_EGRESS:
      attr.egress = 1;
    case VNET_FLOW_DIRECTION_TRANSFER:
      log_warn (port->dev,
		"Flow[%d] Direction is transfer, but octeon driver does not support it. "
		"Defaulting to ingress",
		flow->index);
    case VNET_FLOW_DIRECTION_INGRESS:
    default:
      attr.ingress = 1;
      break;
    }

  npc = &oct_port->npc;

  for (int i = 0; item_info[i].type != ROC_NPC_ITEM_TYPE_END; i++)
    {
      log_debug (port->dev, "Flow[%d] Item[%d] type %d spec 0x%U mask 0x%U",
		 flow->index, i, item_info[i].type, format_hex_bytes,
		 item_info[i].spec, item_info[i].size, format_hex_bytes,
		 item_info[i].mask, item_info[i].size);
    }

  rv = roc_npc_mcam_default_rule_action_get (npc, &npc_default_action);
  if (rv)
    {
      log_err (port->dev, "roc_npc_mcam_default_rule_action_get failed with '%s' error",
	       roc_error_msg_get (rv));
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  npc_flow =
    roc_npc_flow_create (npc, &attr, item_info, actions, npc->pf_func, npc_default_action, &rv);
  if (rv)
    {
      log_err (port->dev, "roc_npc_flow_create failed with '%s' error",
	       roc_error_msg_get (rv));
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
  roc_npc_mcam_clear_counter (npc, npc_flow->ctr_id);

  pool_get_zero (oct_port->flow_entries, flow_entry);
  flow_entry->index = flow_entry - oct_port->flow_entries;
  flow_entry->vnet_flow_index = flow->index;
  flow_entry->npc_flow = npc_flow;

  *private_data = flow_entry->index;

  return VNET_DEV_OK;
}

static int
oct_parse_l2 (oct_flow_parse_state *pst)
{
  struct roc_npc_flow_item_eth *eth_spec =
    (struct roc_npc_flow_item_eth *) &pst->oct_drv.spec[pst->oct_drv.off];
  struct roc_npc_flow_item_eth *eth_mask =
    (struct roc_npc_flow_item_eth *) &pst->oct_drv.mask[pst->oct_drv.off];
  ethernet_header_t *eth_hdr_mask =
    (ethernet_header_t *) &pst->generic.mask[pst->generic.off];
  ethernet_header_t *eth_hdr =
    (ethernet_header_t *) &pst->generic.spec[pst->generic.off];
  u16 tpid, etype;

  tpid = etype = clib_net_to_host_u16 (eth_hdr->type);
  clib_memcpy_fast (eth_spec, eth_hdr, sizeof (ethernet_header_t));
  clib_memcpy_fast (eth_mask, eth_hdr_mask, sizeof (ethernet_header_t));
  eth_spec->has_vlan = 0;

  pst->items[pst->layer].spec = (void *) eth_spec;
  pst->items[pst->layer].mask = (void *) eth_mask;
  pst->items[pst->layer].size = sizeof (ethernet_header_t);
  pst->items[pst->layer].type = ROC_NPC_ITEM_TYPE_ETH;
  pst->generic.off += sizeof (ethernet_header_t);
  pst->oct_drv.off += sizeof (struct roc_npc_flow_item_eth);
  pst->layer++;

  /* Parse VLAN Tags if any */
  struct roc_npc_flow_item_vlan *vlan_spec =
    (struct roc_npc_flow_item_vlan *) &pst->oct_drv.spec[pst->oct_drv.off];
  struct roc_npc_flow_item_vlan *vlan_mask =
    (struct roc_npc_flow_item_vlan *) &pst->oct_drv.mask[pst->oct_drv.off];
  ethernet_vlan_header_t *vlan_hdr, *vlan_hdr_mask;
  u8 vlan_cnt = 0;

  while (tpid == ETHERNET_TYPE_DOT1AD || tpid == ETHERNET_TYPE_VLAN)
    {
      if (pst->generic.off >= pst->generic.len)
	break;

      vlan_hdr =
	(ethernet_vlan_header_t *) &pst->generic.spec[pst->generic.off];
      vlan_hdr_mask =
	(ethernet_vlan_header_t *) &pst->generic.mask[pst->generic.off];
      tpid = etype = clib_net_to_host_u16 (vlan_hdr->type);
      clib_memcpy (&vlan_spec[vlan_cnt], vlan_hdr,
		   sizeof (ethernet_vlan_header_t));
      clib_memcpy (&vlan_mask[vlan_cnt], vlan_hdr_mask,
		   sizeof (ethernet_vlan_header_t));
      pst->items[pst->layer].spec = (void *) &vlan_spec[vlan_cnt];
      pst->items[pst->layer].mask = (void *) &vlan_mask[vlan_cnt];
      pst->items[pst->layer].size = sizeof (ethernet_vlan_header_t);
      pst->items[pst->layer].type = ROC_NPC_ITEM_TYPE_VLAN;
      pst->generic.off += sizeof (ethernet_vlan_header_t);
      pst->oct_drv.off += sizeof (struct roc_npc_flow_item_vlan);
      pst->layer++;
      vlan_cnt++;
    }

  /* Inner most vlan tag */
  if (vlan_cnt)
    vlan_spec[vlan_cnt - 1].has_more_vlan = 0;

  pst->nxt_proto = etype;
  return 0;
}

static int
oct_parse_l3 (oct_flow_parse_state *pst)
{

  if (pst->generic.off >= pst->generic.len || pst->nxt_proto == 0)
    return 0;

  if (pst->nxt_proto == ETHERNET_TYPE_MPLS)
    {
      int label_stack_bottom = 0;
      do
	{

	  u8 *mpls_spec = &pst->generic.spec[pst->generic.off];
	  u8 *mpls_mask = &pst->generic.mask[pst->generic.off];

	  label_stack_bottom = mpls_spec[2] & 1;
	  pst->items[pst->layer].spec = (void *) mpls_spec;
	  pst->items[pst->layer].mask = (void *) mpls_mask;
	  pst->items[pst->layer].size = sizeof (u32);
	  pst->items[pst->layer].type = ROC_NPC_ITEM_TYPE_MPLS;
	  pst->generic.off += sizeof (u32);
	  pst->layer++;
	}
      while (label_stack_bottom);

      pst->nxt_proto = 0;
      return 0;
    }
  else if (pst->nxt_proto == ETHERNET_TYPE_IP4)
    {
      ip4_header_t *ip4_spec =
	(ip4_header_t *) &pst->generic.spec[pst->generic.off];
      ip4_header_t *ip4_mask =
	(ip4_header_t *) &pst->generic.mask[pst->generic.off];
      pst->items[pst->layer].spec = (void *) ip4_spec;
      pst->items[pst->layer].mask = (void *) ip4_mask;
      pst->items[pst->layer].size = sizeof (ip4_header_t);
      pst->items[pst->layer].type = ROC_NPC_ITEM_TYPE_IPV4;
      pst->generic.off += sizeof (ip4_header_t);
      pst->layer++;
      pst->nxt_proto = ip4_spec->protocol;
    }
  else if (pst->nxt_proto == ETHERNET_TYPE_IP6)
    {
      struct roc_npc_flow_item_ipv6 *ip6_spec =
	(struct roc_npc_flow_item_ipv6 *) &pst->oct_drv.spec[pst->oct_drv.off];
      struct roc_npc_flow_item_ipv6 *ip6_mask =
	(struct roc_npc_flow_item_ipv6 *) &pst->oct_drv.mask[pst->oct_drv.off];
      ip6_header_t *ip6_hdr_mask =
	(ip6_header_t *) &pst->generic.mask[pst->generic.off];
      ip6_header_t *ip6_hdr =
	(ip6_header_t *) &pst->generic.spec[pst->generic.off];
      u8 nxt_hdr = ip6_hdr->protocol;

      clib_memcpy (ip6_spec, ip6_hdr, sizeof (ip6_header_t));
      clib_memcpy (ip6_mask, ip6_hdr_mask, sizeof (ip6_header_t));
      pst->items[pst->layer].spec = (void *) ip6_spec;
      pst->items[pst->layer].mask = (void *) ip6_mask;
      pst->items[pst->layer].size = sizeof (ip6_header_t);
      pst->items[pst->layer].type = ROC_NPC_ITEM_TYPE_IPV6;
      pst->generic.off += sizeof (ip6_header_t);
      pst->oct_drv.off += sizeof (struct roc_npc_flow_item_ipv6);
      pst->layer++;

      while (nxt_hdr == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS ||
	     nxt_hdr == IP_PROTOCOL_IP6_DESTINATION_OPTIONS ||
	     nxt_hdr == IP_PROTOCOL_IPV6_ROUTE)
	{
	  if (pst->generic.off >= pst->generic.len)
	    return 0;

	  ip6_ext_header_t *ip6_ext_spec =
	    (ip6_ext_header_t *) &pst->generic.spec[pst->generic.off];
	  ip6_ext_header_t *ip6_ext_mask =
	    (ip6_ext_header_t *) &pst->generic.mask[pst->generic.off];
	  nxt_hdr = ip6_ext_spec->next_hdr;

	  pst->items[pst->layer].spec = (void *) ip6_ext_spec;
	  pst->items[pst->layer].mask = (void *) ip6_ext_mask;
	  pst->items[pst->layer].type = ROC_NPC_ITEM_TYPE_IPV6_EXT;
	  pst->generic.off += ip6_ext_header_len (ip6_ext_spec);
	  pst->layer++;
	}

      if (pst->generic.off >= pst->generic.len)
	return 0;

      if (nxt_hdr == IP_PROTOCOL_IPV6_FRAGMENTATION)
	{
	  ip6_frag_hdr_t *ip6_ext_frag_spec =
	    (ip6_frag_hdr_t *) &pst->generic.spec[pst->generic.off];
	  ip6_frag_hdr_t *ip6_ext_frag_mask =
	    (ip6_frag_hdr_t *) &pst->generic.mask[pst->generic.off];

	  pst->items[pst->layer].spec = (void *) ip6_ext_frag_spec;
	  pst->items[pst->layer].mask = (void *) ip6_ext_frag_mask;
	  pst->items[pst->layer].size = sizeof (ip6_frag_hdr_t);
	  pst->items[pst->layer].type = ROC_NPC_ITEM_TYPE_IPV6_FRAG_EXT;
	  pst->generic.off += sizeof (ip6_frag_hdr_t);
	  pst->layer++;
	}

      pst->nxt_proto = nxt_hdr;
    }
  /* Unsupported L3. */
  else
    return -1;

  return 0;
}

static int
oct_parse_l4 (oct_flow_parse_state *pst)
{

  if (pst->generic.off >= pst->generic.len || pst->nxt_proto == 0)
    return 0;

#define _(protocol_t, protocol_value, ltype)                                  \
  if (pst->nxt_proto == protocol_value)                                       \
                                                                              \
    {                                                                         \
                                                                              \
      protocol_t *spec = (protocol_t *) &pst->generic.spec[pst->generic.off]; \
      protocol_t *mask = (protocol_t *) &pst->generic.mask[pst->generic.off]; \
      pst->items[pst->layer].spec = spec;                                     \
      pst->items[pst->layer].mask = mask;                                     \
                                                                              \
      pst->items[pst->layer].size = sizeof (protocol_t);                      \
                                                                              \
      pst->items[pst->layer].type = ROC_NPC_ITEM_TYPE_##ltype;                \
      pst->generic.off += sizeof (protocol_t);                                \
      pst->layer++;                                                           \
      return 0;                                                               \
    }

  _ (esp_header_t, IP_PROTOCOL_IPSEC_ESP, ESP)
  _ (udp_header_t, IP_PROTOCOL_UDP, UDP)
  _ (tcp_header_t, IP_PROTOCOL_TCP, TCP)
  _ (sctp_header_t, IP_PROTOCOL_SCTP, SCTP)
  _ (icmp46_header_t, IP_PROTOCOL_ICMP, ICMP)
  _ (icmp46_header_t, IP_PROTOCOL_ICMP6, ICMP)
  _ (igmp_header_t, IP_PROTOCOL_IGMP, IGMP)
  _ (gre_header_t, IP_PROTOCOL_GRE, GRE)

  /* Unsupported L4. */
  return -1;
}

static int
oct_parse_tunnel (oct_flow_parse_state *pst)
{
  if (pst->generic.off >= pst->generic.len)
    return 0;

  if (pst->items[pst->layer - 1].type == ROC_NPC_ITEM_TYPE_GRE)
    {
      gre_header_t *gre_hdr = (gre_header_t *) pst->items[pst->layer - 1].spec;
      pst->nxt_proto = clib_net_to_host_u16 (gre_hdr->protocol);
      goto parse_l3;
    }

  else if (pst->items[pst->layer - 1].type == ROC_NPC_ITEM_TYPE_UDP)
    {
      udp_header_t *udp_h = (udp_header_t *) pst->items[pst->layer - 1].spec;
      u16 dport = clib_net_to_host_u16 (udp_h->dst_port);

      if (dport == GTPU_PORT)
	{
	  gtpu_header_t *gtpu_spec =
	    (gtpu_header_t *) &pst->generic.spec[pst->generic.off];
	  gtpu_header_t *gtpu_mask =
	    (gtpu_header_t *) &pst->generic.mask[pst->generic.off];
	  pst->items[pst->layer].spec = (void *) gtpu_spec;
	  pst->items[pst->layer].mask = (void *) gtpu_mask;
	  pst->items[pst->layer].size = sizeof (gtpu_header_t);
	  pst->items[pst->layer].type = ROC_NPC_ITEM_TYPE_GTPU;
	  pst->generic.off += sizeof (gtpu_header_t);
	  pst->layer++;
	  pst->nxt_proto = 0;
	  return 0;
	}
      else if (dport == VXLAN_PORT)
	{
	  octeon_vxlan_header_t *vxlan_spec =
	    (octeon_vxlan_header_t *) &pst->generic.spec[pst->generic.off];
	  octeon_vxlan_header_t *vxlan_mask =
	    (octeon_vxlan_header_t *) &pst->generic.spec[pst->generic.off];
	  pst->items[pst->layer].spec = (void *) vxlan_spec;
	  pst->items[pst->layer].mask = (void *) vxlan_mask;
	  pst->items[pst->layer].size = sizeof (octeon_vxlan_header_t);
	  pst->items[pst->layer].type = ROC_NPC_ITEM_TYPE_VXLAN;
	  pst->generic.off += sizeof (octeon_vxlan_header_t);
	  pst->layer++;
	  pst->nxt_proto = 0;
	  goto parse_l2;
	}
    }
  /* No supported Tunnel detected. */
  else
    {
      log_err (pst->port->dev,
	       "Partially parsed till offset %u, not able to parse further",
	       pst->generic.off);
      return 0;
    }
parse_l2:
  if (oct_parse_l2 (pst))
    return -1;
parse_l3:
  if (oct_parse_l3 (pst))
    return -1;

  return oct_parse_l4 (pst);
}

static vnet_dev_rv_t
oct_flow_generic_pattern_parse (oct_flow_parse_state *pst)
{

  if (oct_parse_l2 (pst))
    goto err;

  if (oct_parse_l3 (pst))
    goto err;

  if (oct_parse_l4 (pst))
    goto err;

  if (oct_parse_tunnel (pst))
    goto err;

  if (pst->generic.off < pst->generic.len)
    {
      log_err (pst->port->dev,
	       "Partially parsed till offset %u, not able to parse further",
	       pst->generic.off);
      goto err;
    }

  pst->items[pst->layer].type = ROC_NPC_ITEM_TYPE_END;
  return VNET_DEV_OK;

err:
  return VNET_DEV_ERR_NOT_SUPPORTED;
}

static vnet_dev_rv_t
oct_flow_add (vlib_main_t *vm, vnet_dev_port_t *port, vnet_flow_t *flow,
	      uword *private_data)
{
  struct roc_npc_item_info item_info[ROC_NPC_ITEM_TYPE_END] = {};
  struct roc_npc_action actions[ROC_NPC_ITEM_TYPE_END] = {};
  oct_port_t *oct_port = vnet_dev_get_port_data (port);
  vnet_dev_port_interfaces_t *ifs = port->interfaces;
  ethernet_header_t eth_spec = {}, eth_mask = {};
  sctp_header_t sctp_spec = {}, sctp_mask = {};
  gtpu_header_t gtpu_spec = {}, gtpu_mask = {};
  ip4_header_t ip4_spec = {}, ip4_mask = {};
  ip6_header_t ip6_spec = {}, ip6_mask = {};
  udp_header_t udp_spec = {}, udp_mask = {};
  tcp_header_t tcp_spec = {}, tcp_mask = {};
  esp_header_t esp_spec = {}, esp_mask = {};
  u16 l4_src_port = 0, l4_dst_port = 0;
  u16 l4_src_mask = 0, l4_dst_mask = 0;
  struct roc_npc_action_rss rss_conf = {};
  struct roc_npc_action_queue conf = {};
  struct roc_npc_action_mark mark = {};
  struct roc_npc *npc = &oct_port->npc;
  u8 *flow_spec = 0, *flow_mask = 0;
  u8 *drv_spec = 0, *drv_mask = 0;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  int layer = 0, index = 0;
  u16 *queues = NULL;
  u64 flow_key = 0;
  u8 proto = 0;
  u16 action = 0;

  if (FLOW_IS_GENERIC_TYPE (flow))
    {
      unformat_input_t input;
      int rc;

      unformat_init_string (
	&input, (const char *) flow->generic.pattern.spec,
	strlen ((const char *) flow->generic.pattern.spec));
      unformat_user (&input, unformat_hex_string, &flow_spec);
      unformat_free (&input);

      unformat_init_string (
	&input, (const char *) flow->generic.pattern.mask,
	strlen ((const char *) flow->generic.pattern.mask));
      unformat_user (&input, unformat_hex_string, &flow_mask);
      unformat_free (&input);

      vec_validate (drv_spec, 1024);
      vec_validate (drv_mask, 1024);
      oct_flow_parse_state pst = {
	.nxt_proto = 0,
	.port = port,
	.items = item_info,
	.oct_drv = { .spec = drv_spec, .mask = drv_mask },
	.generic = { .spec = flow_spec,
		     .mask = flow_mask,
		     .len = vec_len (flow_spec) },
      };

      rc = oct_flow_generic_pattern_parse (&pst);
      if (rc)
	{
	  vec_free (flow_spec);
	  vec_free (flow_mask);
	  vec_free (drv_spec);
	  vec_free (drv_mask);
	  return VNET_DEV_ERR_NOT_SUPPORTED;
	}

      goto parse_flow_actions;
    }

  if (FLOW_IS_ETHERNET_CLASS (flow))
    {
      eth_spec.type = clib_host_to_net_u16 (flow->ethernet.eth_hdr.type);
      eth_mask.type = 0xFFFF;

      item_info[layer].spec = (void *) &eth_spec;
      item_info[layer].mask = (void *) &eth_mask;
      item_info[layer].size = sizeof (ethernet_header_t);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_ETH;
      layer++;
    }

  else if (FLOW_IS_IPV4_CLASS (flow))
    {
      vnet_flow_ip4_t *ip4_hdr = &flow->ip4;
      proto = ip4_hdr->protocol.prot;

      ip4_spec.src_address = ip4_hdr->src_addr.addr;
      ip4_spec.dst_address = ip4_hdr->dst_addr.addr;
      ip4_mask.src_address = ip4_hdr->src_addr.mask;
      ip4_mask.dst_address = ip4_hdr->dst_addr.mask;

      item_info[layer].spec = (void *) &ip4_spec;
      item_info[layer].mask = (void *) &ip4_mask;
      item_info[layer].size = sizeof (ip4_header_t);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_IPV4;
      layer++;

      if (FLOW_IS_L4_TYPE (flow))
	{
	  vnet_flow_ip4_n_tuple_t *ip4_tuple_hdr = &flow->ip4_n_tuple;

	  l4_src_port = clib_host_to_net_u16 (ip4_tuple_hdr->src_port.port);
	  l4_dst_port = clib_host_to_net_u16 (ip4_tuple_hdr->dst_port.port);
	  l4_src_mask = clib_host_to_net_u16 (ip4_tuple_hdr->src_port.mask);
	  l4_dst_mask = clib_host_to_net_u16 (ip4_tuple_hdr->dst_port.mask);
	}
    }
  else if (FLOW_IS_IPV6_CLASS (flow))
    {
      vnet_flow_ip6_t *ip6_hdr = &flow->ip6;
      proto = ip6_hdr->protocol.prot;

      ip6_spec.src_address = ip6_hdr->src_addr.addr;
      ip6_spec.dst_address = ip6_hdr->dst_addr.addr;
      ip6_mask.src_address = ip6_hdr->src_addr.mask;
      ip6_mask.dst_address = ip6_hdr->dst_addr.mask;

      item_info[layer].spec = (void *) &ip6_spec;
      item_info[layer].mask = (void *) &ip6_mask;
      item_info[layer].size = sizeof (ip6_header_t);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_IPV6;
      layer++;

      if (FLOW_IS_L4_TYPE (flow))
	{
	  vnet_flow_ip6_n_tuple_t *ip6_tuple_hdr = &flow->ip6_n_tuple;

	  l4_src_port = clib_host_to_net_u16 (ip6_tuple_hdr->src_port.port);
	  l4_dst_port = clib_host_to_net_u16 (ip6_tuple_hdr->dst_port.port);
	  l4_src_mask = clib_host_to_net_u16 (ip6_tuple_hdr->src_port.mask);
	  l4_dst_mask = clib_host_to_net_u16 (ip6_tuple_hdr->dst_port.mask);
	}
    }

  if (!proto)
    goto end_item_info;

  switch (proto)
    {
    case IP_PROTOCOL_UDP:
      udp_spec.src_port = l4_src_port;
      udp_spec.dst_port = l4_dst_port;
      udp_mask.src_port = l4_src_mask;
      udp_mask.dst_port = l4_dst_mask;

      item_info[layer].spec = (void *) &udp_spec;
      item_info[layer].mask = (void *) &udp_mask;
      item_info[layer].size = sizeof (udp_header_t);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_UDP;
      layer++;

      if (FLOW_IS_L4_TUNNEL_TYPE (flow))
	{
	  switch (flow->type)
	    {
	    case VNET_FLOW_TYPE_IP4_GTPU:
	      gtpu_spec.teid = clib_host_to_net_u32 (flow->ip4_gtpu.teid);
	      gtpu_mask.teid = 0XFFFFFFFF;

	      item_info[layer].spec = (void *) &gtpu_spec;
	      item_info[layer].mask = (void *) &gtpu_mask;
	      item_info[layer].size = sizeof (gtpu_header_t);
	      item_info[layer].type = ROC_NPC_ITEM_TYPE_GTPU;
	      layer++;
	      break;

	    default:
	      log_err (port->dev, "Unsupported L4 tunnel type");
	      return VNET_DEV_ERR_NOT_SUPPORTED;
	    }
	} /* FLOW_IS_L4_TUNNEL_TYPE */
      break;

    case IP_PROTOCOL_TCP:
      tcp_spec.src_port = l4_src_port;
      tcp_spec.dst_port = l4_dst_port;
      tcp_mask.src_port = l4_src_mask;
      tcp_mask.dst_port = l4_dst_mask;

      item_info[layer].spec = (void *) &tcp_spec;
      item_info[layer].mask = (void *) &tcp_mask;
      item_info[layer].size = sizeof (tcp_header_t);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_TCP;
      layer++;
      break;

    case IP_PROTOCOL_SCTP:
      sctp_spec.src_port = l4_src_port;
      sctp_spec.dst_port = l4_dst_port;
      sctp_mask.src_port = l4_src_mask;
      sctp_mask.dst_port = l4_dst_mask;

      item_info[layer].spec = (void *) &sctp_spec;
      item_info[layer].mask = (void *) &sctp_mask;
      item_info[layer].size = sizeof (sctp_header_t);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_SCTP;
      layer++;
      break;

    case IP_PROTOCOL_IPSEC_ESP:
      esp_spec.spi = clib_host_to_net_u32 (flow->ip4_ipsec_esp.spi);
      esp_mask.spi = 0xFFFFFFFF;

      item_info[layer].spec = (void *) &esp_spec;
      item_info[layer].mask = (void *) &esp_mask;
      item_info[layer].size = sizeof (u32);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_ESP;
      layer++;
      break;

    default:
      log_err (port->dev, "Unsupported IP protocol '%U'", format_ip_protocol,
	       proto);
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }

end_item_info:
  item_info[layer].type = ROC_NPC_ITEM_TYPE_END;

parse_flow_actions:
  if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      conf.index = flow->redirect_queue;
      actions[action].type = ROC_NPC_ACTION_TYPE_QUEUE;
      actions[action].conf = &conf;
      action++;
    }

  else if (flow->actions & VNET_FLOW_ACTION_DROP)
    {
      actions[action].type = ROC_NPC_ACTION_TYPE_DROP;
      action++;
    }

  else if (flow->actions & VNET_FLOW_ACTION_RSS)
    {
      if (!flow->queue_num)
	{
	  log_err (port->dev, "RSS action has no queues");
	  return VNET_DEV_ERR_NOT_SUPPORTED;
	}
      queues = clib_mem_alloc (sizeof (u16) * ifs->num_rx_queues);

      for (index = 0; index < flow->queue_num; index++)
	queues[index] = flow->queue_index++;

      oct_flow_convert_rss_types (&flow_key, flow->rss_types);
      if (!flow_key)
	{
	  log_err (port->dev, "Invalid RSS hash function");
	  return VNET_DEV_ERR_NOT_SUPPORTED;
	}
      npc->flowkey_cfg_state = flow_key;
      rss_conf.queue_num = flow->queue_num;
      rss_conf.queue = queues;

      actions[action].type = ROC_NPC_ACTION_TYPE_RSS;
      actions[action].conf = &rss_conf;
      action++;
    }

  if (flow->actions & VNET_FLOW_ACTION_MARK)
    {
      if (flow->mark_flow_id == 0 ||
	  flow->mark_flow_id > (NPC_FLOW_FLAG_VAL - 2))
	{
	  log_err (port->dev, "mark flow id must be > 0 and < 0xfffe");
	  return VNET_DEV_ERR_NOT_SUPPORTED;
	}
      /* RoC library adds 1 to id, so subtract 1 */
      mark.id = flow->mark_flow_id - 1;
      actions[action].type = ROC_NPC_ACTION_TYPE_MARK;
      actions[action].conf = &mark;
      action++;
    }

  /* make count as default action */
  actions[action].type = ROC_NPC_ACTION_TYPE_COUNT;
  actions[action + 1].type = ROC_NPC_ACTION_TYPE_END;

  rv = oct_flow_rule_create (port, actions, item_info, flow, private_data);

  if (queues)
    clib_mem_free (queues);

  vec_free (flow_spec);
  vec_free (flow_mask);
  vec_free (drv_spec);
  vec_free (drv_mask);

  return rv;
}

static vnet_dev_rv_t
oct_flow_del (vlib_main_t *vm, vnet_dev_port_t *port, vnet_flow_t *flow,
	      uword *private_data)
{
  oct_port_t *oct_port = vnet_dev_get_port_data (port);
  struct roc_npc *npc = &oct_port->npc;
  struct roc_npc_flow *npc_flow;
  oct_flow_entry_t *flow_entry;
  int rv = 0, index;

  index = *private_data;
  flow_entry = pool_elt_at_index (oct_port->flow_entries, index);
  npc_flow = flow_entry->npc_flow;
  rv = roc_npc_flow_destroy (npc, npc_flow);
  if (rv)
    {
      log_err (port->dev, "roc_npc_flow_destroy failed with '%s' error",
	       roc_error_msg_get (rv));
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
  pool_put (oct_port->flow_entries, flow_entry);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
oct_flow_query (vlib_main_t *vm, vnet_dev_port_t *port, u32 flow_index,
		uword private_data, u64 *hits)
{
  oct_port_t *oct_port = vnet_dev_get_port_data (port);
  struct roc_npc *npc = &oct_port->npc;
  struct roc_npc_flow *npc_flow;
  oct_flow_entry_t *flow_entry;
  i32 flow_count;
  int rv = 0;

  flow_count = pool_elts (oct_port->flow_entries);
  if (!flow_count)
    {
      log_err (port->dev, "Flow entry pool is empty");
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  flow_entry = pool_elt_at_index (oct_port->flow_entries, private_data);
  npc_flow = flow_entry->npc_flow;
  if (npc_flow->ctr_id == NPC_COUNTER_NONE)
    {
      log_err (port->dev, "Counters are not available for given flow id (%u)",
	       flow_index);
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }

  rv = roc_npc_mcam_read_counter (npc, npc_flow->ctr_id, hits);
  if (rv != 0)
    {
      log_err (port->dev, "Error reading flow counter for given flow id (%u)",
	       flow_index);
      return VNET_DEV_ERR_INTERNAL;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
oct_flow_ops_fn (vlib_main_t *vm, vnet_dev_port_t *port,
		 vnet_dev_port_cfg_type_t type, u32 flow_index,
		 uword *priv_data)
{
  vnet_flow_t *flow = vnet_get_flow (flow_index);

  if (type == VNET_DEV_PORT_CFG_ADD_RX_FLOW)
    return oct_flow_add (vm, port, flow, priv_data);

  if (type == VNET_DEV_PORT_CFG_DEL_RX_FLOW)
    return oct_flow_del (vm, port, flow, priv_data);

  return VNET_DEV_ERR_NOT_SUPPORTED;
}
