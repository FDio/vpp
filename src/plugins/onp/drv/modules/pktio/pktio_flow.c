/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/pktio/pktio_priv.h>

static i32
cnxk_flow_actions_queue_update (vnet_flow_t *flow,
				struct roc_npc_action *actions,
				cnxk_pktio_t *dev)
{
  struct roc_npc_action_queue *conf = 0, *pconf = 0;

  vec_add2 (pconf, conf, 1);

  conf->index = flow->redirect_queue;
  actions[0].type = ROC_NPC_ACTION_TYPE_QUEUE;
  actions[0].conf = (void *) pconf;

  actions[1].type = ROC_NPC_ACTION_TYPE_COUNT;

  actions[2].type = ROC_NPC_ACTION_TYPE_END;

  return 0;
}

static i32
cnxk_flow_actions_update (vnet_flow_t *flow, struct roc_npc_action *actions,
			  cnxk_pktio_t *dev)
{
  switch (flow->actions)
    {
    case VNET_FLOW_ACTION_REDIRECT_TO_QUEUE:
      return cnxk_flow_actions_queue_update (flow, actions, dev);

    case VNET_FLOW_ACTION_RSS:
    case VNET_FLOW_ACTION_DROP:
    case VNET_FLOW_ACTION_COUNT:
    case VNET_FLOW_ACTION_MARK:
    default:
      return CNXK_UNSUPPORTED_OPERATION;
    }
  return 0;
}

static i32
cnxk_flow_type_ipsec_update (vnet_flow_t *flow,
			     struct roc_npc_item_info *pattern,
			     cnxk_pktio_t *dev)
{
  u32 *spi = 0;

  vec_add2 (spi, spi, 2);

  spi[0] = 0;
  spi[1] = 0;

  pattern->spec = (void *) &spi[0];
  pattern->mask = (void *) &spi[1];
  pattern->size = sizeof (spi[0]);
  pattern->type = ROC_NPC_ITEM_TYPE_ESP;
  pattern++;

  pattern->type = ROC_NPC_ITEM_TYPE_END;

  return 0;
}

static i32
cnxk_flow_type_ip_tuple_update (vnet_flow_t *flow,
				struct roc_npc_item_info *pattern,
				cnxk_pktio_t *dev, int is_ip4)
{
  vnet_flow_ip4_n_tuple_t *ip4_hdr;
  u16 src_port = 0, dst_port = 0, src_port_mask = 0, dst_port_mask = 0;

  if (is_ip4)
    {
      ip4_hdr = &flow->ip4_n_tuple;
      ip4_header_t *ip_hdr = 0;
      udp_header_t *udp_hdr = 0;
      tcp_header_t *tcp_hdr = 0;
      u8 ip_protocol;

      vec_add2 (ip_hdr, ip_hdr, 2);
      vec_add2 (udp_hdr, udp_hdr, 2);
      vec_add2 (tcp_hdr, tcp_hdr, 2);

      ip_protocol = ip4_hdr->protocol.prot;

      ip_hdr[0].src_address = ip4_hdr->src_addr.addr;
      ip_hdr[1].src_address = ip4_hdr->src_addr.mask;
      ip_hdr[0].dst_address = ip4_hdr->dst_addr.addr;
      ip_hdr[1].dst_address = ip4_hdr->dst_addr.mask;
      ip_hdr[0].protocol = ip4_hdr->protocol.prot;
      ip_hdr[1].protocol = ip4_hdr->protocol.mask;

      pattern->spec = (void *) &ip_hdr[0];
      pattern->mask = (void *) &ip_hdr[1];
      pattern->size = sizeof (ip4_header_t);
      pattern->type = ROC_NPC_ITEM_TYPE_IPV4;
      pattern++;

      switch (ip_protocol)
	{
	case IP_PROTOCOL_UDP:
	  src_port = ip4_hdr->src_port.port;
	  dst_port = ip4_hdr->dst_port.port;
	  src_port_mask = ip4_hdr->src_port.mask;
	  dst_port_mask = ip4_hdr->dst_port.mask;

	  udp_hdr[0].src_port = clib_host_to_net_u16 (src_port);
	  udp_hdr[1].src_port = clib_host_to_net_u16 (src_port_mask);
	  udp_hdr[0].dst_port = clib_host_to_net_u16 (dst_port);
	  udp_hdr[1].dst_port = clib_host_to_net_u16 (dst_port_mask);

	  pattern->spec = (void *) &udp_hdr[0];
	  pattern->mask = (void *) &udp_hdr[1];
	  pattern->size = sizeof (udp_header_t);
	  pattern->type = ROC_NPC_ITEM_TYPE_UDP;
	  pattern++;

	  break;

	case IP_PROTOCOL_TCP:
	  src_port = ip4_hdr->src_port.port;
	  dst_port = ip4_hdr->dst_port.port;
	  src_port_mask = ip4_hdr->src_port.mask;
	  dst_port_mask = ip4_hdr->dst_port.mask;

	  tcp_hdr[0].src_port = clib_host_to_net_u16 (src_port);
	  tcp_hdr[1].src_port = clib_host_to_net_u16 (src_port_mask);
	  tcp_hdr[0].dst_port = clib_host_to_net_u16 (dst_port);
	  tcp_hdr[1].dst_port = clib_host_to_net_u16 (dst_port_mask);

	  pattern->spec = (void *) &tcp_hdr[0];
	  pattern->mask = (void *) &tcp_hdr[1];
	  pattern->size = sizeof (tcp_header_t);
	  pattern->type = ROC_NPC_ITEM_TYPE_TCP;
	  pattern++;

	  break;
	}
      pattern->type = ROC_NPC_ITEM_TYPE_END;
      return 0;
    }
  else
    {
      return CNXK_UNSUPPORTED_OPERATION;
    }

  return 0;
}

static i32
cnxk_flow_type_ip_update (vnet_flow_t *flow, struct roc_npc_item_info *pattern,
			  cnxk_pktio_t *dev, int is_ip4)
{
  return CNXK_UNSUPPORTED_OPERATION;
}

static i32
cnxk_flow_type_update (vnet_flow_t *flow, struct roc_npc_item_info *pattern,
		       cnxk_pktio_t *dev)
{

  switch (flow->type)
    {
    case VNET_FLOW_TYPE_IP4:
      return cnxk_flow_type_ip_update (flow, pattern, dev, 1);

    case VNET_FLOW_TYPE_IP6:
      return cnxk_flow_type_ip_update (flow, pattern, dev, 0);

    case VNET_FLOW_TYPE_IP4_N_TUPLE:
      return cnxk_flow_type_ip_tuple_update (flow, pattern, dev, 1);

    case VNET_FLOW_TYPE_IP6_N_TUPLE:
      return cnxk_flow_type_ip_tuple_update (flow, pattern, dev, 0);

    case VNET_FLOW_TYPE_IP4_IPSEC_ESP:
      return cnxk_flow_type_ipsec_update (flow, pattern, dev);

    case VNET_FLOW_TYPE_ETHERNET:
    default:
      return CNXK_UNSUPPORTED_OPERATION;
    }
  return 0;
}

static i32
cnxk_flow_rule_add (vnet_main_t *vnm, cnxk_pktio_t *dev,
		    vnet_flow_t *vnet_flow, uword *private_data)
{
  struct roc_npc_item_info pattern[ROC_NPC_ITEM_TYPE_END] = { 0 };
  struct roc_npc_action actions[ROC_NPC_ITEM_TYPE_END] = { 0 };
  struct roc_npc_flow *npc_flow;
  struct roc_npc_attr attr = { 0 };
  struct roc_npc *npc = &dev->npc;
  int rv = 0;

  /* Same priority for all rules */
  attr.priority = 1;

  /* Only ingress port is supported */
  attr.ingress = 1;

  /*
   * One action per flow
   * TODO: Support multiple actions
   */
  rv = cnxk_flow_actions_update (vnet_flow, actions, dev);
  if (rv)
    return rv;

  rv = cnxk_flow_type_update (vnet_flow, pattern, dev);
  if (rv)
    return rv;

  npc_flow =
    roc_npc_flow_create (npc, &attr, pattern, actions, npc->pf_func, &rv);
  if (rv)
    {
      cnxk_pktio_warn ("roc_npc_flow_create failed with '%s' error",
		       roc_error_msg_get (rv));
      return rv;
    }
  else
    {
      cnxk_flow_t *flow_entry;

      roc_npc_mcam_clear_counter (npc, npc_flow->ctr_id);
      pool_get (dev->flow_entries, flow_entry);
      flow_entry->vnet_flow_index = vnet_flow->index;
      flow_entry->npc_flow = npc_flow;
      *private_data = flow_entry - dev->flow_entries;
    }
  return 0;
}

i32
cnxk_pktio_flow_update (vnet_main_t *vnm, vnet_flow_dev_op_t op,
			cnxk_pktio_t *dev, vnet_flow_t *flow,
			uword *private_data)
{
  switch (op)
    {
    case VNET_FLOW_DEV_OP_ADD_FLOW:
      return cnxk_flow_rule_add (vnm, dev, flow, private_data);

    case VNET_FLOW_DEV_OP_DEL_FLOW:
    case VNET_FLOW_DEV_OP_GET_COUNTER:
    case VNET_FLOW_DEV_OP_RESET_COUNTER:
    default:
      return CNXK_UNSUPPORTED_OPERATION;
    }
  return 0;
}

u32
cnxk_pktio_flow_query (vlib_main_t *vm, cnxk_pktio_t *dev, u32 flow_index,
		       cnxk_flow_stats_t *stats)
{
  struct roc_npc *npc = &dev->npc;
  struct roc_npc_flow *npc_flow;
  cnxk_flow_t *flow;
  i32 flow_count;
  u64 hits;

  flow_count = pool_elts (dev->flow_entries);
  if (!flow_count)
    return -1;

  if (flow_index > flow_count)
    return -1;

  flow = &dev->flow_entries[flow_index];
  npc_flow = flow->npc_flow;
  if (npc_flow->ctr_id == NPC_COUNTER_NONE)
    {
      cnxk_pktio_warn ("cnxk flow[%u], vnet_flow: Counter is not available",
		       flow_index, flow->vnet_flow_index);
      return -1;
    }

  roc_npc_mcam_read_counter (npc, npc_flow->ctr_id, &hits);
  stats->flow_index = flow->vnet_flow_index;
  stats->hits = hits;

  return 0;
}

u32
cnxk_pktio_flow_dump (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  struct roc_npc *npc = &dev->npc;

  roc_npc_flow_dump (stdout, npc);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
