/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "flow",
};

static ice_flow_entry_t *
ice_flow_find (vnet_dev_port_t *port, u32 index)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_flow_entry_t *entry;
  pool_foreach (entry, ip->flows)
    if (entry->flow_index == index && entry->installed)
      return entry;
  return 0;
}

vnet_dev_rv_t
ice_flow_validate (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req)
{
  vnet_flow_t *flow = vnet_get_flow (req->flow_index);
  ice_flow_pattern_t pattern;
  u32 destination;
  vnet_dev_rv_t rv;

  if (!flow)
    return VNET_DEV_ERR_INVALID_ARG;
  if (!port->interfaces)
    return VNET_DEV_ERR_NOT_READY;
  if (req->type == VNET_DEV_PORT_CFG_GET_RX_FLOW_COUNTER)
    return VNET_DEV_ERR_NOT_SUPPORTED;
  if (req->type != VNET_DEV_PORT_CFG_ADD_RX_FLOW)
    return ice_flow_find (port, req->flow_index) ? VNET_DEV_OK : VNET_DEV_ERR_NO_SUCH_ENTRY;
  if (ice_flow_find (port, req->flow_index))
    return VNET_DEV_ERR_ALREADY_EXISTS;
  if (flow->actions & ~(VNET_FLOW_ACTION_COUNT | VNET_FLOW_ACTION_DROP |
			VNET_FLOW_ACTION_REDIRECT_TO_QUEUE | VNET_FLOW_ACTION_RSS))
    return VNET_DEV_ERR_NOT_SUPPORTED;
  destination = flow->actions &
		(VNET_FLOW_ACTION_DROP | VNET_FLOW_ACTION_REDIRECT_TO_QUEUE | VNET_FLOW_ACTION_RSS);
  if (count_set_bits (destination) > 1)
    return VNET_DEV_ERR_INVALID_ARG;
  if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      if (flow->redirect_queue >= port->interfaces->num_rx_queues)
	return VNET_DEV_ERR_INVALID_ARG;
      vnet_dev_rx_queue_t *queue = vnet_dev_get_port_rx_queue_by_id (port, flow->redirect_queue);
      if (!queue || !queue->enabled)
	return VNET_DEV_ERR_INVALID_ARG;
    }
  if (flow->actions & VNET_FLOW_ACTION_RSS)
    {
      if (!flow->queue_num || flow->queue_num > 128 || !is_pow2 (flow->queue_num) ||
	  flow->queue_index % flow->queue_num ||
	  flow->queue_index + (u64) flow->queue_num > port->interfaces->num_rx_queues ||
	  (flow->rss_fun != VNET_RSS_FUNC_DEFAULT && flow->rss_fun != VNET_RSS_FUNC_TOEPLITZ))
	return VNET_DEV_ERR_NOT_SUPPORTED;
      for (u32 i = 0; i < flow->queue_num; i++)
	{
	  vnet_dev_rx_queue_t *queue =
	    vnet_dev_get_port_rx_queue_by_id (port, flow->queue_index + i);
	  if (!queue || !queue->enabled)
	    return VNET_DEV_ERR_INVALID_ARG;
	}
    }
  if ((rv = ice_flow_parse (flow, &pattern)))
    return rv;
  if ((flow->actions & VNET_FLOW_ACTION_RSS) && flow->rss_types)
    {
      u64 full_tuple_types = 0;

#define _(p, t) full_tuple_types |= 1ULL << t;
      foreach_ice_rss_full_tuple_ptype;
#undef _
      if (flow->rss_types & ~full_tuple_types)
	return VNET_DEV_ERR_NOT_SUPPORTED;
      for (u32 i = 0; i < ICE_FDIR_PTYPE_COUNT; i++)
	if (pattern.ptypes[i / uword_bits] & ((uword) 1 << (i % uword_bits)))
	  {
	    u64 type = 0;
	    switch (i)
	      {
#define _(p, t)                                                                                    \
  case p:                                                                                          \
    type = 1ULL << t;                                                                              \
    break;
		foreach_ice_rss_full_tuple_ptype;
#undef _
	      default:
		break;
	      }
	    if (!(type & flow->rss_types & ice_rss_flow_types (port)))
	      return VNET_DEV_ERR_NOT_SUPPORTED;
	  }
    }
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ice_flow_config (vlib_main_t *vm, vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  vnet_flow_t *flow = vnet_get_flow (req->flow_index);
  ice_flow_entry_t *entry;
  vnet_dev_rv_t rv = ice_flow_validate (port, req);

  if (rv)
    return rv;
  if (req->type == VNET_DEV_PORT_CFG_ADD_RX_FLOW)
    {
      pool_get_zero (ip->flows, entry);
      entry->flow_index = req->flow_index;
      entry->hw_if_index = vnet_dev_port_get_primary_if (port)->hw_if_index;
      if ((rv = ice_flow_parse (flow, &entry->pattern)))
	goto add_error;
      entry->drop = !!(flow->actions & VNET_FLOW_ACTION_DROP);
      if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
	{
	  entry->queue = flow->redirect_queue;
	  entry->queue_priority = 3;
	}
      if (flow->actions & VNET_FLOW_ACTION_RSS)
	{
	  entry->queue = flow->queue_index;
	  entry->queue_region = min_log2 (flow->queue_num);
	  entry->queue_priority = 3;
	}
      if ((rv = ice_fdir_add (vm, port, entry)))
	goto add_error;
      flow->driver_data.opaque = entry - ip->flows;
      flow->driver_data.hw_if_index = vnet_dev_port_get_primary_if (port)->hw_if_index;
      return VNET_DEV_OK;

    add_error:
      if (!entry->pending)
	pool_put (ip->flows, entry);
      return rv;
    }
  entry = ice_flow_find (port, req->flow_index);
  ASSERT (entry);
  if (req->type == VNET_DEV_PORT_CFG_RESET_RX_FLOW_COUNTER)
    {
      entry->counter_base = ice_fdir_counter_read (port, entry->counter);
      return VNET_DEV_OK;
    }
  if (req->type != VNET_DEV_PORT_CFG_DEL_RX_FLOW)
    return VNET_DEV_ERR_NOT_SUPPORTED;
  if ((rv = ice_fdir_del (vm, port, entry)))
    return rv;
  pool_put (ip->flows, entry);
  flow->driver_data = (vnet_flow_driver_data_t) { .opaque = ~0, .hw_if_index = ~0 };
  return VNET_DEV_OK;
}

void
ice_flow_free (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ice_port_t *ip = vnet_dev_get_port_data (port);
  ice_flow_entry_t *entry;
  pool_foreach (entry, ip->flows)
    {
      vnet_flow_t *flow = vnet_get_flow (entry->flow_index);
      if (flow && entry->installed && flow->driver_data.hw_if_index == entry->hw_if_index &&
	  flow->driver_data.opaque == entry - ip->flows)
	flow->driver_data = (vnet_flow_driver_data_t) { .opaque = ~0, .hw_if_index = ~0 };
      if (entry->installed)
	ice_fdir_del (vm, port, entry);
    }
  ice_fdir_free (vm, port);
  pool_free (ip->flows);
}
