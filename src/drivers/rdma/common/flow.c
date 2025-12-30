/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <common/common.h>
#include <infiniband/verbs.h>
#include <vppinfra/pool.h>

vnet_dev_rv_t
rdma_rxq_add_eth_flow (struct ibv_qp *qp, rdma_rx_flow_t ***flows, u8 ibv_port, const u8 *mac,
		       const u8 *mask, u16 ether_type, u32 flags, u32 *flow_index)
{
  struct
  {
    struct ibv_flow_attr attr;
    struct ibv_flow_spec_eth spec_eth;
  } __attribute__ ((packed)) cmd;
  rdma_rx_flow_t *f;
  rdma_rx_flow_t **fp;

  f = clib_mem_alloc (offsetof (rdma_rx_flow_t, spec) + sizeof (struct ibv_flow_spec_eth));
  if (f == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;

  f->attr = (struct ibv_flow_attr){
    .num_of_specs = 1,
    .port = ibv_port,
    .flags = flags,
    .size = sizeof (struct ibv_flow_attr) + sizeof (struct ibv_flow_spec_eth),
  };
  f->spec.eth = (struct ibv_flow_spec_eth){
    .type = IBV_FLOW_SPEC_ETH,
    .size = sizeof (struct ibv_flow_spec_eth),
    .val.ether_type = ether_type,
    .mask.ether_type = ether_type ? 0xffff : 0,
  };
  clib_memcpy (f->spec.eth.val.dst_mac, mac, sizeof (f->spec.eth.val.dst_mac));
  clib_memcpy (f->spec.eth.mask.dst_mac, mask, sizeof (f->spec.eth.mask.dst_mac));
  cmd = (typeof (cmd)){
    .attr = f->attr,
    .spec_eth = f->spec.eth,
  };

  f->handle = ibv_create_flow (qp, &cmd.attr);
  if (f->handle == 0)
    {
      clib_mem_free (f);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  pool_get_zero (*flows, fp);
  f->pool_index = fp - *flows;
  *fp = f;
  if (flow_index)
    *flow_index = f->pool_index;
  return VNET_DEV_OK;
}

static u8
rdma_flow_state_add_ucast (struct ibv_qp *qp, rdma_port_flow_state_t *flow_state, u8 ibv_port,
			   const u8 *mac)
{
  rdma_rx_mac_flow_t *f;
  u8 ucast_mask[6] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  };
  u32 flow_index;
  vnet_dev_rv_t rv;

  if (rdma_find_ucast_flow (flow_state->ucast_flows, mac) >= 0)
    return 1;

  rv = rdma_rxq_add_eth_flow (qp, &flow_state->flows, ibv_port, mac, ucast_mask, 0, 0, &flow_index);
  if (rv != VNET_DEV_OK)
    return 0;
  vec_add2 (flow_state->ucast_flows, f, 1);
  clib_memcpy (f->mac, mac, sizeof (f->mac));
  f->flow_index = flow_index;
  return 1;
}

static void
rdma_flow_state_del_ucast (rdma_port_flow_state_t *flow_state, const u8 *mac)
{
  i32 i;

  i = rdma_find_ucast_flow (flow_state->ucast_flows, mac);
  if (i < 0)
    return;

  rdma_rxq_remove_flow_index (&flow_state->flows, flow_state->ucast_flows[i].flow_index);
  vec_del1 (flow_state->ucast_flows, i);
}

static u8
rdma_port_has_mac (vnet_dev_port_t *port, const u8 *mac)
{
  vnet_dev_hw_addr_t *a;

  if (clib_memcmp (port->primary_hw_addr.eth_mac, mac, 6) == 0)
    return 1;

  pool_foreach (a, port->secondary_hw_addr)
    if (clib_memcmp (a->eth_mac, mac, 6) == 0)
      return 1;

  return 0;
}

static vnet_dev_rv_t
rdma_flow_state_ensure_mcast (struct ibv_qp *qp, rdma_port_flow_state_t *flow_state, u8 ibv_port)
{
  rdma_rx_flow_t ***flows = &flow_state->flows;
  u8 mcast[6] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  u8 mcast_mask[6] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  if (flow_state->mcast_flow_index != RDMA_RX_FLOW_INDEX_INVALID)
    return VNET_DEV_OK;

  return rdma_rxq_add_eth_flow (qp, flows, ibv_port, mcast, mcast_mask, 0, 0,
				&flow_state->mcast_flow_index);
}

vnet_dev_rv_t
rdma_flow_state_set_promisc (struct ibv_qp *qp, rdma_port_flow_state_t *flow_state,
			     vnet_dev_port_t *port, u8 ibv_port, u8 enabled)
{
  vnet_dev_hw_addr_t *ha;
  rdma_rx_mac_flow_t *f;
  rdma_rx_flow_t ***flows = &flow_state->flows;
  u8 zero[6] = {};
  u32 i;
  vnet_dev_rv_t rv;

  if (enabled)
    {
      if (flow_state->promisc_flow_index == RDMA_RX_FLOW_INDEX_INVALID)
	{
	  rv = rdma_rxq_add_eth_flow (qp, flows, ibv_port, zero, zero, 0, 0,
				      &flow_state->promisc_flow_index);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}

      if (flow_state->mcast_flow_index != RDMA_RX_FLOW_INDEX_INVALID)
	{
	  rdma_rxq_remove_flow_index (flows, flow_state->mcast_flow_index);
	  flow_state->mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
	}

      vec_foreach_index (i, flow_state->ucast_flows)
	rdma_rxq_remove_flow_index (flows, flow_state->ucast_flows[i].flow_index);
      vec_reset_length (flow_state->ucast_flows);

      return VNET_DEV_OK;
    }

  if (flow_state->promisc_flow_index != RDMA_RX_FLOW_INDEX_INVALID)
    {
      rdma_rxq_remove_flow_index (flows, flow_state->promisc_flow_index);
      flow_state->promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
    }

  for (i = vec_len (flow_state->ucast_flows); i > 0; i--)
    {
      f = flow_state->ucast_flows + (i - 1);
      if (rdma_port_has_mac (port, f->mac))
	continue;
      rdma_rxq_remove_flow_index (flows, f->flow_index);
      vec_del1 (flow_state->ucast_flows, i - 1);
    }

  if (rdma_flow_state_add_ucast (qp, flow_state, ibv_port, port->primary_hw_addr.eth_mac) == 0)
    return VNET_DEV_ERR_INIT_FAILED;
  pool_foreach (ha, port->secondary_hw_addr)
    if (rdma_flow_state_add_ucast (qp, flow_state, ibv_port, ha->eth_mac) == 0)
      return VNET_DEV_ERR_INIT_FAILED;

  return rdma_flow_state_ensure_mcast (qp, flow_state, ibv_port);
}

vnet_dev_rv_t
rdma_flow_state_set_primary_mac (struct ibv_qp *qp, rdma_port_flow_state_t *flow_state,
				 const u8 *old_mac, const u8 *new_mac, u8 ibv_port)
{
  rdma_flow_state_del_ucast (flow_state, old_mac);
  if (rdma_flow_state_add_ucast (qp, flow_state, ibv_port, new_mac) == 0)
    return VNET_DEV_ERR_INIT_FAILED;
  return rdma_flow_state_ensure_mcast (qp, flow_state, ibv_port);
}

vnet_dev_rv_t
rdma_flow_state_add_secondary_mac (struct ibv_qp *qp, rdma_port_flow_state_t *flow_state,
				   const u8 *mac, u8 ibv_port)
{
  if (rdma_flow_state_add_ucast (qp, flow_state, ibv_port, mac) == 0)
    return VNET_DEV_ERR_INIT_FAILED;
  return rdma_flow_state_ensure_mcast (qp, flow_state, ibv_port);
}

vnet_dev_rv_t
rdma_flow_state_del_secondary_mac (struct ibv_qp *qp, rdma_port_flow_state_t *flow_state,
				   const u8 *mac, u8 ibv_port)
{
  rdma_flow_state_del_ucast (flow_state, mac);
  return rdma_flow_state_ensure_mcast (qp, flow_state, ibv_port);
}

i32
rdma_find_ucast_flow (rdma_rx_mac_flow_t *ucast_flows, const u8 *mac)
{
  u32 i;

  vec_foreach_index (i, ucast_flows)
    if (clib_memcmp (ucast_flows[i].mac, mac, 6) == 0)
      return i;

  return -1;
}

vnet_dev_rv_t
rdma_program_flow_state (struct ibv_qp *qp, rdma_port_flow_state_t *flow_state,
			 vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req, u8 promisc,
			 u8 ibv_port)
{
  if (promisc)
    return rdma_flow_state_set_promisc (qp, flow_state, port, ibv_port, 1);

  if (req == 0 || req->type == VNET_DEV_PORT_CFG_PROMISC_MODE)
    return rdma_flow_state_set_promisc (qp, flow_state, port, ibv_port, 0);
  else if (req->type == VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR)
    return rdma_flow_state_set_primary_mac (qp, flow_state, port->primary_hw_addr.eth_mac,
					    req->addr.eth_mac, ibv_port);
  else if (req->type == VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR)
    return rdma_flow_state_add_secondary_mac (qp, flow_state, req->addr.eth_mac, ibv_port);
  else if (req->type == VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR)
    return rdma_flow_state_del_secondary_mac (qp, flow_state, req->addr.eth_mac, ibv_port);

  return rdma_flow_state_ensure_mcast (qp, flow_state, ibv_port);
}

void
rdma_rxq_remove_flow_index (rdma_rx_flow_t ***flows, u32 idx)
{
  rdma_rx_flow_t **fp;
  rdma_rx_flow_t *f;

  if (*flows == 0 || pool_is_free_index (*flows, idx))
    return;

  fp = pool_elt_at_index (*flows, idx);
  f = fp[0];
  if (f == 0)
    return;
  if (f->handle)
    ibv_destroy_flow (f->handle);
  clib_mem_free (f);
  pool_put_index (*flows, idx);
}

void
rdma_rxq_destroy_flows (rdma_rx_flow_t ***flows)
{
  u32 i;

  if (*flows == 0)
    return;

  pool_foreach_index (i, *flows)
    {
      rdma_rx_flow_t **fp = pool_elt_at_index (*flows, i);
      rdma_rx_flow_t *f = fp[0];

      if (f == 0)
	continue;
      if (f->handle)
	ibv_destroy_flow (f->handle);
      clib_mem_free (f);
    }

  pool_free (*flows);
  *flows = 0;
}
