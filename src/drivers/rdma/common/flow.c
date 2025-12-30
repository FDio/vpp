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

u8
rdma_mac_in_addrs (vnet_dev_hw_addr_t *addrs, const u8 *mac)
{
  u32 i;

  vec_foreach_index (i, addrs)
    if (clib_memcmp (addrs[i].eth_mac, mac, 6) == 0)
      return 1;

  return 0;
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
rdma_program_flow_state (struct ibv_qp *qp, rdma_rx_flow_t ***flows,
			 rdma_rx_mac_flow_t **ucast_flows, u32 *promisc_flow_index,
			 u32 *mcast_flow_index, vnet_dev_hw_addr_t *addrs, u8 promisc, u8 ibv_port)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  rdma_rx_mac_flow_t *f;
  u8 zero[6] = {};
  u8 ucast_mask[6] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  };
  u8 mcast[6] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  u8 mcast_mask[6] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  u32 flow_index;
  u32 i;

  if (promisc)
    {
      if (*promisc_flow_index == RDMA_RX_FLOW_INDEX_INVALID)
	{
	  rv = rdma_rxq_add_eth_flow (qp, flows, ibv_port, zero, zero, 0, 0, promisc_flow_index);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}
      if (*mcast_flow_index != RDMA_RX_FLOW_INDEX_INVALID)
	{
	  rdma_rxq_remove_flow_index (flows, *mcast_flow_index);
	  *mcast_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
	}
      vec_foreach_index (i, *ucast_flows)
	rdma_rxq_remove_flow_index (flows, (*ucast_flows)[i].flow_index);
      vec_reset_length (*ucast_flows);
      return rv;
    }

  if (*promisc_flow_index != RDMA_RX_FLOW_INDEX_INVALID)
    {
      rdma_rxq_remove_flow_index (flows, *promisc_flow_index);
      *promisc_flow_index = RDMA_RX_FLOW_INDEX_INVALID;
    }
  for (i = vec_len (*ucast_flows); i > 0; i--)
    {
      f = *ucast_flows + (i - 1);
      if (rdma_mac_in_addrs (addrs, f->mac))
	continue;
      rdma_rxq_remove_flow_index (flows, f->flow_index);
      vec_del1 (*ucast_flows, i - 1);
    }

  vec_foreach_index (i, addrs)
    {
      if (rdma_find_ucast_flow (*ucast_flows, addrs[i].eth_mac) >= 0)
	continue;
      rv = rdma_rxq_add_eth_flow (qp, flows, ibv_port, addrs[i].eth_mac, ucast_mask, 0, 0,
				  &flow_index);
      if (rv != VNET_DEV_OK)
	return rv;
      vec_add2 (*ucast_flows, f, 1);
      clib_memcpy (f->mac, addrs[i].eth_mac, sizeof (f->mac));
      f->flow_index = flow_index;
    }

  if (*mcast_flow_index == RDMA_RX_FLOW_INDEX_INVALID)
    {
      rv = rdma_rxq_add_eth_flow (qp, flows, ibv_port, mcast, mcast_mask, 0, 0, mcast_flow_index);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  return rv;
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
