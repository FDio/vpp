/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>
#include <errno.h>
#include <infiniband/verbs.h>
#include <common/common.h>

u32
rdma_port_speed (u8 speed)
{
  u32 speeds[] = {
    [1] = 2500000,   [2] = 5000000,   [4] = 10000000,  [8] = 10000000,
    [16] = 14000000, [32] = 25000000, [64] = 50000000, [128] = 100000000,
  };

  if (speed > ARRAY_LEN (speeds))
    return 0;
  return speeds[speed];
}

u16
rdma_port_mtu (u8 mtu)
{
  u16 mtus[] = {
    [1] = 256, [2] = 512, [3] = 1024, [4] = 2048, [5] = 4096,
  };

  if (mtu > ARRAY_LEN (mtus))
    return 0;
  return mtus[mtu];
}

int
rdma_qp_start (struct ibv_qp *qp, u8 ibv_port, rdma_qp_stage_t *failed_stage)
{
  struct ibv_qp_attr qpa = {};
  int rv_ibv;

  if (failed_stage)
    *failed_stage = RDMA_QP_STAGE_NONE;

  if (qp == 0)
    return EINVAL;

  qpa.qp_state = IBV_QPS_RESET;
  rv_ibv = ibv_modify_qp (qp, &qpa, IBV_QP_STATE);
  if (rv_ibv)
    {
      if (failed_stage)
	*failed_stage = RDMA_QP_STAGE_RESET;
      return rv_ibv;
    }

  qpa.qp_state = IBV_QPS_INIT;
  qpa.port_num = ibv_port;
  rv_ibv = ibv_modify_qp (qp, &qpa, IBV_QP_STATE | IBV_QP_PORT);
  if (rv_ibv)
    {
      if (failed_stage)
	*failed_stage = RDMA_QP_STAGE_INIT;
      return rv_ibv;
    }

  qpa.qp_state = IBV_QPS_RTR;
  rv_ibv = ibv_modify_qp (qp, &qpa, IBV_QP_STATE);
  if (rv_ibv)
    {
      if (failed_stage)
	*failed_stage = RDMA_QP_STAGE_RTR;
      return rv_ibv;
    }

  qpa.qp_state = IBV_QPS_RTS;
  rv_ibv = ibv_modify_qp (qp, &qpa, IBV_QP_STATE);
  if (rv_ibv)
    {
      if (failed_stage)
	*failed_stage = RDMA_QP_STAGE_RTS;
      return rv_ibv;
    }

  return 0;
}

int
rdma_qp_stop (struct ibv_qp *qp)
{
  if (qp == 0)
    return EINVAL;

  return ibv_modify_qp (qp,
			&(struct ibv_qp_attr){
			  .qp_state = IBV_QPS_RESET,
			},
			IBV_QP_STATE);
}

void
rdma_port_collect_addrs (vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req,
			 vnet_dev_hw_addr_t **addrs)
{
  vnet_dev_hw_addr_t addr = port->primary_hw_addr;
  vnet_dev_hw_addr_t *a;

  if (req && req->type == VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR)
    addr = req->addr;

  vec_add1 (*addrs, addr);

  pool_foreach (a, port->secondary_hw_addr)
    {
      if (req && req->type == VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR)
	{
	  if (clib_memcmp (a, &req->addr, sizeof (*a)) == 0)
	    continue;
	}
      vec_add1 (*addrs, *a);
    }

  if (req && req->type == VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR)
    vec_add1 (*addrs, req->addr);
}

vnet_dev_rv_t
rdma_port_cfg_rxq_intr_mode_change (vlib_main_t *vm, vnet_dev_port_t *port, u16 qid, u8 enable,
				    u8 all, rdma_rxq_irq_enable_fn_t *rxq_irq_enable,
				    rdma_rxq_irq_disable_fn_t *rxq_irq_disable)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  if (port->started == 0)
    return rv;

  if (all)
    {
      foreach_vnet_dev_port_rx_queue (rxq, port)
	{
	  if (rxq->started == 0)
	    continue;
	  if (enable)
	    rv = rxq_irq_enable (vm, rxq);
	  else
	    rxq_irq_disable (vm, rxq);
	  if (rv != VNET_DEV_OK)
	    return rv;
	}
    }
  else
    {
      vnet_dev_rx_queue_t *rxq = vnet_dev_get_port_rx_queue_by_id (port, qid);
      if (rxq == 0)
	return VNET_DEV_ERR_BUG;
      if (rxq->started == 0)
	return rv;
      if (enable)
	rv = rxq_irq_enable (vm, rxq);
      else
	rxq_irq_disable (vm, rxq);
    }

  return rv;
}
