/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <common/common.h>
#include <vlib/file.h>
#include <errno.h>

static clib_error_t *
rdma_cq_fd_read_ready (clib_file_t *uf)
{
  rdma_rxq_irq_t *ri = uword_to_pointer (uf->private_data, rdma_rxq_irq_t *);
  struct ibv_cq *cq;
  void *cq_ctx;
  vlib_main_t *vm = vlib_get_main_by_index (ri->rxq->rx_thread_index);
  u32 n_events = 0;

  while (ibv_get_cq_event (ri->ibv_comp_ch, &cq, &cq_ctx) == 0)
    {
      ibv_ack_cq_events (cq, 1);
      if (ibv_req_notify_cq (cq, 0))
	break;
      n_events++;
    }

  if (n_events)
    vlib_node_set_interrupt_pending (vm, vnet_dev_get_port_rx_node_index (ri->rxq->port));

  return 0;
}

static clib_error_t *
rdma_cq_fd_error_ready (clib_file_t *uf)
{
  rdma_rxq_irq_t *ri = uword_to_pointer (uf->private_data, rdma_rxq_irq_t *);
  vnet_dev_t __clib_unused *dev = ri->rxq->port->dev;

  return 0;
}

vnet_dev_rv_t
rdma_rxq_irq_enable (vlib_main_t *vm __clib_unused, rdma_rxq_irq_t *ri)
{
  clib_file_t template = {};
  u32 idx;
  int rv_ibv;

  if (ri->cq_file_added)
    return VNET_DEV_OK;

  if (ri->ibv_comp_ch == 0)
    return VNET_DEV_OK;

  rv_ibv = ibv_req_notify_cq (ri->ibv_cq, 0);
  if (rv_ibv)
    return VNET_DEV_ERR_INIT_FAILED;

  template.file_descriptor = ri->ibv_comp_ch->fd;
  template.read_function = rdma_cq_fd_read_ready;
  template.error_function = rdma_cq_fd_error_ready;
  template.private_data = pointer_to_uword (ri);
  template.dont_close = 1;
  template.description = format (0, "%s-rx-cqfd-q%u%c", ri->driver_name, ri->rxq->queue_id, 0);
  idx = clib_file_add (&file_main, &template);
  clib_file_set_polling_thread (&file_main, idx, ri->rxq->rx_thread_index);
  ri->cq_clib_file_index = idx;
  ri->cq_file_added = 1;
  return VNET_DEV_OK;
}

void
rdma_rxq_irq_disable (vlib_main_t *vm __clib_unused, rdma_rxq_irq_t *ri)
{
  if (ri->cq_file_added == 0)
    return;

  clib_file_del_by_index (&file_main, ri->cq_clib_file_index);
  ri->cq_file_added = 0;
  ri->cq_clib_file_index = 0;
}
