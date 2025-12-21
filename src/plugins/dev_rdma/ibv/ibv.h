/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef _DEV_RDMA_IBV_H_
#define _DEV_RDMA_IBV_H_

#include <vnet/dev/dev.h>
#include <infiniband/verbs.h>

#define RDMA_IBV_RX_REFILL_LOG2_BATCH_SZ 5

extern vnet_dev_node_t rdma_ibv_rx_node;
extern vnet_dev_node_t rdma_ibv_tx_node;

typedef struct
{
  struct ibv_recv_wr recv_wr;
  struct ibv_sge sge;
} rdma_ibv_rx_refill_entry_t;

typedef struct
{
  struct ibv_cq *ibv_cq;
  struct ibv_qp *ibv_qp;
  u32 *buffers;
  rdma_ibv_rx_refill_entry_t *refill_entries;
  u32 head;
  u32 tail;
} rdma_ibv_rxq_t;

typedef struct
{
  struct ibv_cq *ibv_cq;
  struct ibv_qp *ibv_qp;
  u32 *buffers;
  u32 head;
  u32 tail;
} rdma_ibv_txq_t;

vnet_dev_rv_t rdma_ibv_add_port (vlib_main_t *vm, vnet_dev_t *dev,
				 vnet_dev_port_id_t port_id);
vnet_dev_rv_t rdma_ibv_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void rdma_ibv_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t rdma_ibv_txq_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
void rdma_ibv_txq_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);

#endif /* _DEV_RDMA_IBV_H_ */
