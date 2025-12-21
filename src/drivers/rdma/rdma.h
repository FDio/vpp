/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <infiniband/verbs.h>

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, rdma_log.class, "%U: " f,                   \
    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, rdma_log.class, "%U: " f,                     \
    format_vnet_dev_addr, (dev), ##__VA_ARGS__)

#define RDMA_IBV_RX_REFILL_LOG2_BATCH_SZ 5
#define RDMA_IBV_RX_REFILL_BATCH_SZ	 (1u << RDMA_IBV_RX_REFILL_LOG2_BATCH_SZ)
#define RDMA_IBV_RXQ_MAX_CHAIN_SZ	 5

extern vnet_dev_node_t rdma_rx_node;
extern vnet_dev_node_t rdma_tx_node;

typedef struct
{
  struct ibv_context *ctx;
  struct ibv_pd *pd;
  u8 rss : 1;
  u32 max_qp;
  u32 max_cq;
  u32 max_qp_wr;
  u32 max_cqe;
  u32 max_sge;
} rdma_dev_t;

typedef struct
{
  struct ibv_recv_wr recv_wr;
  struct ibv_sge sge[RDMA_IBV_RXQ_MAX_CHAIN_SZ];
} rdma_rx_refill_entry_t;

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
  u32 length;
} rdma_rx_trace_t;

typedef struct
{
  struct ibv_cq *ibv_cq;
  struct ibv_qp *ibv_qp;
  struct ibv_flow **flows;
  u32 *buffers;
  u32 *second_bufs;
  u8 *n_used_per_chain;
  u32 buf_sz;
  u32 n_total_additional_segs;
  u8 n_ds_per_wqe;
  rdma_rx_refill_entry_t *refill_entries;
  u32 head;
  u32 tail;
} rdma_rxq_t;

typedef struct
{
  struct ibv_cq *ibv_cq;
  struct ibv_qp *ibv_qp;
  u32 *buffers;
  u32 head;
  u32 tail;
} rdma_txq_t;

u32 rdma_port_speed (u8 speed);
u16 rdma_port_mtu (u8 mtu);

/* init.c */
vnet_dev_rv_t rdma_add_port (
  vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_port_id_t port_id);

/* port.c */
vnet_dev_rv_t rdma_port_start (vlib_main_t *vm, vnet_dev_port_t *port);
void rdma_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t rdma_port_cfg_change_validate (
  vlib_main_t *vm, vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t rdma_port_cfg_change (
  vlib_main_t *vm, vnet_dev_port_t *port, vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t rdma_port_apply_flows (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t rdma_rxq_add_flow (vnet_dev_t *dev, struct ibv_qp *qp,
  struct ibv_flow ***flows, u8 ibv_port, const u8 *mac, const u8 *mask,
  u16 ether_type, u32 flags);
void rdma_rxq_destroy_flows (vnet_dev_t *dev, struct ibv_flow ***flows);

/* queue.c */
vnet_dev_rv_t rdma_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void rdma_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t rdma_txq_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
void rdma_txq_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);

/* format.c */
format_function_t format_rdma_rx_trace;
