/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <infiniband/verbs.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/packet.h>
#include <rdma/common.h>
#include <mlx5dv.h>

#ifndef MLX5_ETH_L2_INLINE_HEADER_SIZE
#define MLX5_ETH_L2_INLINE_HEADER_SIZE 18
#endif

#ifndef MLX5_OPCODE_ENHANCED_MPSW
#define MLX5_OPCODE_ENHANCED_MPSW 0x29
#endif

#define MLX5_TX_INLINE_OFF (sizeof (mlx5_wqe_ctrl_seg_t) + 14)

#define MLX5_TX_EMPW_TITLE_DS	 2
#define MLX5_TX_EMPW_MAX_PACKETS 56
#define MLX5_TX_EMPW_MAX_WQE_SZ                                                                    \
  ((MLX5_TX_EMPW_TITLE_DS + MLX5_TX_EMPW_MAX_PACKETS + 3) / 4 * MLX5_SEND_WQE_BB)

STATIC_ASSERT (MLX5_TX_EMPW_TITLE_DS + MLX5_TX_EMPW_MAX_PACKETS <= 63,
	       "eMPW WQE exceeds 6-bit DS count");
STATIC_ASSERT (MLX5_TX_EMPW_MAX_PACKETS % 8 == 0, "eMPW packets per WQE must be a multiple of 8");

typedef union
{
  struct mlx5_wqe_data_seg seg;
  vec128_t vec128;
} mlx5_wqe_data_seg_t;

STATIC_ASSERT_SIZEOF (mlx5_wqe_data_seg_t, 16);

typedef union
{
  struct mlx5_wqe_ctrl_seg seg;
  vec128_t vec128;
} mlx5_wqe_ctrl_seg_t;

STATIC_ASSERT_SIZEOF (mlx5_wqe_ctrl_seg_t, 16);

typedef struct
{
  CLIB_ALIGN_MARK (align0, MLX5_SEND_WQE_BB);
  union
  {
    mlx5_wqe_ctrl_seg_t ctrl;
    struct
    {
      u8 opc_mod;
      u8 wqe_index_hi;
      u8 wqe_index_lo;
      u8 opcode;
    };
  };
  struct mlx5_wqe_eth_seg eseg;
  struct mlx5_wqe_data_seg dseg;
} mlx5_wqe_t;
#define RDMA_MLX5_WQE_SZ      sizeof (mlx5_wqe_t)
#define RDMA_MLX5_LOG2_WQE_DS 2
#define RDMA_MLX5_LOG2_DS_SZ  4
#define RDMA_MLX5_WQE_DS      (1 << RDMA_MLX5_LOG2_WQE_DS)
STATIC_ASSERT (RDMA_MLX5_WQE_SZ == MLX5_SEND_WQE_BB &&
		 RDMA_MLX5_WQE_SZ == RDMA_MLX5_WQE_DS * sizeof (struct mlx5_wqe_data_seg),
	       "bad size");
STATIC_ASSERT (sizeof (struct mlx5_wqe_data_seg) == 1 << RDMA_MLX5_LOG2_DS_SZ, "bad ds size");

#define RDMA_RXQ_MAX_CHAIN_LOG_SZ	  3
#define RDMA_RXQ_MAX_CHAIN_SZ		  (1U << RDMA_RXQ_MAX_CHAIN_LOG_SZ)
#define RDMA_RXQ_LEGACY_MODE_MAX_CHAIN_SZ 5

#define foreach_mlx5_rx_node_counter                                                               \
  _ (BUFFER_ALLOC, buffer_alloc, ERROR, "buffer allocation failed")                                \
  _ (DESC_ERROR, desc_error, ERROR, "receive completion error, queue reset")

typedef enum
{
#define _(f, n, s, d) RDMA_MLX5_RX_NODE_CTR_##f,
  foreach_mlx5_rx_node_counter
#undef _
} mlx5_rx_node_counter_t;

#define foreach_mlx5_tx_node_counter                                                               \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")                                      \
  _ (CHAIN_TOO_LONG, chain_too_long, ERROR, "buffer chain too long")                               \
  _ (CQE_ERROR, cqe_error, ERROR, "tx completion error, queue reset")

typedef enum
{
#define _(f, n, s, d) RDMA_MLX5_TX_NODE_CTR_##f,
  foreach_mlx5_tx_node_counter
#undef _
} mlx5_tx_node_counter_t;

typedef enum
{
  MLX5_RXQ_CTR_DROPS,
} mlx5_rxq_counter_id_t;

extern vnet_dev_node_t mlx5_rx_node_legacy;
extern vnet_dev_node_t mlx5_rx_node_striding;
extern vnet_dev_node_t mlx5_tx_node;

typedef struct
{
  u8 striding_rq_supported : 1;
  u8 striding_rq : 1;
  u8 cqe_res_format_hash : 1;
  u8 cqe_compression : 1;
  u8 counters_query_failed : 1;
  u8 empw_supported : 1;
  rdma_rss_t rss;
  u32 netdev_ifindex;
} mlx5_port_t;

typedef struct
{
  struct mlx5_cqe64 cqe;
  mlx5dv_mini_cqe_t mini_cqe;
  u8 compressed;
} mlx5_rx_cqe_copy_t;

#define MLX5_RX_TRACE_MAX_DS 16

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
  u32 length;
  u32 buffer_flags;
  u32 wqe_index;
  u8 n_ds;
  mlx5_rx_cqe_copy_t cqe;
  mlx5dv_wqe_ds_t ds[];
} mlx5_rx_legacy_trace_t;

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
  u32 length;
  u32 buffer_flags;
  u32 first_stride;
  u8 n_strides;
  u8 log_stride_per_wqe;
  mlx5_rx_cqe_copy_t cqe;
  mlx5dv_wqe_ds_t stride_ds[];
} mlx5_rx_striding_trace_t;

typedef struct
{
  u16 qid;
  u16 wqe_index;
  u8 dropped;
  u8 n_ds;
  u8 empw_pkt;
  u8 empw_n_pkts;
  u32 hw_if_index;
  u32 buffer_index;
  u32 data_len;
  u8 wqe[];
} mlx5_tx_trace_t;

typedef struct
{
  struct ibv_cq *ibv_cq;
  mlx5dv_wqe_ds_t *dv_sq_wqes;
  u32 *dv_sq_dbrec;
  struct mlx5_cqe64 *dv_cq_cqes;
  u32 *dv_cq_dbrec;
  u32 *buffers;
  u32 *second_bufs;
  u16 head;
  u16 tail;
  u32 dv_cq_idx;
  u16 dv_cq_size;
  u8 dv_cq_log2;
  u8 mini_cqe_skip;
  u32 wqe_cnt;
  u32 buf_sz;
  u16 striding_wqe_tail;
  u8 n_ds_per_wqe;
  u8 log_wqe_sz;
  u8 log_stride_per_wqe;
  struct ibv_wq *ibv_wq;
  struct mlx5dv_devx_obj *q_counter_obj;
  u8 q_counter_set_id;
  u8 q_counter_valid : 1;
  u8 q_counter_query_failed : 1;
  u8 rx_error;
  u8 rx_error_syndrome;
  u8 single_buffer;
  u8 striding;
  rdma_rxq_irq_t irq;
} mlx5_rxq_t;

typedef struct
{
  struct ibv_cq *ibv_cq;
  struct ibv_qp *ibv_qp;
  mlx5_wqe_t *dv_sq_wqes;
  u32 *dv_sq_dbrec;
  u64 *dv_sq_db;
  struct mlx5_cqe64 *dv_cq_cqes;
  u32 *dv_cq_dbrec;
  u32 *buffers;
  u32 buf_mask;
  u32 buf_head;
  u32 buf_tail;
  u8 *wqe_n_bb;
  u32 *wqe_buf_tail;
  u16 head;
  u16 tail;
  u32 dv_cq_idx;
  u16 dv_cq_size;
  u8 dv_cq_log2;
  u8 empw;
  mlx5_wqe_ctrl_seg_t tmpl_ctrl;
  mlx5_wqe_ctrl_seg_t tmpl_empw_ctrl;
  struct mlx5_wqe_eth_seg tmpl_eseg;
  u32 lkey_be;
} mlx5_txq_t;

#define MLX5_TX_MAX_SEGS     8
#define MLX5_TX_MAX_GSO_SEGS 48

static_always_inline void
mlx5_txq_free_bufs (vlib_main_t *vm, mlx5_txq_t *tq, u32 tail)
{
  u32 n = tail - tq->buf_head;

  if (n)
    vlib_buffer_free_from_ring (vm, tq->buffers, tq->buf_head & tq->buf_mask, tq->buf_mask + 1, n);
  tq->buf_head = tail;
}

vnet_dev_rv_t mlx5_add_port (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_port_id_t port_id);
vnet_dev_rv_t mlx5_port_start (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t mlx5_port_get_module_eeprom (vlib_main_t *vm, vnet_dev_port_t *port, void *p);
void mlx5_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t mlx5_port_init (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t mlx5_port_init_counters (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_port_op_no_rv_t mlx5_port_counter_poll;
vnet_dev_rv_t mlx5_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void mlx5_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t mlx5_rxq_wq_create (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void mlx5_rxq_wq_destroy (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void mlx5_rxq_cq_sync (vnet_dev_rx_queue_t *rxq);
void mlx5_txq_cq_sync (vnet_dev_tx_queue_t *txq);
void mlx5_txq_recover (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, u8 syndrome);
vnet_dev_rv_t mlx5_rxq_irq_enable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void mlx5_rxq_irq_disable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t mlx5_txq_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
void mlx5_txq_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
format_function_t format_mlx5_tx_trace;
format_function_t format_mlx5_cqe64;
format_function_t format_mlx5_port_status;
format_function_t format_mlx5_rxq_info;
format_function_t format_mlx5_rx_legacy_trace;
format_function_t format_mlx5_rx_striding_trace;
format_function_t format_mlx5_txq_info;
format_function_t format_mlx5_dev_info;
