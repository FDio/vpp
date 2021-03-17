/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#ifndef _RDMA_H_
#define _RDMA_H_

#include <infiniband/verbs.h>
#include <vlib/log.h>
#include <vlib/pci/pci.h>
#include <vnet/interface.h>
#include <vnet/ethernet/mac_address.h>
#include <rdma/rdma_mlx5dv.h>

#define foreach_rdma_device_flags \
  _(0, ERROR, "error") \
  _(1, ADMIN_UP, "admin-up") \
  _(2, LINK_UP, "link-up") \
  _(3, PROMISC, "promiscuous") \
  _(4, MLX5DV, "mlx5dv") \
  _(5, STRIDING_RQ, "striding-rq")

enum
{
#define _(a, b, c) RDMA_DEVICE_F_##b = (1 << a),
  foreach_rdma_device_flags
#undef _
};

#ifndef MLX5_ETH_L2_INLINE_HEADER_SIZE
#define MLX5_ETH_L2_INLINE_HEADER_SIZE  18
#endif

typedef struct
{
  CLIB_ALIGN_MARK (align0, MLX5_SEND_WQE_BB);
  union
  {
    struct mlx5_wqe_ctrl_seg ctrl;
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
} rdma_mlx5_wqe_t;
#define RDMA_MLX5_WQE_SZ        sizeof(rdma_mlx5_wqe_t)
#define RDMA_MLX5_WQE_DS        (RDMA_MLX5_WQE_SZ/sizeof(struct mlx5_wqe_data_seg))
STATIC_ASSERT (RDMA_MLX5_WQE_SZ == MLX5_SEND_WQE_BB &&
	       RDMA_MLX5_WQE_SZ % sizeof (struct mlx5_wqe_data_seg) == 0,
	       "bad size");

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  struct ibv_cq *cq;
  struct ibv_wq *wq;
  u32 *bufs;
  u32 size;
  u32 head;
  u32 tail;
  u32 cq_ci;
  u16 log2_cq_size;
  u16 n_mini_cqes;
  u16 n_mini_cqes_left;
  u16 last_cqe_flags;
  mlx5dv_cqe_t *cqes;
  mlx5dv_wqe_ds_t *wqes;
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  volatile u32 *wq_db;
  volatile u32 *cq_db;
  u32 cqn;
  u32 wqe_cnt;
  u32 wq_stride;
  u32 buf_sz;
  u32 queue_index;
  union
  {
    struct
    {
      u32 striding_wqe_tail;	/* Striding RQ: number of released whole WQE */
      u8 log_stride_per_wqe;	/* Striding RQ: number of strides in a single WQE */
    };

    struct
    {
      u8 *n_used_per_chain;	/* Legacy RQ: for each buffer chain, how many additional segments are needed */

      u32 *second_bufs;		/* Legacy RQ: ring of second buffers of each chain */
      u32 incomplete_tail;	/* Legacy RQ: tail index in bufs,
				   corresponds to buffer chains with recycled valid head buffer,
				   but whose other buffers are not yet recycled (due to pool exhaustion). */
      u16 n_total_additional_segs;
      u8 n_ds_per_wqe;		/* Legacy RQ: number of nonnull data segs per WQE */
    };
  };
  u8 log_wqe_sz;		/* log-size of a single WQE (in data segments) */
} rdma_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* following fields are accessed in datapath */
  clib_spinlock_t lock;

  union
  {
    struct
    {
      /* ibverb datapath. Cache of cq, sq below */
      struct ibv_cq *ibv_cq;
      struct ibv_qp *ibv_qp;
    };
    struct
    {
      /* direct verbs datapath */
      rdma_mlx5_wqe_t *dv_sq_wqes;
      volatile u32 *dv_sq_dbrec;
      volatile u64 *dv_sq_db;
      struct mlx5_cqe64 *dv_cq_cqes;
      volatile u32 *dv_cq_dbrec;
    };
  };

  u32 *bufs;			/* vlib_buffer ring buffer */
  u16 head;
  u16 tail;
  u16 dv_cq_idx;		/* monotonic CQE index (valid only for direct verbs) */
  u8 bufs_log2sz;		/* log2 vlib_buffer entries */
  u8 dv_sq_log2sz:4;		/* log2 SQ WQE entries (valid only for direct verbs) */
  u8 dv_cq_log2sz:4;		/* log2 CQ CQE entries (valid only for direct verbs) */
    STRUCT_MARK (cacheline1);

  /* WQE template (valid only for direct verbs) */
  u8 dv_wqe_tmpl[64];

  /* end of 2nd 64-bytes cacheline (or 1st 128-bytes cacheline) */
    STRUCT_MARK (cacheline2);

  /* fields below are not accessed in datapath */
  struct ibv_cq *cq;
  struct ibv_qp *qp;

} rdma_txq_t;
STATIC_ASSERT_OFFSET_OF (rdma_txq_t, cacheline1, 64);
STATIC_ASSERT_OFFSET_OF (rdma_txq_t, cacheline2, 128);

#define RDMA_TXQ_DV_INVALID_ID  0xffffffff

#define RDMA_TXQ_BUF_SZ(txq)    (1U << (txq)->bufs_log2sz)
#define RDMA_TXQ_DV_SQ_SZ(txq)  (1U << (txq)->dv_sq_log2sz)
#define RDMA_TXQ_DV_CQ_SZ(txq)  (1U << (txq)->dv_cq_log2sz)

#define RDMA_TXQ_USED_SZ(head, tail)            ((u16)((u16)(tail) - (u16)(head)))
#define RDMA_TXQ_AVAIL_SZ(txq, head, tail)      ((u16)(RDMA_TXQ_BUF_SZ (txq) - RDMA_TXQ_USED_SZ (head, tail)))
#define RDMA_RXQ_MAX_CHAIN_LOG_SZ 3	/* This should NOT be lower than 3! */
#define RDMA_RXQ_MAX_CHAIN_SZ (1U << RDMA_RXQ_MAX_CHAIN_LOG_SZ)
#define RDMA_RXQ_LEGACY_MODE_MAX_CHAIN_SZ 5

typedef enum
{
  RDMA_RSS4_AUTO = 0,
  RDMA_RSS4_IP,
  RDMA_RSS4_IP_UDP,
  RDMA_RSS4_IP_TCP,
} rdma_rss4_t;

typedef enum
{
  RDMA_RSS6_AUTO = 0,
  RDMA_RSS6_IP,
  RDMA_RSS6_IP_UDP,
  RDMA_RSS6_IP_TCP,
} rdma_rss6_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* following fields are accessed in datapath */
  rdma_rxq_t *rxqs;
  rdma_txq_t *txqs;
  u32 flags;
  u32 per_interface_next_index;
  u32 sw_if_index;
  u32 hw_if_index;
  u32 lkey;			/* cache of mr->lkey */
  u8 pool;			/* buffer pool index */

  /* fields below are not accessed in datapath */
  vlib_pci_device_info_t *pci;
  u8 *name;
  u8 *linux_ifname;
  mac_address_t hwaddr;
  u32 async_event_clib_file_index;
  u32 dev_instance;
  rdma_rss4_t rss4;
  rdma_rss6_t rss6;

  struct ibv_context *ctx;
  struct ibv_pd *pd;
  struct ibv_mr *mr;
  struct ibv_qp *rx_qp4;
  struct ibv_qp *rx_qp6;
  struct ibv_rwq_ind_table *rx_rwq_ind_tbl;
  struct ibv_flow *flow_ucast4;
  struct ibv_flow *flow_mcast4;
  struct ibv_flow *flow_ucast6;
  struct ibv_flow *flow_mcast6;

  clib_error_t *error;
} rdma_device_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  union
  {
    u16 cqe_flags[VLIB_FRAME_SIZE];
    u16x8 cqe_flags8[VLIB_FRAME_SIZE / 8];
    u16x16 cqe_flags16[VLIB_FRAME_SIZE / 16];
  };
  union
  {
    struct
    {
      u32 current_segs[VLIB_FRAME_SIZE];
      u32 to_free_buffers[VLIB_FRAME_SIZE];
    };				/* Specific to STRIDING RQ mode */
    struct
    {
      u32 tmp_bi[VLIB_FRAME_SIZE];
      vlib_buffer_t *tmp_bufs[VLIB_FRAME_SIZE];
    };				/* Specific to LEGACY RQ mode */
  };

  vlib_buffer_t buffer_template;
} rdma_per_thread_data_t;

typedef struct
{
  rdma_per_thread_data_t *per_thread_data;
  rdma_device_t *devices;
  vlib_log_class_t log_class;
  u16 msg_id_base;
} rdma_main_t;

extern rdma_main_t rdma_main;

typedef enum
{
  RDMA_MODE_AUTO = 0,
  RDMA_MODE_IBV,
  RDMA_MODE_DV,
} rdma_mode_t;

typedef struct
{
  u8 *ifname;
  u8 *name;
  u32 rxq_size;
  u32 txq_size;
  u32 rxq_num;
  rdma_mode_t mode;
  u8 no_multi_seg;
  u8 disable_striding_rq;
  u16 max_pktlen;
  rdma_rss4_t rss4;
  rdma_rss6_t rss6;

  /* return */
  int rv;
  u32 sw_if_index;
  clib_error_t *error;
} rdma_create_if_args_t;

void rdma_create_if (vlib_main_t * vm, rdma_create_if_args_t * args);
void rdma_delete_if (vlib_main_t * vm, rdma_device_t * rd);

extern vlib_node_registration_t rdma_input_node;
extern vnet_device_class_t rdma_device_class;

format_function_t format_rdma_device;
format_function_t format_rdma_device_name;
format_function_t format_rdma_input_trace;
format_function_t format_rdma_rxq;
unformat_function_t unformat_rdma_create_if_args;

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  u16 cqe_flags;
} rdma_input_trace_t;

#define foreach_rdma_tx_func_error \
_(SEGMENT_SIZE_EXCEEDED, "segment size exceeded") \
_(NO_FREE_SLOTS, "no free tx slots") \
_(SUBMISSION, "tx submission errors") \
_(COMPLETION, "tx completion errors")

typedef enum
{
#define _(f,s) RDMA_TX_ERROR_##f,
  foreach_rdma_tx_func_error
#undef _
    RDMA_TX_N_ERROR,
} rdma_tx_func_error_t;

#endif /* _RDMA_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
