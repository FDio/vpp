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

#undef always_inline
#include <infiniband/mlx5dv.h>
#define always_inline static_always_inline

#define foreach_rdma_device_flags \
  _(0, ERROR, "error") \
  _(1, ADMIN_UP, "admin-up") \
  _(2, LINK_UP, "link-up") \
  _(3, PROMISC, "promiscuous") \
  _(4, MLX5DV, "mlx5dv")

enum
{
#define _(a, b, c) RDMA_DEVICE_F_##b = (1 << a),
  foreach_rdma_device_flags
#undef _
};


/* CQE flags - bits 16-31 of qword at offset 0x1c */
#define CQE_FLAG_L4_OK			10
#define CQE_FLAG_L3_OK			9
#define CQE_FLAG_L2_OK			8
#define CQE_FLAG_IP_FRAG		7
#define CQE_FLAG_L4_HDR_TYPE(f)		(((f) >> 4) & 7)
#define CQE_FLAG_L4_HDR_TYPE_IP4	1
#define CQE_FLAG_L4_HDR_TYPE_IP6	2
#define CQE_FLAG_L3_HDR_TYPE(f)		(((f) >> 2) & 3)
#define CQE_FLAG_IP_EXT_OPTS		1

typedef struct
{
  struct
  {
    u8 pad1[28];
    u16 flags;
    u8 pad2[14];
    union
    {
      u32 byte_cnt;
      u32 mini_cqe_num;
    };
    u8 pad3[15];
    u8 opcode_cqefmt_se_owner;
  };
} mlx5dv_cqe_t;

STATIC_ASSERT_SIZEOF (mlx5dv_cqe_t, 64);

typedef struct
{
  union
  {
    u32 checksum;
    u32 rx_hash_result;
  };
  u32 byte_count;
} mlx5dv_mini_cqe_t;

typedef struct
{
  u64 dsz_and_lkey;
  u64 addr;
} mlx5dv_rwq_t;

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
  mlx5dv_rwq_t *wqes;
  volatile u32 *wq_db;
  volatile u32 *cq_db;
} rdma_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_spinlock_t lock;
  struct ibv_cq *cq;
  struct ibv_qp *qp;
  u32 *bufs;
  u32 size;
  u32 head;
  u32 tail;
} rdma_txq_t;

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

  struct ibv_context *ctx;
  struct ibv_pd *pd;
  struct ibv_mr *mr;
  struct ibv_qp *rx_qp;
  struct ibv_rwq_ind_table *rx_rwq_ind_tbl;
  struct ibv_flow *flow_ucast;
  struct ibv_flow *flow_mcast;

  clib_error_t *error;
} rdma_device_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
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
format_function_t format_mlx5_cqe_rx;
unformat_function_t unformat_rdma_create_if_args;

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  u16 cqe_flags;
} rdma_input_trace_t;

#define foreach_rdma_tx_func_error	       \
_(NO_FREE_SLOTS, "no free tx slots")

typedef enum
{
#define _(f,s) RDMA_TX_ERROR_##f,
  foreach_rdma_tx_func_error
#undef _
    RDMA_TX_N_ERROR,
} rdma_tx_func_error_t;

#endif /* AVF_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
