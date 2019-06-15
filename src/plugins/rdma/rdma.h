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

#define foreach_rdma_device_flags \
  _(0, INITIALIZED, "initialized") \
  _(1, ERROR, "error") \
  _(2, ADMIN_UP, "admin-up") \
  _(3, VA_DMA, "vaddr-dma") \
  _(4, LINK_UP, "link-up") \
  _(5, SHARED_TXQ_LOCK, "shared-txq-lock") \
  _(6, ELOG, "elog") \

enum
{
#define _(a, b, c) RDMA_DEVICE_F_##b = (1 << a),
  foreach_rdma_device_flags
#undef _
};

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 size;
  u32 n_enq;
  struct ibv_cq *cq;
  struct ibv_wq *wq;
} rdma_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 size;
  u32 n_enq;
  struct ibv_cq *cq;
  struct ibv_qp *qp;
  clib_spinlock_t lock;
} rdma_txq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
  u32 per_interface_next_index;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;

  u32 async_event_clib_file_index;

  rdma_rxq_t *rxqs;
  rdma_txq_t *txqs;

  u8 *name;
  mac_address_t hwaddr;
  vlib_pci_addr_t pci_addr;

  struct ibv_context *ctx;
  struct ibv_pd *pd;
  struct ibv_mr *mr;
  struct ibv_qp *rx_qp;
  struct ibv_rwq_ind_table *rx_rwq_ind_tbl;
  struct ibv_flow *flow_ucast;
  struct ibv_flow *flow_mcast;

  /* error */
  clib_error_t *error;
} rdma_device_t;

typedef struct
{
  rdma_device_t *devices;
  vlib_log_class_t log_class;
} rdma_main_t;

extern rdma_main_t rdma_main;

typedef struct
{
  u8 *ifname;
  u8 *name;
  u32 rxq_size;
  u32 txq_size;
  u32 rxq_num;

  /* return */
  int rv;
  u32 sw_if_index;
  clib_error_t *error;
} rdma_create_if_args_t;

void rdma_create_if (vlib_main_t * vm, rdma_create_if_args_t * args);
void rdma_delete_if (vlib_main_t * vm, rdma_device_t * rd);

extern vlib_node_registration_t rdma_input_node;
extern vnet_device_class_t rdma_device_class;

/* format.c */
format_function_t format_rdma_device;
format_function_t format_rdma_device_name;
format_function_t format_rdma_input_trace;

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
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
