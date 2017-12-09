/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 */

#ifndef included_mlx5_h
#define included_mlx5_h

#include <vlib/pci/pci.h>
#include <mlx5/cmdq.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 cqn;
  u32 sqn;
  volatile u32 *cq_db;
  void *cq_mem;
  volatile u32 *sq_db;
  void *sq_mem;
  u16 slot;
  u8 log_wq_stride;
  u8 log_wq_sz;
  u16 last_wqe_counter;

  u32 *enq;
} mlx5_txq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 cqn;
  u32 rqn;
  volatile u32 *cq_db;
  void *cq_mem;
  volatile u32 *rq_db;
  void *rq_mem;
  u8 log_wq_stride;
  u8 log_wq_sz;
  u16 cq_ci;
  u32 *enq;
  u8 counter_set_id;
} mlx5_rxq_t;

#define foreach_mlx5_device_flags \
  _(0, ADMIN_UP, "admin-up") \
  _(1, ERROR, "error") \
  _(2, ENH_MPSW, "enhanced-mpsw") \
  _(3, IOVA, "iova")

enum
{
#define _(a, b, c) MLX5_DEVICE_F_##b = (1 << a),
  foreach_mlx5_device_flags
#undef _
};

typedef struct
{
  u32 flags;
  /* registers */
  volatile void *hca;

  /* nic resources */
  u32 uar;
  u32 protection_domain;
  u32 transport_domain;
  u32 reserved_lkey;
  u32 tisn;
  u32 tirn;
  u32 rqtn;
  u32 root_rx_flow_table;
  u32 flow_group_id;
  u16 flow_counter_id;

  u8 perm_addr[6];

  /* command qoueue */
  void *cmdq_mem;
  mlx5_cmdq_t *cmdq;

  /* event queue */
  u8 eqn;
  void *eq_physmem;
  u8 log_eq_size;

  /* tx and rx queues */
  mlx5_txq_t *tx_queues;
  mlx5_rxq_t *rx_queues;

  /* Specific next index when using dynamic redirection */
  u32 per_interface_next_index;

  /* PCI bus info. */
  vlib_pci_dev_handle_t pci_dev_handle;

  u16 dev_instance;

  u32 hw_if_index;
  u32 sw_if_index;

  /* device data */
  u16 fw_rev_minor;
  u16 fw_rev_major;
  u16 cmd_interface_rev;
  u16 fw_rev_subminor;

  /* error */
  clib_error_t *error;
} mlx5_device_t;

typedef struct
{
  /* Vector of devices. */
  mlx5_device_t *devices;

  /* logging */
  vlib_log_class_t log_default;
} mlx5_main_t;

enum
{
  MLX5_PROCESS_EVENT_START = 1,
  MLX5_PROCESS_EVENT_STOP = 2,
} mlx5_process_event_t;

extern vnet_device_class_t mlx5_device_class;
extern vlib_node_registration_t mlx5_input_node;
extern mlx5_main_t mlx5_main;

#define mlx5_log_err(dev, f, ...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, mlx5_main.log_default, "%U: " f, \
	   format_vlib_pci_addr, vlib_pci_get_addr(vlib_get_main(), dev->pci_dev_handle), ## __VA_ARGS__)
#define mlx5_log_warn(dev, f, ...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, mlx5_main.log_default, "%U: " f, \
	   format_vlib_pci_addr, vlib_pci_get_addr(vlib_get_main(), dev->pci_dev_handle), ## __VA_ARGS__)
#define mlx5_log_notice(dev, f, ...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, mlx5_main.log_default, "%U: " f, \
	   format_vlib_pci_addr, vlib_pci_get_addr(vlib_get_main(), dev->pci_dev_handle), ## __VA_ARGS__)
#define mlx5_log_info(dev, f, ...) \
  vlib_log(VLIB_LOG_LEVEL_INFO, mlx5_main.log_default, "%U: " f, \
	   format_vlib_pci_addr, vlib_pci_get_addr(vlib_get_main(), dev->pci_dev_handle), ## __VA_ARGS__)
#define mlx5_log_debug(dev, f, ...) \
  vlib_log(VLIB_LOG_LEVEL_DEBUG, mlx5_main.log_default, "%U: " f, \
	   format_vlib_pci_addr, vlib_pci_get_addr(vlib_get_main(), dev->pci_dev_handle), ## __VA_ARGS__)

/* inline functions */

static inline u32
mlx5_get_u32 (void *start, int offset)
{
  return clib_net_to_host_u32 (*(u32 *) (((u8 *) start) + offset));
}

static inline u64
mlx5_get_u64 (void *start, int offset)
{
  return clib_net_to_host_u64 (*(u64 *) (((u8 *) start) + offset));
}

static inline void
mlx5_set_u32 (void *start, int offset, u32 value)
{
  (*(u32 *) (((u8 *) start) + offset)) = clib_host_to_net_u32 (value);
}

static inline void
mlx5_set_u64 (void *start, int offset, u64 value)
{
  (*(u64 *) (((u8 *) start) + offset)) = clib_host_to_net_u64 (value);
}

static inline void
mlx5_set_bits (void *start, int offset, int first, int last, u32 value)
{
  u32 mask = (1 << (first - last + 1)) - 1;
  u32 old = mlx5_get_u32 (start, offset);
  if ((last == 0) && (first == 31))
    {
      mlx5_set_u32 (start, offset, value);
      return;
    }
  ASSERT (value == (value & mask));
  value &= mask;
  old &= ~(mask << last);
  mlx5_set_u32 (start, offset, old | value << last);
}

static inline u32
mlx5_get_bits (void *start, int offset, int first, int last)
{
  u32 value = mlx5_get_u32 (start, offset);
  if ((last == 0) && (first == 31))
    return value;
  value >>= last;
  value &= (1 << (first - last + 1)) - 1;
  return value;
}

static inline mlx5_cmdq_t *
mlx5_get_cmdq (mlx5_device_t * md)
{
  mlx5_cmdq_t *cmdq = 0;
  vec_foreach (cmdq, md->cmdq)
    if (__sync_lock_test_and_set (&cmdq->in_use, 1) == 0)
    return cmdq;

  return 0;
}

static inline void
mlx5_put_cmdq (mlx5_cmdq_t * cmdq)
{
  cmdq->in_use = 0;
}

static inline u64
mlx5_physmem_v2p (mlx5_device_t * md, void *p)
{
  vlib_main_t *vm = vlib_get_main ();
  if (md->flags & MLX5_DEVICE_F_IOVA)
    return pointer_to_uword (p);
  return vlib_physmem_get_pa (vm, p);
}

clib_error_t *mlx5_physmem_alloc (vlib_main_t * vm, mlx5_device_t * md,
				  uword sz, uword al, void **ptr);

typedef struct
{
  vlib_pci_addr_t addr;
  u16 rxq_num;
  u16 rxq_size;
  u16 txq_size;
  /* return */
  int rv;
  u32 sw_if_index;
  clib_error_t *error;
} mlx5_create_if_args_t;

void mlx5_create_if (vlib_main_t * vm, mlx5_create_if_args_t * args);
void mlx5_delete_if (vlib_main_t * vm, mlx5_device_t * ad);

/* Format functions - format.c */
format_function_t format_mlx5_bits;
format_function_t format_mlx5_field;
format_function_t format_mlx5_device_name;
format_function_t format_mlx5_device;
format_function_t format_mlx5_eq_ctx;
format_function_t format_mlx5_cq_ctx;
format_function_t format_mlx5_sq_ctx;
format_function_t format_mlx5_rq_ctx;
format_function_t format_mlx5_wq_ctx;
format_function_t format_mlx5_nic_vport_ctx;
format_function_t format_mlx5_hca_cap_cur_max;
format_function_t format_mlx5_counters;
format_function_t format_mlx5_pddr_module_info;

#include <mlx5/fields.h>
#include <mlx5/cmdq_funcs.h>

#endif /* included_mlx5_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
