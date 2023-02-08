/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_H_
#define _ENA_H_

#include <vppinfra/types.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/lock.h>

#include <vlib/log.h>
#include <vlib/pci/pci.h>

#include <vnet/interface.h>

#include <vnet/devices/devices.h>
#include <vnet/flow/flow.h>
#include <ena/ena_defs.h>

#define ena_log_err(dev, f, ...)                                              \
  vlib_log (VLIB_LOG_LEVEL_ERR, ena_log.class, "%U: " f,                      \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_log_warn(dev, f, ...)                                             \
  vlib_log (VLIB_LOG_LEVEL_WARNING, ena_log.class, "%U: " f,                  \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_log_info(dev, f, ...)                                             \
  vlib_log (VLIB_LOG_LEVEL_INFO, ena_log.class, "%U: " f,                     \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_log_debug(dev, f, ...)                                            \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ena_log.class, "%U: " f,                    \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define ena_stats_log_debug(dev, f, ...)                                      \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ena_stats_log.class, "%U: " f,              \
	    format_vlib_pci_addr, &dev->pci_addr, ##__VA_ARGS__)

#define foreach_ena_device_flags                                              \
  _ (0, INITIALIZED, "initialized")                                           \
  _ (1, ERROR, "error")                                                       \
  _ (2, ADMIN_UP, "admin-up")                                                 \
  _ (3, VA_DMA, "vaddr-dma")                                                  \
  _ (4, LINK_UP, "link-up")                                                   \
  _ (6, ELOG, "elog")                                                         \
  _ (7, PROMISC, "promisc")                                                   \
  _ (8, RX_INT, "rx-interrupts")                                              \
  _ (9, RX_FLOW_OFFLOAD, "rx-flow-offload")

enum
{
#define _(a, b, c) ENA_DEVICE_F_##b = (1 << a),
  foreach_ena_device_flags
#undef _
};

typedef struct
{
  u64 qword[2];
} ena_tx_desc_t;

STATIC_ASSERT_SIZEOF (ena_tx_desc_t, 16);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *qrx_tail;
  u16 next;
  u16 size;
  u32 *bufs;
  u16 n_enqueued;
  u8 int_mode;
  u8 buffer_pool_index;
  u32 queue_index;
} ena_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile u32 *qtx_tail;
  u16 next;
  u16 size;
  u32 *ph_bufs;
  clib_spinlock_t lock;
  ena_tx_desc_t *descs;
  u32 *bufs;
  u16 n_enqueued;
  u16 *rs_slots;

  ena_tx_desc_t *tmp_descs;
  u32 *tmp_bufs;
  u32 queue_index;
} ena_txq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
  u32 per_interface_next_index;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;
  vlib_pci_dev_handle_t pci_dev_handle;
  vlib_pci_addr_t pci_addr;
  u32 numa_node;
  void *bar0;
  u8 *name;

  /* admin queue */
  ena_aq_entry_t *aq_entries;
  u16 aq_n_entries;
  u16 aq_head;
  u16 aq_tail;
  ena_acq_entry_t *acq_entries;
  u16 acq_n_entries;
  u16 acq_head;

  /* queues */
  ena_rxq_t *rxqs;
  ena_txq_t *txqs;
  u16 n_tx_queues;
  u16 n_rx_queues;

  /* error */
  clib_error_t *error;
} ena_device_t;

#define ENA_RX_VECTOR_SZ VLIB_FRAME_SIZE

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_buffer_t buffer_template;
} ena_per_thread_data_t;

typedef struct
{
  u16 msg_id_base;

  ena_device_t **devices;
  ena_per_thread_data_t *per_thread_data;
} ena_main_t;

extern ena_main_t ena_main;

typedef struct
{
  vlib_pci_addr_t addr;
  u8 *name;
  u16 rxq_num;
  u16 txq_num;
  u16 rxq_size;
  u16 txq_size;
  /* return */
  u32 sw_if_index;
} ena_create_if_args_t;

clib_error_t *ena_create_if (vlib_main_t *vm, ena_create_if_args_t *args);
void ena_delete_if (vlib_main_t *vm, u32 dev_instance);

extern vlib_node_registration_t ena_input_node;
extern vlib_node_registration_t ena_process_node;
extern vnet_device_class_t ena_device_class;

/* format.c */
format_function_t format_ena_device;
format_function_t format_ena_device_name;
format_function_t format_ena_input_trace;
format_function_t format_ena_vf_cap_flags;
format_function_t format_ena_vlan_supported_caps;
format_function_t format_ena_vlan_caps;
format_function_t format_ena_vlan_support;
format_function_t format_ena_eth_stats;
format_function_t format_ena_regs;

static_always_inline ena_device_t *
ena_get_device (u32 dev_instance)
{
  return pool_elt_at_index (ena_main.devices, dev_instance)[0];
}

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
} ena_input_trace_t;

#define foreach_ena_tx_func_error                                             \
  _ (SEGMENT_SIZE_EXCEEDED, "segment size exceeded")                          \
  _ (NO_FREE_SLOTS, "no free tx slots")

typedef enum
{
#define _(f, s) ENA_TX_ERROR_##f,
  foreach_ena_tx_func_error
#undef _
    ENA_TX_N_ERROR,
} ena_tx_func_error_t;

static_always_inline u32
reg_get (void *regs, u32 off, u8 first, u8 n_bits)
{
  u32 v = *(u32u *) (regs + off);
  v >>= first;
  v &= pow2_mask (n_bits);
  return v;
}

#define _(o, f, l, rn, fn)                                                    \
  static_always_inline u32 ena_reg_get_##rn##_f_##fn (ena_device_t *ed)       \
  {                                                                           \
    return reg_get (ed->bar0, o, f, l);                                       \
  }
// foreach_ena_reg_field;
#undef _
#endif /* ENA_H */
