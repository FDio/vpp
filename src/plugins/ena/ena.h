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

#define ENA_ADMIN_QUEUE_LOG2_DEPTH 2
#define ENA_ASYNC_QUEUE_LOG2_DEPTH 5
#define ENA_ADMIN_QUEUE_DEPTH	   (1 << ENA_ADMIN_QUEUE_LOG2_DEPTH)
#define ENA_ASYNC_QUEUE_DEPTH	   (1 << ENA_ASYNC_QUEUE_LOG2_DEPTH)

#define foreach_ena_device_flags                                              \
  _ (initialized)                                                             \
  _ (readless)                                                                \
  _ (va_dma)                                                                  \
  _ (admin_up)                                                                \
  _ (error)                                                                   \
  _ (elog)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  ena_rx_desc_t *sqes;
  ena_rx_cdesc_t *cqes;
  u16 n_desc;
  u32 *bufs;
  u32 queue_index;

  u16 cq_idx;
  u16 sq_idx;
} ena_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  ena_tx_desc_t *sqes;
  ena_tx_cdesc_t *cqes;
  u16 n_desc;
  u32 queue_index;
  clib_spinlock_t lock;

  u16 cq_idx;
  u16 sq_idx;
} ena_txq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define _(a) u32 a : 1;
  foreach_ena_device_flags
#undef _
    u32 per_interface_next_index;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;
  vlib_pci_dev_handle_t pci_dev_handle;
  vlib_pci_addr_t pci_addr;
  u32 numa_node;
  void *bar0;
  u8 *name;

  /* mmio */
  ena_mmio_resp_t *mmio_resp;

  /* admin queue */
  ena_aq_entry_t *aq_entries;
  u32 aq_next;
  ena_acq_entry_t *acq_entries;
  u16 acq_n_entries;
  u16 acq_head;

  /* async event notification */
  ena_aenq_entry_t *aenq_entries;
  u16 aenq_head;

  ena_host_info_t *host_info;
  void *debug_area;

  /* queues */
  ena_rxq_t *rxqs;
  ena_txq_t *txqs;
  u16 n_tx_queues;
  u16 n_rx_queues;

  /* device info */
  u32 supported_feat_id;
  u8 mac_addr[6];

  /* error */
  clib_error_t *err;
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

/* process.c */
typedef enum
{
  ENA_PROCESS_EVENT_UNKNOWN = 0,
  ENA_PROCESS_EVENT_START,
  ENA_PROCESS_EVENT_STOP,
} ena_process_event_t;

/* reg.c */
void ena_reg_write (ena_device_t *ed, ena_reg_t reg, void *v);
void ena_reg_read (ena_device_t *ed, ena_reg_t reg, const void *v);
void ena_set_mmio_resp (vlib_main_t *vm, ena_device_t *ed);

/* admin.c */
clib_error_t *ena_admin_create_sq (vlib_main_t *vm, ena_device_t *ed,
				   ena_aq_create_sq_cmd_t *cmd,
				   ena_aq_create_sq_resp_t *resp);
clib_error_t *ena_admin_create_cq (vlib_main_t *vm, ena_device_t *ed,
				   ena_aq_create_cq_cmd_t *cmd,
				   ena_aq_create_cq_resp_t *resp);
clib_error_t *ena_admin_destroy_sq (vlib_main_t *vm, ena_device_t *ed,
				    ena_aq_destroy_sq_cmd_t *cmd);
clib_error_t *ena_admin_destroy_cq (vlib_main_t *vm, ena_device_t *ed,
				    ena_aq_destroy_cq_cmd_t *cmd);
clib_error_t *ena_admin_set_feature (vlib_main_t *vm, ena_device_t *ed,
				     ena_aq_feature_id_t feat_id, void *data);
clib_error_t *ena_admin_get_feature (vlib_main_t *vm, ena_device_t *ed,
				     ena_aq_feature_id_t feat_id, void *data);

/* format.c */
typedef struct
{
  char *name;
  u8 version;
  u8 data_sz;
} ena_admin_feature_info_t;
extern ena_admin_feature_info_t ena_admin_feature_info[];

format_function_t format_ena_device;
format_function_t format_ena_device_name;
format_function_t format_ena_input_trace;
format_function_t format_ena_vf_cap_flags;
format_function_t format_ena_vlan_supported_caps;
format_function_t format_ena_vlan_caps;
format_function_t format_ena_vlan_support;
format_function_t format_ena_eth_stats;
format_function_t format_ena_regs;
format_function_t format_ena_aq_feat_id_bitmap;
format_function_t format_ena_mem_addr;

#endif /* ENA_H */
