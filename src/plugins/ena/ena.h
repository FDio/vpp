/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_H_
#define _ENA_H_

#include <vppinfra/clib.h>
#include <vlib/log.h>
#include <vlib/pci/pci.h>

#include <vnet/interface.h>

#include <vnet/devices/devices.h>
#include <ena/ena_defs.h>

#define ENA_ADMIN_QUEUE_LOG2_DEPTH  2
#define ENA_ASYNC_QUEUE_LOG2_DEPTH  5
#define ENA_ADMIN_QUEUE_DEPTH	    (1 << ENA_ADMIN_QUEUE_LOG2_DEPTH)
#define ENA_ASYNC_QUEUE_DEPTH	    (1 << ENA_ASYNC_QUEUE_LOG2_DEPTH)
#define ENA_DEFAULT_LOG2_RXQ_SIZE   9
#define ENA_DEFAULT_LOG2_TXQ_SIZE   9
#define ENA_MIN_LOG2_RXQ_SIZE	    8
#define ENA_MIN_LOG2_TXQ_SIZE	    8
#define ENA_MAX_LOG2_RXQ_SIZE	    11
#define ENA_MAX_LOG2_TXQ_SIZE	    11
#define ENA_TX_BUFFER_FREE_BATCH_SZ 32
#define ENA_TX_MAX_TAIL_LEN	    5

#define foreach_ena_device_flags                                              \
  _ (initialized)                                                             \
  _ (readless)                                                                \
  _ (va_dma)                                                                  \
  _ (link_up)                                                                 \
  _ (admin_up)                                                                \
  _ (error)

typedef enum
{
  ENA_QUEUE_STATE_DISABLED = 0,
  ENA_QUEUE_STATE_READY = 1,
  ENA_QUEUE_STATE_IN_USE = 2,
} __clib_packed ena_queue_state_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  ena_queue_state_t state;
  u8 cq_created : 1;
  u8 sq_created : 1;
  u8 log2_n_desc;
  u8 buffer_pool_index;
  u8 qid;
  u32 compl_sq_indices_off;
  u16 n_compl_sqes;
  u32 sq_next;
  u32 cq_next;
  u32 *sq_db;
  ena_rx_desc_t *sqes;
  ena_rx_cdesc_t *cqes;
  u32 queue_index;
  u16 cq_idx;
  u16 sq_idx;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u32 sq_buffer_indices[];
} ena_rxq_t;

STATIC_ASSERT_SIZEOF (ena_rxq_t, 1 * CLIB_CACHE_LINE_BYTES);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  ena_queue_state_t state;
  u8 cq_created : 1;
  u8 sq_created : 1;
  u8 log2_n_desc;
  u8 n_pending_free;
  u32 sqe_templates_offset;
  u32 cq_next;
  u32 sq_head;
  u32 sq_tail;
  u32 *sq_db;
  ena_tx_desc_t *sqes;
  ena_tx_cdesc_t *cqes;
  u32 queue_index;
  u16 cq_idx;
  u16 sq_idx;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u32 sq_buffer_indices[];
} ena_txq_t;

STATIC_ASSERT_SIZEOF (ena_txq_t, 1 * CLIB_CACHE_LINE_BYTES);

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
  void *reg_bar;
  u8 *name;

  /* mmio */
  ena_mmio_resp_t *mmio_resp;

  /* admin queue */
  ena_admin_sq_entry_t *admin_sq_entries;
  ena_admin_cq_entry_t *admin_cq_entries;
  u32 admin_sq_next;
  u16 admin_cq_head;

  /* host info */
  ena_admin_host_info_t *host_info;

  /* async event notification */
  ena_aenq_entry_t *aenq_entries;
  u16 aenq_head;

  /* queues */
  ena_rxq_t **rxqs;
  ena_txq_t **txqs;

  /* device info */
  ena_admin_feat_device_attr_t dev_attr;

  /* stats */
  f64 last_keepalive;
  u64 tx_drops, tx_drops0;
  u64 rx_drops, rx_drops0;
  ena_admin_basic_stats_t basic, basic0;
  ena_admin_eni_stats_t eni, eni0;

  /* buffer template */
  vlib_buffer_t buffer_template;
} ena_device_t;

#define ENA_RX_VECTOR_SZ VLIB_FRAME_SIZE

typedef struct
{
  u32 *buffer_indices;
} ena_per_thread_data_t;

typedef struct
{
  u16 msg_id_base;

  ena_device_t **devices;
  ena_per_thread_data_t *per_thread_data;
} ena_main_t;

extern ena_main_t ena_main;

extern vlib_node_registration_t ena_input_node;
extern vlib_node_registration_t ena_process_node;
extern vnet_device_class_t ena_device_class;

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
  ena_rx_cdesc_status_t status;
  u16 length;
  u16 n_desc;
  u16 req_id;
} ena_input_trace_t;

#define foreach_ena_tx_func_error                                             \
  _ (CHAIN_TO_LONG, "buffer chain too long")                                  \
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
  ENA_PROCESS_EVENT_ADMIN_REQ,
  ENA_PROCESS_EVENT_DEVICE_INIT,
} ena_process_event_t;

typedef struct
{
  u32 calling_process_index;
  ena_device_t *ed;
  clib_error_t *err;

  union
  {
    struct
    {
      ena_admin_opcode_t opcode;
      void *sqe_data, *cqe_data;
      u8 sqe_data_sz, cqe_data_sz;
    } admin_req;

    struct
    {
      ena_reset_reason_t reset_reason;
    } device_init;
  };
} ena_process_event_data_t;

/* reg.c */
void ena_reg_write (ena_device_t *ed, ena_reg_t reg, void *v);
void ena_reg_read (ena_device_t *ed, ena_reg_t reg, const void *v);
clib_error_t *ena_reg_reset (vlib_main_t *vm, ena_device_t *ed,
			     ena_reset_reason_t reason);
clib_error_t *ena_reg_init_aq (vlib_main_t *vm, ena_device_t *ed, u16 depth);
clib_error_t *ena_reg_init_aenq (vlib_main_t *vm, ena_device_t *ed, u16 depth);

/* admin.c */
typedef struct
{
  char *name;
  u8 version;
  u8 data_sz;
  u8 get;
  u8 set;
} ena_admin_feat_info_t;

ena_admin_feat_info_t *ena_admin_get_feat_info (ena_admin_feature_id_t id);
clib_error_t *ena_admin_req (vlib_main_t *vm, ena_device_t *ed,
			     ena_admin_opcode_t opcode, void *sqe_data,
			     u8 sqe_data_sz, void *cqe_data, u8 cqe_data_sz);
clib_error_t *ena_admin_create_sq (vlib_main_t *, ena_device_t *,
				   ena_admin_create_sq_cmd_t *,
				   ena_admin_create_sq_resp_t *);
clib_error_t *ena_admin_create_cq (vlib_main_t *, ena_device_t *,
				   ena_admin_create_cq_cmd_t *,
				   ena_admin_create_cq_resp_t *);
clib_error_t *ena_admin_destroy_sq (vlib_main_t *, ena_device_t *,
				    ena_admin_destroy_sq_cmd_t *);
clib_error_t *ena_admin_destroy_cq (vlib_main_t *, ena_device_t *,
				    ena_admin_destroy_cq_cmd_t *);
clib_error_t *ena_admin_set_feature (vlib_main_t *, ena_device_t *,
				     ena_admin_feature_id_t, void *);
clib_error_t *ena_admin_get_feature (vlib_main_t *, ena_device_t *,
				     ena_admin_feature_id_t, void *);
clib_error_t *ena_admin_get_stats (vlib_main_t *, ena_device_t *,
				   ena_admin_stats_type_t,
				   ena_admin_stats_scope_t, u16, void *);

/* queue.c */

clib_error_t *ena_rx_queue_alloc (vlib_main_t *vm, ena_device_t *ed,
				  u16 log2_n_desc, u16 *queue_index);
clib_error_t *ena_tx_queue_alloc (vlib_main_t *vm, ena_device_t *ed,
				  u16 log2_n_desc, u16 *queue_index);
void ena_rx_queue_free (vlib_main_t *vm, ena_device_t *ed, u16 queue_index);
void ena_tx_queue_free (vlib_main_t *vm, ena_device_t *ed, u16 queue_index);
void ena_rx_queue_enable (vlib_main_t *vm, ena_device_t *ed, u16 queue_index);
void ena_tx_queue_enable (vlib_main_t *vm, ena_device_t *ed, u16 queue_index);
void ena_rx_queue_disable (vlib_main_t *vm, ena_device_t *ed, u16 queue_index);
void ena_tx_queue_disable (vlib_main_t *vm, ena_device_t *ed, u16 queue_index);

/* device.c */
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
void ena_device_set_link_state (vlib_main_t *vm, ena_device_t *ed, int state);
clib_error_t *ena_device_init (vlib_main_t *vm, ena_device_t *ed,
			       ena_reset_reason_t reset_reason);
clib_error_t *ena_reset_if (vlib_main_t *vm, u32 dev_instance);

/* format_admin.c */
format_function_t format_ena_admin_feat_desc;
format_function_t format_ena_admin_feat_name;
format_function_t format_ena_admin_opcode;
format_function_t format_ena_admin_status;
format_function_t format_ena_admin_feat_id_bitmap;
format_function_t format_ena_admin_create_sq_cmd;
format_function_t format_ena_admin_create_cq_cmd;
format_function_t format_ena_admin_create_sq_resp;
format_function_t format_ena_admin_create_cq_resp;
format_function_t format_ena_admin_destroy_sq_cmd;
format_function_t format_ena_admin_destroy_cq_cmd;
format_function_t format_ena_admin_basic_stats;
format_function_t format_ena_admin_eni_stats;

/* format.c */
format_function_t format_ena_device;
format_function_t format_ena_device_name;
format_function_t format_ena_input_trace;
format_function_t format_ena_eth_stats;
format_function_t format_ena_regs;
format_function_t format_ena_mem_addr;
format_function_t format_ena_rx_desc_status;
format_function_t format_ena_tx_desc;

#endif /* ENA_H */
