/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_H_
#define _ENA_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_ena/ena_defs.h>

#define ENA_ADMIN_QUEUE_LOG2_DEPTH 2
#define ENA_ASYNC_QUEUE_LOG2_DEPTH 5
#define ENA_ADMIN_QUEUE_DEPTH	   (1 << ENA_ADMIN_QUEUE_LOG2_DEPTH)
#define ENA_ASYNC_QUEUE_DEPTH	   (1 << ENA_ASYNC_QUEUE_LOG2_DEPTH)

typedef struct
{
  u8 readless : 1;
  void *reg_bar;

  /* mmio */
  ena_mmio_resp_t *mmio_resp;

  /* admin queue */
  struct
  {
    ena_admin_sq_entry_t *sq_entries;
    ena_admin_cq_entry_t *cq_entries;
    u16 sq_next;
    u16 cq_head;
    u16 depth;
  } aq;

  /* host info */
  ena_admin_host_info_t *host_info;

  /* device info */
  ena_admin_feat_device_attr_t dev_attr;

  /* async event notification */
  struct
  {
    ena_aenq_entry_t *entries;
    u16 head;
    u16 depth;
  } aenq;
} ena_device_t;

typedef struct
{
  u32 last_status;
} ena_port_t;

typedef struct
{
  u32 *buffer_indices;
  u16 *compl_sqe_indices;
  ena_rx_desc_t *sqes;
  ena_rx_cdesc_t *cqes;
  u32 *sq_db;
  u32 sq_next;
  u16 cq_idx;
  u16 sq_idx;
  u16 n_compl_sqes;
  u8 cq_created : 1;
  u8 sq_created : 1;
} ena_rxq_t;

typedef struct
{
  u32 *buffer_indices;
  ena_rx_desc_t *sqes;
  ena_rx_cdesc_t *cqes;
  u64 *sqe_templates;
  u32 *sq_db;
  u32 sq_tail;
  u32 sq_head;
  u32 cq_next;
  u16 cq_idx;
  u16 sq_idx;
  u8 cq_created : 1;
  u8 sq_created : 1;
  u8 llq : 1;
} ena_txq_t;


/* admin.c */
typedef struct
{
  char *name;
  u8 version;
  u8 data_sz;
  u8 get;
  u8 set;
} ena_admin_feat_info_t;

ena_admin_feat_info_t *ena_admin_get_feat_info (ena_admin_feature_id_t);
vnet_dev_rv_t ena_admin_create_sq (vlib_main_t *, vnet_dev_t *,
				   ena_admin_create_sq_cmd_t *,
				   ena_admin_create_sq_resp_t *);
vnet_dev_rv_t ena_admin_create_cq (vlib_main_t *, vnet_dev_t *,
				   ena_admin_create_cq_cmd_t *,
				   ena_admin_create_cq_resp_t *);
vnet_dev_rv_t ena_admin_destroy_sq (vlib_main_t *, vnet_dev_t *,
				    ena_admin_destroy_sq_cmd_t *);
vnet_dev_rv_t ena_admin_destroy_cq (vlib_main_t *, vnet_dev_t *,
				    ena_admin_destroy_cq_cmd_t *);
vnet_dev_rv_t ena_admin_set_feature (vlib_main_t *, vnet_dev_t *,
				     ena_admin_feature_id_t, void *);
vnet_dev_rv_t ena_admin_get_feature (vlib_main_t *, vnet_dev_t *,
				     ena_admin_feature_id_t, void *);
vnet_dev_rv_t ena_admin_get_stats (vlib_main_t *, vnet_dev_t *,
				   ena_admin_stats_type_t,
				   ena_admin_stats_scope_t, u16, void *);

/* reg.c */
void ena_reg_write (vnet_dev_t *, ena_reg_t, void *);
void ena_reg_read (vnet_dev_t *, ena_reg_t, const void *);
vnet_dev_rv_t ena_reg_reset (vlib_main_t *, vnet_dev_t *, ena_reset_reason_t);
vnet_dev_rv_t ena_reg_aq_olloc (vlib_main_t *, vnet_dev_t *, u16);
vnet_dev_rv_t ena_reg_aq_start (vlib_main_t *, vnet_dev_t *);
void ena_reg_aq_stop (vlib_main_t *, vnet_dev_t *);
void ena_reg_aq_free (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t ena_reg_aenq_olloc (vlib_main_t *, vnet_dev_t *, u16);
vnet_dev_rv_t ena_reg_aenq_start (vlib_main_t *, vnet_dev_t *);
void ena_reg_aenq_stop (vlib_main_t *, vnet_dev_t *);
void ena_reg_aenq_free (vlib_main_t *, vnet_dev_t *);

/* queue.c */
vnet_dev_rv_t ena_rx_queue_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t ena_tx_queue_alloc (vlib_main_t *, vnet_dev_tx_queue_t *);
void ena_rx_queue_free (vlib_main_t *, vnet_dev_rx_queue_t *);
void ena_tx_queue_free (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t ena_rx_queue_start (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t ena_tx_queue_start (vlib_main_t *, vnet_dev_tx_queue_t *);
void ena_rx_queue_stop (vlib_main_t *, vnet_dev_rx_queue_t *);
void ena_tx_queue_stop (vlib_main_t *, vnet_dev_tx_queue_t *);

/* format.c */
format_function_t format_ena_port_status;
format_function_t format_ena_mem_addr;

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

#endif /* _ENA_H_ */
