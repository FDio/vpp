/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_H_
#define _ENA_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/types.h>
#include <dev_ena/ena_defs.h>

#define ENA_ADMIN_QUEUE_LOG2_DEPTH 2
#define ENA_ASYNC_QUEUE_LOG2_DEPTH 5
#define ENA_ADMIN_QUEUE_DEPTH	   (1 << ENA_ADMIN_QUEUE_LOG2_DEPTH)
#define ENA_ASYNC_QUEUE_DEPTH	   (1 << ENA_ASYNC_QUEUE_LOG2_DEPTH)

typedef struct
{
  u8 readless : 1;
  u8 aq_started : 1;
  u8 aenq_started : 1;
  u8 llq : 1;

  void *reg_bar;

  /* mmio */
  ena_mmio_resp_t *mmio_resp;

  /* admin queue */
  struct
  {
    ena_aq_sq_entry_t *sq_entries;
    ena_aq_cq_entry_t *cq_entries;
    u16 sq_next;
    u16 cq_head;
    u16 depth;
  } aq;

  /* host info */
  ena_aq_host_info_t *host_info;

  /* device info */
  ena_aq_feat_device_attr_t dev_attr;

  /* async event notification */
  struct
  {
    ena_aenq_entry_t *entries;
    u16 head;
    u16 depth;
    f64 last_keepalive;
    u64 tx_drops, tx_drops0;
    u64 rx_drops, rx_drops0;
  } aenq;

} ena_device_t;

typedef struct
{
} ena_port_t;

typedef struct
{
  u32 *buffer_indices;
  u16 *compl_sqe_indices;
  ena_rx_desc_t *sqes;
  ena_rx_cdesc_t *cqes;
  u32 *sq_db;
  u32 sq_next;
  u32 cq_next;
  u16 cq_idx;
  u16 sq_idx;
  u16 n_compl_sqes;
  u8 cq_created : 1;
  u8 sq_created : 1;
} ena_rxq_t;

typedef struct
{
  u32 *buffer_indices;
  ena_tx_desc_t *sqes;
  ena_tx_llq_desc128_t *llq_descs;
  ena_tx_cdesc_t *cqes;
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

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
  ena_rx_cdesc_status_t status;
  u16 length;
  u16 n_desc;
  u16 req_id;
} ena_rx_trace_t;

/* admin.c */
typedef struct
{
  char *name;
  u8 version;
  u8 data_sz;
  u8 get;
  u8 set;
} ena_aq_feat_info_t;

ena_aq_feat_info_t *ena_aq_get_feat_info (ena_aq_feature_id_t);
vnet_dev_rv_t ena_aq_olloc (vlib_main_t *, vnet_dev_t *, u16);
vnet_dev_rv_t ena_aq_start (vlib_main_t *, vnet_dev_t *);
void ena_aq_stop (vlib_main_t *, vnet_dev_t *);
void ena_aq_free (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t ena_aq_create_sq (vlib_main_t *, vnet_dev_t *,
				ena_aq_create_sq_cmd_t *,
				ena_aq_create_sq_resp_t *);
vnet_dev_rv_t ena_aq_create_cq (vlib_main_t *, vnet_dev_t *,
				ena_aq_create_cq_cmd_t *,
				ena_aq_create_cq_resp_t *);
vnet_dev_rv_t ena_aq_destroy_sq (vlib_main_t *, vnet_dev_t *,
				 ena_aq_destroy_sq_cmd_t *);
vnet_dev_rv_t ena_aq_destroy_cq (vlib_main_t *, vnet_dev_t *,
				 ena_aq_destroy_cq_cmd_t *);
vnet_dev_rv_t ena_aq_set_feature (vlib_main_t *, vnet_dev_t *,
				  ena_aq_feature_id_t, void *);
vnet_dev_rv_t ena_aq_get_feature (vlib_main_t *, vnet_dev_t *,
				  ena_aq_feature_id_t, void *);
vnet_dev_rv_t ena_aq_get_stats (vlib_main_t *, vnet_dev_t *,
				ena_aq_stats_type_t, ena_aq_stats_scope_t, u16,
				void *);

/* aenq.c */
vnet_dev_rv_t ena_aenq_olloc (vlib_main_t *, vnet_dev_t *, u16);
vnet_dev_rv_t ena_aenq_start (vlib_main_t *, vnet_dev_t *);
void ena_aenq_stop (vlib_main_t *, vnet_dev_t *);
void ena_aenq_free (vlib_main_t *, vnet_dev_t *);

/* reg.c */
void ena_reg_write (vnet_dev_t *, ena_reg_t, void *);
void ena_reg_read (vnet_dev_t *, ena_reg_t, const void *);
void ena_reg_set_dma_addr (vlib_main_t *, vnet_dev_t *, u32, u32, void *);
vnet_dev_rv_t ena_reg_reset (vlib_main_t *, vnet_dev_t *, ena_reset_reason_t);

/* port.c */
vnet_dev_rv_t ena_port_init (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t ena_port_start (vlib_main_t *, vnet_dev_port_t *);
void ena_port_stop (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t ena_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				   vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t ena_port_cfg_change_validate (vlib_main_t *, vnet_dev_port_t *,
					    vnet_dev_port_cfg_change_req_t *);

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
format_function_t format_ena_dev_info;
format_function_t format_ena_mem_addr;
format_function_t format_ena_tx_desc;
format_function_t format_ena_rx_trace;

/* format_admin.c */
format_function_t format_ena_aq_feat_desc;
format_function_t format_ena_aq_feat_name;
format_function_t format_ena_aq_opcode;
format_function_t format_ena_aq_status;
format_function_t format_ena_aq_feat_id_bitmap;
format_function_t format_ena_aq_create_sq_cmd;
format_function_t format_ena_aq_create_cq_cmd;
format_function_t format_ena_aq_create_sq_resp;
format_function_t format_ena_aq_create_cq_resp;
format_function_t format_ena_aq_destroy_sq_cmd;
format_function_t format_ena_aq_destroy_cq_cmd;
format_function_t format_ena_aq_basic_stats;
format_function_t format_ena_aq_eni_stats;

#define foreach_ena_rx_node_counter                                           \
  _ (BUFFER_ALLOC, buffer_alloc, ERROR, "buffer alloc error")

typedef enum
{
#define _(f, lf, t, s) ENA_RX_NODE_CTR_##f,
  foreach_ena_rx_node_counter
#undef _
    ENA_RX_NODE_N_CTRS,
} ena_rx_node_ctr_t;

#define foreach_ena_tx_node_counter                                           \
  _ (CHAIN_TOO_LONG, chain_too_long, ERROR, "buffer chain too long")          \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")

typedef enum
{
#define _(f, lf, t, s) ENA_TX_NODE_CTR_##f,
  foreach_ena_tx_node_counter
#undef _
    ENA_TX_NODE_N_CTRS,
} ena_tx_node_ctr_t;

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ena_log.class, "%U" f, format_vnet_dev_log, \
	    (dev), clib_string_skip_prefix (__func__, "ena_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, ena_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, ena_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, ena_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, ena_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)

#endif /* _ENA_H_ */
