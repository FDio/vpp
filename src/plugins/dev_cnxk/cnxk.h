/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _CNXK_H_
#define _CNXK_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <roc/base/roc_api.h>
#include <dev_cnxk/hw_defs.h>

typedef enum
{
  CNXK_DEVICE_TYPE_UNKNOWN = 0,
  CNXK_DEVICE_TYPE_RVU_PF,
  CNXK_DEVICE_TYPE_CPT_VF,
} __clib_packed cnxk_device_type_t;

typedef struct
{
  cnxk_device_type_t type;
  u8 nix_initialized : 1;
  u8 status : 1;
  u8 full_duplex : 1;
  u32 speed;
  struct plt_pci_device plt_pci_dev;
  struct roc_cpt cpt;
  struct roc_nix *nix;
} cnxk_device_t;

typedef struct
{
  u8 lf_allocated : 1;
  u8 tm_initialized : 1;
  u8 npc_initialized : 1;
  struct roc_npc npc;
} cnxk_port_t;

typedef struct
{
  u8 npa_pool_initialized : 1;
  u8 cq_initialized : 1;
  u8 rq_initialized : 1;
  u16 hdr_off;
  u32 n_enq;
  u64 aura_handle;
  u64 aura_batch_free_ioaddr;
  u64 lmt_base_addr;
  CLIB_CACHE_LINE_ALIGN_MARK (data0);
  struct roc_nix_cq cq;
  struct roc_nix_rq rq;
} cnxk_rxq_t;

typedef struct
{
  CLIB_ALIGN_MARK (cl, 128);
  union
  {
    struct npa_batch_alloc_status_s status;
    u64 iova[16];
  };
} cnxk_npa_batch_alloc_cl128_t;

STATIC_ASSERT_SIZEOF (cnxk_npa_batch_alloc_cl128_t, 128);

typedef struct
{
  u8 sq_initialized : 1;
  u8 npa_pool_initialized : 1;
  u16 hdr_off;
  u32 n_enq;
  u64 aura_handle;
  u64 io_addr;
  void *lmt_addr;

  cnxk_npa_batch_alloc_cl128_t *ba_buffer;
  u8 ba_first_cl;
  u8 ba_num_cl;
  CLIB_CACHE_LINE_ALIGN_MARK (data0);
  struct roc_nix_sq sq;
} cnxk_txq_t;

/* format.c */
format_function_t format_cnxk_port_status;
format_function_t format_cnxk_rx_trace;
format_function_t format_cnxk_tx_trace;

/* port.c */
vnet_dev_rv_t cnxk_port_init (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t cnxk_port_start (vlib_main_t *, vnet_dev_port_t *);
void cnxk_port_stop (vlib_main_t *, vnet_dev_port_t *);
void cnxk_port_deinit (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t cnxk_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				    vnet_dev_port_cfg_change_req_t *);

/* queue.c */
vnet_dev_rv_t cnxk_rx_queue_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t cnxk_tx_queue_alloc (vlib_main_t *, vnet_dev_tx_queue_t *);
void cnxk_rx_queue_free (vlib_main_t *, vnet_dev_rx_queue_t *);
void cnxk_tx_queue_free (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t cnxk_rxq_init (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t cnxk_txq_init (vlib_main_t *, vnet_dev_tx_queue_t *);
void cnxk_rxq_deinit (vlib_main_t *, vnet_dev_rx_queue_t *);
void cnxk_txq_deinit (vlib_main_t *, vnet_dev_tx_queue_t *);
format_function_t format_cnxk_rxq_info;
format_function_t format_cnxk_txq_info;

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, cnxk_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, cnxk_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, cnxk_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, cnxk_log.class, "%U: " f,                 \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, cnxk_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)

#define foreach_cnxk_tx_node_counter                                          \
  _ (CHAIN_TOO_LONG, chain_too_logn, ERROR, "drop due to buffer chain > 3")   \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")                 \
  _ (AURA_BATCH_ALLOC_ISSUE_FAIL, aura_batch_alloc_issue_fail, ERROR,         \
     "aura batch alloc issue failed")                                         \
  _ (AURA_BATCH_ALLOC_NOT_READY, aura_batch_alloc_not_ready, ERROR,           \
     "aura batch alloc not ready")

typedef enum
{
#define _(f, n, s, d) CNXK_TX_NODE_CTR_##f,
  foreach_cnxk_tx_node_counter
#undef _
} cnxk_tx_node_counter_t;

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  cnxk_nix_rx_cqe_desc_t desc;
} cnxk_rx_trace_t;

typedef struct
{
  u32 sw_if_index;
  cnxk_tx_desc_t desc;
} cnxk_tx_trace_t;

#endif /* _CNXK_H_ */
