
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */
#ifndef _OCTEON_H_
#define _OCTEON_H_
#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/flow/flow.h>
#include <vnet/udp/udp.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ip/igmp_packet.h>
#include <vnet/gre/packet.h>
#include <vxlan/vxlan.h>
#include <base/roc_api.h>
#include <dev_octeon/hw_defs.h>

#define OCT_BATCH_ALLOC_IOVA0_MASK 0xFFFFFFFFFFFFFF80

typedef enum
{
  OCT_DEV_ARG_CRYPTO_N_DESC = 1,
  OCT_DEV_ARG_END,
} oct_dev_args_t;

typedef enum
{
  OCT_DEVICE_TYPE_UNKNOWN = 0,
  OCT_DEVICE_TYPE_RVU_PF,
  OCT_DEVICE_TYPE_RVU_VF,
  OCT_DEVICE_TYPE_LBK_VF,
  OCT_DEVICE_TYPE_SDP_VF,
  OCT_DEVICE_TYPE_O10K_CPT_VF,
  OCT_DEVICE_TYPE_O9K_CPT_VF,
} __clib_packed oct_device_type_t;

typedef struct
{
  oct_device_type_t type;
  u8 nix_initialized : 1;
  u8 status : 1;
  u8 full_duplex : 1;
  u32 speed;
  struct plt_pci_device plt_pci_dev;
  struct roc_nix *nix;
} oct_device_t;

typedef struct
{
  /* vnet flow index */
  u32 vnet_flow_index;

  u32 index;
  /* Internal flow object */
  struct roc_npc_flow *npc_flow;
} oct_flow_entry_t;

typedef struct
{
  u8 lf_allocated : 1;
  u8 tm_initialized : 1;
  u8 npc_initialized : 1;
  struct roc_npc npc;
  oct_flow_entry_t *flow_entries;
} oct_port_t;

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
} oct_rxq_t;

typedef struct
{
  CLIB_ALIGN_MARK (cl, 128);
  u64 iova[16];
} oct_npa_batch_alloc_cl128_t;

typedef union
{
  struct npa_batch_alloc_status_s status;
  u64 as_u64;
} oct_npa_batch_alloc_status_t;

STATIC_ASSERT_SIZEOF (oct_npa_batch_alloc_cl128_t, 128);

typedef struct
{
  u8 sq_initialized : 1;
  u8 npa_pool_initialized : 1;
  u16 hdr_off;
  u32 n_enq;
  u64 aura_handle;
  u64 io_addr;
  void *lmt_addr;
  oct_npa_batch_alloc_cl128_t *ba_buffer;
  u8 ba_first_cl;
  u8 ba_num_cl;
  CLIB_CACHE_LINE_ALIGN_MARK (data0);
  struct roc_nix_sq sq;
} oct_txq_t;

/* format.c */
format_function_t format_oct_port_status;
format_function_t format_oct_rx_trace;
format_function_t format_oct_tx_trace;
format_function_t format_oct_port_flow;

/* port.c */
vnet_dev_rv_t oct_port_init (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t oct_port_start (vlib_main_t *, vnet_dev_port_t *);
void oct_port_stop (vlib_main_t *, vnet_dev_port_t *);
void oct_port_deinit (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t oct_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				   vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t oct_port_cfg_change_validate (vlib_main_t *, vnet_dev_port_t *,
					    vnet_dev_port_cfg_change_req_t *);

/* queue.c */
vnet_dev_rv_t oct_rx_queue_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t oct_tx_queue_alloc (vlib_main_t *, vnet_dev_tx_queue_t *);
void oct_rx_queue_free (vlib_main_t *, vnet_dev_rx_queue_t *);
void oct_tx_queue_free (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t oct_rxq_init (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t oct_txq_init (vlib_main_t *, vnet_dev_tx_queue_t *);
void oct_rxq_deinit (vlib_main_t *, vnet_dev_rx_queue_t *);
int oct_drain_queue (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void oct_txq_deinit (vlib_main_t *, vnet_dev_tx_queue_t *);
format_function_t format_oct_rxq_info;
format_function_t format_oct_txq_info;

/* flow.c */
vnet_dev_rv_t oct_flow_ops_fn (vlib_main_t *, vnet_dev_port_t *,
			       vnet_dev_port_cfg_type_t, u32, uword *);
vnet_dev_rv_t oct_flow_validate_params (vlib_main_t *, vnet_dev_port_t *,
					vnet_dev_port_cfg_type_t, u32,
					uword *);
vnet_dev_rv_t oct_flow_query (vlib_main_t *, vnet_dev_port_t *, u32, uword,
			      u64 *);

/* counter.c */
void oct_port_add_counters (vlib_main_t *, vnet_dev_port_t *);
void oct_port_clear_counters (vlib_main_t *, vnet_dev_port_t *);
void oct_rxq_clear_counters (vlib_main_t *, vnet_dev_rx_queue_t *);
void oct_txq_clear_counters (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t oct_port_get_stats (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t oct_rxq_get_stats (vlib_main_t *, vnet_dev_port_t *,
				 vnet_dev_rx_queue_t *);
vnet_dev_rv_t oct_txq_get_stats (vlib_main_t *, vnet_dev_port_t *,
				 vnet_dev_tx_queue_t *);

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, oct_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, oct_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, oct_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, oct_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, oct_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)

#define foreach_oct_tx_node_counter                                           \
  _ (CHAIN_TOO_LONG, chain_too_long, ERROR, "drop due to buffer chain > 6")   \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")                 \
  _ (AURA_BATCH_ALLOC_ISSUE_FAIL, aura_batch_alloc_issue_fail, ERROR,         \
     "aura batch alloc issue failed")                                         \
  _ (AURA_BATCH_ALLOC_NOT_READY, aura_batch_alloc_not_ready, ERROR,           \
     "aura batch alloc not ready")                                            \
  _ (MTU_EXCEEDED, mtu_exceeded, ERROR, "mtu exceeded")

typedef enum
{
#define _(f, n, s, d) OCT_TX_NODE_CTR_##f,
  foreach_oct_tx_node_counter
#undef _
} oct_tx_node_counter_t;

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  oct_nix_rx_cqe_desc_t desc;
} oct_rx_trace_t;

typedef struct
{
  u32 sw_if_index;
  oct_tx_desc_t desc;
} oct_tx_trace_t;
#endif /* _OCTEON_H_ */
