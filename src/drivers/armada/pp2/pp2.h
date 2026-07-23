/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef _PP2_H_
#define _PP2_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vppinfra/devicetree.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#include <net/if.h>

#include <pp2/pp2_hw.h>

#define MVPP2_NUM_HIFS	       9
#define MVPP2_REGSPACE_SIZE	  0x10000
#define MVPP2_NUM_BPOOLS	  8
#define MVPP2_MAX_THREADS      4
#define MRVL_PP2_BUFF_BATCH_SZ 32
#define MVPP2_LOOPBACK_PORT	  3
#define MVPP2_LOOPBACK_TXQ_ID	  ((MVPP2_MAX_TCONT + MVPP2_LOOPBACK_PORT) * MVPP2_MAX_TXQ)
#define MV_SYS_DMA_MAX_NUM_MEM_ID 4
#define MVPP2_PORT_MAX_RX_QUEUES  4
#define MVPP2_PORT_MAX_TX_QUEUES  4
#define MVPP2_TC_MAX_BPOOLS	  2

typedef struct mvpp2_parser_shadow mvpp2_parser_shadow_t;
typedef u8 eth_addr_t[6];

enum mvpp2_port_hash_type
{
  MVPP2_PORT_HASH_NONE = 0,
  MVPP2_PORT_HASH_2_TUPLE,
  MVPP2_PORT_HASH_5_TUPLE,
  MVPP2_PORT_HASH_OUT_OF_RANGE,
};

enum mvpp2_port_eth_start_hdr
{
  MVPP2_PORT_HDR_ETH = 0,
  MVPP2_PORT_HDR_ETH_DSA,
  MVPP2_PORT_HDR_ETH_EXT_DSA,
  MVPP2_PORT_HDR_ETH_CUSTOM,
  MVPP2_PORT_HDR_OUT_OF_RANGE,
};

typedef struct
{
  u8 id;
  u32 buf_sz;
  uintptr_t virt_base;
  uintptr_t phys_base;
  u8 is_initialized : 1;
} mvpp2_bpool_t;

typedef struct
{
  u64 addr;
  u64 cookie;
} mvpp2_buff_info_t;

#define PP2_HW_PORT_NUM_RXQS 32

typedef struct
{
  u8 up : 1;
  u8 full_duplex : 1;
  u32 speed;
} mvpp2_port_link_info_t;

typedef struct
{
  uintptr_t base;
  unsigned int obj_size;
} mvpp2_mac_unit_desc_t;

typedef struct
{
  u16 next;
  u16 n_enq;
  u32 *buffers;
  mvpp2_tx_desc_t desc_template;
  u32 hw_id;
  u32 desc_total;
  uintptr_t desc_phys_arr;
  mvpp2_tx_desc_t *desc_virt_arr;
  u32 desc_rsrvd;
} mvpp2_txq_t;

typedef struct
{
  u32 id;
  uintptr_t base;

  /* tx descriptor ring */
  u32 n_desc;
  u32 n_free;
  u32 next;
  mvpp2_tx_desc_t *descs;
} mvpp2_hif_t;

typedef struct
{
  mvpp2_tx_desc_t bpool_desc_template;
  u16 n_bpool_refill;
  u32 hw_id;
  u32 desc_received;
  u32 desc_next_idx;
  mvpp2_rx_desc_t *hw_descs;
} mvpp2_rxq_t;

typedef struct
{
  mvpp2_hif_t hif;
} mvpp2_dev_thread_t;

typedef struct
{
  u8 pp_id;
  u8 version;
  u8 lbk_is_initialized : 1;
  u8 classifier_initialized : 1;
  u8 force_bppe_addr : 1;
  u8 bppe_window_set : 1;
  u8 bppe_window_addr;
  u16 free_bpools;
  u16 hif_reserved_map;
  u16 bm_pool_reserved_map;
  uintptr_t pp_base;
  mvpp2_mac_unit_desc_t gop_hw_gmac;
  mvpp2_mac_unit_desc_t gop_hw_xlg_mac;
  uintptr_t gop_hw_mspg;
  uintptr_t cm3_base;
  mvpp2_tx_desc_t *lbk_desc_virt_arr;
  u32 lbk_desc_rsrvd[MVPP2_MAX_THREADS];
  mvpp2_parser_shadow_t *prs_shadow;
  mvpp2_dev_thread_t threads[MVPP2_MAX_THREADS];
} mvpp2_device_t;

typedef struct
{
  u8 addr[6];
} mvpp2_uc_addr_t;

typedef struct
{
  u8 is_enabled : 1;
  u8 rx_pause_en : 1;
  u8 is_xlg : 1;
  u8 has_xlg : 1;
  u8 is_open;
  u8 gop_index;
  u32 id;
  u32 if_index;
  char *phy_mode;
  mvpp2_uc_addr_t *added_uc_addrs;
  u32 num_added_mc_addr;
  u32 saved_rx_isr[PP2_MAX_NUM_USED_INTERRUPTS];
  mvpp2_port_link_info_t last_link_info;
  mvpp2_bpool_t bpool;
} mvpp2_port_t;

#include <pp2/pp2_funcs.h>

/* classifier.c */
vnet_dev_rv_t mvpp2_cls_mng_init (vnet_dev_t *);
void mvpp2_cls_mng_config_default_cos_queue (vnet_dev_port_t *);
vnet_dev_rv_t mvpp2_cls_mng_modify_default_flows (vnet_dev_port_t *);
vnet_dev_rv_t mvpp2_cls_rss_enable (vnet_dev_port_t *, int);
vnet_dev_rv_t mvpp2_cls_rss_is_enabled (vnet_dev_port_t *, int *);
void mvpp2x_cls_oversize_rxq_set (vnet_dev_port_t *);
void mvpp2_cls_c2_hw_read (vnet_dev_t *, int, struct mv_pp2x_cls_c2_entry *);

/* parser.c */
vnet_dev_rv_t mvpp2_parser_init (vnet_dev_t *);
vnet_dev_rv_t mvpp2_port_clear_prs_vlans (vnet_dev_port_t *);
int mvpp2_port_flush_mac_addrs (vnet_dev_port_t *, u32, u32);
int mvpp2_parser_eth_start_header_set (vnet_dev_port_t *, enum mvpp2_port_eth_start_hdr);
vnet_dev_rv_t mvpp2_port_set_mac_addr (vnet_dev_port_t *, const eth_addr_t);
vnet_dev_rv_t mvpp2_port_add_mac_addr (vnet_dev_port_t *, const eth_addr_t);
vnet_dev_rv_t mvpp2_port_remove_mac_addr (vnet_dev_port_t *, const eth_addr_t);
vnet_dev_rv_t mvpp2_port_set_promisc (vnet_dev_port_t *, int);
vnet_dev_rv_t mvpp2_parser_get_filter_counts (vnet_dev_port_t *, u32 *, u32 *);
vnet_dev_rv_t mvpp2_parser_get_promisc (vnet_dev_port_t *, int *);
vnet_dev_rv_t mvpp2_parser_hw_entry_read (vnet_dev_t *, u32, union mv_pp2x_prs_tcam_entry *,
					  union mv_pp2x_prs_sram_entry *);

/* rss.c */
void mvpp2_rss_port_init (vnet_dev_port_t *, enum mvpp2_port_hash_type);

/* bpool.c */
vnet_dev_rv_t mvpp2_bpool_init (vlib_main_t *, vnet_dev_t *, u8, u32, mvpp2_bpool_t *);
void mvpp2_bpool_deinit (vlib_main_t *, vnet_dev_t *, mvpp2_bpool_t *);
vnet_dev_rv_t mvpp2_bpool_get_buff (vlib_main_t *, vnet_dev_t *, mvpp2_bpool_t *,
				    mvpp2_buff_info_t *);
void mvpp2_bm_flush_pools (vnet_dev_t *, u16);
void mvpp2_bpool_assign (vnet_dev_port_t *, u32, u32);

/* loopback.c */
vnet_dev_rv_t mvpp2_loopback_init (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t mvpp2_loopback_deinit (vlib_main_t *, vnet_dev_t *);

/* netdev.c */
vnet_dev_rv_t mvpp2_netdev_ioctl (vnet_dev_t *, u32, struct ifreq *);
vnet_dev_rv_t mvpp2_netdev_set_enable (vnet_dev_port_t *, int);
vnet_dev_rv_t mvpp2_netdev_set_priv_flags (vnet_dev_port_t *, u32);
vnet_dev_rv_t mvpp2_netdev_set_vlan_filtering (vnet_dev_port_t *, int);
vnet_dev_rv_t mvpp2_netdev_clear_vlan (vnet_dev_port_t *, u16);

typedef struct
{
  mvpp2_rx_desc_t desc;
  u32 sw_if_index;
  u16 next_index;
  u16 n_buf_hdrs;
  mvpp2_rx_buf_hdr_t buf_hdrs[];
} mvpp2_rx_trace_t;

typedef struct
{
  u32 sw_if_index;
  u32 buffer_index;
  u16 queue_id;
  u16 n_desc;
  mvpp2_tx_desc_t desc[];
} mvpp2_tx_trace_t;

/* counters.c */
void mvpp2_port_add_counters (vlib_main_t *, vnet_dev_port_t *);
void mvpp2_port_counters_init (vlib_main_t *, vnet_dev_port_t *);
void mvpp2_port_clear_counters (vlib_main_t *, vnet_dev_port_t *);
void mvpp2_rxq_clear_counters (vlib_main_t *, vnet_dev_rx_queue_t *);
void mvpp2_txq_clear_counters (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t mvpp2_port_get_stats (vlib_main_t *, vnet_dev_port_t *);

/* flow_control.c */
void mvpp2_port_clear_fc_isr (vnet_dev_port_t *);
void mvpp2_port_interrupts_disable (vnet_dev_port_t *);
void mvpp2_port_restore_fc_isr (vnet_dev_port_t *);

/* format.c */
format_function_t format_mvpp2_port_link_info;
format_function_t format_mvpp2_port_status;
format_function_t format_mvpp2_dev_info;
format_function_t format_mvpp2_parser_tables;
format_function_t format_mvpp2_classifier_tables;
format_function_t format_mvpp2_rxq_info;
format_function_t format_mvpp2_txq_info;
format_function_t format_mvpp2_rx_trace;
format_function_t format_mvpp2_rx_desc;
format_function_t format_mvpp2_tx_trace;
format_function_t format_mvpp2_tx_desc;

/* gop.c */
void mvpp2_gop_get_link_info (vnet_dev_port_t *, mvpp2_port_link_info_t *);
void mvpp2_gop_max_rx_size_set (vnet_dev_port_t *, u16);

/* hif.c */
vnet_dev_rv_t mvpp2_hif_alloc (vlib_main_t *, vnet_dev_t *, mvpp2_hif_t *, u32);
void mvpp2_hif_free (vlib_main_t *, vnet_dev_t *, u32);

/* port.c */
vnet_dev_port_op_t mvpp2_port_init;
vnet_dev_port_op_no_rv_t mvpp2_port_deinit;
vnet_dev_port_op_t mvpp2_port_start;
vnet_dev_port_op_no_rv_t mvpp2_port_stop;
vnet_dev_rv_t mvpp2_port_set_rx_pause (vnet_dev_port_t *, int);
vnet_dev_rv_t mvpp2_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				     vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t
mvpp2_port_cfg_change_validate (vlib_main_t *, vnet_dev_port_t *,
				vnet_dev_port_cfg_change_req_t *);

/* rx.c */
u32 mrvl_pp2_bpool_put_no_inline (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);

/* rx_queue.c */
vnet_dev_rv_t mvpp2_rxq_init (vlib_main_t *, vnet_dev_rx_queue_t *);
void mvpp2_rxq_deinit (vnet_dev_rx_queue_t *);

/* tx_queue.c */
vnet_dev_tx_queue_op_t mvpp2_txq_alloc;
vnet_dev_tx_queue_op_no_rv_t mvpp2_txq_free;
vnet_dev_rv_t mvpp2_txq_init (vlib_main_t *, vnet_dev_tx_queue_t *);
void mvpp2_port_txq_deinit (vnet_dev_tx_queue_t *);
vnet_dev_rv_t mvpp2_port_set_txq_state (vnet_dev_tx_queue_t *, int);

/* tx_sched.c */
vnet_dev_rv_t mvpp2_tx_sched_config (vnet_dev_port_t *);

/* inline funcs */

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, mvpp2_log.class, "%U" f,                    \
	    format_vnet_dev_log, (dev),                                       \
	    clib_string_skip_prefix (__func__, "mvpp2_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, mvpp2_log.class, "%U" f,                     \
	    format_vnet_dev_log, (dev), 0, ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, mvpp2_log.class, "%U" f,                   \
	    format_vnet_dev_log, (dev), 0, ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, mvpp2_log.class, "%U" f,                  \
	    format_vnet_dev_log, (dev), 0, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, mvpp2_log.class, "%U" f, format_vnet_dev_log, \
	    (dev), 0, ##__VA_ARGS__)

#define foreach_mvpp2_tx_node_counter _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")

typedef enum
{
#define _(f, n, s, d) MVPP2_TX_NODE_CTR_##f,
  foreach_mvpp2_tx_node_counter
#undef _
} mvpp2_tx_node_counter_t;

#define foreach_mvpp2_rx_node_counter _ (BUFFER_ALLOC, buffer_alloc, ERROR, "buffer alloc error")

typedef enum
{
#define _(f, n, s, d) MVPP2_RX_NODE_CTR_##f,
  foreach_mvpp2_rx_node_counter
#undef _
} mvpp2_rx_node_counter_t;


#endif /* _PP2_H_ */
