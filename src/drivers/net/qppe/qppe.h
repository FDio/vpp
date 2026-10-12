/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/devicetree.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>

#define foreach_qppe_rx_node_counter                                                               \
  _ (BUFFER_ALLOC, buffer_alloc, ERROR, "RX buffer allocation failed")

#define foreach_qppe_tx_node_counter                                                               \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx descriptors")                                \
  _ (BUFFER_CHAIN_TOO_LONG, buffer_chain_too_long, ERROR, "buffer chain too long")

#define QPPE_MAX_RX_CHAIN_LEN 4
#define QPPE_MAX_TX_CHAIN_LEN 8

enum
{
#define _(f, n, s, d) QPPE_RX_NODE_CTR_##f,
  foreach_qppe_rx_node_counter
#undef _
};

enum
{
#define _(f, n, s, d) QPPE_TX_NODE_CTR_##f,
  foreach_qppe_tx_node_counter
#undef _
};

typedef struct
{
  u32 off;
  u32 val;
  u32 mask;
} qppe_reg_val_t;

typedef struct __clib_aligned (CLIB_CACHE_LINE_BYTES)
{
  edma_rxfill_desc_t *descs;
  u32 prod_mmio_off;
  u32 cons_mmio_off;
  u16 size;
  u16 prod;
  u16 n_refill;
  u8 n_rx_queues;
  u8 buffer_pool_index;
  u8 ring_id;
  u8 buffers_posted : 1;
} qppe_rxfill_ring_t;

typedef struct
{
  /* register region managed by the generic platform resource broker */
  void *regs;
  u8 *dt_path;

  /* device attributes */
  u32 avail_rx_ring_bmp;
  u32 avail_tx_ring_bmp;
  qppe_rxfill_ring_t rxfill_rings[EDMA_RXFILL_RING_COUNT];
  u8 edma_enabled : 1;
} qppe_device_t;

typedef struct
{
  const char *label;
  const char *phy_mode;
  const char *managed;
  char *clock_node_name;
  clib_dt_property_t *reset_names;
  char *ethernet_phy_node_name;
  char *ethernet_phy_name;
  u32 phy_speed_mbps;
  u8 source_profile;
  u8 is_enabled : 1;
  u8 phy_aneg_started : 1;
  u8 phy_state_valid : 1;
  u8 phy_link_up : 1;
  u8 phy_full_duplex : 1;
  u8 is_xgmac : 1;
  u8 link_configured : 1;

  /* PCS/UNIPHY: register window for this port's PCS channel (mode select,
   * AN/in-band status, link state - see pcs.c), the kdi clock-provider
   * resource that lets this process answer the in-kernel rx/tx MAC clock
   * requests nsscc makes against the owning UNIPHY block, and the UNIPHY's
   * own supply clocks/resets (also siblings of this port's PPE device, not
   * children of it - opened via vnet_dev_platform_open_resource_on_device). */
  void *pcs_regs;
  int pcs_clock_provider_fd;
  int pcs_sys_clk_fd;
  int pcs_ahb_clk_fd;
  int pcs_xpcs_reset_fd;
  int pcs_sys_reset_fd;
  int pcs_soft_reset_fd;
  /* nsscc's gated feedback into this channel's own digital MII/TX-framer
   * logic - distinct from the UNIPHY's raw SerDes clock output that the
   * clock-provider resource above feeds to nsscc. Must be enabled (not
   * just the UNIPHY's own sys/ahb supply) for the TX datapath to actually
   * run; the SerDes PLL can still reach RX block-lock without it. */
  int pcs_mii_rx_clk_fd;
  int pcs_mii_tx_clk_fd;
  u32 pcs_mii_index;
  u8 pcs_mode;
  u8 has_pcs : 1;
  u8 pcs_mode_configured : 1;
  u8 pcs_link_was_up : 1;
} qppe_port_t;

typedef struct
{
  edma_rx_desc_t *descs;
  edma_rx_sec_desc_t *preheader_descs;
  u8 desc_ring_id;
  u8 fill_ring_index;
  u32 rxdesc_prod_mmio_off;
  u32 rxdesc_cons_mmio_off;
  u8 ring_ids_allocated : 1;
  u8 started : 1;
  u8 multibuf : 1;
  u16 desc_cons;
} qppe_rxq_t;

typedef struct
{
  edma_tx_desc_t *descs;
  edma_tx_sec_desc_t *sec_descs;
  edma_txcmpl_desc_t *cmpl_descs;
  edma_tx_desc_t desc_template;
  u32 txdesc_prod_mmio_off;
  u32 txdesc_cons_mmio_off;
  u32 txcmpl_prod_mmio_off;
  u32 txcmpl_cons_mmio_off;
  u32 avail_desc;
  u8 desc_ring_id;
  u8 cmpl_ring_id;
  u8 ring_ids_allocated : 1;
  u8 started : 1;
  u16 prod;
  u16 cmpl_cons;
} qppe_txq_t;

typedef struct
{
  u32 ceil;
  u32 weight;
  u32 resume_offset;
  u32 resume_threshold;
  u32 react_limit;
  u32 pre_alloc;
  u8 dynamic;
  u8 enable;
} qppe_bm_port_config_t;

/* one RX descriptor/preheader pair, as captured for a trace record. */
typedef struct
{
  edma_rx_desc_t desc;
  edma_rx_sec_desc_t sec_desc;
} qppe_rx_trace_descs_t;

typedef struct
{
  u32 sw_if_index;
  u16 next_index;
  u16 n_tail;
  qppe_rx_trace_descs_t head;
  qppe_rx_trace_descs_t tail[];
} qppe_rx_trace_t;

typedef struct
{
  u32 hw_if_index;
  u16 queue_id;
  u16 n_descs;
  edma_tx_desc_t desc;
} qppe_tx_trace_t;

/* Shared formatting data */
typedef struct
{
  const char *field_name;
  u8 n_bits;
} qppe_reg_field_t;

/* fdb.c */
vnet_dev_rv_t qppe_fdb_mac_add (vnet_dev_port_t *, const vnet_dev_hw_addr_t *);
vnet_dev_rv_t qppe_fdb_mac_del (vnet_dev_port_t *, const vnet_dev_hw_addr_t *);

/* acl.c */
vnet_dev_rv_t qppe_acl_init (vnet_dev_t *);
vnet_dev_rv_t qppe_acl_pre_ipo_init (vnet_dev_t *);
vnet_dev_rv_t qppe_acl_pre_ipo_port_configure (vnet_dev_port_t *, const vnet_dev_hw_addr_t *);
vnet_dev_rv_t qppe_acl_pre_ipo_write_row (vnet_dev_t *, u32 row, const vnet_dev_hw_addr_t *,
					  u8 exact_match, u32 pri, u32 fwd_cmd, u32 port_bitmap);
void qppe_acl_pre_ipo_read_row (vnet_dev_t *, u32 row, u32 *port_bitmap, vnet_dev_hw_addr_t *);

/* bm.c */
vnet_dev_rv_t qppe_bm_init (vnet_dev_t *);
vnet_dev_rv_t qppe_bm_port_configure (vnet_dev_t *, u32 bm_port_id, const qppe_bm_port_config_t *);

/* ac.c */

/* init.c */
vnet_dev_rv_t qppe_mmio_write_validate (vnet_dev_t *, const qppe_reg_val_t rv[], int n_rv);

/* qm.c */
vnet_dev_rv_t qppe_qm_port_queue_map_configure (vnet_dev_port_t *, vnet_dev_rss_config_t *);
vnet_dev_rv_t qppe_qm_init (vnet_dev_t *);
vnet_dev_rv_t qppe_qm_ucast_queue_map_set (vnet_dev_t *, u32 vp, u32 queue_id, u8 profile);

/* edma.c */
vnet_dev_rv_t qppe_edma_init (vnet_dev_t *);
vnet_dev_rv_t qppe_edma_rx_ring_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t qppe_edma_rx_ring_configure (vlib_main_t *, vnet_dev_rx_queue_t *);
void qppe_edma_rx_ring_free (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t qppe_edma_rx_ring_start (vlib_main_t *, vnet_dev_rx_queue_t *);
void qppe_edma_rx_ring_stop (vnet_dev_rx_queue_t *);
vnet_dev_rv_t qppe_edma_tx_ring_alloc (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t qppe_edma_tx_ring_configure (vlib_main_t *, vnet_dev_tx_queue_t *);
void qppe_edma_tx_ring_free (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t qppe_edma_tx_ring_start (vlib_main_t *, vnet_dev_tx_queue_t *);
void qppe_edma_tx_ring_stop (vnet_dev_tx_queue_t *);

/* rss.c */
vnet_dev_rv_t qppe_rss_init (vnet_dev_t *);

/* edma_rxfill.c */
vnet_dev_rv_t qppe_edma_rxfill_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
u32 qppe_edma_rxfill_started_queues (vnet_dev_t *, qppe_rxfill_ring_t *);
void qppe_edma_rxfill_free (vlib_main_t *, vnet_dev_t *, qppe_rxfill_ring_t *);
vnet_dev_rv_t qppe_edma_rxfill_configure (vlib_main_t *, vnet_dev_t *, qppe_rxfill_ring_t *);
vnet_dev_rv_t qppe_edma_rxfill_start (vlib_main_t *, vnet_dev_t *, qppe_rxfill_ring_t *);
void qppe_edma_rxfill_stop (vlib_main_t *, vnet_dev_t *, qppe_rxfill_ring_t *);

/* vsi.c */
vnet_dev_rv_t qppe_vsi_port_configure (vnet_dev_rx_queue_t *);

/* counters.c */
vnet_dev_rv_t qppe_port_counters_init (vlib_main_t *, vnet_dev_port_t *);
void qppe_port_counters_poll (vlib_main_t *, vnet_dev_port_t *);

/* mac.c */
vnet_dev_rv_t qppe_mac_set_addr (vnet_dev_port_t *, const vnet_dev_hw_addr_t *);
vnet_dev_rv_t qppe_mac_init (vnet_dev_port_t *);
vnet_dev_rv_t qppe_mac_link_set (vnet_dev_port_t *, u32);

/* sched.c */
vnet_dev_rv_t qppe_sched_init (vnet_dev_t *);

/* pcs.c */
vnet_dev_rv_t qppe_pcs_port_probe (vnet_dev_t *, qppe_port_t *, clib_dt_node_t *port_node);
void qppe_pcs_port_deinit (vnet_dev_port_t *);
vnet_dev_rv_t qppe_pcs_port_start (vlib_main_t *, vnet_dev_port_t *);
void qppe_pcs_poll (vlib_main_t *, vnet_dev_port_t *);

/* port.c */
void qppe_port_phy_poll (vlib_main_t *, vnet_dev_port_t *);
void qppe_port_apply_link (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_port_op_t qppe_port_init;
vnet_dev_port_op_no_rv_t qppe_port_deinit;
vnet_dev_port_op_t qppe_port_start;
vnet_dev_port_op_no_rv_t qppe_port_stop;
vnet_dev_port_cfg_change_op_t qppe_port_cfg_change_validate;
vnet_dev_port_cfg_change_op_t qppe_port_cfg_change;

/* queue.c */
vnet_dev_rx_queue_op_t qppe_rxq_alloc;
vnet_dev_rx_queue_op_no_rv_t qppe_rxq_free;
vnet_dev_tx_queue_op_t qppe_txq_alloc;
vnet_dev_tx_queue_op_no_rv_t qppe_txq_free;

/* ac_format.c */
format_function_t format_qppe_ac_grp_cfg;
format_function_t format_qppe_ac_unicast_queue_cfg;
format_function_t format_qppe_ac_multicast_queue_cfg;
format_function_t format_qppe_ac_mseq;
format_function_t format_qppe_ac_unicast_queue_cnt;
format_function_t format_qppe_ac_multicast_queue_cnt;
format_function_t format_qppe_ac_grp_cnt;
format_function_t format_qppe_ac_unicast_queue_drop_state;
format_function_t format_qppe_ac_multicast_queue_drop_state;
format_function_t format_qppe_ac_grp_drop_state;

/* acl_format.c */
format_function_t format_qppe_acl_ipo_tbl;
format_function_t format_qppe_acl_pre_ipo_tbl;

/* bm_format.c */
format_function_t format_qppe_bm_shared_group_cfg;
format_function_t format_qppe_bm_port_fc_cfg;
format_function_t format_qppe_bm_cfg;
format_function_t format_qppe_bm_total_react_profile;
format_function_t format_qppe_bm_deq_fifo_cfg;
format_function_t format_qppe_bm_port_status;
format_function_t format_qppe_bm_port_profile;
format_function_t format_qppe_bm_group_status;
format_function_t format_qppe_bm_llm;
format_function_t format_qppe_bm_rcm;
format_function_t format_qppe_bm_dm;

/* edma_format.c */
format_function_t format_qppe_edma_info;
format_function_t format_qppe_edma_cfg;
format_function_t format_qppe_edma_status;
format_function_t format_qppe_edma_errors;
format_function_t format_qppe_edma_rxfill_descriptors;
format_function_t format_qppe_edma_rxdesc_rings;
format_function_t format_qppe_edma_rxfill_rings;
format_function_t format_qppe_edma_txdesc_rings;
format_function_t format_qppe_edma_txcmpl_rings;
format_function_t format_qppe_edma_ring_queue_map;
format_function_t format_qppe_edma_qid2rid;
format_function_t format_qppe_edma_rxdesc2fill_map;
format_function_t format_qppe_edma_txdesc2cmpl_map;
format_function_t format_qppe_edma_rxq_info;
format_function_t format_qppe_edma_txq_info;
format_function_t format_qppe_edma_rx_trace;
format_function_t format_qppe_edma_tx_trace;
format_function_t format_qppe_edma_service_tbl;
format_function_t format_qppe_edma_in_l2_service_tbl;
format_function_t format_qppe_edma_eg_service_tbl;
format_function_t format_qppe_edma_tl_service_tbl;

/* fdb_format.c */
format_function_t format_qppe_fdb_cfg;
format_function_t format_qppe_fdb_port_ctrl;
format_function_t format_qppe_fdb_learning_limits;
format_function_t format_qppe_fdb_reserved_table;
format_function_t format_qppe_fdb_table;

/* mac_format.c */
format_function_t format_qppe_mac_cfg;
format_function_t format_qppe_mac_addresses;
format_function_t format_qppe_mac_port_status;

/* port_format.c */
format_function_t format_qppe_port_status;
format_function_t format_qppe_port_cfg;
format_function_t format_qppe_port_my_mac_tbl;
format_function_t format_qppe_port_forward_fifo;
format_function_t format_qppe_port_tdm;
format_function_t format_qppe_port_mru_mtu_ctrl_tbl;
format_function_t format_qppe_port_mc_mtu_ctrl_tbl;

/* rss_format.c */
format_function_t format_qppe_rss_cfg;

/* qm_format.c */
format_function_t format_qppe_qm_cfg;
format_function_t format_qppe_qm_ucast_hash_map;
format_function_t format_qppe_qm_aggregation;
format_function_t format_qppe_qm_unicast_head;
format_function_t format_qppe_qm_multicast_head;
format_function_t format_qppe_qm_unicast_links;
format_function_t format_qppe_qm_multicast_links;
format_function_t format_qppe_qm_packet_descriptors;
format_function_t format_qppe_enq_deq_opr;
format_function_t format_qppe_ucast_queue_map_tbl;
format_function_t format_qppe_ucast_priority_map;
format_function_t format_qppe_mcast_priority_map;
format_function_t format_qppe_mcast_queue_map;

/* format.c */
format_function_t format_qppe_reg_fields;
format_function_t format_qppe_dev_info;
format_function_t format_qppe_port_bitmap;

/* sched_format.c */
format_function_t format_qppe_sched_cfg;
format_function_t format_qppe_sched_tables;
format_function_t format_qppe_sched_memory;

/* vsi_format.c */
format_function_t format_qppe_rule_and_action_tbl;
format_function_t format_qppe_vsi_tbl;
format_function_t format_qppe_vsi_remap_tbl;
format_function_t format_qppe_port_vsi_enqueue_map;
format_function_t format_qppe_l2_vp_port_tbl;
format_function_t format_qppe_vsi_vp_learning;
format_function_t format_qppe_vsi_vp_isolation;
format_function_t format_qppe_vsi_l3_vp_port_tbl;
format_function_t format_qppe_vsi_egress_tags;
format_function_t format_qppe_vsi_counters;

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, qppe_log.class, "%U" f, format_vnet_dev_log, (dev),              \
	    clib_string_skip_prefix (__func__, "qppe_"), ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,          \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,         \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,             \
	    ##__VA_ARGS__)

#include <qppe_funcs.h>
