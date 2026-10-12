/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef _QPPE_H_
#define _QPPE_H_

#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/devicetree.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/platform.h>
#include <ppe_hw.h>
#include <edma_hw.h>

#define foreach_qppe_rx_node_counter                                                               \
  _ (BUFFER_ALLOC, buffer_alloc, ERROR, "RX buffer allocation failed")

#define foreach_qppe_tx_node_counter                                                               \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx descriptors")                                \
  _ (BUFFER_CHAIN_TOO_LONG, buffer_chain_too_long, ERROR, "buffer chain too long")

/* maximum number of additional (chained) buffers a scattered RX packet may
 * use beyond its first, bounding how large a multi-buffer frame can be. */
#define QPPE_MAX_RX_CHAIN_LEN 4

/* maximum number of descriptors (buffers) a single TX packet may be spread
 * over; chosen to match EDMA_TX_TSO_SEG_MAX in the vendor driver. */
#define QPPE_MAX_TX_CHAIN_LEN 32

static_always_inline void
qppe_dma_cache_clean (void *addr __clib_unused, int size)
{
  uword start = pointer_to_uword (addr) & ~(CLIB_CACHE_LINE_BYTES - 1);

  for (; size > 0; start += CLIB_CACHE_LINE_BYTES, size -= CLIB_CACHE_LINE_BYTES)
    asm volatile ("dc cvac, %0" : : "r"(start) : "memory");
}

static_always_inline void
qppe_dma_cache_clean_invalidate (void *addr, uword size)
{
  uword start = pointer_to_uword (addr) & ~(CLIB_CACHE_LINE_BYTES - 1);

  for (; size > 0; start += CLIB_CACHE_LINE_BYTES, size -= CLIB_CACHE_LINE_BYTES)
    asm volatile ("dc civac, %0" : : "r"(start) : "memory");
}

typedef enum
{
#define _(f, n, s, d) QPPE_RX_NODE_CTR_##f,
  foreach_qppe_rx_node_counter
#undef _
} qppe_rx_node_counter_t;

typedef enum
{
#define _(f, n, s, d) QPPE_TX_NODE_CTR_##f,
  foreach_qppe_tx_node_counter
#undef _
} qppe_tx_node_counter_t;

typedef struct
{
  /* register region managed by the generic platform resource broker */
  void *regs;
  u8 *dt_path;

  /* device attributes */
  u32 avail_rxfill_ring_bmp;
  u32 avail_rxdesc_ring_bmp;
  u32 avail_txdesc_ring_bmp;
  u32 avail_txcmpl_ring_bmp;
  u32 n_active_rx_queues;
  u32 n_active_tx_queues;
  u8 edma_enabled : 1;
} qppe_device_t;

static_always_inline u32
qppe_mmio_read32 (qppe_device_t *qd, u32 offset)
{
  return __atomic_load_n ((u32 *) ((u8 *) qd->regs + offset), __ATOMIC_ACQUIRE);
}

static_always_inline void
qppe_mmio_write32 (qppe_device_t *qd, u32 offset, u32 value)
{
  __atomic_store_n ((u32 *) ((u8 *) qd->regs + offset), value, __ATOMIC_RELEASE);
}

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
} qppe_port_t;

typedef struct
{
  edma_rxfill_desc_t *fill_descs;
  edma_rx_desc_t *descs;
  edma_rx_sec_desc_t *preheader_descs;
  u32 *buffer_indices;
  u32 n_buffers;
  u8 fill_ring_id;
  u8 desc_ring_id;
  u32 rxfill_prod_offset;
  u32 rxdesc_offset;
  u32 rxdesc_cons_offset;
  u8 ring_ids_allocated : 1;
  u8 started : 1;
  u8 multibuf : 1;
  u16 fill_prod;
  u16 desc_cons;
} qppe_rxq_t;

typedef struct
{
  edma_tx_desc_t *descs;
  edma_tx_sec_desc_t *sec_descs;
  edma_txcmpl_desc_t *cmpl_descs;
  /* every field that doesn't vary packet-to-packet for this queue -
   * service_code, int_pri_valid, destination_type/port_id - prefilled once
   * at configure time; qppe_tx_fill_desc starts from this instead of
   * rebuilding those fields on every packet. */
  edma_tx_desc_t desc_template;
  u32 txdesc_prod_offset;
  u32 txdesc_cons_offset;
  u32 txcmpl_prod_offset;
  u32 txcmpl_cons_offset;
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
} qppe_rx_trace_frag_t;

typedef struct
{
  u32 sw_if_index;
  u16 next_index;
  /* number of additional (chained) fragments beyond head, present for a
   * multi-buffer (scattered) packet. */
  u16 n_tail;
  qppe_rx_trace_frag_t head;
  qppe_rx_trace_frag_t tail[];
} qppe_rx_trace_t;

typedef struct
{
  u32 hw_if_index;
  u32 buffer_index;
  u16 queue_id;
  u16 n_descs;
  edma_tx_desc_t desc;
} qppe_tx_trace_t;

/* format.c */
format_function_t format_qppe_dev_info;
format_function_t format_qppe_port_status;
format_function_t format_qppe_rxq_info;
format_function_t format_qppe_txq_info;
format_function_t format_edma_rx_desc;
format_function_t format_edma_rx_sec_desc;
format_function_t format_qppe_rx_trace;
format_function_t format_edma_tx_desc;
format_function_t format_edma_txcmpl_desc;
format_function_t format_qppe_tx_trace;

/* fdb.c */
vnet_dev_rv_t qppe_fdb_mac_add (vnet_dev_port_t *, const vnet_dev_hw_addr_t *);
vnet_dev_rv_t qppe_fdb_mac_del (vnet_dev_port_t *, const vnet_dev_hw_addr_t *);
format_function_t format_qppe_fdb_table;

/* bm.c */
vnet_dev_rv_t qppe_bm_init (vnet_dev_t *);
vnet_dev_rv_t qppe_bm_port_configure (vnet_dev_t *, u32 bm_port_id, const qppe_bm_port_config_t *);
format_function_t format_qppe_bm_shared_group_cfg;
format_function_t format_qppe_bm_port_fc_cfg;

/* ac.c */
format_function_t format_qppe_ac_grp_cfg;
format_function_t format_qppe_ac_unicast_queue_cfg;
format_function_t format_qppe_ac_multicast_queue_cfg;

/* qm.c */
vnet_dev_rv_t qppe_qm_init (vnet_dev_t *);
format_function_t format_qppe_enq_deq_opr;

/* edma.c */
vnet_dev_rv_t qppe_edma_init (vnet_dev_t *);
format_function_t format_qppe_service_tbl;
format_function_t format_qppe_in_l2_service_tbl;
format_function_t format_qppe_eg_service_tbl;
format_function_t format_qppe_tl_service_tbl;
format_function_t format_qppe_uni_drop_cnt_tbl;
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

/* vsi.c */
vnet_dev_rv_t qppe_vsi_port_configure (vnet_dev_rx_queue_t *);
vnet_dev_rv_t qppe_vsi_set_promisc (vnet_dev_port_t *, u8);
format_function_t format_qppe_rule_and_action_tbl;
format_function_t format_qppe_vsi_tbl;
format_function_t format_qppe_vsi_remap_tbl;
format_function_t format_qppe_port_vsi_enqueue_map;
format_function_t format_qppe_ucast_queue_map_tbl;
format_function_t format_qppe_l2_vp_port_tbl;

/* counters.c */
vnet_dev_rv_t qppe_port_counters_init (vlib_main_t *, vnet_dev_port_t *);
void qppe_port_counters_poll (vlib_main_t *, vnet_dev_port_t *);
void qppe_port_phy_poll (vlib_main_t *, vnet_dev_port_t *);
void qppe_port_apply_link (vlib_main_t *, vnet_dev_port_t *);

/* port.c */
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

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, qppe_log.class, "%U" f, format_vnet_dev_log, (dev),              \
	    clib_string_skip_prefix (__func__, "qppe_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_INFO, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,            \
	    ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,          \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,         \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, qppe_log.class, "%U" f, format_vnet_dev_log, (dev), 0,             \
	    ##__VA_ARGS__)

#endif /* _QPPE_H_ */
