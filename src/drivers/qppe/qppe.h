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

#define foreach_qppe_rx_node_counter                                                               \
  _ (BUFFER_ALLOC, buffer_alloc, ERROR, "RX buffer allocation failed")

typedef enum
{
#define _(f, n, s, d) QPPE_RX_NODE_CTR_##f,
  foreach_qppe_rx_node_counter
#undef _
} qppe_rx_node_counter_t;

typedef struct
{
  /* register region managed by the generic platform resource broker */
  void *regs;
  ppe_hw_device_state_t hw_state;
  u8 *dt_path;
  vnet_dev_platform_clock_t *clocks;
  vnet_dev_platform_reset_t *resets;
  vnet_dev_platform_interconnect_t *interconnects;
  vnet_dev_platform_phy_t *phys;
  int *ethernet_phy_fds;

  /* device attributes */
  u32 n_ports;
  u32 avail_rxfill_ring_bmp;
  u32 avail_rxdesc_ring_bmp;
  u32 n_active_rx_queues;
  u8 hw_initialized : 1;
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
  ppe_hw_port_state_t hw_state;
  const char *label;
  const char *phy_mode;
  const char *managed;
  int ethernet_phy_fd;
  int rx_clock_fd;
  int tx_clock_fd;
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
  ppe_edma_rxfill_desc_t *fill_descs;
  ppe_edma_rx_desc_t *descs;
  ppe_edma_rx_sec_desc_t *preheader_descs;
  u32 *buffer_indices;
  u32 n_buffers;
  u8 fill_ring_id;
  u8 desc_ring_id;
  u32 rxfill_prod_offset;
  u32 rxdesc_offset;
  u32 rxdesc_cons_offset;
  u8 ring_ids_allocated : 1;
  u8 started : 1;
  u16 fill_prod;
  u16 desc_cons;
} qppe_rxq_t;

typedef struct
{
  u32 *buffers;
} qppe_txq_t;

/* format.c */
format_function_t format_qppe_dev_info;
format_function_t format_qppe_port_status;
format_function_t format_qppe_rxq_info;
format_function_t format_ppe_edma_rx_metadata;
format_function_t format_ppe_edma_rx_desc;
format_function_t format_ppe_edma_rx_sec_desc;

/* hw.c */
vnet_dev_rv_t qppe_hw_init (vnet_dev_t *);

/* edma.c */
vnet_dev_rv_t qppe_edma_rx_ring_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t qppe_edma_rx_ring_configure (vlib_main_t *, vnet_dev_rx_queue_t *);
void qppe_edma_rx_ring_free (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t qppe_edma_rx_ring_start (vlib_main_t *, vnet_dev_rx_queue_t *);
void qppe_edma_rx_ring_stop (vnet_dev_rx_queue_t *);

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
