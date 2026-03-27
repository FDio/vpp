/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef included_cadence_h
#define included_cadence_h

#include <stdio.h>
#include <unistd.h>
#include <vnet/dev/dev.h>

extern vlib_log_class_registration_t cdn_log;

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, cdn_log.class, "%U" f, format_vnet_dev_log, (dev),               \
	    clib_string_skip_prefix (__func__, "cdn_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_INFO, cdn_log.class, "%U" f, format_vnet_dev_log, (dev), 0,             \
	    ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, cdn_log.class, "%U" f, format_vnet_dev_log, (dev), 0,           \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, cdn_log.class, "%U" f, format_vnet_dev_log, (dev), 0,          \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, cdn_log.class, "%U" f, format_vnet_dev_log, (dev), 0, ##__VA_ARGS__)

typedef struct
{
  void *regs;
  u32 regs_size;
  u8 is_gem : 1;
  u8 queue_mask;
  int uio_fd;
} cdn_device_t;

typedef struct
{
  u8 link_up : 1;
} cdn_port_t;

#include <cadenee_hw.h>

typedef struct
{
  u32 *buffer_indices;
  cdn_rx_desc_t *descs;
  u16 head;
  u16 tail;
  uword rbqp_reg;
  uword rbqph_reg;
  uword rbqs_reg;
} cdn_rxq_t;

typedef struct
{
  u32 *buffer_indices;
  cdn_tx_desc_t *descs;
  u16 head;
  u16 tail;
  uword tbqp_reg;
  uword tbqph_reg;
} cdn_txq_t;

typedef struct
{
  cdn_rx_desc_t desc;
  u32 buffer_index;
  u32 hw_if_index;
  u16 queue_id;
  u16 next_index;
} cdn_rx_trace_t;

typedef struct
{
  cdn_tx_desc_t desc;
  u32 buffer_index;
  u32 hw_if_index;
  u16 queue_id;
} cdn_tx_trace_t;

#define foreach_cdn_rx_node_counter                                                                \
  _ (0, NO_BUFFER, ERROR, "buffer allocation failed")                                              \
  _ (1, INCOMPLETE_CHAIN, ERROR, "multi-descriptor packet not supported")

typedef enum
{
#define _(i, n, s, d) CDN_RX_NODE_CTR_##n = i,
  foreach_cdn_rx_node_counter
#undef _
    CDN_RX_NODE_N_CTR
} cdn_rx_node_counter_t;

#define foreach_cdn_tx_node_counter                                                                \
  _ (0, NO_FREE_SLOTS, ERROR, "no free tx slots")                                                  \
  _ (1, CHAIN_TOO_LONG, ERROR, "buffer chain too long")

typedef enum
{
#define _(i, n, s, d) CDN_TX_NODE_CTR_##n = i,
  foreach_cdn_tx_node_counter
#undef _
    CDN_TX_NODE_N_CTR
} cdn_tx_node_counter_t;

static_always_inline uword
cdn_rbqp_reg (u16 q)
{
  return q ? 0x0480 + ((q - 1) << 2) : 0x0018;
}

static_always_inline uword
cdn_rbqph_reg (u16 q __clib_unused)
{
  return 0x04d4;
}

static_always_inline uword
cdn_tbqp_reg (u16 q)
{
  return q ? 0x0440 + ((q - 1) << 2) : 0x001c;
}

static_always_inline uword
cdn_tbqph_reg (u16 q __clib_unused)
{
  return 0x04c8;
}

static_always_inline uword
cdn_rbqs_reg (u16 q)
{
  ASSERT (q > 0);
  return 0x04a0 + ((q - 1) << 2);
}

static_always_inline uword
cdn_ier_reg (u16 q)
{
  return q ? CDN_IER + ((q - 1) << 2) : CDN_IER;
}

static_always_inline uword
cdn_idr_reg (u16 q)
{
  return q ? CDN_IDR + ((q - 1) << 2) : CDN_IDR;
}

static_always_inline uword
cdn_isr_reg (u16 q)
{
  return q ? CDN_ISR + ((q - 1) << 2) : CDN_ISR;
}

static_always_inline u32
cdn_readl (cdn_device_t *cd, uword offset)
{
  u32 value;

  fprintf (stderr, "cadence mmio read [0x%lx]\n", offset);
  fflush (stderr);
  fsync (fileno (stderr));
  value = __atomic_load_n ((u32 *) ((u8 *) cd->regs + offset), __ATOMIC_RELAXED);
  fprintf (stderr, "cadence mmio read [0x%lx] -> 0x%08x\n", offset, value);
  fflush (stderr);
  fsync (fileno (stderr));

  return value;
}

static_always_inline u32
cdn_dma_addr_lo (u64 addr)
{
  return addr;
}

static_always_inline u32
cdn_dma_addr_hi (u64 addr)
{
  return addr >> 32;
}

static_always_inline void
cdn_writel (cdn_device_t *cd, uword offset, u32 value)
{
  fprintf (stderr, "cadence mmio write [0x%lx] <- 0x%08x\n", offset, value);
  fflush (stderr);
  fsync (fileno (stderr));
  __atomic_store_n ((u32 *) ((u8 *) cd->regs + offset), value, __ATOMIC_RELAXED);
}

vnet_dev_rv_t cdn_port_init (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t cdn_port_start (vlib_main_t *vm, vnet_dev_port_t *port);
void cdn_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);
void cdn_port_clear_counters (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t cdn_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
					    vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t cdn_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
				   vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t cdn_port_counters_init (vlib_main_t *vm, vnet_dev_port_t *port);
void cdn_port_counter_poll (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t cdn_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void cdn_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t cdn_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
void cdn_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);

extern vnet_dev_node_t cdn_rx_node;
extern vnet_dev_node_t cdn_tx_node;

format_function_t format_cdn_dev_info;
format_function_t format_cdn_rx_desc;
format_function_t format_cdn_rx_trace;
format_function_t format_cdn_tx_desc;
format_function_t format_cdn_tx_trace;

#endif /* included_cadence_h */
