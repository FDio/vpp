/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/types.h>

#include <ige_regs.h>

typedef union
{
  struct
  {
    u64 pkt_addr;
    u64 hdr_addr;
  };
  struct
  {
    u64 rss_type : 4;

    /* packet type */
    u64 ipv4 : 1;
    u64 ipv4e : 1;
    u64 ipv6 : 1;
    u64 ipv6e : 1;
    u64 tcp : 1;
    u64 udp : 1;
    u64 sctp : 1;
    u64 nfs : 1;
    u64 etqf : 3;
    u64 l2pkt : 1;
    u64 vpkt : 1;

    u64 _reserved_17 : 2;
    u64 hdr_len_hi : 2;
    u64 hdr_len_lo : 10;
    u64 sph : 1;
    u64 rss_hash : 32;

    /* ext status */
    u64 dd : 1;
    u64 eop : 1;
    u64 _rsv1 : 1;
    u64 vp : 1;
    u64 udpcs : 1;
    u64 l4i : 1;
    u64 ipcs : 1;
    u64 pif : 1;
    u64 _rsv2 : 1;
    u64 vext : 1;
    u64 udpv : 1;
    u64 llint : 1;
    u64 strip_crc : 1;
    u64 smd_type : 2;
    u64 tsip : 1;
    u64 _rsv3 : 3;
    u64 mc : 1;

    /* ext error */
    u64 _rsv4 : 3;
    u64 hbo : 1;
    u64 _rsv5 : 5;
    u64 l4e : 1;
    u64 ipe : 1;
    u64 rxe : 1;

    u64 pkt_len : 16;
    u64 vlan_tag : 16;
  };
} ige_rx_desc_t;

STATIC_ASSERT_SIZEOF (ige_rx_desc_t, 16);

typedef union
{
  u64 qwords[2];
  struct
  {
    u64 addr;
    u64 dtalen : 16;
    u64 ptp1 : 4;
    u64 dtyp : 4;

    u64 eop : 1;
    u64 ifcs : 1;
    u64 _reserved_26 : 1;
    u64 rs : 1;
    u64 _reserved_28 : 1;
    u64 dext : 1;
    u64 vle : 1;
    u64 tse : 1;

    /* status */
    u64 dd : 1;
    u64 ts_stat : 1;
    u64 _reserved_35_36 : 2;

    u64 idx : 1;
    u64 ptp2 : 3;
    u64 popts : 6;
    u64 paylen : 18;
  };

  /* writeback */
  struct
  {
    u64 dma_timestamp;
    u64 _reserved_64_95 : 32;
    u64 sta : 4;
    u64 _reserved_100_127 : 28;
  };
} ige_tx_desc_t;

STATIC_ASSERT_SIZEOF (ige_tx_desc_t, 16);

typedef enum
{
  IGE_PHY_TYPE_UNKNOWN = 0,
  IGE_PHY_TYPE_I210_INTERNAL,
  IGE_PHY_TYPE_GPY211,
} __clib_packed ige_phy_type_t;

typedef enum
{
  IGE_DEV_TYPE_I211,
  IGE_DEV_TYPE_I225,
  IGE_DEV_TYPE_I226,
} __clib_packed ige_dev_type_t;

typedef struct
{
  ige_phy_type_t phy_type;
  u8 supports_2_5g : 1;
} ige_dev_config_t;

typedef struct
{
  void *bar0;
  u8 avail_rxq_bmp;
  u8 avail_txq_bmp;
  ige_phy_type_t phy_type;
  ige_dev_config_t config;
} ige_device_t;

typedef struct
{
  ige_reg_status_t last_status;
} ige_port_t;

typedef struct
{
  u32 *buffer_indices;
  ige_rx_desc_t *descs;
  u16 head;
  u16 tail;
  u32 *reg_rdt;
} ige_rxq_t;

typedef struct
{
  u32 *buffer_indices;
  ige_tx_desc_t *descs;
  u16 head;
  u16 tail;
  u32 *reg_tdt;
  u32 *wb;
} ige_txq_t;

typedef struct
{
  ige_rx_desc_t desc;
  u32 buffer_index;
  u32 hw_if_index;
  u16 queue_id;
  u16 next_index;
} ige_rx_trace_t;

typedef struct
{
  ige_tx_desc_t desc;
  u32 buffer_index;
  u32 hw_if_index;
  u16 queue_id;
} ige_tx_trace_t;

/* counters.c */
vnet_dev_rv_t ige_port_counters_init (vlib_main_t *, vnet_dev_port_t *);
void ige_port_counter_poll (vlib_main_t *, vnet_dev_port_t *);

/* format.c */
format_function_t format_ige_reg_write;
format_function_t format_ige_reg_read;
format_function_t format_ige_reg_diff;
format_function_t format_ige_port_status;
format_function_t format_ige_rx_desc;
format_function_t format_ige_rx_trace;
format_function_t format_ige_tx_desc;
format_function_t format_ige_tx_trace;
format_function_t format_ige_receive_addr_table;

/* phy.c */
vnet_dev_rv_t ige_phy_init (vlib_main_t *, vnet_dev_t *);

/* port.c */
vnet_dev_rv_t ige_port_init (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t ige_port_start (vlib_main_t *, vnet_dev_port_t *);
void ige_port_stop (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t ige_port_cfg_change_validate (vlib_main_t *, vnet_dev_port_t *,
					    vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t ige_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				   vnet_dev_port_cfg_change_req_t *);

/* queue.c */
vnet_dev_rv_t ige_rx_queue_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t ige_tx_queue_alloc (vlib_main_t *, vnet_dev_tx_queue_t *);
void ige_rx_queue_free (vlib_main_t *, vnet_dev_rx_queue_t *);
void ige_tx_queue_free (vlib_main_t *, vnet_dev_tx_queue_t *);

static_always_inline u16
ige_rxq_refill_no_wrap (vlib_main_t *vm, u32 *buffer_indices,
			ige_rx_desc_t *descs, u16 n_refill,
			u8 buffer_pool_index, int use_va_dma)
{
  u16 n_alloc;
  vlib_buffer_t *b;

  n_alloc = vlib_buffer_alloc_from_pool (vm, buffer_indices, n_refill,
					 buffer_pool_index);

  if (use_va_dma)
    for (u32 i = 0; i < n_alloc; i++)
      {
	b = vlib_get_buffer (vm, buffer_indices[i]);
	descs[i].pkt_addr = vlib_buffer_get_va (b);
	descs[i].hdr_addr = 0;
      }
  else
    for (u32 i = 0; i < n_alloc; i++)
      {
	b = vlib_get_buffer (vm, buffer_indices[i]);
	descs[i].pkt_addr = vlib_buffer_get_pa (vm, b);
	descs[i].hdr_addr = 0;
      }

  return n_alloc;
}

/* reg.c */
vnet_dev_rv_t ige_reg_poll (vlib_main_t *, vnet_dev_t *, u32, u32, u32, f64,
			    f64);
int ige_reg_sw_fw_sync_acquire (vlib_main_t *, vnet_dev_t *);
void ige_reg_sw_fw_sync_release (vlib_main_t *, vnet_dev_t *);

/* inlines */
static_always_inline void
ige_reg_rd (vnet_dev_t *dev, u32 reg, u32 *val)
{
  ige_device_t *id = vnet_dev_get_data (dev);
  u32 rv = __atomic_load_n ((u32 *) ((u8 *) id->bar0 + reg), __ATOMIC_ACQUIRE);
  *val = rv;
}

static_always_inline void
ige_reg_wr (vnet_dev_t *dev, u32 reg, u32 val)
{
  ige_device_t *id = vnet_dev_get_data (dev);
  __atomic_store_n ((u32 *) ((u8 *) id->bar0 + reg), val, __ATOMIC_RELEASE);
}

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ige_log.class, "%U" f, format_vnet_dev_log, \
	    (dev), clib_string_skip_prefix (__func__, "ige_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, ige_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, ige_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, ige_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, ige_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

#define foreach_ige_tx_node_counter                                           \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")                 \
  _ (BUFFER_CHAIN_TOO_LONG, buffer_chain_too_long, ERROR,                     \
     "buffer chain too long")

typedef enum
{
#define _(f, n, s, d) IGE_TX_NODE_CTR_##f,
  foreach_ige_tx_node_counter
#undef _
} ige_tx_node_counter_t;
