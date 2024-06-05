/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _IGE_H_
#define _IGE_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/types.h>

#include <dev_ige/ige_regs.h>

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
    u64 packet_type : 13;
    u64 _reserved_17 : 2;
    u64 hdr_len_hi : 2;
    u64 hdr_len_lo : 10;
    u64 sph : 1;
    u64 rss_hash : 32;

    u64 ext_status : 20;
    u64 ext_error : 12;
    u64 pkt_len : 16;
    u64 vlan_tag : 16;
  };
} ige_rx_desc_t;

STATIC_ASSERT_SIZEOF (ige_rx_desc_t, 16);

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
} ige_txq_t;

typedef struct
{
  u32 *buffer_indices;
  ige_rx_desc_t *descs;
  u16 head;
  u16 tail;
  u32 *reg_rdt;
} ige_rxq_t;

/* counters.c */
vnet_dev_rv_t ige_port_counters_init (vlib_main_t *, vnet_dev_port_t *);
void ige_port_counter_poll (vlib_main_t *, vnet_dev_port_t *);

/* format.c */
format_function_t format_ige_reg_write;
format_function_t format_ige_reg_read;
format_function_t format_ige_reg_diff;
format_function_t format_ige_port_status;

/* phy.c */
vnet_dev_rv_t ige_phy_init (vlib_main_t *, vnet_dev_t *);

/* port.c */
vnet_dev_rv_t ige_port_init (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t ige_port_start (vlib_main_t *, vnet_dev_port_t *);
void ige_port_stop (vlib_main_t *, vnet_dev_port_t *);

/* queue.c */
vnet_dev_rv_t ige_rx_queue_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t ige_tx_queue_alloc (vlib_main_t *, vnet_dev_tx_queue_t *);
void ige_rx_queue_free (vlib_main_t *, vnet_dev_rx_queue_t *);
void ige_tx_queue_free (vlib_main_t *, vnet_dev_tx_queue_t *);

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

#endif /* _IGE_H_ */
