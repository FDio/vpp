/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/types.h>
#include <mhi_defs.h>

#define MHI_CMD_RING_SIZE 128

typedef struct
{
  void *bar0;
  void *bhi;
  u8 n_events;
  u8 n_chans;
  u8 n_cmds;
  mhi_chan_ctxt_t *chan_ctxt;
  mhi_event_ctxt_t *event_ctxt;
  mhi_cmd_ctxt_t *cmd_ctxt;
  mhi_tre_t *cmd_ring;
  mhi_tre_t **event_rings;
  mhi_tre_t *chan_rings[128];
  void *ch_db[128];
  u64 *er_db;
  void **dma_allocs;
} mhi_dev_t;

/* Logging macros */

/* Format functions */
format_function_t format_mhi_reg_read;
format_function_t format_mhi_reg_write;
format_function_t format_mhi_reg_diff;
format_function_t format_bhi_reg_read;
format_function_t format_mhi_ee;
format_function_t format_mhi_state;
format_function_t format_mhi_pkt_type;
format_function_t format_mhi_tre;
format_function_t format_mhi_chan_state;

/* Functions */
vnet_dev_rv_t mhi_irq_init (vlib_main_t *vm, vnet_dev_t *dev);
void mhi_process_event_ring (vlib_main_t *vm, vnet_dev_t *dev, u16 er_index);
void mhi_process_events (vlib_main_t *vm, vnet_dev_t *dev);
vnet_dev_rv_t mhi_queue_cmd (vnet_dev_t *dev, mhi_tre_t *cmd);
vnet_dev_rv_t mhi_channel_start (vlib_main_t *vm, vnet_dev_t *dev, u32 ch_id);
vnet_dev_rv_t mhi_queue_transfer (vnet_dev_t *dev, u32 ch_id, mhi_tre_t *tre);

static_always_inline void
mhi_reg_rd (vnet_dev_t *dev, u32 reg, u32 *val)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  u32 rv = __atomic_load_n ((u32 *) ((u8 *) md->bar0 + reg), __ATOMIC_ACQUIRE);
  *val = rv;
}

static_always_inline void
mhi_reg_wr (vnet_dev_t *dev, u32 reg, u32 val)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  __atomic_store_n ((u32 *) ((u8 *) md->bar0 + reg), val, __ATOMIC_RELEASE);
}

static_always_inline void
mhi_reg_wr64 (vnet_dev_t *dev, u32 reg, u64 val)
{
  mhi_reg_wr (dev, reg + 4, (u32) (val >> 32));
  mhi_reg_wr (dev, reg + 0, (u32) val);
}

static_always_inline void
bhi_reg_rd (vnet_dev_t *dev, u32 reg, u32 *val)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  u32 rv = __atomic_load_n ((u32 *) ((u8 *) md->bhi + reg), __ATOMIC_ACQUIRE);
  *val = rv;
}

static_always_inline void
bhi_reg_wr (vnet_dev_t *dev, u32 reg, u32 val)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  __atomic_store_n ((u32 *) ((u8 *) md->bhi + reg), val, __ATOMIC_RELEASE);
}

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, mhi_log.class, "%U" f, format_vnet_dev_log, \
	    (dev), clib_string_skip_prefix (__func__, "mhi_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, mhi_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, mhi_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, mhi_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, mhi_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
