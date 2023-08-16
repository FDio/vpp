/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#ifndef _ENA_INLINES_H_
#define _ENA_INLINES_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <dev_ena/ena.h>

#define ena_log_err(dev, f, ...)                                              \
  vlib_log (VLIB_LOG_LEVEL_ERR, ena_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

#define ena_log_warn(dev, f, ...)                                             \
  vlib_log (VLIB_LOG_LEVEL_WARNING, ena_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

#define ena_log_notice(dev, f, ...)                                           \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, ena_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

#define ena_log_info(dev, f, ...)                                             \
  vlib_log (VLIB_LOG_LEVEL_INFO, ena_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

#define ena_log_debug(dev, f, ...)                                            \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ena_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

#define ena_log_is_debug()                                                    \
  vlib_log_is_enabled (VLIB_LOG_LEVEL_DEBUG, ena_log.class)

#define ena_stats_log_err(dev, f, ...)                                        \
  vlib_log (VLIB_LOG_LEVEL_ERR, ena_stats_log.class, "%U: " f,                \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

#define ena_stats_log_debug(dev, f, ...)                                      \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ena_stats_log.class, "%U: " f,              \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

#define ena_stats_log_is_debug()                                              \
  vlib_log_is_enabled (VLIB_LOG_LEVEL_DEBUG, ena_stats_log.class)

static_always_inline void
ena_set_mem_addr (vlib_main_t *vm, vnet_dev_t *dev, ena_mem_addr_t *m, void *p)
{
  u64 pa = vnet_dev_get_dma_addr (vm, dev, p);
  *m = (ena_mem_addr_t){ .addr_lo = (u32) pa, .addr_hi = (u16) (pa >> 32) };
}

static_always_inline int
ena_aq_feature_is_supported (ena_device_t *ed, ena_aq_feature_id_t feat_id)
{
  return (ed->dev_attr.supported_features & (1U << feat_id)) != 0;
}

#endif /* ENA_INLINES_H */
