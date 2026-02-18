/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#pragma once

#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <vppinfra/error.h>
#include <vnet/ethernet/ethernet.h>

typedef struct
{
  vnet_eth_rss_type_t type;
  vnet_eth_rss_type_t ipv4_type;
  vnet_eth_rss_type_t ipv6_type;
  u8 with_main_thread : 1;
  u16 l2_hdr_offset; /* typically 0, used if another header exists (e.g. DSA */
  clib_bitmap_t *threads; /* bitmap of RSS threads, NULL means all */
  u8 *key;		  /* vector, NULL means default */
} soft_rss_config_t;

typedef clib_error_t *(soft_rss_config_fn_t) (vlib_main_t *vm,
					      const soft_rss_config_t *config,
					      u32 hw_if_index);
typedef clib_error_t *(soft_rss_clear_fn_t) (vlib_main_t *vm, u32 hw_if_index);
typedef clib_error_t *(soft_rss_enable_fn_t) (vlib_main_t *vm,
					      u32 hw_if_index);
typedef clib_error_t *(soft_rss_disable_fn_t) (vlib_main_t *vm,
					       u32 hw_if_index);

#ifdef SOFT_RSS_PLUGIN_INTERNAL

__clib_export soft_rss_config_fn_t soft_rss_config;
__clib_export soft_rss_clear_fn_t soft_rss_clear;
__clib_export soft_rss_enable_fn_t soft_rss_enable;
__clib_export soft_rss_disable_fn_t soft_rss_disable;

#else /* SOFT_RSS_PLUGIN_INTERNAL */

static inline clib_error_t *
soft_rss_config (vlib_main_t *vm, const soft_rss_config_t *config,
		 u32 hw_if_index)
{
  soft_rss_config_fn_t *fn = (soft_rss_config_fn_t *) vlib_get_plugin_symbol (
    "soft_rss_plugin.so", "soft_rss_config");
  if (!fn)
    return clib_error_return (0, "soft-rss plugin not loaded");
  return fn (vm, config, hw_if_index);
}

static inline clib_error_t *
soft_rss_clear (vlib_main_t *vm, u32 hw_if_index)
{
  soft_rss_clear_fn_t *fn = (soft_rss_clear_fn_t *) vlib_get_plugin_symbol (
    "soft_rss_plugin.so", "soft_rss_clear");
  if (!fn)
    return clib_error_return (0, "soft-rss plugin not loaded");
  return fn (vm, hw_if_index);
}

static inline clib_error_t *
soft_rss_enable (vlib_main_t *vm, u32 hw_if_index)
{
  soft_rss_enable_fn_t *fn = (soft_rss_enable_fn_t *) vlib_get_plugin_symbol (
    "soft_rss_plugin.so", "soft_rss_enable");
  if (!fn)
    return clib_error_return (0, "soft-rss plugin not loaded");
  return fn (vm, hw_if_index);
}

static inline clib_error_t *
soft_rss_disable (vlib_main_t *vm, u32 hw_if_index)
{
  soft_rss_disable_fn_t *fn =
    (soft_rss_disable_fn_t *) vlib_get_plugin_symbol ("soft_rss_plugin.so",
						      "soft_rss_disable");
  if (!fn)
    return clib_error_return (0, "soft-rss plugin not loaded");
  return fn (vm, hw_if_index);
}

#endif /* SOFT_RSS_PLUGIN_INTERNAL */
