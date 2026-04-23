/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#pragma once

#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <vppinfra/error.h>

#define foreach_soft_rss_type                                                 \
  _ (DISABLED, "disabled")                                                    \
  _ (4_TUPLE, "4-tuple")                                                      \
  _ (2_TUPLE, "2-tuple")                                                      \
  _ (SRC_IP, "src-ip")                                                        \
  _ (DST_IP, "dst-ip")

typedef enum
{
  SOFT_RSS_TYPE_NOT_SET = 0,
#define _(a, b) SOFT_RSS_TYPE_##a,
  foreach_soft_rss_type
#undef _
    SOFT_RSS_N_TYPES,
} __clib_packed soft_rss_type_t;

typedef struct
{
  soft_rss_type_t type;
  soft_rss_type_t ipv4_type;
  soft_rss_type_t ipv6_type;
  u8 with_main_thread : 1;
  u8 l3_offset : 1;	  /* 0: offset is EtherType position, 1: IP header */
  u16 offset;		  /* byte offset from frame start; 0 in L2 mode means
			     default 12 (standard Ethernet) */
  clib_bitmap_t *threads; /* NULL means all workers */
  u8 *key;		  /* NULL means default Toeplitz key */
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
