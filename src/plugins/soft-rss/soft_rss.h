#pragma once

#define SOFT_RSS_PLUGIN_INTERNAL 1
#include <soft-rss/export.h>
#undef SOFT_RSS_PLUGIN_INTERNAL

#include <vlib/vlib.h>
#include <vnet/vnet.h>

typedef struct
{
  soft_rss_hash_type_t hash_type;
} soft_rss_rt_data_t;

typedef struct
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  soft_rss_rt_data_t **rt_by_sw_if_index;
} soft_rss_main_t;

extern soft_rss_main_t soft_rss_main;

int soft_rss_enable_disable (u32 sw_if_index, int enable_disable);
