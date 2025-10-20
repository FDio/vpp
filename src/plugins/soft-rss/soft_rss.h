#pragma once

#define SOFT_RSS_PLUGIN_INTERNAL 1
#include <soft-rss/export.h>
#undef SOFT_RSS_PLUGIN_INTERNAL

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/format.h>
#include <vppinfra/vector/toeplitz.h>

typedef struct
{
  u8x16 mask;
  u8x16 match;
  u8 key_start;
  u8 key_len;
} soft_rss_rt_match_t;

typedef struct
{
  u8 enabled : 1;
  soft_rss_type_t type;
  clib_toeplitz_hash_key_t *key;
  u8 n_match;
  u16 match_offset;
  clib_thread_index_t reta_mask;
  clib_thread_index_t reta[256];
  soft_rss_rt_match_t match[8];
} soft_rss_rt_data_t;

typedef struct
{
  u32 sw_if_index;
  u16 hash;
  u16 thread_index;
} soft_rss_trace_t;

typedef struct
{
  u32 sw_if_index;
  u16 next_index;
} soft_rss_handoff_trace_t;

typedef struct
{
  soft_rss_rt_data_t **rt_by_sw_if_index;
  u32 frame_queue_index;
} soft_rss_main_t;

extern soft_rss_main_t soft_rss_main;
extern vlib_node_registration_t soft_rss_handoff_node;

format_function_t format_soft_rss_if;
format_function_t format_soft_rss_trace;
format_function_t format_soft_rss_handoff_trace;
format_function_t format_soft_rss_type;
unformat_function_t unformat_soft_rss_type;
