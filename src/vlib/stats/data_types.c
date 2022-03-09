/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>
#include <vppinfra/time_range.h>

static u8 *
format_vlib_stats_uint64 (u8 *s, va_list *args)
{
  return format (s, "%lu", va_arg (*args, u64 *)[0]);
}

static u8 *
format_vlib_stats_uint64_pair (u8 *s, va_list *args)
{
  u64 *data = va_arg (*args, u64 *);
  return format (s, "%lu, %lu", data[0], data[1]);
}

static u8 *
format_vlib_stats_float64 (u8 *s, va_list *args)
{
  return format (s, "%.2f", va_arg (*args, f64 *)[0]);
}

static u8 *
format_vlib_stats_float64_pair (u8 *s, va_list *args)
{
  f64 *data = va_arg (*args, f64 *);
  return format (s, "%f, %f", data[0], data[1]);
}

static u8 *
format_vlib_stats_epoch (u8 *s, va_list *args)
{
  return format (s, "%U UTC", format_clib_timebase_time,
		 va_arg (*args, f64 *)[0]);
}

static u8 *
format_vlib_stats_string (u8 *s, va_list *args)
{
  return format (s, "%s", va_arg (*args, char **)[0]);
}

static u8 *
format_vlib_stats_blob (u8 *s, va_list *args)
{
  u8 *data = va_arg (*args, u8 **)[0];
  return format (s, "%U", format_hexdump, data, vec_len (data));
}

static u8 *
format_vlib_stats_symlink (u8 *s, va_list *args)
{
  u32 *data = va_arg (*args, u32 *);
  return format (s, "%u:%u", data[0], data[1]);
}

vlib_stats_data_type_info_t vlib_stats_data_types[VLIB_STATS_N_DATA_TYPES] = {
  [VLIB_STATS_TYPE_UINT64] = {
    .name = "uint64",
    .format_fn = format_vlib_stats_uint64,
    .size = sizeof (u64),
  },
  [VLIB_STATS_TYPE_UINT64_PAIR] = {
    .name = "uint64-pair",
    .format_fn = format_vlib_stats_uint64_pair,
    .size = 2 * sizeof (u64),
  },
  [VLIB_STATS_TYPE_FLOAT64] = {
    .name = "float64",
    .format_fn = format_vlib_stats_float64,
    .size = sizeof (f64),
  },
  [VLIB_STATS_TYPE_FLOAT64_PAIR] = {
    .name = "float64-pair",
    .format_fn = format_vlib_stats_float64_pair,
    .size = sizeof (f64),
  },
  [VLIB_STATS_TYPE_EPOCH] = {
    .name = "epoch",
    .format_fn = format_vlib_stats_epoch,
    .size = sizeof (f64),
  },
  [VLIB_STATS_TYPE_STRING] = {
    .name = "string",
    .format_fn = format_vlib_stats_string,
    .size = sizeof (u8 *),
  },
  [VLIB_STATS_TYPE_BLOB] = {
    .name = "blob",
    .format_fn = format_vlib_stats_blob,
    .size = sizeof (u8 *),
  },
  [VLIB_STATS_TYPE_SYMLINK] = {
    .name = "symlink",
    .format_fn = format_vlib_stats_symlink,
    .size = sizeof (u64),
  }
};
