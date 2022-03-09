/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#ifndef included_stat_segment_shared_h
#define included_stat_segment_shared_h

typedef enum
{
  VLIB_STATS_TYPE_UINT64 = 0,
  VLIB_STATS_TYPE_UINT64_PAIR,
  VLIB_STATS_TYPE_UINT32 = 0,
  VLIB_STATS_TYPE_UINT32_PAIR,
  VLIB_STATS_TYPE_FLOAT64,
  VLIB_STATS_TYPE_FLOAT64_PAIR,
  VLIB_STATS_TYPE_DURATION,
  VLIB_STATS_TYPE_EPOCH,
  VLIB_STATS_TYPE_STRING,
  VLIB_STATS_TYPE_BLOB,
  VLIB_STATS_TYPE_SYMLINK,
  VLIB_STATS_N_DATA_TYPES,
} vlib_stats_data_type_t;

typedef struct
{
  uint8_t in_use : 1;
  vlib_stats_data_type_t data_type : 8;
  uint8_t n_dimensions;
  union
  {
    struct
    {
      uint32_t index1;
      uint32_t index2;
    };
    uint64_t index;
    uint64_t value;
    double value_as_float64;
    void *data;
    uint8_t **string_vector;
  };
#define VLIB_STATS_MAX_NAME_SZ 128
  char name[VLIB_STATS_MAX_NAME_SZ];
} vlib_stats_entry_t;

/*
 * Shared header first in the shared memory segment.
 */
typedef struct
{
  uint64_t version;
  void *base;
  volatile uint64_t epoch;
  volatile uint64_t in_progress;
  volatile vlib_stats_entry_t *directory_vector;
} vlib_stats_shared_header_t;

#endif /* included_stat_segment_shared_h */
