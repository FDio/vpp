/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#ifndef included_stat_segment_shared_h
#define included_stat_segment_shared_h

typedef enum
{
  STAT_DIR_TYPE_ILLEGAL = 0,
  STAT_DIR_TYPE_SCALAR_INDEX,
  STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE,
  STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED,
  STAT_DIR_TYPE_NAME_VECTOR,
  STAT_DIR_TYPE_EMPTY,
  STAT_DIR_TYPE_SYMLINK,
} stat_directory_type_t;

typedef struct
{
  stat_directory_type_t type;
  union
  {
    struct
    {
      uint32_t index1;
      uint32_t index2;
    };
    uint64_t index;
    uint64_t value;
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
