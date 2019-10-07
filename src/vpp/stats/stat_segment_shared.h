/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_stat_segment_shared_h
#define included_stat_segment_shared_h

typedef enum
{
  STAT_DIR_TYPE_ILLEGAL = 0,
  STAT_DIR_TYPE_SCALAR_INDEX,
  STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE,
  STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED,
  STAT_DIR_TYPE_ERROR_INDEX,
  STAT_DIR_TYPE_NAME_VECTOR,
} stat_directory_type_t;

typedef struct
{
  stat_directory_type_t type;
  union {
    uint64_t offset;
    uint64_t index;
    uint64_t value;
  };
  uint64_t offset_vector;
  char name[128]; // TODO change this to pointer to "somewhere"
} stat_segment_directory_entry_t;

/*
 * Shared header first in the shared memory segment.
 */
typedef struct
{
  uint64_t version;
  volatile uint64_t epoch;
  volatile uint64_t in_progress;
  volatile uint64_t directory_offset;
  volatile uint64_t error_offset;
  volatile uint64_t stats_offset;
} stat_segment_shared_header_t;

static inline void *
stat_segment_pointer (void *start, uint64_t offset)
{
  return ((char *) start + offset);
}

#endif /* included_stat_segment_shared_h */
