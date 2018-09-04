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

#ifndef included_stat_segment_h
#define included_stat_segment_h

/* Default socket to exchange segment fd */
#define STAT_SEGMENT_SOCKET_FILE "/run/vpp/stats.sock"

typedef enum
{
  STAT_DIR_TYPE_ILLEGAL = 0,
  STAT_DIR_TYPE_SCALAR_POINTER,
  STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE,
  STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED,
  STAT_DIR_TYPE_ERROR_INDEX,
  STAT_DIR_TYPE_SERIALIZED_NODES,
} stat_directory_type_t;

typedef struct
{
  stat_directory_type_t type;
  uint64_t offset;
  uint64_t offset_vector;
  char name[128];
} stat_segment_directory_entry_t;

/* Default stat segment 32m */
#define STAT_SEGMENT_DEFAULT_SIZE	(32<<20)

#define STAT_SEGMENT_OPAQUE_LOCK		0
#define STAT_SEGMENT_OPAQUE_OFFSET		1
#define STAT_SEGMENT_OPAQUE_EPOCH		2
#define STAT_SEGMENT_OPAQUE_ERROR_OFFSET	3

typedef struct
{
  /* Spin-lock */
  volatile uint32_t lock;
  volatile uint32_t owner_pid;
  int recursion_count;
  uint32_t tag;			/* for debugging */

  /* The allocation arena */
  void *heap;

  /* Segment must be mapped at this address, or no supper */
  uint64_t ssvm_va;
  /* The actual mmap size */
  uint64_t ssvm_size;
  uint32_t master_pid;
  uint32_t slave_pid;
  uint8_t *name;
  void *opaque[8];

  /* Set when the master application thinks it's time to make the donuts */
  volatile uint32_t ready;

  int type;
} stat_segment_shared_header_t;

#endif
