/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#ifndef SRC_VNET_SESSION_SEGMENT_MANAGER_H_
#define SRC_VNET_SESSION_SEGMENT_MANAGER_H_

#include <vnet/vnet.h>
#include <svm/svm_fifo_segment.h>

#include <vlibmemory/unix_shared_memory_queue.h>
#include <vlibmemory/api.h>
#include <vppinfra/lock.h>

typedef struct _segment_manager_properties
{
  /** Session fifo sizes.  */
  u32 rx_fifo_size;
  u32 tx_fifo_size;

  /** Preallocated pool sizes */
  u32 preallocated_fifo_pairs;

  /** Configured additional segment size */
  u32 add_segment_size;

  /** Flag that indicates if additional segments should be created */
  u8 add_segment;

  /** Use private memory segment instead of shared memory */
  u8 use_private_segment;

  /** Use one or more private mheaps, instead of the global heap */
  u32 private_segment_count;
  u32 private_segment_size;
} segment_manager_properties_t;

typedef struct _segment_manager
{
  clib_spinlock_t lockp;

  /** segments mapped by this manager */
  u32 *segment_indices;

  /** Owner app index */
  u32 app_index;

  /**
   * Pointer to manager properties. Could be shared among all of
   * an app's segment managers s
   */
  segment_manager_properties_t *properties;

  /**
   * First segment should not be deleted unless segment manger is deleted.
   * This also indicates that the segment manager is the first to have been
   * allocated for the app.
   */
  u8 first_is_protected;
} segment_manager_t;

#define SEGMENT_MANAGER_INVALID_APP_INDEX ((u32) ~0)

/** Pool of segment managers */
extern segment_manager_t *segment_managers;

always_inline segment_manager_t *
segment_manager_get (u32 index)
{
  return pool_elt_at_index (segment_managers, index);
}

always_inline segment_manager_t *
segment_manager_get_if_valid (u32 index)
{
  if (pool_is_free_index (segment_managers, index))
    return 0;
  return pool_elt_at_index (segment_managers, index);
}

always_inline u32
segment_manager_index (segment_manager_t * sm)
{
  return sm - segment_managers;
}

segment_manager_t *segment_manager_new ();
int
segment_manager_init (segment_manager_t * sm,
		      segment_manager_properties_t * properties,
		      u32 seg_size);

void segment_manager_get_segment_info (u32 index, u8 ** name, u32 * size);
int
session_manager_add_first_segment (segment_manager_t * sm, u32 segment_size);
int session_manager_add_segment (segment_manager_t * sm);
void segment_manager_del_sessions (segment_manager_t * sm);
void segment_manager_del (segment_manager_t * sm);
void segment_manager_init_del (segment_manager_t * sm);
u8 segment_manager_has_fifos (segment_manager_t * sm);
int
segment_manager_alloc_session_fifos (segment_manager_t * sm,
				     svm_fifo_t ** server_rx_fifo,
				     svm_fifo_t ** server_tx_fifo,
				     u32 * fifo_segment_index);
void
segment_manager_dealloc_fifos (u32 svm_segment_index, svm_fifo_t * rx_fifo,
			       svm_fifo_t * tx_fifo);
unix_shared_memory_queue_t *segment_manager_alloc_queue (segment_manager_t *
							 sm, u32 queue_size);
void segment_manager_dealloc_queue (segment_manager_t * sm,
				    unix_shared_memory_queue_t * q);

#endif /* SRC_VNET_SESSION_SEGMENT_MANAGER_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
