/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#ifndef SRC_VLIBMEMORY_MEMORY_SHARED_H_
#define SRC_VLIBMEMORY_MEMORY_SHARED_H_

#include <vlibapi/api_common.h>
#include <vppinfra/error.h>

/* Allocated in shared memory */

/*
 * Ring-allocation scheme for client API messages
 *
 * Only one proc/thread has control of a given message buffer.
 * To free a buffer allocated from one of these rings, we clear
 * a field in the buffer (header), and leave.
 *
 * No locks, no hits, no errors...
 */
typedef struct ring_alloc_
{
  svm_queue_t *rp;
  u16 size;
  u16 nitems;
  u32 hits;
  u32 misses;
} ring_alloc_t;

typedef enum
{
  VL_API_VLIB_RING,
  VL_API_CLIENT_RING,
  VL_API_QUEUE
} vl_api_shm_config_type_t;

typedef struct vl_api_shm_elem_config_
{
  u8 type;
  u8 _pad;
  u16 count;
  u32 size;
} vl_api_shm_elem_config_t;

STATIC_ASSERT (sizeof (vl_api_shm_elem_config_t) == 8,
	       "Size must be exactly 8 bytes");

/*
 * Initializers for the (shared-memory) rings
 * _(size, n). Note: each msg has space for a header.
 */
#define foreach_vl_aring_size                   \
_(64+sizeof(ring_alloc_t), 1024)                \
_(256+sizeof(ring_alloc_t), 128)                \
_(1024+sizeof(ring_alloc_t), 64)

#define foreach_clnt_aring_size                 \
 _(1024+sizeof(ring_alloc_t), 1024)             \
 _(2048+sizeof(ring_alloc_t), 128)              \
 _(4096+sizeof(ring_alloc_t), 8)

typedef struct vl_shmem_hdr_
{
  int version;

  /* getpid () for the VLIB client process */
  volatile int vl_pid;

  /* Client sends VLIB msgs here. */
  svm_queue_t *vl_input_queue;

  /* Vector of rings; one for each size. */

  /* VLIB allocates buffers to send msgs to clients here. */
  ring_alloc_t *vl_rings;

  /* Clients allocate buffer to send msgs to VLIB here. */
  ring_alloc_t *client_rings;

  /* Number of detected application restarts */
  u32 application_restarts;

  /* Number of messages reclaimed during application restart */
  u32 restart_reclaims;

  /* Number of garbage-collected messages */
  u32 garbage_collects;

  /* Socket file index used to bootstrap shmem region */
  u32 clib_file_index;
} vl_shmem_hdr_t;

#define VL_SHM_VERSION 2
#define VL_API_EPOCH_MASK 0xFF
#define VL_API_EPOCH_SHIFT 8

void *vl_msg_api_alloc (int nbytes);
void *vl_msg_api_alloc_or_null (int nbytes);
void *vl_msg_api_alloc_as_if_client (int nbytes);
void *vl_msg_api_alloc_as_if_client_or_null (int nbytes);
void *vl_mem_api_alloc_as_if_client_w_reg (vl_api_registration_t * reg,
					   int nbytes);
void vl_msg_api_free (void *a);
int vl_map_shmem (const char *region_name, int is_vlib);
void vl_unmap_shmem (void);
void vl_unmap_shmem_client (void);
void vl_register_mapped_shmem_region (svm_region_t * rp);
void vl_msg_api_send_shmem (svm_queue_t * q, u8 * elem);
int vl_mem_api_can_send (svm_queue_t * q);
void vl_set_memory_region_name (const char *name);
void vl_set_memory_root_path (const char *root_path);
void vl_set_memory_uid (int uid);
void vl_set_memory_gid (int gid);
void vl_set_global_memory_baseva (u64 baseva);
void vl_set_global_memory_size (u64 size);
void vl_set_api_memory_size (u64 size);
void vl_set_global_pvt_heap_size (u64 size);
void vl_set_api_pvt_heap_size (u64 size);
void vl_init_shmem (svm_region_t * vlib_rp, vl_api_shm_elem_config_t * config,
		    int is_vlib, int is_private_region);

#endif /* SRC_VLIBMEMORY_MEMORY_SHARED_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
