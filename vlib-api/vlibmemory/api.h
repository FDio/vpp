/*
 *------------------------------------------------------------------
 * api.h
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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

#ifndef included_vlibmemory_api_h
#define included_vlibmemory_api_h

#include <vppinfra/error.h>
#include <svm.h>
#include <vlib/vlib.h>
#include <vlibmemory/unix_shared_memory_queue.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>

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
  unix_shared_memory_queue_t *rp;
  u16 size;
  u16 nitems;
  u32 hits;
  u32 misses;
} ring_alloc_t;

/*
 * Initializers for the (shared-memory) rings
 * _(size, n). Note: each msg has an 8 byte header.
 * Might want to change that to an index sometime.
 */
#define foreach_vl_aring_size                   \
_(64+8, 1024)                                   \
_(256+8, 128)                                   \
_(1024+8, 64)

#define foreach_clnt_aring_size                 \
_(1024+8, 1024)                                 \
_(2048+8, 128)                                  \
_(4096+8, 8)

typedef struct vl_shmem_hdr_
{
  int version;

  /* getpid () for the VLIB client process */
  volatile int vl_pid;

  /* Client sends VLIB msgs here. */
  unix_shared_memory_queue_t *vl_input_queue;

  /* Vector of rings; one for each size. */

  /* VLIB allocates buffers to send msgs to clients here. */
  ring_alloc_t *vl_rings;

  /* Clients allocate buffer to send msgs to VLIB here. */
  ring_alloc_t *client_rings;

  /* Number of detected application restarts */
  u32 application_restarts;

  /* Number of messages reclaimed during application restart */
  u32 restart_reclaims;

} vl_shmem_hdr_t;

#define VL_SHM_VERSION 2

#define VL_API_EPOCH_MASK 0xFF
#define VL_API_EPOCH_SHIFT 8

static inline u32
vl_msg_api_handle_get_epoch (u32 index)
{
  return (index & VL_API_EPOCH_MASK);
}

static inline u32
vl_msg_api_handle_get_index (u32 index)
{
  return (index >> VL_API_EPOCH_SHIFT);
}

static inline u32
vl_msg_api_handle_from_index_and_epoch (u32 index, u32 epoch)
{
  u32 handle;
  ASSERT (index < 0x00FFFFFF);

  handle = (index << VL_API_EPOCH_SHIFT) | (epoch & VL_API_EPOCH_MASK);
  return handle;
}

void *vl_msg_api_alloc (int nbytes);
void *vl_msg_api_alloc_or_null (int nbytes);
void *vl_msg_api_alloc_as_if_client (int nbytes);
void *vl_msg_api_alloc_as_if_client_or_null (int nbytes);
void vl_msg_api_free (void *a);
int vl_map_shmem (char *region_name, int is_vlib);
void vl_register_mapped_shmem_region (svm_region_t * rp);
void vl_unmap_shmem (void);
void vl_msg_api_send_shmem (unix_shared_memory_queue_t * q, u8 * elem);
void vl_msg_api_send_shmem_nolock (unix_shared_memory_queue_t * q, u8 * elem);
void vl_msg_api_send (vl_api_registration_t * rp, u8 * elem);
int vl_client_connect (char *name, int ctx_quota, int input_queue_size);
void vl_client_disconnect (void);
unix_shared_memory_queue_t *vl_api_client_index_to_input_queue (u32 index);
vl_api_registration_t *vl_api_client_index_to_registration (u32 index);
int vl_client_api_map (char *region_name);
void vl_client_api_unmap (void);
void vl_set_memory_region_name (char *name);
void vl_set_memory_root_path (char *root_path);
void vl_set_memory_uid (int uid);
void vl_set_memory_gid (int gid);
void vl_set_global_memory_baseva (u64 baseva);
void vl_set_global_memory_size (u64 size);
void vl_set_api_memory_size (u64 size);
void vl_set_global_pvt_heap_size (u64 size);
void vl_set_api_pvt_heap_size (u64 size);
void vl_enable_disable_memory_api (vlib_main_t * vm, int yesno);
void vl_client_disconnect_from_vlib (void);
int vl_client_connect_to_vlib (char *svm_name, char *client_name,
			       int rx_queue_size);
int vl_client_connect_to_vlib_no_rx_pthread (char *svm_name,
					     char *client_name,
					     int rx_queue_size);
u16 vl_client_get_first_plugin_msg_id (char *plugin_name);

void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);

#endif /* included_vlibmemory_api_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
