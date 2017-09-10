/*
 *------------------------------------------------------------------
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

#ifndef included_vlibmemory_api_common_h
#define included_vlibmemory_api_common_h

#include <svm/svm_common.h>
#include <vppinfra/file.h>
#include <vlibapi/api_common.h>
#include <vlibmemory/unix_shared_memory_queue.h>

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

  /* Number of garbage-collected messages */
  u32 garbage_collects;
} vl_shmem_hdr_t;

#define VL_SHM_VERSION 2

#define VL_API_EPOCH_MASK 0xFF
#define VL_API_EPOCH_SHIFT 8

void *vl_msg_api_alloc (int nbytes);
void *vl_msg_api_alloc_or_null (int nbytes);
void *vl_msg_api_alloc_as_if_client (int nbytes);
void *vl_msg_api_alloc_as_if_client_or_null (int nbytes);
void vl_msg_api_free (void *a);
int vl_map_shmem (const char *region_name, int is_vlib);
void vl_register_mapped_shmem_region (svm_region_t * rp);
void vl_unmap_shmem (void);
void vl_msg_api_send_shmem (unix_shared_memory_queue_t * q, u8 * elem);
void vl_msg_api_send_shmem_nolock (unix_shared_memory_queue_t * q, u8 * elem);
void vl_msg_api_send (vl_api_registration_t * rp, u8 * elem);
int vl_client_connect (const char *name, int ctx_quota, int input_queue_size);
void vl_client_disconnect (void);
unix_shared_memory_queue_t *vl_api_client_index_to_input_queue (u32 index);
vl_api_registration_t *vl_api_client_index_to_registration (u32 index);
int vl_client_api_map (const char *region_name);
void vl_client_api_unmap (void);
void vl_set_memory_region_name (const char *name);
void vl_set_memory_root_path (const char *root_path);
void vl_set_memory_uid (int uid);
void vl_set_memory_gid (int gid);
void vl_set_global_memory_baseva (u64 baseva);
void vl_set_global_memory_size (u64 size);
void vl_set_api_memory_size (u64 size);
void vl_set_global_pvt_heap_size (u64 size);
void vl_set_api_pvt_heap_size (u64 size);
void vl_client_disconnect_from_vlib (void);
int vl_client_connect_to_vlib (const char *svm_name, const char *client_name,
			       int rx_queue_size);
int vl_client_connect_to_vlib_no_rx_pthread (const char *svm_name,
					     const char *client_name,
					     int rx_queue_size);
u16 vl_client_get_first_plugin_msg_id (const char *plugin_name);

void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);
u32 vl_api_memclnt_create_internal (char *, unix_shared_memory_queue_t *);

/* API messages over sockets */

extern vlib_node_registration_t memclnt_node;

/* Events sent to the memclnt process */
#define QUEUE_SIGNAL_EVENT 1
#define SOCKET_READ_EVENT 2

#define API_SOCKET_FILE "/run/vpp/api.sock"

typedef struct
{
  clib_file_t *clib_file;
  vl_api_registration_t *regp;
  u8 *data;
} vl_socket_args_for_process_t;

typedef struct
{
  /* Server port number */
  int portno;

  /* By default, localhost... */
  u32 bind_address;

  /*
   * (listen, server, client) registrations. Shared memory
   * registrations are in shared memory
   */
  vl_api_registration_t *registration_pool;
  /*
   * Chain-drag variables, so message API handlers
   * (generally) don't know whether they're talking to a socket
   * or to a shared-memory connection.
   */
  vl_api_registration_t *current_rp;
  clib_file_t *current_uf;
  /* One input buffer, shared across all sockets */
  i8 *input_buffer;

  /* pool of process args for socket clients */
  vl_socket_args_for_process_t *process_args;

  /* Listen for API connections here */
  clib_socket_t socksvr_listen_socket;
} socket_main_t;

extern socket_main_t socket_main;

void socksvr_add_pending_output (struct clib_file *uf,
				 struct vl_api_registration_ *cf,
				 u8 * buffer, uword buffer_bytes);

void vl_free_socket_registration_index (u32 pool_index);
void vl_socket_process_msg (struct clib_file *uf,
			    struct vl_api_registration_ *rp, i8 * input_v);
clib_error_t *vl_socket_read_ready (struct clib_file *uf);
void vl_socket_add_pending_output (struct clib_file *uf,
				   struct vl_api_registration_ *rp,
				   u8 * buffer, uword buffer_bytes);
void vl_socket_add_pending_output_no_flush (struct clib_file *uf,
					    struct vl_api_registration_ *rp,
					    u8 * buffer, uword buffer_bytes);
clib_error_t *vl_socket_write_ready (struct clib_file *uf);
void vl_socket_api_send (vl_api_registration_t * rp, u8 * elem);
u32 sockclnt_open_index (char *client_name, char *hostname, int port);
void sockclnt_close_index (u32 index);
void vl_client_msg_api_send (vl_api_registration_t * cm, u8 * elem);
vl_api_registration_t *sockclnt_get_registration (u32 index);
void socksvr_set_port (u16 port);
void socksvr_set_bind_address (u32 bind_address);
void vl_api_socket_process_msg (clib_file_t * uf, vl_api_registration_t * rp,
				i8 * input_v);
#endif /* included_vlibmemory_api_common_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
