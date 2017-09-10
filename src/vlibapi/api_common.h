/*
 *------------------------------------------------------------------
 * api_common.h
 *
 * Copyright (c) 2009-2015 Cisco and/or its affiliates.
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

#ifndef included_api_common_h
#define included_api_common_h

#include <vppinfra/clib_error.h>
#include <svm/svm_common.h>
#include <vlibmemory/unix_shared_memory_queue.h>

typedef enum
{
  REGISTRATION_TYPE_FREE = 0,
  REGISTRATION_TYPE_SHMEM,
  REGISTRATION_TYPE_SOCKET_LISTEN,
  REGISTRATION_TYPE_SOCKET_SERVER,
  REGISTRATION_TYPE_SOCKET_CLIENT,
} vl_registration_type_t;

typedef struct vl_api_registration_
{
  vl_registration_type_t registration_type;

  /* Index in VLIB's brain (not shared memory). */
  u32 vl_api_registration_pool_index;

  u8 *name;

  /*
   * The following groups of data could be unioned, but my fingers are
   * going to be sore enough.
   */

  /* shared memory only */
  unix_shared_memory_queue_t *vl_input_queue;

  /* socket server and client */
  u32 clib_file_index;
  i8 *unprocessed_input;
  u8 *output_vector;

  /* socket client only */
  u32 server_handle;
  u32 server_index;

} vl_api_registration_t;


/* Trace configuration for a single message */
typedef struct
{
  int size;
  int trace_enable;
  int replay_enable;
} trace_cfg_t;

/*
 * API recording
 */
typedef struct
{
  u8 endian;
  u8 enabled;
  u8 wrapped;
  u8 pad;
  u32 nitems;
  u32 curindex;
  u8 **traces;
} vl_api_trace_t;

typedef enum
{
  VL_API_TRACE_TX,
  VL_API_TRACE_RX,
} vl_api_trace_which_t;

#define VL_API_LITTLE_ENDIAN 0x00
#define VL_API_BIG_ENDIAN 0x01

typedef struct
{
  u8 *name;
  u16 first_msg_id;
  u16 last_msg_id;
} vl_api_msg_range_t;

typedef struct
{
  int id;
  char *name;
  u32 crc;
  void *handler;
  void *cleanup;
  void *endian;
  void *print;
  int size;
  int traced;
  int replay;
  int message_bounce;
  int is_mp_safe;
} vl_msg_api_msg_config_t;

typedef struct msgbuf_
{
  unix_shared_memory_queue_t *q;
  u32 data_len;
  u32 gc_mark_timestamp;
  u8 data[0];
} msgbuf_t;

/* api_shared.c prototypes */
void vl_msg_api_handler (void *the_msg);
void vl_msg_api_handler_no_free (void *the_msg);
void vl_msg_api_handler_no_trace_no_free (void *the_msg);
void vl_msg_api_trace_only (void *the_msg);
void vl_msg_api_cleanup_handler (void *the_msg);
void vl_msg_api_replay_handler (void *the_msg);
void vl_msg_api_socket_handler (void *the_msg);
void vl_msg_api_set_handlers (int msg_id, char *msg_name,
			      void *handler,
			      void *cleanup,
			      void *endian,
			      void *print, int msg_size, int traced);
void vl_msg_api_config (vl_msg_api_msg_config_t *);
void vl_msg_api_set_cleanup_handler (int msg_id, void *fp);
void vl_msg_api_queue_handler (unix_shared_memory_queue_t * q);

void vl_msg_api_barrier_sync (void) __attribute__ ((weak));
void vl_msg_api_barrier_release (void) __attribute__ ((weak));
#ifdef BARRIER_TRACING
void vl_msg_api_barrier_trace_context (const char *context)
  __attribute__ ((weak));
#else
#define vl_msg_api_barrier_trace_context(X)
#endif
void vl_msg_api_free (void *);
void vl_noop_handler (void *mp);
void vl_msg_api_increment_missing_client_counter (void);
void vl_msg_api_post_mortem_dump (void);
void vl_msg_api_post_mortem_dump_enable_disable (int enable);
void vl_msg_api_register_pd_handler (void *handler,
				     u16 msg_id_host_byte_order);
int vl_msg_api_pd_handler (void *mp, int rv);

void vl_msg_api_set_first_available_msg_id (u16 first_avail);
u16 vl_msg_api_get_msg_ids (const char *name, int n);
u32 vl_api_get_msg_index (u8 * name_and_crc);

typedef clib_error_t *(vl_msg_api_init_function_t) (u32 client_index);

typedef struct _vl_msg_api_init_function_list_elt
{
  struct _vl_msg_api_init_function_list_elt *next_init_function;
  vl_msg_api_init_function_t *f;
} _vl_msg_api_function_list_elt_t;

typedef struct
{
  void (**msg_handlers) (void *);
  int (**pd_msg_handlers) (void *, int);
  void (**msg_cleanup_handlers) (void *);
  void (**msg_endian_handlers) (void *);
  void (**msg_print_handlers) (void *, void *);
  const char **msg_names;
  u8 *message_bounce;
  u8 *is_mp_safe;
  struct ring_alloc_ *arings;
  u32 ring_misses;
  u32 garbage_collects;
  u32 missing_clients;
  vl_api_trace_t *rx_trace;
  vl_api_trace_t *tx_trace;
  int msg_print_flag;
  trace_cfg_t *api_trace_cfg;
  int our_pid;
  svm_region_t *vlib_rp;
  svm_region_t **mapped_shmem_regions;
  struct vl_shmem_hdr_ *shmem_hdr;
  vl_api_registration_t **vl_clients;

  u8 *serialized_message_table_in_shmem;

  /* For plugin msg allocator */
  u16 first_available_msg_id;

  /* message range by name hash */
  uword *msg_range_by_name;

  /* vector of message ranges */
  vl_api_msg_range_t *msg_ranges;

  /* uid for the api shared memory region */
  int api_uid;
  /* gid for the api shared memory region */
  int api_gid;

  /* base virtual address for global VM region */
  u64 global_baseva;

  /* size of the global VM region */
  u64 global_size;

  /* size of the API region */
  u64 api_size;

  /* size of the global VM private mheap */
  u64 global_pvt_heap_size;

  /* size of the api private mheap */
  u64 api_pvt_heap_size;

  /* Client-only data structures */
  unix_shared_memory_queue_t *vl_input_queue;

  /*
   * All VLIB-side message handlers use my_client_index to identify
   * the queue / client. This works in sim replay.
   */
  int my_client_index;
  /*
   * This is the (shared VM) address of the registration,
   * don't use it to id the connection since it can't possibly
   * work in simulator replay.
   */
  vl_api_registration_t *my_registration;

  i32 vlib_signal;

  /* vlib input queue length */
  u32 vlib_input_queue_length;

  /* client side message index hash table */
  uword *msg_index_by_name_and_crc;

  const char *region_name;
  const char *root_path;

  /* Replay in progress? */
  int replay_in_progress;

  /* List of API client reaper functions */
  _vl_msg_api_function_list_elt_t *reaper_function_registrations;

} api_main_t;

extern api_main_t api_main;


#endif /* included_api_common_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
