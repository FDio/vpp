/*
 *------------------------------------------------------------------
 * api.h
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

#ifndef included_api_h
#define included_api_h

#include <vppinfra/error.h>
#include <svm/svm.h>
#include <vlib/vlib.h>
#include <vlibmemory/unix_shared_memory_queue.h>
#include <vlib/unix/unix.h>
#include <stddef.h>

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
  u32 unix_file_index;
  i8 *unprocessed_input;
  u32 unprocessed_msg_length;
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

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct
 {
   u8 endian; u8 wrapped;
   u32 nitems;
}) vl_api_trace_file_header_t;
/* *INDENT-ON* */

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
int vl_msg_api_rx_trace_enabled (api_main_t * am);
int vl_msg_api_tx_trace_enabled (api_main_t * am);
void vl_msg_api_trace (api_main_t * am, vl_api_trace_t * tp, void *msg);
int vl_msg_api_trace_onoff (api_main_t * am, vl_api_trace_which_t which,
			    int onoff);
int vl_msg_api_trace_free (api_main_t * am, vl_api_trace_which_t which);
int vl_msg_api_trace_save (api_main_t * am,
			   vl_api_trace_which_t which, FILE * fp);
int vl_msg_api_trace_configure (api_main_t * am, vl_api_trace_which_t which,
				u32 nitems);
void vl_msg_api_handler_with_vm_node (api_main_t * am,
				      void *the_msg, vlib_main_t * vm,
				      vlib_node_runtime_t * node);
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
vl_api_trace_t *vl_msg_api_trace_get (api_main_t * am,
				      vl_api_trace_which_t which);

void vl_msg_api_barrier_sync (void) __attribute__ ((weak));
void vl_msg_api_barrier_release (void) __attribute__ ((weak));
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
void vl_msg_api_add_msg_name_crc (api_main_t * am, const char *string,
				  u32 id);
u32 vl_api_get_msg_index (u8 * name_and_crc);
u32 vl_msg_api_get_msg_length (void *msg_arg);

/* node_serialize.c prototypes */
u8 *vlib_node_serialize (vlib_node_main_t * nm, u8 * vector,
			 u32 max_threads, int include_nexts,
			 int include_stats);
vlib_node_t **vlib_node_unserialize (u8 * vector);

#define VLIB_API_INIT_FUNCTION(x) VLIB_DECLARE_INIT_FUNCTION(x,api_init)

/* Call given init function: used for init function dependencies. */
#define vlib_call_api_init_function(vm, x)                              \
  ({                                                                    \
    extern vlib_init_function_t * _VLIB_INIT_FUNCTION_SYMBOL (x,api_init); \
    vlib_init_function_t * _f = _VLIB_INIT_FUNCTION_SYMBOL (x,api_init); \
    clib_error_t * _error = 0;                                          \
    if (! hash_get (vm->init_functions_called, _f))                     \
      {                                                                 \
	hash_set1 (vm->init_functions_called, _f);                      \
	_error = _f (vm);                                               \
      }                                                                 \
    _error;                                                             \
  })


#define _VL_MSG_API_FUNCTION_SYMBOL(x, type)	\
  _vl_msg_api_##type##_function_##x

#define VL_MSG_API_FUNCTION_SYMBOL(x)		\
  _VL_MSG_API_FUNCTION_SYMBOL(x, reaper)

#define VLIB_DECLARE_REAPER_FUNCTION(x, tag)                            \
vl_msg_api_init_function_t * _VL_MSG_API_FUNCTION_SYMBOL (x, tag) = x;  \
static void __vl_msg_api_add_##tag##_function_##x (void)                \
    __attribute__((__constructor__)) ;                                  \
                                                                        \
static void __vl_msg_api_add_##tag##_function_##x (void)                \
{                                                                       \
 api_main_t * am = &api_main;                                           \
 static _vl_msg_api_function_list_elt_t _vl_msg_api_function;           \
 _vl_msg_api_function.next_init_function                                \
    = am->tag##_function_registrations;                                 \
  am->tag##_function_registrations = &_vl_msg_api_function;             \
 _vl_msg_api_function.f = &x;                                           \
}

#define VL_MSG_API_REAPER_FUNCTION(x) VLIB_DECLARE_REAPER_FUNCTION(x,reaper)

/* Call reaper function with client index */
#define vl_msg_api_call_reaper_function(ci)                             \
  ({                                                                    \
    extern vlib_init_function_t * VLIB_INIT_FUNCTION_SYMBOL (reaper);   \
    vlib_init_function_t * _f = VLIB_INIT_FUNCTION_SYMBOL (reaper);     \
    clib_error_t * _error = 0;                                          \
    _error = _f (ci);                                                   \
  })

static inline u32
vl_msg_api_get_msg_length_inline (void *msg_arg)
{
  u8 *msg = (u8 *) msg_arg;

  msgbuf_t *header = (msgbuf_t *) (msg - offsetof (msgbuf_t, data));

  return clib_net_to_host_u32 (header->data_len);
}
#endif /* included_api_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
