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

/** \file api_common.h
 *  API common definitions
 * See api_doc.md for more info
 */

#include <vppinfra/clib_error.h>
#include <vppinfra/elog.h>
#include <vlibapi/api_types.h>
#include <svm/svm_common.h>
#include <svm/queue.h>

/** API registration types
 */
typedef enum
{
  REGISTRATION_TYPE_FREE = 0,
  REGISTRATION_TYPE_SHMEM,	/**< Shared memory connection */
  REGISTRATION_TYPE_SOCKET_LISTEN, /**< Socket listener  */
  REGISTRATION_TYPE_SOCKET_SERVER, /**< Socket server */
  REGISTRATION_TYPE_SOCKET_CLIENT, /**< Socket client */
} vl_registration_type_t;

/** An API client registration, only in vpp/vlib */

typedef struct vl_api_registration_
{
  vl_registration_type_t registration_type; /**< type */

  /** Index in VLIB's brain (not shared memory). */
  u32 vl_api_registration_pool_index;

  u8 *name;			/**< Client name */

  /* Zombie apocalypse checking */
  f64 last_heard;
  int last_queue_head;
  int unanswered_pings;
  int is_being_removed;

  /** shared memory only: pointer to client input queue */
  svm_queue_t *vl_input_queue;
  svm_region_t *vlib_rp;
  void *shmem_hdr;

  /* socket server and client */
  u32 clib_file_index;		/**< Socket only: file index */
  i8 *unprocessed_input;	/**< Socket only: pending input */
  u32 unprocessed_msg_length;	/**< Socket only: unprocssed length */
  u8 *output_vector;		/**< Socket only: output vector */
  int *additional_fds_to_close;

  /* socket client only */
  u32 server_handle;		/**< Socket client only: server handle */
  u32 server_index;		/**< Socket client only: server index */
} vl_api_registration_t;

#define VL_API_INVALID_FI ((u32)~0)

/** Trace configuration for a single message */
typedef struct
{
  int size;			/**< for sanity checking */
  int trace_enable;		/**< trace this message  */
  int replay_enable;		/**< This message can be replayed  */
} trace_cfg_t;

/**
 * API trace state
 */
typedef struct
{
  u8 endian;			/**< trace endianness */
  u8 enabled;			/**< trace is enabled  */
  u8 wrapped;			/**< trace has wrapped */
  u8 pad;
  u32 nitems;			/**< Number of trace records */
  u32 curindex;			/**< Current index in circular buffer  */
  u8 **traces;			/**< Trace ring */
} vl_api_trace_t;

/** Trace RX / TX enum */
typedef enum
{
  VL_API_TRACE_TX,
  VL_API_TRACE_RX,
} vl_api_trace_which_t;

#define VL_API_LITTLE_ENDIAN 0x00
#define VL_API_BIG_ENDIAN 0x01

/** Message range (belonging to a plugin) */
typedef struct
{
  u8 *name;			/**< name of the plugin  */
  u16 first_msg_id;		/**< first assigned message ID */
  u16 last_msg_id;		/**< last assigned message ID */
} vl_api_msg_range_t;

/** Message configuration definition */
typedef struct
{
  int id;			/**< the message ID */
  char *name;			/**< the message name */
  u32 crc;			/**< message definition CRC  */
  void *handler;		/**< the message handler  */
  void *cleanup;		/**< non-default message cleanup handler */
  void *endian;			/**< message endian function  */
  void *print;			/**< message print function  */
  int size;			/**< message size  */
  int traced;			/**< is this message to be traced?  */
  int replay;			/**< is this message to be replayed?  */
  int message_bounce;		/**< do not free message after processing */
  int is_mp_safe;		/**< worker thread barrier required?  */
  int is_autoendian;		/**< endian conversion required?  */
} vl_msg_api_msg_config_t;

/** Message header structure */
typedef struct msgbuf_
{
  svm_queue_t *q; /**< message allocated in this shmem ring  */
  u32 data_len;			 /**< message length not including header  */
  u32 gc_mark_timestamp;	 /**< message garbage collector mark TS  */
  u8 data[0];			 /**< actual message begins here  */
} msgbuf_t;

CLIB_NOSANITIZE_ADDR static inline void
VL_MSG_API_UNPOISON (const void *a)
{
  const msgbuf_t *m = &((const msgbuf_t *) a)[-1];
  CLIB_MEM_UNPOISON (m, sizeof (*m) + ntohl (m->data_len));
}

CLIB_NOSANITIZE_ADDR static inline void
VL_MSG_API_SVM_QUEUE_UNPOISON (const svm_queue_t * q)
{
  CLIB_MEM_UNPOISON (q, sizeof (*q) + q->elsize * q->maxsize);
}

static inline void
VL_MSG_API_POISON (const void *a)
{
  const msgbuf_t *m = &((const msgbuf_t *) a)[-1];
  CLIB_MEM_POISON (m, sizeof (*m) + ntohl (m->data_len));
}

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
void vl_msg_api_clean_handlers (int msg_id);
void vl_msg_api_config (vl_msg_api_msg_config_t *);
void vl_msg_api_set_cleanup_handler (int msg_id, void *fp);
void vl_msg_api_queue_handler (svm_queue_t * q);

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
u32 vl_msg_api_get_msg_index (u8 * name_and_crc);
void *vl_msg_push_heap (void);
void *vl_msg_push_heap_w_region (svm_region_t * vlib_rp);
void vl_msg_pop_heap (void *oldheap);
void vl_msg_pop_heap_w_region (svm_region_t * vlib_rp, void *oldheap);

typedef clib_error_t *(vl_msg_api_init_function_t) (u32 client_index);

typedef struct _vl_msg_api_init_function_list_elt
{
  struct _vl_msg_api_init_function_list_elt *next_init_function;
  vl_msg_api_init_function_t *f;
} _vl_msg_api_function_list_elt_t;

typedef struct
{
  u32 major;
  u32 minor;
  u32 patch;
  char name[64];
} api_version_t;

/** API main structure, used by both vpp and binary API clients */
typedef struct api_main_t
{
  /** Message handler vector  */
  void (**msg_handlers) (void *);
  /** Plaform-dependent (aka hardware) message handler vector */
  int (**pd_msg_handlers) (void *, int);

  /** non-default message cleanup handler vector */
  void (**msg_cleanup_handlers) (void *);

  /** Message endian handler vector */
  void (**msg_endian_handlers) (void *);

  /** Message print function vector */
  void (**msg_print_handlers) (void *, void *);

  /** Message name vector */
  const char **msg_names;

  /** Don't automatically free message buffer vetor */
  u8 *message_bounce;

  /** Message is mp safe vector */
  u8 *is_mp_safe;

  /** Message requires us to do endian conversion */
  u8 *is_autoendian;

  /** Allocator ring vectors (in shared memory) */
  struct ring_alloc_ *arings;

  /** Number of times that the ring allocator failed */
  u32 ring_misses;

  /** Number of garbage-collected message buffers */
  u32 garbage_collects;

  /** Number of missing clients / failed message sends */
  u32 missing_clients;

  /** Received message trace configuration */
  vl_api_trace_t *rx_trace;

  /** Sent message trace configuration */
  vl_api_trace_t *tx_trace;

  /** Print every received message */
  int msg_print_flag;

  /** Current trace configuration */
  trace_cfg_t *api_trace_cfg;

  /** Current process PID */
  int our_pid;

  /** Current binary api segment descriptor */
  svm_region_t *vlib_rp;

  /** Primary api segment descriptor */
  svm_region_t *vlib_primary_rp;

  /** Vector of all mapped shared-VM segments */
  svm_region_t **vlib_private_rps;
  svm_region_t **mapped_shmem_regions;

  /** Binary API shared-memory segment header pointer */
  struct vl_shmem_hdr_ *shmem_hdr;

  /** vlib/vpp only: vector of client registrations */
  vl_api_registration_t **vl_clients;

  /** vlib/vpp only: serialized (message, name, crc) table */
  u8 *serialized_message_table_in_shmem;

  /** First available message ID, for theplugin msg allocator */
  u16 first_available_msg_id;

  /** Message range by name hash */
  uword *msg_range_by_name;

  /** vector of message ranges */
  vl_api_msg_range_t *msg_ranges;

  /** uid for the api shared memory region */
  int api_uid;

  /** gid for the api shared memory region */
  int api_gid;

  /** base virtual address for global VM region */
  u64 global_baseva;

  /** size of the global VM region */
  u64 global_size;

  /** size of the API region */
  u64 api_size;

  /** size of the global VM private mheap */
  u64 global_pvt_heap_size;

  /** size of the api private mheap */
  u64 api_pvt_heap_size;

  /** Peer input queue pointer */
  svm_queue_t *vl_input_queue;

  /**
   * All VLIB-side message handlers use my_client_index to identify
   * the queue / client. This works in sim replay.
   */
  int my_client_index;
  /**
   * This is the (shared VM) address of the registration,
   * don't use it to id the connection since it can't possibly
   * work in simulator replay.
   */
  vl_api_registration_t *my_registration;

  /** vpp/vlib input queue length */
  u32 vlib_input_queue_length;

  /** client message index hash table */
  uword *msg_index_by_name_and_crc;

  /** api version list */
  api_version_t *api_version_list;

  /** Shared VM binary API region name */
  const char *region_name;

  /** Chroot path to the shared memory API files */
  const char *root_path;

  /** Replay in progress? */
  int replay_in_progress;

  /** Dump (msg-name, crc) snapshot here at startup */
  u8 *save_msg_table_filename;

  /** List of API client reaper functions */
  _vl_msg_api_function_list_elt_t *reaper_function_registrations;

  /** Bin API thread handle */
  pthread_t rx_thread_handle;

  /** event log */
  elog_main_t *elog_main;
  int elog_trace_api_messages;

  /** performance counter callback **/
  void (**perf_counter_cbs)
    (struct api_main_t *, u32 id, int before_or_after);
  void (**perf_counter_cbs_tmp)
    (struct api_main_t *, u32 id, int before_or_after);

} api_main_t;

extern __thread api_main_t *my_api_main;
extern api_main_t api_global_main;

always_inline api_main_t *
vlibapi_get_main (void)
{
  return my_api_main;
}

always_inline void
vlibapi_set_main (api_main_t * am)
{
  my_api_main = am;
}

#endif /* included_api_common_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
