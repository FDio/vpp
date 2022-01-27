
/*
 * http_static.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) <current-year> <your-organization>
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
#ifndef __included_http_static_h__
#define __included_http_static_h__

//#include <vnet/vnet.h>
//#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
//#include <vnet/ip/ip.h>
//#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
//#include <vppinfra/time_range.h>
//#include <vppinfra/tw_timer_2t_1w_2048sl.h>
#include <vppinfra/bihash_vec8_8.h>

/** @file http_static.h
 * Static http server definitions
 */

//typedef struct
//{
//  /* API message ID base */
//  u16 msg_id_base;
//
//  /* convenience */
//  vlib_main_t *vlib_main;
//  vnet_main_t *vnet_main;
//} http_static_main_t;
//
//extern http_static_main_t http_static_main;

///** \brief Session States
// */
//
// typedef enum
//{
//  /** Session is closed */
//  HTTP_STATE_CLOSED,
//  /** Session is established */
//  HTTP_STATE_ESTABLISHED,
//  /** Session has sent an OK response */
//  HTTP_STATE_OK_SENT,
//  /** Session has sent an HTML response */
//  HTTP_STATE_SEND_MORE_DATA,
//  /** Number of states */
//  HTTP_STATE_N_STATES,
//} http_session_state_t;

typedef enum
{
  HTTP_BUILTIN_METHOD_GET = 0,
  HTTP_BUILTIN_METHOD_POST,
} http_builtin_method_type_t;

/** \brief Application session
 */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /** Base class instance variables */
//#define _(type, name) type name;
//  foreach_app_session_field
//#undef _
  u32 session_index;
  /** rx thread index */
  u32 thread_index;
  /** rx buffer */
  u8 *rx_buf;
  /** vpp session index, handle */
  u32 vpp_session_index;
  session_handle_t vpp_session_handle;
  //  /** Timeout timer handle */
  //  u32 timer_handle;
  /** Fully-resolved file path */
  u8 *path;
  /** File data, a vector */
  u8 *data;
  /** Current data send offset */
  u32 data_offset;
  /** Need to free data in detach_cache_entry */
  int free_data;
  /** File cache pool index */
  u32 cache_pool_index;
} hss_session_t;

/** \brief In-memory file data cache entry
 */
typedef struct
{
  /** Name of the file */
  u8 *filename;
  /** Contents of the file, as a u8 * vector */
  u8 *data;
  /** Last time the cache entry was used */
  f64 last_used;
  /** Cache LRU links */
  u32 next_index;
  u32 prev_index;
  /** Reference count, so we don't recycle while referenced */
  int inuse;
} file_data_cache_t;

/** \brief Main data structure
 */

typedef struct
{
  /** Per thread vector of session pools */
  hss_session_t **sessions;
  /** Session pool reader writer lock */
  clib_spinlock_t cache_lock;

  /** Enable debug messages */
  int debug_level;

  /** Unified file data cache pool */
  file_data_cache_t *cache_pool;
  /** Hash table which maps file name to file data */
    BVT (clib_bihash) name_to_data;

  /** Hash tables for built-in GET and POST handlers */
  uword *get_url_handlers;
  uword *post_url_handlers;

  /** Current cache size */
  u64 cache_size;
  /** Max cache size in bytes */
  u64 cache_limit;
  /** Number of cache evictions */
  u64 cache_evictions;

  /** Cache LRU listheads */
  u32 first_index;
  u32 last_index;

  /** root path to be served */
  u8 *www_root;

  /** Application index */
  u32 app_index;

  /** Cert and key pair for tls */
  u32 ckpair_index;

  /* API message ID base */
  u16 msg_id_base;

  vlib_main_t *vlib_main;

  /*
   * Config
   */

  /** Number of preallocated fifos, usually 0 */
  u32 prealloc_fifos;
  /** Private segment size, usually 0 */
  u64 private_segment_size;
  /** Size of the allocated rx, tx fifos, roughly 8K or so */
  u32 fifo_size;
  /** The bind URI, defaults to tcp://0.0.0.0/80 */
  u8 *uri;
  /** Threshold for switching to ptr data in http msgs */
  u32 use_ptr_thresh;
} hss_main_t;

extern hss_main_t hss_main;

int hss_create (vlib_main_t *vm);

void http_static_server_register_builtin_handler
  (void *fp, char *url, int type);

#endif /* __included_http_static_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
