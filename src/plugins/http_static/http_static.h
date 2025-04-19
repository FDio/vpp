/*
 * Copyright (c) 2017-2022 Cisco and/or its affiliates.
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

#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <http/http.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <http_static/http_cache.h>

#define HSS_DEFAULT_MAX_AGE 600
#define HSS_DEFAULT_MAX_BODY_SIZE     8192
#define HSS_DEFAULT_RX_BUFFER_THRESH  1 << 20
#define HSS_DEFAULT_KEEPALIVE_TIMEOUT 60

/** @file http_static.h
 * Static http server definitions
 */

/** \brief Application session
 */
typedef struct hss_session_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 session_index;
  /** rx thread index */
  clib_thread_index_t thread_index;
  /** vpp session index, handle */
  u32 vpp_session_index;
  session_handle_t vpp_session_handle;
  /** Index of listener for which connection was accepted */
  u32 listener_index;
  u8 *target_path;
  u8 *target_query;
  http_req_method_t rt;
  /** Fully-resolved file path */
  u8 *path;
  /** Data to send */
  u8 *data;
  /** Data length */
  u64 data_len;
  /** Current data send offset */
  u64 data_offset;
  /** Need to free data in detach_cache_entry */
  int free_data;
  /** File cache pool index */
  u32 cache_pool_index;
  /** Response header ctx */
  http_headers_ctx_t resp_headers;
  /** Response header buffer */
  u8 *headers_buf;
  /** RX buffer (POST body) */
  u8 *rx_buff;
  /** Current RX buffer offset */
  u64 rx_buff_offset;
  /** POST body left to receive */
  u64 left_recv;
  /** threshold for switching to pointers */
  u64 use_ptr_thresh;
  int (*read_body_handler) (struct hss_session_ *hs, session_t *ts);
} hss_session_t;

typedef struct hss_session_handle_
{
  union
  {
    struct
    {
      u32 session_index;
      clib_thread_index_t thread_index;
    };
    u64 as_u64;
  };
} hss_session_handle_t;

STATIC_ASSERT_SIZEOF (hss_session_handle_t, sizeof (u64));


typedef struct hss_url_handler_args_
{
  hss_session_handle_t sh;

  union
  {
    /* Request args */
    struct
    {
      u8 *query;
      u8 *req_data;
      http_req_method_t req_type;
    };

    /* Reply args */
    struct
    {
      u8 *data;
      uword data_len;
      u8 free_vec_data;
      http_status_code_t sc;
      http_content_type_t ct;
    };
  };
} hss_url_handler_args_t;

typedef enum hss_url_handler_rc_
{
  HSS_URL_HANDLER_OK,
  HSS_URL_HANDLER_ERROR,
  HSS_URL_HANDLER_ASYNC,
} hss_url_handler_rc_t;

typedef hss_url_handler_rc_t (*hss_url_handler_fn) (hss_url_handler_args_t *);
typedef void (*hss_register_url_fn) (hss_url_handler_fn, char *, int);
typedef void (*hss_session_send_fn) (hss_url_handler_args_t *args);

typedef struct hss_listener_
{
  /** Path to file hash table */
  hss_cache_t cache;
  /** The bind session endpoint e.g., tcp://0.0.0.0:80 */
  session_endpoint_cfg_t sep;
  /** root path to be served */
  u8 *www_root;
  /** Threshold for switching to ptr data in http msgs */
  u64 use_ptr_thresh;
  /** Max cache size before LRU occurs */
  u64 cache_size;
  /** Maximum size of a request body (in bytes) **/
  u64 max_body_size;
  /** Maximum size of a large memory allocation */
  u32 rx_buff_thresh;
  /** Timeout during which client connection will stay open */
  u32 keepalive_timeout;
  /** How long a response is considered fresh (in seconds) */
  u32 max_age;
  /** Formatted max_age: "max-age=xyz" */
  u8 *max_age_formatted;
  /** Enable the use of builtinurls */
  u8 enable_url_handlers;
  /** Index in listener pool */
  u32 l_index;
  /** Listener session handle */
  session_handle_t session_handle;
} hss_listener_t;

/** \brief Main data structure
 */
typedef struct
{
  /** Per thread vector of session pools */
  hss_session_t **sessions;

  /** Listeners pool */
  hss_listener_t *listeners;

  /** Hash tables for built-in GET and POST handlers */
  uword *get_url_handlers;
  uword *post_url_handlers;

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

  /** Listener configured with server, if any */
  hss_listener_t default_listener;
  u8 have_default_listener;
  u8 is_init;

  /** Enable debug messages */
  int debug_level;
  /** Number of preallocated fifos, usually 0 */
  u32 prealloc_fifos;
  /** Private segment size, usually 0 */
  u64 private_segment_size;
  /** Size of the allocated rx, tx fifos, roughly 8K or so */
  u32 fifo_size;

  /** hash table of file extensions to mime types string indices */
  uword *mime_type_indices_by_file_extensions;
} hss_main_t;

extern hss_main_t hss_main;

int hss_create (vlib_main_t *vm);

static inline hss_listener_t *
hss_listener_get (u32 l_index)
{
  hss_main_t *hsm = &hss_main;

  if (pool_is_free_index (hsm->listeners, l_index))
    return 0;
  return pool_elt_at_index (hsm->listeners, l_index);
}

/**
 * Register a GET or POST URL handler
 */
void hss_register_url_handler (hss_url_handler_fn fp, const char *url,
			       http_req_method_t type);
void hss_session_send_data (hss_url_handler_args_t *args);
void hss_builtinurl_json_handlers_init (void);
hss_session_t *hss_session_get (clib_thread_index_t thread_index,
				u32 hs_index);

#endif /* __included_http_static_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
