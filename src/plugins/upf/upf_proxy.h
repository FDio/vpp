/*
 * upf_proxy.h - 3GPP TS 29.244 GTP-U UP plug-in header file
 *
 * Copyright (c) 2018,2019 Travelping GmbH
 *
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
#ifndef __included_upf_proxy_h__
#define __included_upf_proxy_h__

#include <vnet/vnet.h>
#include <vnet/session/application.h>

extern vlib_node_registration_t upf_ip4_proxy_server_output_node;
extern vlib_node_registration_t upf_ip6_proxy_server_output_node;

typedef struct
{
  svm_fifo_t *rx_fifo;
  svm_fifo_t *tx_fifo;

  u32 session_index;

  u32 proxy_session_index;
  u32 proxy_thread_index;
  u32 active_open_session_index;
  u32 active_open_thread_index;

  u32 flow_index;

  u8 *rx_buf;				/**< intermediate rx buffers */
} upf_proxy_session_t;

#define foreach_upf_proxy_config_fields						\
  _(u16, mss)				/**< TCP MSS */				\
  _(uword, fifo_size)			/**< initial fifo size */		\
  _(uword, max_fifo_size)			/**< max fifo size */			\
  _(u8, high_watermark)			/**< high watermark (%) */		\
  _(u8, low_watermark)			/**< low watermark (%) */		\
  _(u32, private_segment_count)		/**< Number of private fifo segs */	\
  _(uword, private_segment_size)		/**< size of private fifo segs */	\
  _(u8, prealloc_fifos)			/**< Request fifo preallocation */	\

typedef struct
{
  u16 tcp4_server_output_next;
  u16 tcp6_server_output_next;

  svm_queue_t *vl_input_queue;	/**< vpe input queue */
  /** per-thread vectors */
  svm_msg_q_t **server_event_queue;
  svm_msg_q_t **active_open_event_queue;

  u32 cli_node_index;			/**< cli process node index */
  u32 server_client_index;		/**< server API client handle */
  u32 server_app_index;			/**< server app index */
  u32 active_open_client_index;		/**< active open API client handle */
  u32 active_open_app_index;		/**< active open index after attach */

  u32 **session_to_proxy_session;
  u32 **session_to_active_open_session;

  /*
   * Configuration params
   */
  /* *INDENT-OFF* */
#define _(type, name) type name;
  foreach_upf_proxy_config_fields
#undef _
  /* *INDENT-ON* */

  /*
   * Test state variables
   */
  upf_proxy_session_t *sessions;	/**< Session pool, shared */
  clib_rwlock_t sessions_lock;
  u32 **connection_index_by_thread;
  pthread_t client_thread_handle;

  /*
   * Flags
   */
  u8 is_init;
} upf_proxy_main_t;

extern upf_proxy_main_t upf_proxy_main;

static inline void
proxy_server_sessions_reader_lock (void)
{
  clib_rwlock_reader_lock (&upf_proxy_main.sessions_lock);
}

static inline void
proxy_server_sessions_reader_unlock (void)
{
  clib_rwlock_reader_unlock (&upf_proxy_main.sessions_lock);
}

static inline void
proxy_server_sessions_writer_lock (void)
{
  clib_rwlock_writer_lock (&upf_proxy_main.sessions_lock);
}

static inline void
proxy_server_sessions_writer_unlock (void)
{
  clib_rwlock_writer_unlock (&upf_proxy_main.sessions_lock);
}

static inline upf_proxy_session_t *
proxy_session_get (u32 ps_index)
{
  upf_proxy_main_t *pm = &upf_proxy_main;

  if (pool_is_free_index (pm->sessions, ps_index))
    return 0;
  return pool_elt_at_index (pm->sessions, ps_index);
}

static inline upf_proxy_session_t *
proxy_session_lookup_by_index (u32 session_index, u32 thread_index)
{
  upf_proxy_main_t *pm = &upf_proxy_main;
  u32 ps_index;

  if (session_index < vec_len (pm->session_to_proxy_session[thread_index]))
    {
      ps_index = pm->session_to_proxy_session[thread_index][session_index];
      return proxy_session_get (ps_index);
    }
  return 0;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
