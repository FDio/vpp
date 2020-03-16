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
  u32 configured_segment_size;
  u32 fifo_size;
  u32 private_segment_count;		/**< Number of private fifo segs */
  u32 private_segment_size;		/**< size of private fifo segs */
  int rcv_buffer_size;

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
  u8 prealloc_fifos;		/**< Request fifo preallocation */
} upf_proxy_main_t;

extern upf_proxy_main_t upf_proxy_main;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
