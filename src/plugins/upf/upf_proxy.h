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

typedef struct
{
  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;

  u64 vpp_server_handle;
  u64 vpp_active_open_handle;
} upf_proxy_session_t;

typedef struct
{
  svm_queue_t *vl_input_queue;	/**< vpe input queue */
  /** per-thread vectors */
  svm_msg_q_t **server_event_queue;
  svm_msg_q_t **active_open_event_queue;
  u8 **rx_buf;				/**< intermediate rx buffers */

  u32 cli_node_index;			/**< cli process node index */
  u32 server_client_index;		/**< server API client handle */
  u32 server_app_index;			/**< server app index */
  u32 active_open_client_index;		/**< active open API client handle */
  u32 active_open_app_index;		/**< active open index after attach */

  uword *session_by_server_handle;
  uword *session_by_active_open_handle;

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
  clib_spinlock_t sessions_lock;
  u32 **connection_index_by_thread;
  pthread_t client_thread_handle;

  /*
   * Flags
   */
  u8 is_init;
  u8 prealloc_fifos;		/**< Request fifo preallocation */

  u32 *ip4_listen_session_by_fib_index;
  u32 *ip6_listen_session_by_fib_index;
} upf_proxy_main_t;

extern upf_proxy_main_t upf_proxy_main;

u32 upf_proxy_create (u32 fib_index, int is_ip4);

static inline u32
upf_proxy_session (u32 fib_index, int is_ip4)
{
  upf_proxy_main_t *pm = &upf_proxy_main;

  if (is_ip4)
    {
      vec_validate_init_empty (pm->ip4_listen_session_by_fib_index,
			       fib_index, ~0);

      if (PREDICT_TRUE
	  (pm->ip4_listen_session_by_fib_index[fib_index] != ~0))
	return pm->ip4_listen_session_by_fib_index[fib_index];
    }
  else
    {
      vec_validate_init_empty (pm->ip6_listen_session_by_fib_index,
			       fib_index, ~0);

      if (PREDICT_TRUE
	  (pm->ip6_listen_session_by_fib_index[fib_index] != ~0))
	return pm->ip6_listen_session_by_fib_index[fib_index];
    }

  return upf_proxy_create (fib_index, is_ip4);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
