
/*
 * builtin_proxy.h - skeleton vpp engine plug-in header file
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
#ifndef __included_builtin_proxy_h__
#define __included_builtin_proxy_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vlibmemory/unix_shared_memory_queue.h>
#include <svm/svm_fifo_segment.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

typedef struct
{
  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;

  u64 vpp_server_handle;
  u64 vpp_active_open_handle;
} proxy_session_t;

typedef struct
{
  unix_shared_memory_queue_t *vl_input_queue;	/**< vpe input queue */
  /** per-thread vectors */
  unix_shared_memory_queue_t **server_event_queue;
  unix_shared_memory_queue_t **active_open_event_queue;
  u8 **rx_buf;				/**< intermediate rx buffers */

  u32 cli_node_index;			/**< cli process node index */
  u32 server_client_index;		/**< server API client handle */
  u32 server_app_index;			/**< server app index */
  u32 active_open_client_index;		/**< active open API client handle */
  u32 active_open_app_index;		/**< active open index after attach */

  uword *proxy_session_by_server_handle;
  uword *proxy_session_by_active_open_handle;

  /*
   * Configuration params
   */
  u8 *connect_uri;			/**< URI for slave's connect */
  u32 configured_segment_size;
  u32 fifo_size;
  u32 private_segment_count;		/**< Number of private fifo segs */
  u32 private_segment_size;		/**< size of private fifo segs */
  int rcv_buffer_size;

  /*
   * Test state variables
   */
  proxy_session_t *sessions;		/**< Session pool, shared */
  clib_spinlock_t sessions_lock;
  u32 **connection_index_by_thread;
  pthread_t client_thread_handle;

  /*
   * Flags
   */
  u8 is_init;
  u8 prealloc_fifos;		/**< Request fifo preallocation */

  /*
   * Convenience
   */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;
} builtin_proxy_main_t;

builtin_proxy_main_t builtin_proxy_main;

#endif /* __included_builtin_proxy_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
