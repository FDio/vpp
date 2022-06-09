
/*
 * builtin_proxy.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
#ifndef __included_proxy_h__
#define __included_proxy_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

typedef struct
{
  svm_fifo_t *server_rx_fifo;
  svm_fifo_t *server_tx_fifo;

  session_handle_t vpp_server_handle;
  session_handle_t vpp_active_open_handle;
  volatile int active_open_establishing;
  volatile int po_disconnected;
  volatile int ao_disconnected;

  u32 ps_index;
  u32 po_thread_index;
} proxy_session_t;

typedef struct
{
  proxy_session_t *sessions;		/**< session pool, shared */
  clib_spinlock_t sessions_lock;	/**< lock for session pool */
  u8 **rx_buf;				/**< intermediate rx buffers */

  u32 server_client_index;		/**< server API client handle */
  u32 server_app_index;			/**< server app index */
  u32 active_open_client_index;		/**< active open API client handle */
  u32 active_open_app_index;		/**< active open index after attach */
  u32 ckpair_index;			/**< certkey pair index for tls */

  /*
   * Configuration params
   */
  u32 fifo_size;			/**< initial fifo size */
  u32 max_fifo_size;			/**< max fifo size */
  u8 high_watermark;			/**< high watermark (%) */
  u8 low_watermark;			/**< low watermark (%) */
  u32 private_segment_count;		/**< Number of private fifo segs */
  u64 segment_size;			/**< size of fifo segs */
  u8 prealloc_fifos;			/**< Request fifo preallocation */
  int rcv_buffer_size;
  session_endpoint_cfg_t server_sep;
  session_endpoint_cfg_t client_sep;

  /*
   * Flags
   */
  u8 is_init;
} proxy_main_t;

extern proxy_main_t proxy_main;

#endif /* __included_proxy_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
