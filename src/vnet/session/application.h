/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_SESSION_APPLICATION_H_
#define SRC_VNET_SESSION_APPLICATION_H_

#include <vnet/vnet.h>
#include <vnet/session/session.h>

typedef enum
{
  APP_SERVER,
  APP_CLIENT
} application_type_t;

typedef struct _stream_session_cb_vft
{
  /** Notify server of new segment */
  int (*add_segment_callback) (u32 api_client_index, const u8 * seg_name,
			       u32 seg_size);

  /** Notify server of newly accepted session */
  int (*session_accept_callback) (stream_session_t * new_session);

  /* Connection request callback */
  int (*session_connected_callback) (u32 api_client_index,
				     stream_session_t * s, u8 code);

  /** Notify app that session is closing */
  void (*session_disconnect_callback) (stream_session_t * s);

  /** Notify app that session was reset */
  void (*session_reset_callback) (stream_session_t * s);

  /* Direct RX callback, for built-in servers */
  int (*builtin_server_rx_callback) (stream_session_t * session);

  /* Redirect connection to local server */
  int (*redirect_connect_callback) (u32 api_client_index, void *mp);
} session_cb_vft_t;

typedef struct _application
{
  /** Index in server pool */
  u32 index;

  /** Flags */
  u32 flags;

  /** Binary API connection index, ~0 if internal */
  u32 api_client_index;

  /* */
  u32 api_context;

  /** Application listens for events on this svm queue */
  unix_shared_memory_queue_t *event_queue;

  /** Stream session type */
  u8 session_type;

  /* Stream server mode: accept or connect */
  u8 mode;

  u32 session_manager_index;

  /*
   * Bind/Listen specific
   */

  /** Accept cookie, for multiple session flavors ($$$ maybe) */
  u32 accept_cookie;

  /** Index of the listen session or connect session */
  u32 session_index;

  /** Session thread index for client connect sessions */
  u32 thread_index;

  /*
   * Callbacks: shoulder-taps for the server/client
   */
  session_cb_vft_t cb_fns;
} application_t;

application_t *application_new (application_type_t type, session_type_t sst,
				u32 api_client_index, u32 flags,
				session_cb_vft_t * cb_fns);
void application_del (application_t * app);
application_t *application_get (u32 index);
application_t *application_lookup (u32 api_client_index);
u32 application_get_index (application_t * app);

int
application_server_init (application_t * server, u32 segment_size,
			 u32 add_segment_size, u32 rx_fifo_size,
			 u32 tx_fifo_size, u8 ** segment_name);
int application_api_queue_is_full (application_t * app);

#endif /* SRC_VNET_SESSION_APPLICATION_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
