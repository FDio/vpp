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
#include <vnet/session/segment_manager.h>

typedef enum
{
  APP_SERVER,
  APP_CLIENT,
  APP_N_TYPES
} application_type_t;

typedef struct _stream_session_cb_vft
{
  /** Notify server of new segment */
  int (*add_segment_callback) (u32 api_client_index, const u8 * seg_name,
			       u32 seg_size);

  /** Notify server of newly accepted session */
  int (*session_accept_callback) (stream_session_t * new_session);

  /* Connection request callback */
  int (*session_connected_callback) (u32 app_index, u32 opaque,
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

  /*
   * Binary API interface to external app
   */

  /** Binary API connection index, ~0 if internal */
  u32 api_client_index;

  /** Application listens for events on this svm queue */
  unix_shared_memory_queue_t *event_queue;

  /*
   * Callbacks: shoulder-taps for the server/client
   */

  session_cb_vft_t cb_fns;

  /*
   * svm segment management
   */
  u32 connects_seg_manager;

  /** Lookup tables for listeners. Value is segment manager index */
  uword *listeners_table;

  /** First segment manager has in the the first segment the application's
   * event fifo. Depending on what the app does, it may be either used for
   * a listener or for connects. */
  u32 first_segment_manager;
  u8 first_segment_manager_in_use;

  /** Segment manager properties. Shared by all segment managers */
  segment_manager_properties_t sm_properties;
} application_t;

#define APP_INVALID_SEGMENT_MANAGER_INDEX ((u32) ~0)

application_t *application_new ();
int
application_init (application_t * app, u32 api_client_index, u64 * options,
		  session_cb_vft_t * cb_fns);
void application_del (application_t * app);
application_t *application_get (u32 index);
application_t *application_get_if_valid (u32 index);
application_t *application_lookup (u32 api_client_index);
u32 application_get_index (application_t * app);

int
application_start_listen (application_t * app, session_type_t session_type,
			  transport_endpoint_t * tep, u64 * handle);
int application_stop_listen (application_t * srv, u64 handle);
int
application_open_session (application_t * app, session_type_t sst,
			  transport_endpoint_t * tep, u32 api_context);
int application_api_queue_is_full (application_t * app);

segment_manager_t *application_get_listen_segment_manager (application_t *
							   app,
							   stream_session_t *
							   s);
segment_manager_t *application_get_connect_segment_manager (application_t *
							    app);
int application_is_proxy (application_t * app);
int application_add_segment_notify (u32 app_index, u32 fifo_segment_index);

#endif /* SRC_VNET_SESSION_APPLICATION_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
