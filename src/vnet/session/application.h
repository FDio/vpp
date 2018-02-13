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
#include <vnet/session/application_namespace.h>
typedef enum
{
  APP_SERVER,
  APP_CLIENT,
  APP_N_TYPES
} application_type_t;

typedef struct _stream_session_cb_vft
{
  /** Notify server of new segment */
  int (*add_segment_callback) (u32 api_client_index,
			       const ssvm_private_t * ssvm_seg);
  /** Notify server of new segment */
  int (*del_segment_callback) (u32 api_client_index,
			       const ssvm_private_t * ssvm_seg);

  /** Notify server of newly accepted session */
  int (*session_accept_callback) (stream_session_t * new_session);

  /** Connection request callback */
  int (*session_connected_callback) (u32 app_index, u32 opaque,
				     stream_session_t * s, u8 code);

  /** Notify app that session is closing */
  void (*session_disconnect_callback) (stream_session_t * s);

  /** Notify app that session was reset */
  void (*session_reset_callback) (stream_session_t * s);

  /** Direct RX callback, for built-in servers */
  int (*builtin_server_rx_callback) (stream_session_t * session);

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

  /** Namespace the application belongs to */
  u32 ns_index;

  /** Application listens for events on this svm queue */
  svm_queue_t *event_queue;

  /*
   * Callbacks: shoulder-taps for the server/client
   */

  session_cb_vft_t cb_fns;

  /*
   * ssvm (fifo) segment management
   */
  /** Segment manager used for outgoing connects issued by the app */
  u32 connects_seg_manager;

  /** Lookup tables for listeners. Value is segment manager index */
  uword *listeners_table;

  /**
   * First segment manager has in the the first segment the application's
   * event fifo. Depending on what the app does, it may be either used for
   * a listener or for connects.
   */
  u32 first_segment_manager;
  u8 first_segment_manager_in_use;

  /** Segment manager properties. Shared by all segment managers */
  segment_manager_properties_t sm_properties;

  u16 proxied_transports;

  /*
   * Local "cut through" connections specific
   */

  /** Segment manager used for incoming "cut through" connects */
  u32 local_segment_manager;

  /** Pool of local listen sessions */
  local_session_t *local_listen_sessions;

  /** Pool of local sessions the app owns (as a server) */
  local_session_t *local_sessions;

  /** Hash table of the app's local connects */
  uword *local_connects;
} application_t;

#define APP_INVALID_INDEX ((u32)~0)
#define APP_NS_INVALID_INDEX ((u32)~0)
#define APP_INVALID_SEGMENT_MANAGER_INDEX ((u32) ~0)

application_t *application_new ();
int application_init (application_t * app, u32 api_client_index,
		      u64 * options, session_cb_vft_t * cb_fns);
void application_del (application_t * app);
application_t *application_get (u32 index);
application_t *application_get_if_valid (u32 index);
application_t *application_lookup (u32 api_client_index);
u32 application_get_index (application_t * app);

int application_start_listen (application_t * app,
			      session_endpoint_t * tep,
			      session_handle_t * handle);
int application_start_local_listen (application_t * server,
				    session_endpoint_t * sep,
				    session_handle_t * handle);
int application_stop_listen (application_t * srv, session_handle_t handle);
int application_stop_local_listen (application_t * server,
				   session_handle_t listener_handle);
int application_open_session (application_t * app, session_endpoint_t * tep,
			      u32 api_context);
int application_api_queue_is_full (application_t * app);

segment_manager_t *application_get_listen_segment_manager (application_t *
							   app,
							   stream_session_t *
							   ls);
segment_manager_t *application_get_connect_segment_manager (application_t *
							    app);
int application_is_proxy (application_t * app);
int application_is_builtin (application_t * app);
int application_is_builtin_proxy (application_t * app);
int application_add_segment_notify (u32 app_index, ssvm_private_t * fs);
u32 application_session_table (application_t * app, u8 fib_proto);
u32 application_local_session_table (application_t * app);
u8 *application_name_from_index (u32 app_index);

u8 application_has_local_scope (application_t * app);
u8 application_has_global_scope (application_t * app);
u32 application_n_listeners (application_t * app);
stream_session_t *application_first_listener (application_t * app,
					      u8 fib_proto,
					      u8 transport_proto);
void application_setup_proxy (application_t * app);
void application_remove_proxy (application_t * app);

segment_manager_properties_t *application_get_segment_manager_properties (u32
									  app_index);
segment_manager_properties_t
  * application_segment_manager_properties (application_t * app);

local_session_t *application_alloc_local_session (application_t * app);
void application_free_local_session (application_t * app,
				     local_session_t * ls);
local_session_t *application_get_local_session (application_t * app,
						u32 session_index);
local_session_t *application_get_local_session_from_handle (session_handle_t
							    handle);
int application_local_session_connect (u32 table_index,
				       application_t * client,
				       application_t * server,
				       local_session_t * ll, u32 opaque);
int application_local_session_connect_notify (local_session_t * ls);
int application_local_session_disconnect (u32 app_index,
					  local_session_t * ls);
void application_local_sessions_del (application_t * app);

always_inline u32
local_session_id (local_session_t * ll)
{
  ASSERT (ll->app_index < (2 << 16) && ll->session_index < (2 << 16));
  return ((u32) ll->app_index << 16 | (u32) ll->session_index);
}

always_inline void
local_session_parse_id (u32 ls_id, u32 * app_index, u32 * session_index)
{
  *app_index = ls_id >> 16;
  *session_index = ls_id & 0xFFF;
}

always_inline void
local_session_parse_handle (session_handle_t handle, u32 * server_index,
			    u32 * session_index)
{
  u32 bottom;
  ASSERT ((handle >> 32) == SESSION_LOCAL_TABLE_PREFIX);
  bottom = (handle & 0xFFFFFFFF);
  local_session_parse_id (bottom, server_index, session_index);
}

always_inline session_handle_t
application_local_session_handle (local_session_t * ls)
{
  return ((u64) SESSION_LOCAL_TABLE_PREFIX << 32) | local_session_id (ls);
}

always_inline local_session_t *
application_get_local_listen_session (application_t * app, u32 session_index)
{
  return pool_elt_at_index (app->local_listen_sessions, session_index);
}

always_inline u8
application_local_session_listener_has_transport (local_session_t * ls)
{
  transport_proto_t tp;
  tp = session_type_transport_proto (ls->listener_session_type);
  return (tp != TRANSPORT_PROTO_NONE);
}


#endif /* SRC_VNET_SESSION_APPLICATION_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
