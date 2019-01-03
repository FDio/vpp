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

#include <vnet/session/session.h>
#include <vnet/session/segment_manager.h>
#include <vnet/session/application_namespace.h>

#define APP_DEBUG 0

#if APP_DEBUG > 0
#define APP_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define APP_DBG(_fmt, _args...)
#endif

typedef struct _stream_session_cb_vft
{
  /** Notify server of new segment */
  int (*add_segment_callback) (u32 api_client_index, u64 segment_handle);

  /** Notify server of new segment */
  int (*del_segment_callback) (u32 api_client_index, u64 segment_handle);

  /** Notify server of newly accepted session */
  int (*session_accept_callback) (stream_session_t * new_session);

  /** Connection request callback */
  int (*session_connected_callback) (u32 app_wrk_index, u32 opaque,
				     stream_session_t * s, u8 code);

  /** Notify app that session is closing */
  void (*session_disconnect_callback) (stream_session_t * s);

  /** Notify app that session was reset */
  void (*session_reset_callback) (stream_session_t * s);

  /** Direct RX callback for built-in application */
  int (*builtin_app_rx_callback) (stream_session_t * session);

  /** Direct TX callback for built-in application */
  int (*builtin_app_tx_callback) (stream_session_t * session);

} session_cb_vft_t;

typedef struct app_worker_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /** Worker index in global worker pool*/
  u32 wrk_index;

  /** Worker index in app's map pool */
  u32 wrk_map_index;

  /** Index of owning app */
  u32 app_index;

  /** Application listens for events on this svm queue */
  svm_msg_q_t *event_queue;

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

  /*
   * Local "cut through" connections specific
   */

  /** Segment manager used for incoming "cut through" connects */
  u32 local_segment_manager;

  /** Pool of local sessions the app owns (as a server) */
  local_session_t *local_sessions;

  /** Hash table of the app's local connects */
  uword *local_connects;

  /** API index for the worker. Needed for multi-process apps */
  u32 api_client_index;

  u8 app_is_builtin;
} app_worker_t;

typedef struct app_worker_map_
{
  u32 wrk_index;
} app_worker_map_t;

typedef struct app_listener_
{
  clib_bitmap_t *workers;	/**< workers accepting connections */
  u32 accept_rotor;		/**< last worker to accept a connection */
  u32 al_index;
} app_listener_t;

typedef struct application_
{
  /** App index in app pool */
  u32 app_index;

  /** Flags */
  u32 flags;

  /** Callbacks: shoulder-taps for the server/client */
  session_cb_vft_t cb_fns;

  /** Segment manager properties. Shared by all segment managers */
  segment_manager_properties_t sm_properties;

  /** Pool of mappings that keep track of workers associated to this app */
  app_worker_map_t *worker_maps;

  /** Name registered by builtin apps */
  u8 *name;

  /** Namespace the application belongs to */
  u32 ns_index;

  u16 proxied_transports;

  /** Pool of listeners for the app */
  app_listener_t *listeners;

  /** Pool of local listeners for app */
  app_listener_t *local_listeners;

  /** Pool of local listen sessions */
  local_session_t *local_listen_sessions;

  /*
   * TLS Specific
   */

  /** Certificate to be used for listen sessions */
  u8 *tls_cert;

  /** PEM encoded key */
  u8 *tls_key;

  /** Preferred tls engine */
  u8 tls_engine;

} application_t;

typedef struct app_main_
{
  /**
   * Pool from which we allocate all applications
   */
  application_t *app_pool;

  /**
   * Pool of workers associated to apps
   */
  app_worker_t *workers;

  /**
   * Hash table of apps by api client index
   */
  uword *app_by_api_client_index;

  /**
   * Hash table of builtin apps by name
   */
  uword *app_by_name;
} app_main_t;

#define foreach_app_init_args			\
  _(u32, api_client_index)			\
  _(u8 *, name)					\
  _(u64 *, options)				\
  _(u8 *, namespace_id)				\
  _(session_cb_vft_t *, session_cb_vft)		\
  _(u32, app_index)				\

typedef struct app_init_args_
{
#define _(_type, _name) _type _name;
  foreach_app_init_args
#undef _
} app_init_args_t;

typedef struct _vnet_app_worker_add_del_args
{
  u32 app_index;		/**< App for which a new worker is requested */
  u32 wrk_map_index;		/**< Index to delete or return value if add */
  u32 api_client_index;		/**< Binary API client index */
  ssvm_private_t *segment;	/**< First segment in segment manager */
  u64 segment_handle;		/**< Handle for the segment */
  svm_msg_q_t *evt_q;		/**< Worker message queue */
  u8 is_add;			/**< Flag set if addition */
} vnet_app_worker_add_del_args_t;

#define APP_INVALID_INDEX ((u32)~0)
#define APP_NS_INVALID_INDEX ((u32)~0)
#define APP_INVALID_SEGMENT_MANAGER_INDEX ((u32) ~0)

app_worker_t *app_worker_alloc (application_t * app);
int app_worker_alloc_and_init (application_t * app, app_worker_t ** wrk);
app_worker_t *app_worker_get (u32 wrk_index);
app_worker_t *app_worker_get_if_valid (u32 wrk_index);
application_t *app_worker_get_app (u32 wrk_index);
void app_worker_free (app_worker_t * app_wrk);
int app_worker_open_session (app_worker_t * app, session_endpoint_t * tep,
			     u32 api_context);
segment_manager_t *app_worker_get_listen_segment_manager (app_worker_t *,
							  stream_session_t *);
segment_manager_t *app_worker_get_connect_segment_manager (app_worker_t *);
segment_manager_t *
app_worker_get_or_alloc_connect_segment_manager (app_worker_t * );
int app_worker_alloc_connects_segment_manager (app_worker_t * app);
int app_worker_add_segment_notify (u32 app_or_wrk, u64 segment_handle);
u32 app_worker_n_listeners (app_worker_t * app);
stream_session_t *app_worker_first_listener (app_worker_t * app,
					     u8 fib_proto,
					     u8 transport_proto);
u8 app_worker_application_is_builtin (app_worker_t * app_wrk);
int app_worker_send_event (app_worker_t * app, stream_session_t * s, u8 evt);
int app_worker_lock_and_send_event (app_worker_t * app, stream_session_t * s,
				    u8 evt_type);
clib_error_t *vnet_app_worker_add_del (vnet_app_worker_add_del_args_t * a);

int application_start_listen (application_t * app,
			      session_endpoint_cfg_t * tep,
			      session_handle_t * handle);
int application_stop_listen (u32 app_index, u32 app_or_wrk,
			     session_handle_t handle);

application_t *application_alloc (void);
int application_alloc_and_init (app_init_args_t * args);
void application_free (application_t * app);
void application_detach_process (application_t * app, u32 api_client_index);
application_t *application_get (u32 index);
application_t *application_get_if_valid (u32 index);
application_t *application_lookup (u32 api_client_index);
application_t *application_lookup_name (const u8 * name);
app_worker_t *application_get_worker (application_t * app, u32 wrk_index);
app_worker_t *application_get_default_worker (application_t * app);
app_worker_t *application_listener_select_worker (stream_session_t * ls,
						  u8 is_local);

int application_is_proxy (application_t * app);
int application_is_builtin (application_t * app);
int application_is_builtin_proxy (application_t * app);
u32 application_session_table (application_t * app, u8 fib_proto);
u32 application_local_session_table (application_t * app);
const u8 *application_name_from_index (u32 app_or_wrk);
u8 application_has_local_scope (application_t * app);
u8 application_has_global_scope (application_t * app);
u8 application_use_mq_for_ctrl (application_t * app);
void application_setup_proxy (application_t * app);
void application_remove_proxy (application_t * app);

segment_manager_properties_t *application_get_segment_manager_properties (u32
									  app_index);

segment_manager_properties_t
  * application_segment_manager_properties (application_t * app);

/*
 * Local session
 */

local_session_t *application_local_session_alloc (app_worker_t * app);
void application_local_session_free (app_worker_t * app,
				     local_session_t * ls);
local_session_t *application_get_local_session (app_worker_t * app,
						u32 session_index);
local_session_t *application_get_local_session_from_handle (session_handle_t
							    handle);
local_session_t
  * application_get_local_listen_session_from_handle (session_handle_t lh);
int application_start_local_listen (application_t * server,
				    session_endpoint_cfg_t * sep,
				    session_handle_t * handle);
int application_stop_local_listen (u32 app_index, u32 app_or_wrk,
				   session_handle_t lh);
int application_local_session_connect (app_worker_t * client,
				       app_worker_t * server,
				       local_session_t * ls, u32 opaque);
int application_local_session_connect_notify (local_session_t * ls);
int application_local_session_disconnect (u32 app_or_wrk,
					  local_session_t * ls);
int application_local_session_disconnect_w_index (u32 app_or_wrk,
						  u32 ls_index);
void app_worker_local_sessions_free (app_worker_t * app);

always_inline u32
local_session_id (local_session_t * ls)
{
  ASSERT (ls->session_index < (2 << 16));
  u32 app_or_wrk_index;

  if (ls->session_state == SESSION_STATE_LISTENING)
    {
      ASSERT (ls->app_index < (2 << 16));
      app_or_wrk_index = ls->app_index;
    }
  else
    {
      ASSERT (ls->app_wrk_index < (2 << 16));
      app_or_wrk_index = ls->app_wrk_index;
    }

  return ((u32) app_or_wrk_index << 16 | (u32) ls->session_index);
}

always_inline void
local_session_parse_id (u32 ls_id, u32 * app_or_wrk, u32 * session_index)
{
  *app_or_wrk = ls_id >> 16;
  *session_index = ls_id & 0xFF;
}

always_inline void
local_session_parse_handle (session_handle_t handle, u32 * app_or_wrk_index,
			    u32 * session_index)
{
  u32 bottom;
  ASSERT ((handle >> 32) == SESSION_LOCAL_HANDLE_PREFIX);
  bottom = (handle & 0xFFFFFFFF);
  local_session_parse_id (bottom, app_or_wrk_index, session_index);
}

always_inline session_handle_t
application_local_session_handle (local_session_t * ls)
{
  return ((u64) SESSION_LOCAL_HANDLE_PREFIX << 32)
    | (u64) local_session_id (ls);
}

always_inline local_session_t *
application_get_local_listen_session (application_t * app, u32 session_index)
{
  return pool_elt_at_index (app->local_listen_sessions, session_index);
}

always_inline local_session_t *
application_get_local_listener_w_handle (session_handle_t handle)
{
  u32 server_index, session_index;
  application_t *app;
  local_session_parse_handle (handle, &server_index, &session_index);
  app = application_get (server_index);
  return application_get_local_listen_session (app, session_index);
}

always_inline u8
application_local_session_listener_has_transport (local_session_t * ls)
{
  transport_proto_t tp;
  tp = session_type_transport_proto (ls->listener_session_type);
  return (tp != TRANSPORT_PROTO_NONE);
}

void mq_send_local_session_disconnected_cb (u32 app_or_wrk,
					    local_session_t * ls);

uword unformat_application_proto (unformat_input_t * input, va_list * args);

#endif /* SRC_VNET_SESSION_APPLICATION_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
