/*
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

#ifndef SRC_VNET_SESSION_APPLICATION_H_
#define SRC_VNET_SESSION_APPLICATION_H_

#include <vnet/session/application_interface.h>
#include <vnet/session/application_namespace.h>
#include <vnet/session/session_types.h>
#include <vnet/session/segment_manager.h>

#define APP_DEBUG 0

#if APP_DEBUG > 0
#define APP_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define APP_DBG(_fmt, _args...)
#endif

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
  u32 app_index;
  u32 local_index;
  u32 session_index;
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
  segment_manager_props_t sm_properties;

  /** Pool of mappings that keep track of workers associated to this app */
  app_worker_map_t *worker_maps;

  /** Name registered by builtin apps */
  u8 *name;

  /** Namespace the application belongs to */
  u32 ns_index;

  u16 proxied_transports;

  /** Pool of listeners for the app */
  app_listener_t *listeners;

  /*
   * TLS & QUIC Specific
   */

  /** Certificate to be used for listen sessions */
  u8 *tls_cert;

  /** PEM encoded key */
  u8 *tls_key;

  /** Preferred tls engine */
  u8 tls_engine;

  u64 *quicly_ctx;

} application_t;

typedef struct app_main_
{
  /**
   * Pool from which we allocate all applications
   */
  application_t *app_pool;

  /**
   * Hash table of apps by api client index
   */
  uword *app_by_api_client_index;

  /**
   * Hash table of builtin apps by name
   */
  uword *app_by_name;
} app_main_t;

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

app_listener_t *app_listener_get (application_t * app, u32 al_index);
int app_listener_alloc_and_init (application_t * app,
				 session_endpoint_cfg_t * sep,
				 app_listener_t ** listener);
void app_listener_cleanup (app_listener_t * app_listener);
session_handle_t app_listener_handle (app_listener_t * app_listener);
app_listener_t *app_listener_lookup (application_t * app,
				     session_endpoint_cfg_t * sep);
app_listener_t *app_listener_get_w_handle (session_handle_t handle);
app_listener_t *app_listener_get_w_session (session_t * ls);
session_t *app_listener_get_session (app_listener_t * al);
session_t *app_listener_get_local_session (app_listener_t * al);

application_t *application_get (u32 index);
application_t *application_get_if_valid (u32 index);
application_t *application_lookup (u32 api_client_index);
application_t *application_lookup_name (const u8 * name);
app_worker_t *application_get_worker (application_t * app, u32 wrk_index);
app_worker_t *application_get_default_worker (application_t * app);
app_worker_t *application_listener_select_worker (session_t * ls);
int application_change_listener_owner (session_t * s, app_worker_t * app_wrk);
int application_is_proxy (application_t * app);
int application_is_builtin (application_t * app);
int application_is_builtin_proxy (application_t * app);
u32 application_session_table (application_t * app, u8 fib_proto);
u32 application_local_session_table (application_t * app);
const u8 *application_name_from_index (u32 app_or_wrk);
u8 application_has_local_scope (application_t * app);
u8 application_has_global_scope (application_t * app);
void application_setup_proxy (application_t * app);
void application_remove_proxy (application_t * app);

segment_manager_props_t *application_get_segment_manager_properties (u32
								     app_index);

segment_manager_props_t
  * application_segment_manager_properties (application_t * app);

/*
 * App worker
 */

app_worker_t *app_worker_alloc (application_t * app);
int application_alloc_worker_and_init (application_t * app,
				       app_worker_t ** wrk);
app_worker_t *app_worker_get (u32 wrk_index);
app_worker_t *app_worker_get_if_valid (u32 wrk_index);
application_t *app_worker_get_app (u32 wrk_index);
int app_worker_own_session (app_worker_t * app_wrk, session_t * s);
void app_worker_free (app_worker_t * app_wrk);
int app_worker_connect_session (app_worker_t * app, session_endpoint_t * tep,
				u32 api_context);
int app_worker_start_listen (app_worker_t * app_wrk, app_listener_t * lstnr);
int app_worker_stop_listen (app_worker_t * app_wrk, app_listener_t * al);
int app_worker_init_accepted (session_t * s);
int app_worker_accept_notify (app_worker_t * app_wrk, session_t * s);
int app_worker_init_connected (app_worker_t * app_wrk, session_t * s);
int app_worker_connect_notify (app_worker_t * app_wrk, session_t * s,
			       u32 opaque);
int app_worker_close_notify (app_worker_t * app_wrk, session_t * s);
int app_worker_reset_notify (app_worker_t * app_wrk, session_t * s);
int app_worker_builtin_rx (app_worker_t * app_wrk, session_t * s);
segment_manager_t *app_worker_get_listen_segment_manager (app_worker_t *,
							  session_t *);
segment_manager_t *app_worker_get_connect_segment_manager (app_worker_t *);
segment_manager_t
  * app_worker_get_or_alloc_connect_segment_manager (app_worker_t *);
int app_worker_alloc_connects_segment_manager (app_worker_t * app);
int app_worker_add_segment_notify (app_worker_t * app_wrk,
				   u64 segment_handle);
int app_worker_del_segment_notify (app_worker_t * app_wrk,
				   u64 segment_handle);
u32 app_worker_n_listeners (app_worker_t * app);
session_t *app_worker_first_listener (app_worker_t * app,
				      u8 fib_proto, u8 transport_proto);
int app_worker_send_event (app_worker_t * app, session_t * s, u8 evt);
int app_worker_lock_and_send_event (app_worker_t * app, session_t * s,
				    u8 evt_type);
session_t *app_worker_proxy_listener (app_worker_t * app, u8 fib_proto,
				      u8 transport_proto);
u8 *format_app_worker (u8 * s, va_list * args);
u8 *format_app_worker_listener (u8 * s, va_list * args);
void app_worker_format_connects (app_worker_t * app_wrk, int verbose);
int vnet_app_worker_add_del (vnet_app_worker_add_del_args_t * a);

uword unformat_application_proto (unformat_input_t * input, va_list * args);

#endif /* SRC_VNET_SESSION_APPLICATION_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
