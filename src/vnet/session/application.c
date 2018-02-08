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

#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/application_namespace.h>
#include <vnet/session/session.h>

/**
 * Pool from which we allocate all applications
 */
static application_t *app_pool;

/**
 * Hash table of apps by api client index
 */
static uword *app_by_api_client_index;

static u8 *
app_get_name_from_reg_index (application_t * app)
{
  u8 *app_name;

  vl_api_registration_t *regp;
  regp = vl_api_client_index_to_registration (app->api_client_index);
  if (!regp)
    app_name = format (0, "builtin-%d%c", app->index, 0);
  else
    app_name = format (0, "%s%c", regp->name, 0);

  return app_name;
}

u32
application_session_table (application_t * app, u8 fib_proto)
{
  app_namespace_t *app_ns;
  app_ns = app_namespace_get (app->ns_index);
  if (!application_has_global_scope (app))
    return APP_INVALID_INDEX;
  if (fib_proto == FIB_PROTOCOL_IP4)
    return session_lookup_get_index_for_fib (fib_proto,
					     app_ns->ip4_fib_index);
  else
    return session_lookup_get_index_for_fib (fib_proto,
					     app_ns->ip6_fib_index);
}

u32
application_local_session_table (application_t * app)
{
  app_namespace_t *app_ns;
  if (!application_has_local_scope (app))
    return APP_INVALID_INDEX;
  app_ns = app_namespace_get (app->ns_index);
  return app_ns->local_table_index;
}

int
application_api_queue_is_full (application_t * app)
{
  svm_queue_t *q;

  /* builtin servers are always OK */
  if (app->api_client_index == ~0)
    return 0;

  q = vl_api_client_index_to_input_queue (app->api_client_index);
  if (!q)
    return 1;

  if (q->cursize == q->maxsize)
    return 1;
  return 0;
}

/**
 * Returns app name
 *
 * Since the name is not stored per app, we generate it on the fly. It is
 * the caller's responsibility to free the vector
 */
u8 *
application_name_from_index (u32 app_index)
{
  application_t *app = application_get (app_index);
  if (!app)
    return 0;
  return app_get_name_from_reg_index (app);
}

static void
application_table_add (application_t * app)
{
  hash_set (app_by_api_client_index, app->api_client_index, app->index);
}

static void
application_table_del (application_t * app)
{
  hash_unset (app_by_api_client_index, app->api_client_index);
}

application_t *
application_lookup (u32 api_client_index)
{
  uword *p;
  p = hash_get (app_by_api_client_index, api_client_index);
  if (p)
    return application_get (p[0]);

  return 0;
}

application_t *
application_new ()
{
  application_t *app;
  pool_get (app_pool, app);
  memset (app, 0, sizeof (*app));
  app->index = application_get_index (app);
  app->connects_seg_manager = APP_INVALID_SEGMENT_MANAGER_INDEX;
  app->first_segment_manager = APP_INVALID_SEGMENT_MANAGER_INDEX;
  app->local_segment_manager = APP_INVALID_SEGMENT_MANAGER_INDEX;
  if (CLIB_DEBUG > 1)
    clib_warning ("[%d] New app (%d)", getpid (), app->index);
  return app;
}

void
application_del (application_t * app)
{
  vnet_unbind_args_t _a, *a = &_a;
  u64 handle, *handles = 0;
  segment_manager_t *sm;
  u32 index;
  int i;

  /*
   * The app event queue allocated in first segment is cleared with
   * the segment manager. No need to explicitly free it.
   */
  if (CLIB_DEBUG > 1)
    clib_warning ("[%d] Delete app (%d)", getpid (), app->index);

  if (application_is_proxy (app))
    application_remove_proxy (app);

  /*
   *  Listener cleanup
   */

  /* *INDENT-OFF* */
  hash_foreach (handle, index, app->listeners_table,
  ({
    vec_add1 (handles, handle);
    sm = segment_manager_get (index);
    sm->app_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (handles); i++)
    {
      a->app_index = app->index;
      a->handle = handles[i];
      /* seg manager is removed when unbind completes */
      vnet_unbind (a);
    }

  /*
   * Connects segment manager cleanup
   */

  if (app->connects_seg_manager != APP_INVALID_SEGMENT_MANAGER_INDEX)
    {
      sm = segment_manager_get (app->connects_seg_manager);
      sm->app_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
      segment_manager_init_del (sm);
    }

  /* If first segment manager is used by a listener */
  if (app->first_segment_manager != APP_INVALID_SEGMENT_MANAGER_INDEX
      && app->first_segment_manager != app->connects_seg_manager)
    {
      sm = segment_manager_get (app->first_segment_manager);
      /* .. and has no fifos, e.g. it might be used for redirected sessions,
       * remove it */
      if (!segment_manager_has_fifos (sm))
	{
	  sm->app_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
	  segment_manager_del (sm);
	}
    }

  /*
   * Local connections cleanup
   */
  application_local_sessions_del (app);

  application_table_del (app);
  pool_put (app_pool, app);
}

static void
application_verify_cb_fns (session_cb_vft_t * cb_fns)
{
  if (cb_fns->session_accept_callback == 0)
    clib_warning ("No accept callback function provided");
  if (cb_fns->session_connected_callback == 0)
    clib_warning ("No session connected callback function provided");
  if (cb_fns->session_disconnect_callback == 0)
    clib_warning ("No session disconnect callback function provided");
  if (cb_fns->session_reset_callback == 0)
    clib_warning ("No session reset callback function provided");
}

/**
 * Check app config for given segment type
 *
 * Returns 1 on success and 0 otherwise
 */
static u8
application_verify_cfg (ssvm_segment_type_t st)
{
  u8 is_valid;
  if (st == SSVM_SEGMENT_MEMFD)
    {
      is_valid = (session_manager_get_evt_q_segment () != 0);
      if (!is_valid)
	clib_warning ("memfd seg: vpp's event qs IN binary api svm region");
      return is_valid;
    }
  else if (st == SSVM_SEGMENT_SHM)
    {
      is_valid = (session_manager_get_evt_q_segment () == 0);
      if (!is_valid)
	clib_warning ("shm seg: vpp's event qs NOT IN binary api svm region");
      return is_valid;
    }
  else
    return 1;
}

int
application_init (application_t * app, u32 api_client_index, u64 * options,
		  session_cb_vft_t * cb_fns)
{
  ssvm_segment_type_t seg_type = SSVM_SEGMENT_MEMFD;
  u32 first_seg_size, prealloc_fifo_pairs;
  segment_manager_properties_t *props;
  vl_api_registration_t *reg;
  segment_manager_t *sm;
  int rv;

  /*
   * Make sure we support the requested configuration
   */

  if (!(options[APP_OPTIONS_FLAGS] & APP_OPTIONS_FLAGS_IS_BUILTIN))
    {
      reg = vl_api_client_index_to_registration (api_client_index);
      if (!reg)
	return VNET_API_ERROR_APP_UNSUPPORTED_CFG;
      if (vl_api_registration_file_index (reg) == VL_API_INVALID_FI)
	seg_type = SSVM_SEGMENT_SHM;
    }
  else
    {
      seg_type = SSVM_SEGMENT_PRIVATE;
    }

  if (!application_verify_cfg (seg_type))
    return VNET_API_ERROR_APP_UNSUPPORTED_CFG;

  /*
   * Setup segment manager
   */
  sm = segment_manager_new ();
  sm->app_index = app->index;
  props = application_segment_manager_properties (app);
  segment_manager_properties_init (props);
  if (options[APP_OPTIONS_ADD_SEGMENT_SIZE])
    {
      props->add_segment_size = options[APP_OPTIONS_ADD_SEGMENT_SIZE];
      props->add_segment = 1;
    }
  if (options[APP_OPTIONS_RX_FIFO_SIZE])
    props->rx_fifo_size = options[APP_OPTIONS_RX_FIFO_SIZE];
  if (options[APP_OPTIONS_TX_FIFO_SIZE])
    props->tx_fifo_size = options[APP_OPTIONS_TX_FIFO_SIZE];
  if (options[APP_OPTIONS_EVT_QUEUE_SIZE])
    props->evt_q_size = options[APP_OPTIONS_EVT_QUEUE_SIZE];
  props->segment_type = seg_type;

  first_seg_size = options[APP_OPTIONS_SEGMENT_SIZE];
  prealloc_fifo_pairs = options[APP_OPTIONS_PREALLOC_FIFO_PAIRS];

  if ((rv = segment_manager_init (sm, first_seg_size, prealloc_fifo_pairs)))
    return rv;
  sm->first_is_protected = 1;

  /*
   * Setup application
   */
  app->first_segment_manager = segment_manager_index (sm);
  app->api_client_index = api_client_index;
  app->flags = options[APP_OPTIONS_FLAGS];
  app->cb_fns = *cb_fns;
  app->ns_index = options[APP_OPTIONS_NAMESPACE];
  app->listeners_table = hash_create (0, sizeof (u64));
  app->local_connects = hash_create (0, sizeof (u64));
  app->proxied_transports = options[APP_OPTIONS_PROXY_TRANSPORT];
  app->event_queue = segment_manager_event_queue (sm);

  /* If no scope enabled, default to global */
  if (!application_has_global_scope (app)
      && !application_has_local_scope (app))
    app->flags |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;

  /* Check that the obvious things are properly set up */
  application_verify_cb_fns (cb_fns);

  /* Add app to lookup by api_client_index table */
  application_table_add (app);

  /*
   * Segment manager for local sessions
   */
  sm = segment_manager_new ();
  sm->app_index = app->index;
  app->local_segment_manager = segment_manager_index (sm);

  return 0;
}

application_t *
application_get (u32 index)
{
  if (index == APP_INVALID_INDEX)
    return 0;
  return pool_elt_at_index (app_pool, index);
}

application_t *
application_get_if_valid (u32 index)
{
  if (pool_is_free_index (app_pool, index))
    return 0;

  return pool_elt_at_index (app_pool, index);
}

u32
application_get_index (application_t * app)
{
  return app - app_pool;
}

static segment_manager_t *
application_alloc_segment_manager (application_t * app)
{
  segment_manager_t *sm = 0;

  /* If the first segment manager is not in use, don't allocate a new one */
  if (app->first_segment_manager != APP_INVALID_SEGMENT_MANAGER_INDEX
      && app->first_segment_manager_in_use == 0)
    {
      sm = segment_manager_get (app->first_segment_manager);
      app->first_segment_manager_in_use = 1;
      return sm;
    }

  sm = segment_manager_new ();
  sm->app_index = app->index;

  return sm;
}

/**
 * Start listening local transport endpoint for requested transport.
 *
 * Creates a 'dummy' stream session with state LISTENING to be used in session
 * lookups, prior to establishing connection. Requests transport to build
 * it's own specific listening connection.
 */
int
application_start_listen (application_t * srv, session_endpoint_t * sep,
			  session_handle_t * res)
{
  segment_manager_t *sm;
  stream_session_t *s;
  session_handle_t handle;
  session_type_t sst;

  sst = session_type_from_proto_and_ip (sep->transport_proto, sep->is_ip4);
  s = listen_session_new (sst);
  s->app_index = srv->index;

  if (stream_session_listen (s, sep))
    goto err;

  /* Allocate segment manager. All sessions derived out of a listen session
   * have fifos allocated by the same segment manager. */
  sm = application_alloc_segment_manager (srv);
  if (sm == 0)
    goto err;

  /* Add to app's listener table. Useful to find all child listeners
   * when app goes down, although, just for unbinding this is not needed */
  handle = listen_session_get_handle (s);
  hash_set (srv->listeners_table, handle, segment_manager_index (sm));

  *res = handle;
  return 0;

err:
  listen_session_del (s);
  return -1;
}

/**
 * Stop listening on session associated to handle
 */
int
application_stop_listen (application_t * srv, session_handle_t handle)
{
  stream_session_t *listener;
  uword *indexp;
  segment_manager_t *sm;

  if (srv && hash_get (srv->listeners_table, handle) == 0)
    {
      clib_warning ("app doesn't own handle %llu!", handle);
      return -1;
    }

  listener = listen_session_get_from_handle (handle);
  stream_session_stop_listen (listener);

  indexp = hash_get (srv->listeners_table, handle);
  ASSERT (indexp);

  sm = segment_manager_get (*indexp);
  if (srv->first_segment_manager == *indexp)
    {
      /* Delete sessions but don't remove segment manager */
      srv->first_segment_manager_in_use = 0;
      segment_manager_del_sessions (sm);
    }
  else
    {
      segment_manager_init_del (sm);
    }
  hash_unset (srv->listeners_table, handle);
  listen_session_del (listener);

  return 0;
}

int
application_open_session (application_t * app, session_endpoint_t * sep,
			  u32 api_context)
{
  segment_manager_t *sm;
  int rv;

  /* Make sure we have a segment manager for connects */
  if (app->connects_seg_manager == APP_INVALID_SEGMENT_MANAGER_INDEX)
    {
      sm = application_alloc_segment_manager (app);
      if (sm == 0)
	return -1;
      app->connects_seg_manager = segment_manager_index (sm);
    }

  if ((rv = session_open (app->index, sep, api_context)))
    return rv;

  return 0;
}

segment_manager_t *
application_get_connect_segment_manager (application_t * app)
{
  ASSERT (app->connects_seg_manager != (u32) ~ 0);
  return segment_manager_get (app->connects_seg_manager);
}

segment_manager_t *
application_get_listen_segment_manager (application_t * app,
					stream_session_t * s)
{
  uword *smp;
  smp = hash_get (app->listeners_table, listen_session_get_handle (s));
  ASSERT (smp != 0);
  return segment_manager_get (*smp);
}

segment_manager_t *
application_get_local_segment_manager (application_t * app)
{
  return segment_manager_get (app->local_segment_manager);
}

segment_manager_t *
application_get_local_segment_manager_w_session (application_t * app,
						 local_session_t * ls)
{
  stream_session_t *listener;
  if (application_local_session_listener_has_transport (ls))
    {
      listener = listen_session_get (ls->listener_session_type,
				     ls->listener_index);
      return application_get_listen_segment_manager (app, listener);
    }
  return segment_manager_get (app->local_segment_manager);
}

int
application_is_proxy (application_t * app)
{
  return (app->flags & APP_OPTIONS_FLAGS_IS_PROXY);
}

int
application_is_builtin (application_t * app)
{
  return (app->flags & APP_OPTIONS_FLAGS_IS_BUILTIN);
}

int
application_is_builtin_proxy (application_t * app)
{
  return (application_is_proxy (app) && application_is_builtin (app));
}

/**
 * Send an API message to the external app, to map new segment
 */
int
application_add_segment_notify (u32 app_index, ssvm_private_t * fs)
{
  application_t *app = application_get (app_index);
  return app->cb_fns.add_segment_callback (app->api_client_index, fs);
}

u8
application_has_local_scope (application_t * app)
{
  return app->flags & APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
}

u8
application_has_global_scope (application_t * app)
{
  return app->flags & APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
}

u32
application_n_listeners (application_t * app)
{
  return hash_elts (app->listeners_table);
}

stream_session_t *
application_first_listener (application_t * app, u8 fib_proto,
			    u8 transport_proto)
{
  stream_session_t *listener;
  u64 handle;
  u32 sm_index;
  u8 sst;

  sst = session_type_from_proto_and_ip (transport_proto,
					fib_proto == FIB_PROTOCOL_IP4);

  /* *INDENT-OFF* */
   hash_foreach (handle, sm_index, app->listeners_table, ({
     listener = listen_session_get_from_handle (handle);
     if (listener->session_type == sst
	 && listener->listener_index != SESSION_PROXY_LISTENER_INDEX)
       return listener;
   }));
  /* *INDENT-ON* */

  return 0;
}

stream_session_t *
application_proxy_listener (application_t * app, u8 fib_proto,
			    u8 transport_proto)
{
  stream_session_t *listener;
  u64 handle;
  u32 sm_index;
  u8 sst;

  sst = session_type_from_proto_and_ip (transport_proto,
					fib_proto == FIB_PROTOCOL_IP4);

  /* *INDENT-OFF* */
   hash_foreach (handle, sm_index, app->listeners_table, ({
     listener = listen_session_get_from_handle (handle);
     if (listener->session_type == sst
	 && listener->listener_index == SESSION_PROXY_LISTENER_INDEX)
       return listener;
   }));
  /* *INDENT-ON* */

  return 0;
}

static clib_error_t *
application_start_stop_proxy_fib_proto (application_t * app, u8 fib_proto,
					u8 transport_proto, u8 is_start)
{
  app_namespace_t *app_ns = app_namespace_get (app->ns_index);
  u8 is_ip4 = (fib_proto == FIB_PROTOCOL_IP4);
  session_endpoint_t sep = SESSION_ENDPOINT_NULL;
  transport_connection_t *tc;
  stream_session_t *s;
  u64 handle;

  if (is_start)
    {
      s = application_first_listener (app, fib_proto, transport_proto);
      if (!s)
	{
	  sep.is_ip4 = is_ip4;
	  sep.fib_index = app_namespace_get_fib_index (app_ns, fib_proto);
	  sep.sw_if_index = app_ns->sw_if_index;
	  sep.transport_proto = transport_proto;
	  application_start_listen (app, &sep, &handle);
	  s = listen_session_get_from_handle (handle);
	  s->listener_index = SESSION_PROXY_LISTENER_INDEX;
	}
    }
  else
    {
      s = application_proxy_listener (app, fib_proto, transport_proto);
      ASSERT (s);
    }

  tc = listen_session_get_transport (s);

  if (!ip_is_zero (&tc->lcl_ip, 1))
    {
      u32 sti;
      sep.is_ip4 = is_ip4;
      sep.fib_index = app_namespace_get_fib_index (app_ns, fib_proto);
      sep.transport_proto = transport_proto;
      sep.port = 0;
      sti = session_lookup_get_index_for_fib (fib_proto, sep.fib_index);
      if (is_start)
	session_lookup_add_session_endpoint (sti, &sep, s->session_index);
      else
	session_lookup_del_session_endpoint (sti, &sep);
    }

  return 0;
}

static void
application_start_stop_proxy_local_scope (application_t * app,
					  u8 transport_proto, u8 is_start)
{
  session_endpoint_t sep = SESSION_ENDPOINT_NULL;
  app_namespace_t *app_ns;
  app_ns = app_namespace_get (app->ns_index);
  sep.is_ip4 = 1;
  sep.transport_proto = transport_proto;
  sep.port = 0;

  if (is_start)
    {
      session_lookup_add_session_endpoint (app_ns->local_table_index, &sep,
					   app->index);
      sep.is_ip4 = 0;
      session_lookup_add_session_endpoint (app_ns->local_table_index, &sep,
					   app->index);
    }
  else
    {
      session_lookup_del_session_endpoint (app_ns->local_table_index, &sep);
      sep.is_ip4 = 0;
      session_lookup_del_session_endpoint (app_ns->local_table_index, &sep);
    }
}

void
application_start_stop_proxy (application_t * app,
			      transport_proto_t transport_proto, u8 is_start)
{
  if (application_has_local_scope (app))
    application_start_stop_proxy_local_scope (app, transport_proto, is_start);

  if (application_has_global_scope (app))
    {
      application_start_stop_proxy_fib_proto (app, FIB_PROTOCOL_IP4,
					      transport_proto, is_start);
      application_start_stop_proxy_fib_proto (app, FIB_PROTOCOL_IP6,
					      transport_proto, is_start);
    }
}

void
application_setup_proxy (application_t * app)
{
  u16 transports = app->proxied_transports;
  transport_proto_t tp;

  ASSERT (application_is_proxy (app));

  /* *INDENT-OFF* */
  transport_proto_foreach (tp, ({
    if (transports & (1 << tp))
      application_start_stop_proxy (app, tp, 1);
  }));
  /* *INDENT-ON* */
}

void
application_remove_proxy (application_t * app)
{
  u16 transports = app->proxied_transports;
  transport_proto_t tp;

  ASSERT (application_is_proxy (app));

  /* *INDENT-OFF* */
  transport_proto_foreach (tp, ({
    if (transports & (1 << tp))
      application_start_stop_proxy (app, tp, 0);
  }));
  /* *INDENT-ON* */
}

segment_manager_properties_t *
application_segment_manager_properties (application_t * app)
{
  return &app->sm_properties;
}

segment_manager_properties_t *
application_get_segment_manager_properties (u32 app_index)
{
  application_t *app = application_get (app_index);
  return &app->sm_properties;
}

local_session_t *
application_alloc_local_session (application_t * app)
{
  local_session_t *s;
  pool_get (app->local_sessions, s);
  memset (s, 0, sizeof (*s));
  s->app_index = app->index;
  s->session_index = s - app->local_sessions;
  s->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_NONE, 0);
  return s;
}

void
application_free_local_session (application_t * app, local_session_t * s)
{
  pool_put (app->local_sessions, s);
  if (CLIB_DEBUG)
    memset (s, 0xfc, sizeof (*s));
}

local_session_t *
application_get_local_session (application_t * app, u32 session_index)
{
  return pool_elt_at_index (app->local_sessions, session_index);
}

local_session_t *
application_get_local_session_from_handle (session_handle_t handle)
{
  application_t *server;
  u32 session_index, server_index;
  local_session_parse_handle (handle, &server_index, &session_index);
  server = application_get (server_index);
  return application_get_local_session (server, session_index);
}

always_inline int
application_parse_local_listener_handle (session_handle_t handle,
					 u32 * session_index)
{
  if (handle >> 32 != SESSION_LOCAL_TABLE_PREFIX)
    return -1;
  *session_index = handle & 0xFFFFFFFFULL;
  return 0;
}

always_inline void
application_local_listener_session_endpoint (local_session_t * ll,
					     session_endpoint_t * sep)
{
  sep->transport_proto =
    session_get_transport_proto ((stream_session_t *) ll);
  sep->port = ll->port;
  sep->is_ip4 = ll->session_type & 1;
}

int
application_start_local_listen (application_t * server,
				session_endpoint_t * sep,
				session_handle_t * handle)
{
  session_handle_t lh;
  local_session_t *ll;
  u32 table_index;

  table_index = application_local_session_table (server);

  /* An exact sep match, as opposed to session_lookup_local_listener */
  lh = session_lookup_endpoint_listener (table_index, sep, 1);
  if (lh != SESSION_INVALID_HANDLE)
    return VNET_API_ERROR_ADDRESS_IN_USE;

  pool_get (server->local_listen_sessions, ll);
  memset (ll, 0, sizeof (*ll));
  ll->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_NONE, 0);
  ll->app_index = server->index;
  ll->session_index = ll - server->local_listen_sessions;
  ll->port = sep->port;

  *handle = application_local_session_handle (ll);
  session_lookup_add_session_endpoint (table_index, sep, ll->session_index);

  return 0;
}

/**
 * Clean up local session table. If we have a listener session use it to
 * find the port and proto. If not, the handle must be a local table handle
 * so parse it.
 */
int
application_stop_local_listen (application_t * server, session_handle_t lh)
{
  session_endpoint_t sep = SESSION_ENDPOINT_NULL;
  stream_session_t *sl = 0;
  u32 table_index, ll_index;
  local_session_t *ll, *ls;

  table_index = application_local_session_table (server);

  /* We have both local and global table binds. Figure from global what
   * the sep we should be cleaning up is.
   */
  if (!session_handle_is_local (lh))
    {
      sl = listen_session_get_from_handle (lh);
      if (!sl || listen_session_get_local_session_endpoint (sl, &sep))
	{
	  clib_warning ("broken listener");
	  return -1;
	}
      lh = session_lookup_endpoint_listener (table_index, &sep, 0);
      if (lh == SESSION_INVALID_HANDLE)
	{
	  clib_warning ("no local listener");
	  return -1;
	}
    }

  if (application_parse_local_listener_handle (lh, &ll_index))
    {
      clib_warning ("can't parse handle");
      return -1;
    }
  if (!(ll = application_get_local_listen_session (server, ll_index)))
    {
      clib_warning ("no local listener");
      return -1;
    }
  application_local_listener_session_endpoint (ll, &sep);
  session_lookup_del_session_endpoint (table_index, &sep);

  /* *INDENT-OFF* */
  pool_foreach (ls, server->local_sessions, ({
    if (ls->listener_index == ll->session_index)
      application_local_session_disconnect (server->index, ls);
  }));
  /* *INDENT-ON* */
  pool_put_index (server->local_listen_sessions, ll->session_index);

  return 0;
}

int
application_local_session_connect (u32 table_index, application_t * client,
				   application_t * server,
				   local_session_t * ll, u32 opaque)
{
  u32 seg_size, evt_q_sz, evt_q_elts, margin = 16 << 10;
  segment_manager_properties_t *props, *cprops;
  int rv, has_transport, seg_index;
  svm_fifo_segment_private_t *seg;
  segment_manager_t *sm;
  local_session_t *ls;
  svm_queue_t *sq, *cq;

  ls = application_alloc_local_session (server);

  props = application_segment_manager_properties (server);
  cprops = application_segment_manager_properties (client);
  evt_q_elts = props->evt_q_size + cprops->evt_q_size;
  evt_q_sz = evt_q_elts * sizeof (session_fifo_event_t);
  seg_size = props->rx_fifo_size + props->tx_fifo_size + evt_q_sz + margin;

  has_transport = session_has_transport ((stream_session_t *) ll);
  if (!has_transport)
    {
      /* Local sessions don't have backing transport */
      ls->port = ll->port;
      sm = application_get_local_segment_manager (server);
    }
  else
    {
      stream_session_t *sl = (stream_session_t *) ll;
      transport_connection_t *tc;
      tc = listen_session_get_transport (sl);
      ls->port = tc->lcl_port;
      sm = application_get_listen_segment_manager (server, sl);
    }

  seg_index = segment_manager_add_segment (sm, seg_size);
  if (seg_index < 0)
    {
      clib_warning ("failed to add new cut-through segment");
      return seg_index;
    }
  seg = segment_manager_get_segment_w_lock (sm, seg_index);
  sq = segment_manager_alloc_queue (seg, props->evt_q_size);
  cq = segment_manager_alloc_queue (seg, cprops->evt_q_size);
  ls->server_evt_q = pointer_to_uword (sq);
  ls->client_evt_q = pointer_to_uword (cq);
  rv = segment_manager_try_alloc_fifos (seg, props->rx_fifo_size,
					props->tx_fifo_size,
					&ls->server_rx_fifo,
					&ls->server_tx_fifo);
  if (rv)
    {
      clib_warning ("failed to add fifos in cut-through segment");
      segment_manager_segment_reader_unlock (sm);
      goto failed;
    }
  ls->server_rx_fifo->master_session_index = ls->session_index;
  ls->server_tx_fifo->master_session_index = ls->session_index;
  ls->server_rx_fifo->master_thread_index = ~0;
  ls->server_tx_fifo->master_thread_index = ~0;
  ls->svm_segment_index = seg_index;
  ls->listener_index = ll->session_index;
  ls->client_index = client->index;
  ls->client_opaque = opaque;
  ls->listener_session_type = ll->session_type;

  if ((rv = server->cb_fns.add_segment_callback (server->api_client_index,
						 &seg->ssvm)))
    {
      clib_warning ("failed to notify server of new segment");
      segment_manager_segment_reader_unlock (sm);
      goto failed;
    }
  segment_manager_segment_reader_unlock (sm);
  if ((rv = server->cb_fns.session_accept_callback ((stream_session_t *) ls)))
    {
      clib_warning ("failed to send accept cut-through notify to server");
      goto failed;
    }

  return 0;

failed:
  if (!has_transport)
    segment_manager_del_segment (sm, seg);
  return rv;
}

static uword
application_client_local_connect_key (local_session_t * ls)
{
  return ((uword) ls->app_index << 32 | (uword) ls->session_index);
}

static void
application_client_local_connect_key_parse (uword key, u32 * app_index,
					    u32 * session_index)
{
  *app_index = key >> 32;
  *session_index = key & 0xFFFFFFFF;
}

int
application_local_session_connect_notify (local_session_t * ls)
{
  svm_fifo_segment_private_t *seg;
  application_t *client, *server;
  segment_manager_t *sm;
  int rv, is_fail = 0;
  uword client_key;

  client = application_get (ls->client_index);
  server = application_get (ls->app_index);
  sm = application_get_local_segment_manager_w_session (server, ls);
  seg = segment_manager_get_segment_w_lock (sm, ls->svm_segment_index);
  if ((rv = client->cb_fns.add_segment_callback (client->api_client_index,
						 &seg->ssvm)))
    {
      clib_warning ("failed to notify client %u of new segment",
		    ls->client_index);
      segment_manager_segment_reader_unlock (sm);
      application_local_session_disconnect (ls->client_index, ls);
      is_fail = 1;
    }
  else
    {
      segment_manager_segment_reader_unlock (sm);
    }

  client->cb_fns.session_connected_callback (client->index, ls->client_opaque,
					     (stream_session_t *) ls,
					     is_fail);

  client_key = application_client_local_connect_key (ls);
  hash_set (client->local_connects, client_key, client_key);
  return 0;
}

int
application_local_session_disconnect (u32 app_index, local_session_t * ls)
{
  svm_fifo_segment_private_t *seg;
  application_t *client, *server;
  segment_manager_t *sm;
  uword client_key;

  client = application_get (ls->client_index);
  server = application_get (ls->app_index);

  if (ls->session_state != SESSION_STATE_READY)
    {
      client->cb_fns.session_connected_callback (client->index,
						 ls->client_opaque,
						 (stream_session_t *) ls,
						 1 /* is_fail */ );
    }
  else if (app_index == ls->client_index)
    {
      send_local_session_disconnect_callback (ls->app_index, ls);
    }
  else
    {
      send_local_session_disconnect_callback (ls->client_index, ls);
    }

  client_key = application_client_local_connect_key (ls);
  hash_unset (client->local_connects, client_key);

  sm = application_get_local_segment_manager_w_session (server, ls);
  seg = segment_manager_get_segment (sm, ls->svm_segment_index);
  client->cb_fns.del_segment_callback (client->api_client_index, &seg->ssvm);
  server->cb_fns.del_segment_callback (server->api_client_index, &seg->ssvm);
  segment_manager_del_segment (sm, seg);
  application_free_local_session (server, ls);

  return 0;
}

void
application_local_sessions_del (application_t * app)
{
  u32 index, server_index, session_index, table_index;
  segment_manager_t *sm;
  u64 handle, *handles = 0;
  local_session_t *ls, *ll;
  application_t *server;
  session_endpoint_t sep;
  int i;

  /*
   * Local listens. Don't bother with local sessions, we clean them lower
   */
  table_index = application_local_session_table (app);
  /* *INDENT-OFF* */
  pool_foreach (ll, app->local_listen_sessions, ({
    application_local_listener_session_endpoint (ll, &sep);
    session_lookup_del_session_endpoint (table_index, &sep);
  }));
  /* *INDENT-ON* */

  /*
   * Local sessions
   */
  if (app->local_sessions)
    {
      /* *INDENT-OFF* */
      pool_foreach (ls, app->local_sessions, ({
	application_local_session_disconnect (app->index, ls);
      }));
      /* *INDENT-ON* */
    }

  /*
   * Local connects
   */
  vec_reset_length (handles);
  /* *INDENT-OFF* */
  hash_foreach (handle, index, app->local_connects, ({
    vec_add1 (handles, handle);
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (handles); i++)
    {
      application_client_local_connect_key_parse (handles[i], &server_index,
						  &session_index);
      server = application_get_if_valid (server_index);
      if (server)
	{
	  ls = application_get_local_session (server, session_index);
	  application_local_session_disconnect (app->index, ls);
	}
    }

  sm = segment_manager_get (app->local_segment_manager);
  sm->app_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
  segment_manager_del (sm);
}

u8 *
format_application_listener (u8 * s, va_list * args)
{
  application_t *app = va_arg (*args, application_t *);
  u64 handle = va_arg (*args, u64);
  u32 sm_index = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  stream_session_t *listener;
  u8 *app_name, *str;

  if (app == 0)
    {
      if (verbose)
	s = format (s, "%-40s%-20s%-15s%-15s%-10s", "Connection", "App",
		    "API Client", "ListenerID", "SegManager");
      else
	s = format (s, "%-40s%-20s", "Connection", "App");

      return s;
    }

  app_name = app_get_name_from_reg_index (app);
  listener = listen_session_get_from_handle (handle);
  str = format (0, "%U", format_stream_session, listener, verbose);

  if (verbose)
    {
      s = format (s, "%-40s%-20s%-15u%-15u%-10u", str, app_name,
		  app->api_client_index, handle, sm_index);
    }
  else
    s = format (s, "%-40s%-20s", str, app_name);

  vec_free (app_name);
  return s;
}

void
application_format_connects (application_t * app, int verbose)
{
  svm_fifo_segment_private_t *fifo_segment;
  vlib_main_t *vm = vlib_get_main ();
  segment_manager_t *sm;
  u8 *app_name, *s = 0;

  /* Header */
  if (app == 0)
    {
      if (verbose)
	vlib_cli_output (vm, "%-40s%-20s%-15s%-10s", "Connection", "App",
			 "API Client", "SegManager");
      else
	vlib_cli_output (vm, "%-40s%-20s", "Connection", "App");
      return;
    }

  /* make sure */
  if (app->connects_seg_manager == (u32) ~ 0)
    return;

  app_name = app_get_name_from_reg_index (app);

  /* Across all fifo segments */
  sm = segment_manager_get (app->connects_seg_manager);

  /* *INDENT-OFF* */
  segment_manager_foreach_segment_w_lock (fifo_segment, sm, ({
    svm_fifo_t *fifo;
    u8 *str;

    fifo = svm_fifo_segment_get_fifo_list (fifo_segment);
    while (fifo)
	{
	  u32 session_index, thread_index;
	  stream_session_t *session;

	  session_index = fifo->master_session_index;
	  thread_index = fifo->master_thread_index;

	  session = session_get (session_index, thread_index);
	  str = format (0, "%U", format_stream_session, session, verbose);

	  if (verbose)
	    s = format (s, "%-40s%-20s%-15u%-10u", str, app_name,
			app->api_client_index, app->connects_seg_manager);
	  else
	    s = format (s, "%-40s%-20s", str, app_name);

	  vlib_cli_output (vm, "%v", s);
	  vec_reset_length (s);
	  vec_free (str);

	  fifo = fifo->next;
	}
    vec_free (s);
  }));
  /* *INDENT-ON* */

  vec_free (app_name);
}

void
application_format_local_sessions (application_t * app, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 app_index, session_index;
  application_t *server;
  local_session_t *ls;
  uword client_key;
  u64 value;

  /* Header */
  if (app == 0)
    {
      if (verbose)
	vlib_cli_output (vm, "%-40s%-15s%-20s%-10s", "Connection", "App",
			 "Peer App", "SegManager");
      else
	vlib_cli_output (vm, "%-40s%-15s%-20s", "Connection", "App",
			 "Peer App");
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach (ls, app->local_sessions, ({
    vlib_cli_output (vm, "%-40s%-15s%-20s", "TODO", ls->app_index,
                     ls->client_index);
  }));

  hash_foreach (client_key, value, app->local_connects, ({
    application_client_local_connect_key_parse (client_key, &app_index,
                                                &session_index);
    server = application_get (app_index);
    ls = application_get_local_session (server, session_index);
    vlib_cli_output (vm, "%-40s%-15s%-20s", "TODO", ls->app_index,
                     ls->client_index);
  }));
  /* *INDENT-ON* */
}

void
application_format_local_connects (application_t * app, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 app_index, session_index;
  application_t *server;
  local_session_t *ls;
  uword client_key;
  u64 value;

  /* Header */
  if (app == 0)
    {
      if (verbose)
	vlib_cli_output (vm, "%-40s%-15s%-20s%-10s", "Connection", "App",
			 "Peer App", "SegManager");
      else
	vlib_cli_output (vm, "%-40s%-15s%-20s", "Connection", "App",
			 "Peer App");
      return;
    }

  /* *INDENT-OFF* */
  hash_foreach (client_key, value, app->local_connects, ({
    application_client_local_connect_key_parse (client_key, &app_index,
                                                &session_index);
    server = application_get (app_index);
    ls = application_get_local_session (server, session_index);
    vlib_cli_output (vm, "%-40s%-15s%-20s", "TODO", ls->app_index, ls->client_index);
  }));
  /* *INDENT-ON* */
}

u8 *
format_application (u8 * s, va_list * args)
{
  application_t *app = va_arg (*args, application_t *);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);
  segment_manager_properties_t *props;
  const u8 *app_ns_name;
  u8 *app_name;

  if (app == 0)
    {
      if (verbose)
	s = format (s, "%-10s%-20s%-15s%-15s%-15s%-15s%-15s", "Index", "Name",
		    "API Client", "Namespace", "Add seg size", "Rx fifo size",
		    "Tx fifo size");
      else
	s =
	  format (s, "%-10s%-20s%-15s%-40s", "Index", "Name", "API Client",
		  "Namespace");
      return s;
    }

  app_name = app_get_name_from_reg_index (app);
  app_ns_name = app_namespace_id_from_index (app->ns_index);
  props = application_segment_manager_properties (app);
  if (verbose)
    s =
      format (s, "%-10d%-20s%-15d%-15d%-15d%-15d%-15d", app->index, app_name,
	      app->api_client_index, app->ns_index,
	      props->add_segment_size,
	      props->rx_fifo_size, props->tx_fifo_size);
  else
    s = format (s, "%-10d%-20s%-15d%-40s", app->index, app_name,
		app->api_client_index, app_ns_name);
  return s;
}


void
application_format_all_listeners (vlib_main_t * vm, int do_local, int verbose)
{
  application_t *app;
  u32 sm_index;
  u64 handle;

  if (!pool_elts (app_pool))
    {
      vlib_cli_output (vm, "No active server bindings");
      return;
    }

  if (do_local)
    {
      application_format_local_sessions (0, verbose);
      /* *INDENT-OFF* */
      pool_foreach (app, app_pool, ({
        if (!app->local_sessions && !hash_elts (app->local_connects))
          continue;
        application_format_local_sessions (app, verbose);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      vlib_cli_output (vm, "%U", format_application_listener, 0 /* header */ ,
		       0, 0, verbose);

      /* *INDENT-OFF* */
      pool_foreach (app, app_pool, ({
        if (hash_elts (app->listeners_table) == 0)
          continue;
        hash_foreach (handle, sm_index, app->listeners_table, ({
          vlib_cli_output (vm, "%U", format_application_listener, app,
                           handle, sm_index, verbose);
        }));
      }));
      /* *INDENT-ON* */
    }
}

void
application_format_all_clients (vlib_main_t * vm, int do_local, int verbose)
{
  application_t *app;

  if (!pool_elts (app_pool))
    {
      vlib_cli_output (vm, "No active apps");
      return;
    }

  if (do_local)
    {
      application_format_local_connects (0, verbose);

      /* *INDENT-OFF* */
      pool_foreach (app, app_pool, ({
        if (app->local_connects)
          application_format_local_connects (app, verbose);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      application_format_connects (0, verbose);

      /* *INDENT-OFF* */
      pool_foreach (app, app_pool, ({
        if (app->connects_seg_manager == (u32)~0)
          continue;
        application_format_connects (app, verbose);
      }));
      /* *INDENT-ON* */
    }
}

static clib_error_t *
show_app_command_fn (vlib_main_t * vm, unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  int do_server = 0, do_client = 0, do_local = 0;
  application_t *app;
  int verbose = 0;

  session_cli_return_if_not_enabled ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "server"))
	do_server = 1;
      else if (unformat (input, "client"))
	do_client = 1;
      else if (unformat (input, "local"))
	do_local = 1;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else
	break;
    }

  if (do_server)
    application_format_all_listeners (vm, do_local, verbose);

  if (do_client)
    application_format_all_clients (vm, do_local, verbose);

  /* Print app related info */
  if (!do_server && !do_client)
    {
      vlib_cli_output (vm, "%U", format_application, 0, verbose);
      /* *INDENT-OFF* */
      pool_foreach (app, app_pool, ({
	vlib_cli_output (vm, "%U", format_application, app, verbose);
      }));
      /* *INDENT-ON* */
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_app_command, static) =
{
  .path = "show app",
  .short_help = "show app [server|client] [verbose]",
  .function = show_app_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
