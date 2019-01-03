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

static app_main_t app_main;

static app_listener_t *
app_listener_alloc (application_t * app)
{
  app_listener_t *app_listener;
  pool_get (app->listeners, app_listener);
  clib_memset (app_listener, 0, sizeof (*app_listener));
  app_listener->al_index = app_listener - app->listeners;
  return app_listener;
}

static app_listener_t *
app_listener_get (application_t * app, u32 app_listener_index)
{
  return pool_elt_at_index (app->listeners, app_listener_index);
}

static void
app_listener_free (application_t * app, app_listener_t * app_listener)
{
  clib_bitmap_free (app_listener->workers);
  pool_put (app->listeners, app_listener);
  if (CLIB_DEBUG)
    clib_memset (app_listener, 0xfa, sizeof (*app_listener));
}

static app_listener_t *
app_local_listener_alloc (application_t * app)
{
  app_listener_t *app_listener;
  pool_get (app->local_listeners, app_listener);
  clib_memset (app_listener, 0, sizeof (*app_listener));
  app_listener->al_index = app_listener - app->local_listeners;
  return app_listener;
}

static app_listener_t *
app_local_listener_get (application_t * app, u32 app_listener_index)
{
  return pool_elt_at_index (app->local_listeners, app_listener_index);
}

static void
app_local_listener_free (application_t * app, app_listener_t * app_listener)
{
  clib_bitmap_free (app_listener->workers);
  pool_put (app->local_listeners, app_listener);
  if (CLIB_DEBUG)
    clib_memset (app_listener, 0xfa, sizeof (*app_listener));
}

static app_worker_map_t *
app_worker_map_alloc (application_t * app)
{
  app_worker_map_t *map;
  pool_get (app->worker_maps, map);
  clib_memset (map, 0, sizeof (*map));
  return map;
}

static u32
app_worker_map_index (application_t * app, app_worker_map_t * map)
{
  return (map - app->worker_maps);
}

static void
app_worker_map_free (application_t * app, app_worker_map_t * map)
{
  pool_put (app->worker_maps, map);
}

static app_worker_map_t *
app_worker_map_get (application_t * app, u32 map_index)
{
  if (pool_is_free_index (app->worker_maps, map_index))
    return 0;
  return pool_elt_at_index (app->worker_maps, map_index);
}

static const u8 *
app_get_name (application_t * app)
{
  return app->name;
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

static void
application_local_listener_session_endpoint (local_session_t * ll,
					     session_endpoint_t * sep)
{
  sep->transport_proto =
    session_type_transport_proto (ll->listener_session_type);
  sep->port = ll->port;
  sep->is_ip4 = ll->listener_session_type & 1;
}

/**
 * Returns app name for app-index
 */
const u8 *
application_name_from_index (u32 app_index)
{
  application_t *app = application_get (app_index);
  if (!app)
    return 0;
  return app_get_name (app);
}

static void
application_api_table_add (u32 app_index, u32 api_client_index)
{
  if (api_client_index != APP_INVALID_INDEX)
    hash_set (app_main.app_by_api_client_index, api_client_index, app_index);
}

static void
application_api_table_del (u32 api_client_index)
{
  hash_unset (app_main.app_by_api_client_index, api_client_index);
}

static void
application_name_table_add (application_t * app)
{
  hash_set_mem (app_main.app_by_name, app->name, app->app_index);
}

static void
application_name_table_del (application_t * app)
{
  hash_unset_mem (app_main.app_by_name, app->name);
}

application_t *
application_lookup (u32 api_client_index)
{
  uword *p;
  p = hash_get (app_main.app_by_api_client_index, api_client_index);
  if (p)
    return application_get_if_valid (p[0]);

  return 0;
}

application_t *
application_lookup_name (const u8 * name)
{
  uword *p;
  p = hash_get_mem (app_main.app_by_name, name);
  if (p)
    return application_get (p[0]);

  return 0;
}

application_t *
application_alloc (void)
{
  application_t *app;
  pool_get (app_main.app_pool, app);
  clib_memset (app, 0, sizeof (*app));
  app->app_index = app - app_main.app_pool;
  return app;
}

application_t *
application_get (u32 app_index)
{
  if (app_index == APP_INVALID_INDEX)
    return 0;
  return pool_elt_at_index (app_main.app_pool, app_index);
}

application_t *
application_get_if_valid (u32 app_index)
{
  if (pool_is_free_index (app_main.app_pool, app_index))
    return 0;

  return pool_elt_at_index (app_main.app_pool, app_index);
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
application_alloc_and_init (app_init_args_t * a)
{
  ssvm_segment_type_t seg_type = SSVM_SEGMENT_MEMFD;
  segment_manager_properties_t *props;
  vl_api_registration_t *reg;
  application_t *app;
  u64 *options;

  app = application_alloc ();
  options = a->options;
  /*
   * Make sure we support the requested configuration
   */
  if (!(options[APP_OPTIONS_FLAGS] & APP_OPTIONS_FLAGS_IS_BUILTIN))
    {
      reg = vl_api_client_index_to_registration (a->api_client_index);
      if (!reg)
	return VNET_API_ERROR_APP_UNSUPPORTED_CFG;
      if (vl_api_registration_file_index (reg) == VL_API_INVALID_FI)
	seg_type = SSVM_SEGMENT_SHM;
    }
  else
    {
      if (options[APP_OPTIONS_FLAGS] & APP_OPTIONS_FLAGS_EVT_MQ_USE_EVENTFD)
	{
	  clib_warning ("mq eventfds can only be used if socket transport is "
			"used for api");
	  return VNET_API_ERROR_APP_UNSUPPORTED_CFG;
	}
      seg_type = SSVM_SEGMENT_PRIVATE;
    }

  if (!application_verify_cfg (seg_type))
    return VNET_API_ERROR_APP_UNSUPPORTED_CFG;

  /* Check that the obvious things are properly set up */
  application_verify_cb_fns (a->session_cb_vft);

  app->flags = options[APP_OPTIONS_FLAGS];
  app->cb_fns = *a->session_cb_vft;
  app->ns_index = options[APP_OPTIONS_NAMESPACE];
  app->proxied_transports = options[APP_OPTIONS_PROXY_TRANSPORT];
  app->name = vec_dup (a->name);

  /* If no scope enabled, default to global */
  if (!application_has_global_scope (app)
      && !application_has_local_scope (app))
    app->flags |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;

  props = application_segment_manager_properties (app);
  segment_manager_properties_init (props);
  props->segment_size = options[APP_OPTIONS_ADD_SEGMENT_SIZE];
  props->prealloc_fifos = options[APP_OPTIONS_PREALLOC_FIFO_PAIRS];
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
  if (options[APP_OPTIONS_FLAGS] & APP_OPTIONS_FLAGS_EVT_MQ_USE_EVENTFD)
    props->use_mq_eventfd = 1;
  if (options[APP_OPTIONS_TLS_ENGINE])
    app->tls_engine = options[APP_OPTIONS_TLS_ENGINE];
  props->segment_type = seg_type;

  /* Add app to lookup by api_client_index table */
  if (!application_is_builtin (app))
    application_api_table_add (app->app_index, a->api_client_index);
  else
    application_name_table_add (app);

  a->app_index = app->app_index;

  APP_DBG ("New app name: %v api index: %u index %u", app->name,
	   app->api_client_index, app->app_index);

  return 0;
}

void
application_free (application_t * app)
{
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;
  u32 table_index;
  local_session_t *ll;
  session_endpoint_t sep;

  /*
   * The app event queue allocated in first segment is cleared with
   * the segment manager. No need to explicitly free it.
   */
  APP_DBG ("Delete app name %v api index: %d index: %d", app->name,
	   app->api_client_index, app->app_index);

  if (application_is_proxy (app))
    application_remove_proxy (app);

  /*
   * Free workers
   */

  /* *INDENT-OFF* */
  pool_flush (wrk_map, app->worker_maps, ({
    app_wrk = app_worker_get (wrk_map->wrk_index);
    app_worker_free (app_wrk);
  }));
  /* *INDENT-ON* */
  pool_free (app->worker_maps);

  /*
   * Free local listeners. Global table unbinds stop local listeners
   * as well, but if we have only local binds, these won't be cleaned up.
   * Don't bother with local accepted sessions, we clean them when
   * cleaning up the worker.
   */
  table_index = application_local_session_table (app);
  /* *INDENT-OFF* */
  pool_foreach (ll, app->local_listen_sessions, ({
    application_local_listener_session_endpoint (ll, &sep);
    session_lookup_del_session_endpoint (table_index, &sep);
  }));
  /* *INDENT-ON* */
  pool_free (app->local_listen_sessions);

  /*
   * Cleanup remaining state
   */
  if (application_is_builtin (app))
    application_name_table_del (app);
  vec_free (app->name);
  vec_free (app->tls_cert);
  vec_free (app->tls_key);
  pool_put (app_main.app_pool, app);
}

void
application_detach_process (application_t * app, u32 api_client_index)
{
  vnet_app_worker_add_del_args_t _args = { 0 }, *args = &_args;
  app_worker_map_t *wrk_map;
  u32 *wrks = 0, *wrk_index;
  app_worker_t *app_wrk;

  if (api_client_index == ~0)
    {
      application_free (app);
      return;
    }

  APP_DBG ("Detaching for app %v index %u api client index %u", app->name,
	   app->app_index, app->api_client_index);

  /* *INDENT-OFF* */
  pool_foreach (wrk_map, app->worker_maps, ({
    app_wrk = app_worker_get (wrk_map->wrk_index);
    if (app_wrk->api_client_index == api_client_index)
      vec_add1 (wrks, app_wrk->wrk_index);
  }));
  /* *INDENT-ON* */

  if (!vec_len (wrks))
    {
      clib_warning ("no workers for app %u api_index %u", app->app_index,
		    api_client_index);
      return;
    }

  args->app_index = app->app_index;
  args->api_client_index = api_client_index;
  vec_foreach (wrk_index, wrks)
  {
    app_wrk = app_worker_get (wrk_index[0]);
    args->wrk_map_index = app_wrk->wrk_map_index;
    args->is_add = 0;
    vnet_app_worker_add_del (args);
  }
  vec_free (wrks);
}

app_worker_t *
application_get_worker (application_t * app, u32 wrk_map_index)
{
  app_worker_map_t *map;
  map = app_worker_map_get (app, wrk_map_index);
  if (!map)
    return 0;
  return app_worker_get (map->wrk_index);
}

app_worker_t *
application_get_default_worker (application_t * app)
{
  return application_get_worker (app, 0);
}

u32
application_n_workers (application_t * app)
{
  return pool_elts (app->worker_maps);
}

app_worker_t *
application_listener_select_worker (stream_session_t * ls, u8 is_local)
{
  app_listener_t *app_listener;
  application_t *app;
  u32 wrk_index;

  app = application_get (ls->app_index);
  if (!is_local)
    app_listener = app_listener_get (app, ls->listener_db_index);
  else
    app_listener = app_local_listener_get (app, ls->listener_db_index);

  wrk_index = clib_bitmap_next_set (app_listener->workers,
				    app_listener->accept_rotor + 1);
  if (wrk_index == ~0)
    wrk_index = clib_bitmap_first_set (app_listener->workers);

  ASSERT (wrk_index != ~0);
  app_listener->accept_rotor = wrk_index;
  return application_get_worker (app, wrk_index);
}

app_worker_t *
app_worker_alloc (application_t * app)
{
  app_worker_t *app_wrk;
  pool_get (app_main.workers, app_wrk);
  clib_memset (app_wrk, 0, sizeof (*app_wrk));
  app_wrk->wrk_index = app_wrk - app_main.workers;
  app_wrk->app_index = app->app_index;
  app_wrk->wrk_map_index = ~0;
  app_wrk->connects_seg_manager = APP_INVALID_SEGMENT_MANAGER_INDEX;
  app_wrk->first_segment_manager = APP_INVALID_SEGMENT_MANAGER_INDEX;
  app_wrk->local_segment_manager = APP_INVALID_SEGMENT_MANAGER_INDEX;
  APP_DBG ("New app %v worker %u", app_get_name (app), app_wrk->wrk_index);
  return app_wrk;
}

app_worker_t *
app_worker_get (u32 wrk_index)
{
  return pool_elt_at_index (app_main.workers, wrk_index);
}

app_worker_t *
app_worker_get_if_valid (u32 wrk_index)
{
  if (pool_is_free_index (app_main.workers, wrk_index))
    return 0;
  return pool_elt_at_index (app_main.workers, wrk_index);
}

void
app_worker_free (app_worker_t * app_wrk)
{
  application_t *app = application_get (app_wrk->app_index);
  vnet_unbind_args_t _a, *a = &_a;
  u64 handle, *handles = 0;
  segment_manager_t *sm;
  u32 sm_index;
  int i;

  /*
   *  Listener cleanup
   */

  /* *INDENT-OFF* */
  hash_foreach (handle, sm_index, app_wrk->listeners_table,
  ({
    vec_add1 (handles, handle);
    sm = segment_manager_get (sm_index);
    sm->app_wrk_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (handles); i++)
    {
      a->app_index = app->app_index;
      a->wrk_map_index = app_wrk->wrk_map_index;
      a->handle = handles[i];
      /* seg manager is removed when unbind completes */
      vnet_unbind (a);
    }

  /*
   * Connects segment manager cleanup
   */

  if (app_wrk->connects_seg_manager != APP_INVALID_SEGMENT_MANAGER_INDEX)
    {
      sm = segment_manager_get (app_wrk->connects_seg_manager);
      sm->app_wrk_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
      segment_manager_init_del (sm);
    }

  /* If first segment manager is used by a listener */
  if (app_wrk->first_segment_manager != APP_INVALID_SEGMENT_MANAGER_INDEX
      && app_wrk->first_segment_manager != app_wrk->connects_seg_manager)
    {
      sm = segment_manager_get (app_wrk->first_segment_manager);
      sm->first_is_protected = 0;
      sm->app_wrk_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
      /* .. and has no fifos, e.g. it might be used for redirected sessions,
       * remove it */
      if (!segment_manager_has_fifos (sm))
	segment_manager_del (sm);
    }

  /*
   * Local sessions
   */
  app_worker_local_sessions_free (app_wrk);

  pool_put (app_main.workers, app_wrk);
  if (CLIB_DEBUG)
    clib_memset (app_wrk, 0xfe, sizeof (*app_wrk));
}

int
app_worker_alloc_and_init (application_t * app, app_worker_t ** wrk)
{
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;
  segment_manager_t *sm;
  int rv;

  app_wrk = app_worker_alloc (app);
  wrk_map = app_worker_map_alloc (app);
  wrk_map->wrk_index = app_wrk->wrk_index;
  app_wrk->wrk_map_index = app_worker_map_index (app, wrk_map);

  /*
   * Setup first segment manager
   */
  sm = segment_manager_new ();
  sm->app_wrk_index = app_wrk->wrk_index;

  if ((rv = segment_manager_init (sm, app->sm_properties.segment_size,
				  app->sm_properties.prealloc_fifos)))
    {
      app_worker_free (app_wrk);
      return rv;
    }
  sm->first_is_protected = 1;

  /*
   * Setup app worker
   */
  app_wrk->first_segment_manager = segment_manager_index (sm);
  app_wrk->listeners_table = hash_create (0, sizeof (u64));
  app_wrk->event_queue = segment_manager_event_queue (sm);
  app_wrk->app_is_builtin = application_is_builtin (app);

  /*
   * Segment manager for local sessions
   */
  sm = segment_manager_new ();
  sm->app_wrk_index = app_wrk->wrk_index;
  app_wrk->local_segment_manager = segment_manager_index (sm);
  app_wrk->local_connects = hash_create (0, sizeof (u64));

  *wrk = app_wrk;

  return 0;
}

application_t *
app_worker_get_app (u32 wrk_index)
{
  app_worker_t *app_wrk;
  app_wrk = app_worker_get_if_valid (wrk_index);
  if (!app_wrk)
    return 0;
  return application_get_if_valid (app_wrk->app_index);
}

static segment_manager_t *
app_worker_alloc_segment_manager (app_worker_t * app_wrk)
{
  segment_manager_t *sm = 0;

  /* If the first segment manager is not in use, don't allocate a new one */
  if (app_wrk->first_segment_manager != APP_INVALID_SEGMENT_MANAGER_INDEX
      && app_wrk->first_segment_manager_in_use == 0)
    {
      sm = segment_manager_get (app_wrk->first_segment_manager);
      app_wrk->first_segment_manager_in_use = 1;
      return sm;
    }

  sm = segment_manager_new ();
  sm->app_wrk_index = app_wrk->wrk_index;

  return sm;
}

int
app_worker_start_listen (app_worker_t * app_wrk, stream_session_t * ls)
{
  segment_manager_t *sm;

  /* Allocate segment manager. All sessions derived out of a listen session
   * have fifos allocated by the same segment manager. */
  if (!(sm = app_worker_alloc_segment_manager (app_wrk)))
    return -1;

  /* Add to app's listener table. Useful to find all child listeners
   * when app goes down, although, just for unbinding this is not needed */
  hash_set (app_wrk->listeners_table, listen_session_get_handle (ls),
	    segment_manager_index (sm));

  if (!ls->server_rx_fifo
      && session_transport_service_type (ls) == TRANSPORT_SERVICE_CL)
    {
      if (session_alloc_fifos (sm, ls))
	return -1;
    }
  return 0;
}

int
app_worker_stop_listen (app_worker_t * app_wrk, session_handle_t handle)
{
  segment_manager_t *sm;
  uword *sm_indexp;

  sm_indexp = hash_get (app_wrk->listeners_table, handle);
  if (PREDICT_FALSE (!sm_indexp))
    {
      clib_warning ("listener handle was removed %llu!", handle);
      return -1;
    }

  sm = segment_manager_get (*sm_indexp);
  if (app_wrk->first_segment_manager == *sm_indexp)
    {
      /* Delete sessions but don't remove segment manager */
      app_wrk->first_segment_manager_in_use = 0;
      segment_manager_del_sessions (sm);
    }
  else
    {
      segment_manager_init_del (sm);
    }
  hash_unset (app_wrk->listeners_table, handle);

  return 0;
}

/**
 * Start listening local transport endpoint for requested transport.
 *
 * Creates a 'dummy' stream session with state LISTENING to be used in session
 * lookups, prior to establishing connection. Requests transport to build
 * it's own specific listening connection.
 */
int
application_start_listen (application_t * app,
			  session_endpoint_cfg_t * sep_ext,
			  session_handle_t * res)
{
  app_listener_t *app_listener;
  u32 table_index, fib_proto;
  session_endpoint_t *sep;
  app_worker_t *app_wrk;
  stream_session_t *ls;
  session_handle_t lh;
  session_type_t sst;

  /*
   * Check if sep is already listened on
   */
  sep = (session_endpoint_t *) sep_ext;
  fib_proto = session_endpoint_fib_proto (sep);
  table_index = application_session_table (app, fib_proto);
  lh = session_lookup_endpoint_listener (table_index, sep, 1);
  if (lh != SESSION_INVALID_HANDLE)
    {
      ls = listen_session_get_from_handle (lh);
      if (ls->app_index != app->app_index)
	return VNET_API_ERROR_ADDRESS_IN_USE;

      app_wrk = app_worker_get (sep_ext->app_wrk_index);
      if (ls->app_wrk_index == app_wrk->wrk_index)
	return VNET_API_ERROR_ADDRESS_IN_USE;

      if (app_worker_start_listen (app_wrk, ls))
	return -1;

      app_listener = app_listener_get (app, ls->listener_db_index);
      app_listener->workers = clib_bitmap_set (app_listener->workers,
					       app_wrk->wrk_map_index, 1);

      *res = listen_session_get_handle (ls);
      return 0;
    }

  /*
   * Allocate new listener for application
   */
  sst = session_type_from_proto_and_ip (sep_ext->transport_proto,
					sep_ext->is_ip4);
  ls = listen_session_new (0, sst);
  ls->app_index = app->app_index;
  lh = listen_session_get_handle (ls);
  if (session_listen (ls, sep_ext))
    goto err;


  ls = listen_session_get_from_handle (lh);
  app_listener = app_listener_alloc (app);
  ls->listener_db_index = app_listener->al_index;

  /*
   * Setup app worker as a listener
   */
  app_wrk = app_worker_get (sep_ext->app_wrk_index);
  ls->app_wrk_index = app_wrk->wrk_index;
  if (app_worker_start_listen (app_wrk, ls))
    goto err;
  app_listener->workers = clib_bitmap_set (app_listener->workers,
					   app_wrk->wrk_map_index, 1);

  *res = lh;
  return 0;

err:
  listen_session_del (ls);
  return -1;
}

/**
 * Stop listening on session associated to handle
 *
 * @param handle	listener handle
 * @param app_index	index of the app owning the handle.
 * @param app_wrk_index	index of the worker requesting the stop
 */
int
application_stop_listen (u32 app_index, u32 app_wrk_index,
			 session_handle_t handle)
{
  app_listener_t *app_listener;
  stream_session_t *listener;
  app_worker_t *app_wrk;
  application_t *app;

  listener = listen_session_get_from_handle (handle);
  app = application_get (app_index);
  if (PREDICT_FALSE (!app || app->app_index != listener->app_index))
    {
      clib_warning ("app doesn't own handle %llu!", handle);
      return -1;
    }

  app_listener = app_listener_get (app, listener->listener_db_index);
  if (!clib_bitmap_get (app_listener->workers, app_wrk_index))
    {
      clib_warning ("worker %u not listening on handle %lu", app_wrk_index,
		    handle);
      return 0;
    }

  app_wrk = application_get_worker (app, app_wrk_index);
  app_worker_stop_listen (app_wrk, handle);
  clib_bitmap_set_no_check (app_listener->workers, app_wrk_index, 0);

  if (clib_bitmap_is_zero (app_listener->workers))
    {
      session_stop_listen (listener);
      app_listener_free (app, app_listener);
      listen_session_del (listener);
    }

  return 0;
}

int
app_worker_open_session (app_worker_t * app, session_endpoint_t * sep,
			 u32 api_context)
{
  int rv;

  /* Make sure we have a segment manager for connects */
  app_worker_alloc_connects_segment_manager (app);

  if ((rv = session_open (app->wrk_index, sep, api_context)))
    return rv;

  return 0;
}

int
app_worker_alloc_connects_segment_manager (app_worker_t * app_wrk)
{
  segment_manager_t *sm;

  if (app_wrk->connects_seg_manager == APP_INVALID_SEGMENT_MANAGER_INDEX)
    {
      sm = app_worker_alloc_segment_manager (app_wrk);
      if (sm == 0)
	return -1;
      app_wrk->connects_seg_manager = segment_manager_index (sm);
    }
  return 0;
}

segment_manager_t *
app_worker_get_connect_segment_manager (app_worker_t * app)
{
  ASSERT (app->connects_seg_manager != (u32) ~ 0);
  return segment_manager_get (app->connects_seg_manager);
}

segment_manager_t *
app_worker_get_or_alloc_connect_segment_manager (app_worker_t * app_wrk)
{
  if (app_wrk->connects_seg_manager == (u32) ~ 0)
    app_worker_alloc_connects_segment_manager (app_wrk);
  return segment_manager_get (app_wrk->connects_seg_manager);
}

segment_manager_t *
app_worker_get_listen_segment_manager (app_worker_t * app,
				       stream_session_t * listener)
{
  uword *smp;
  smp = hash_get (app->listeners_table, listen_session_get_handle (listener));
  ASSERT (smp != 0);
  return segment_manager_get (*smp);
}

clib_error_t *
vnet_app_worker_add_del (vnet_app_worker_add_del_args_t * a)
{
  svm_fifo_segment_private_t *fs;
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;
  segment_manager_t *sm;
  application_t *app;
  int rv;

  app = application_get (a->app_index);
  if (!app)
    return clib_error_return_code (0, VNET_API_ERROR_INVALID_VALUE, 0,
				   "App %u does not exist", a->app_index);

  if (a->is_add)
    {
      if ((rv = app_worker_alloc_and_init (app, &app_wrk)))
	return clib_error_return_code (0, rv, 0, "app wrk init: %d", rv);

      /* Map worker api index to the app */
      app_wrk->api_client_index = a->api_client_index;
      application_api_table_add (app->app_index, a->api_client_index);

      sm = segment_manager_get (app_wrk->first_segment_manager);
      fs = segment_manager_get_segment_w_lock (sm, 0);
      a->segment = &fs->ssvm;
      a->segment_handle = segment_manager_segment_handle (sm, fs);
      segment_manager_segment_reader_unlock (sm);
      a->evt_q = app_wrk->event_queue;
      a->wrk_map_index = app_wrk->wrk_map_index;
    }
  else
    {
      wrk_map = app_worker_map_get (app, a->wrk_map_index);
      if (!wrk_map)
	return clib_error_return_code (0, VNET_API_ERROR_INVALID_VALUE, 0,
				       "App %u does not have worker %u",
				       app->app_index, a->wrk_map_index);
      app_wrk = app_worker_get (wrk_map->wrk_index);
      if (!app_wrk)
	return clib_error_return_code (0, VNET_API_ERROR_INVALID_VALUE, 0,
				       "No worker %u", a->wrk_map_index);
      application_api_table_del (app_wrk->api_client_index);
      app_worker_free (app_wrk);
      app_worker_map_free (app, wrk_map);
      if (application_n_workers (app) == 0)
	application_free (app);
    }
  return 0;
}

segment_manager_t *
application_get_local_segment_manager (app_worker_t * app)
{
  return segment_manager_get (app->local_segment_manager);
}

segment_manager_t *
application_get_local_segment_manager_w_session (app_worker_t * app,
						 local_session_t * ls)
{
  stream_session_t *listener;
  if (application_local_session_listener_has_transport (ls))
    {
      listener = listen_session_get (ls->listener_index);
      return app_worker_get_listen_segment_manager (app, listener);
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

u8
application_use_mq_for_ctrl (application_t * app)
{
  return app->flags & APP_OPTIONS_FLAGS_USE_MQ_FOR_CTRL_MSGS;
}

/**
 * Send an API message to the external app, to map new segment
 */
int
app_worker_add_segment_notify (u32 app_wrk_index, u64 segment_handle)
{
  app_worker_t *app_wrk = app_worker_get (app_wrk_index);
  application_t *app = application_get (app_wrk->app_index);
  return app->cb_fns.add_segment_callback (app_wrk->api_client_index,
					   segment_handle);
}

u32
application_n_listeners (app_worker_t * app)
{
  return hash_elts (app->listeners_table);
}

stream_session_t *
app_worker_first_listener (app_worker_t * app, u8 fib_proto,
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
	 && listener->enqueue_epoch != SESSION_PROXY_LISTENER_INDEX)
       return listener;
   }));
  /* *INDENT-ON* */

  return 0;
}

u8
app_worker_application_is_builtin (app_worker_t * app_wrk)
{
  return app_wrk->app_is_builtin;
}

stream_session_t *
application_proxy_listener (app_worker_t * app, u8 fib_proto,
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
	 && listener->enqueue_epoch == SESSION_PROXY_LISTENER_INDEX)
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
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  transport_connection_t *tc;
  app_worker_t *app_wrk;
  stream_session_t *s;
  u64 handle;

  /* TODO decide if we want proxy to be enabled for all workers */
  app_wrk = application_get_default_worker (app);
  if (is_start)
    {
      s = app_worker_first_listener (app_wrk, fib_proto, transport_proto);
      if (!s)
	{
	  sep.is_ip4 = is_ip4;
	  sep.fib_index = app_namespace_get_fib_index (app_ns, fib_proto);
	  sep.sw_if_index = app_ns->sw_if_index;
	  sep.transport_proto = transport_proto;
	  sep.app_wrk_index = app_wrk->wrk_index;	/* only default */
	  application_start_listen (app, &sep, &handle);
	  s = listen_session_get_from_handle (handle);
	  s->enqueue_epoch = SESSION_PROXY_LISTENER_INDEX;
	}
    }
  else
    {
      s = application_proxy_listener (app_wrk, fib_proto, transport_proto);
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
	session_lookup_add_session_endpoint (sti,
					     (session_endpoint_t *) & sep,
					     s->session_index);
      else
	session_lookup_del_session_endpoint (sti,
					     (session_endpoint_t *) & sep);
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
					   app->app_index);
      sep.is_ip4 = 0;
      session_lookup_add_session_endpoint (app_ns->local_table_index, &sep,
					   app->app_index);
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

static inline int
app_enqueue_evt (svm_msg_q_t * mq, svm_msg_q_msg_t * msg, u8 lock)
{
  if (PREDICT_FALSE (svm_msg_q_is_full (mq)))
    {
      clib_warning ("evt q full");
      svm_msg_q_free_msg (mq, msg);
      if (lock)
	svm_msg_q_unlock (mq);
      return -1;
    }

  if (lock)
    {
      svm_msg_q_add_and_unlock (mq, msg);
      return 0;
    }

  /* Even when not locking the ring, we must wait for queue mutex */
  if (svm_msg_q_add (mq, msg, SVM_Q_WAIT))
    {
      clib_warning ("msg q add returned");
      return -1;
    }
  return 0;
}

static inline int
app_send_io_evt_rx (app_worker_t * app_wrk, stream_session_t * s, u8 lock)
{
  session_event_t *evt;
  svm_msg_q_msg_t msg;
  svm_msg_q_t *mq;

  if (PREDICT_FALSE (s->session_state != SESSION_STATE_READY
		     && s->session_state != SESSION_STATE_LISTENING))
    {
      /* Session is closed so app will never clean up. Flush rx fifo */
      if (s->session_state == SESSION_STATE_CLOSED)
	svm_fifo_dequeue_drop_all (s->server_rx_fifo);
      return 0;
    }

  if (app_worker_application_is_builtin (app_wrk))
    {
      application_t *app = application_get (app_wrk->app_index);
      return app->cb_fns.builtin_app_rx_callback (s);
    }

  if (svm_fifo_has_event (s->server_rx_fifo)
      || svm_fifo_is_empty (s->server_rx_fifo))
    return 0;

  mq = app_wrk->event_queue;
  if (lock)
    svm_msg_q_lock (mq);

  if (PREDICT_FALSE (svm_msg_q_ring_is_full (mq, SESSION_MQ_IO_EVT_RING)))
    {
      clib_warning ("evt q rings full");
      if (lock)
	svm_msg_q_unlock (mq);
      return -1;
    }

  msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
  ASSERT (!svm_msg_q_msg_is_invalid (&msg));

  evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
  evt->fifo = s->server_rx_fifo;
  evt->event_type = FIFO_EVENT_APP_RX;

  (void) svm_fifo_set_event (s->server_rx_fifo);

  if (app_enqueue_evt (mq, &msg, lock))
    return -1;
  return 0;
}

static inline int
app_send_io_evt_tx (app_worker_t * app_wrk, stream_session_t * s, u8 lock)
{
  svm_msg_q_t *mq;
  session_event_t *evt;
  svm_msg_q_msg_t msg;

  if (app_worker_application_is_builtin (app_wrk))
    return 0;

  mq = app_wrk->event_queue;
  if (lock)
    svm_msg_q_lock (mq);

  if (PREDICT_FALSE (svm_msg_q_ring_is_full (mq, SESSION_MQ_IO_EVT_RING)))
    {
      clib_warning ("evt q rings full");
      if (lock)
	svm_msg_q_unlock (mq);
      return -1;
    }

  msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
  ASSERT (!svm_msg_q_msg_is_invalid (&msg));

  evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
  evt->event_type = FIFO_EVENT_APP_TX;
  evt->fifo = s->server_tx_fifo;

  return app_enqueue_evt (mq, &msg, lock);
}

/* *INDENT-OFF* */
typedef int (app_send_evt_handler_fn) (app_worker_t *app,
				       stream_session_t *s,
				       u8 lock);
static app_send_evt_handler_fn * const app_send_evt_handler_fns[3] = {
    app_send_io_evt_rx,
    0,
    app_send_io_evt_tx,
};
/* *INDENT-ON* */

/**
 * Send event to application
 *
 * Logic from queue perspective is non-blocking. If there's
 * not enough space to enqueue a message, we return.
 */
int
app_worker_send_event (app_worker_t * app, stream_session_t * s, u8 evt_type)
{
  ASSERT (app && evt_type <= FIFO_EVENT_APP_TX);
  return app_send_evt_handler_fns[evt_type] (app, s, 0 /* lock */ );
}

/**
 * Send event to application
 *
 * Logic from queue perspective is blocking. However, if queue is full,
 * we return.
 */
int
app_worker_lock_and_send_event (app_worker_t * app, stream_session_t * s,
				u8 evt_type)
{
  return app_send_evt_handler_fns[evt_type] (app, s, 1 /* lock */ );
}

local_session_t *
application_local_session_alloc (app_worker_t * app_wrk)
{
  local_session_t *s;
  pool_get (app_wrk->local_sessions, s);
  clib_memset (s, 0, sizeof (*s));
  s->app_wrk_index = app_wrk->wrk_index;
  s->session_index = s - app_wrk->local_sessions;
  s->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_NONE, 0);
  return s;
}

void
application_local_session_free (app_worker_t * app, local_session_t * s)
{
  pool_put (app->local_sessions, s);
  if (CLIB_DEBUG)
    clib_memset (s, 0xfc, sizeof (*s));
}

local_session_t *
application_get_local_session (app_worker_t * app_wrk, u32 session_index)
{
  if (pool_is_free_index (app_wrk->local_sessions, session_index))
    return 0;
  return pool_elt_at_index (app_wrk->local_sessions, session_index);
}

local_session_t *
application_get_local_session_from_handle (session_handle_t handle)
{
  app_worker_t *server_wrk;
  u32 session_index, server_wrk_index;
  local_session_parse_handle (handle, &server_wrk_index, &session_index);
  server_wrk = app_worker_get_if_valid (server_wrk_index);
  if (!server_wrk)
    return 0;
  return application_get_local_session (server_wrk, session_index);
}

local_session_t *
application_local_listen_session_alloc (application_t * app)
{
  local_session_t *ll;
  pool_get (app->local_listen_sessions, ll);
  clib_memset (ll, 0, sizeof (*ll));
  return ll;
}

u32
application_local_listener_index (application_t * app, local_session_t * ll)
{
  return (ll - app->local_listen_sessions);
}

void
application_local_listen_session_free (application_t * app,
				       local_session_t * ll)
{
  pool_put (app->local_listen_sessions, ll);
  if (CLIB_DEBUG)
    clib_memset (ll, 0xfb, sizeof (*ll));
}

int
application_start_local_listen (application_t * app,
				session_endpoint_cfg_t * sep_ext,
				session_handle_t * handle)
{
  app_listener_t *app_listener;
  session_endpoint_t *sep;
  app_worker_t *app_wrk;
  session_handle_t lh;
  local_session_t *ll;
  u32 table_index;

  sep = (session_endpoint_t *) sep_ext;
  table_index = application_local_session_table (app);
  app_wrk = app_worker_get (sep_ext->app_wrk_index);

  /* An exact sep match, as opposed to session_lookup_local_listener */
  lh = session_lookup_endpoint_listener (table_index, sep, 1);
  if (lh != SESSION_INVALID_HANDLE)
    {
      ll = application_get_local_listener_w_handle (lh);
      if (ll->app_index != app->app_index)
	return VNET_API_ERROR_ADDRESS_IN_USE;

      if (ll->app_wrk_index == app_wrk->wrk_index)
	return VNET_API_ERROR_ADDRESS_IN_USE;

      app_listener = app_local_listener_get (app, ll->listener_db_index);
      app_listener->workers = clib_bitmap_set (app_listener->workers,
					       app_wrk->wrk_map_index, 1);
      *handle = application_local_session_handle (ll);
      return 0;
    }

  ll = application_local_listen_session_alloc (app);
  ll->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_NONE, 0);
  ll->app_wrk_index = app_wrk->app_index;
  ll->session_index = application_local_listener_index (app, ll);
  ll->port = sep_ext->port;
  /* Store the original session type for the unbind */
  ll->listener_session_type =
    session_type_from_proto_and_ip (sep_ext->transport_proto,
				    sep_ext->is_ip4);
  ll->transport_listener_index = ~0;
  ll->app_index = app->app_index;

  app_listener = app_local_listener_alloc (app);
  ll->listener_db_index = app_listener->al_index;
  app_listener->workers = clib_bitmap_set (app_listener->workers,
					   app_wrk->wrk_map_index, 1);

  *handle = application_local_session_handle (ll);
  session_lookup_add_session_endpoint (table_index, sep, *handle);

  return 0;
}

/**
 * Clean up local session table. If we have a listener session use it to
 * find the port and proto. If not, the handle must be a local table handle
 * so parse it.
 */
int
application_stop_local_listen (u32 app_index, u32 wrk_map_index,
			       session_handle_t lh)
{
  session_endpoint_t sep = SESSION_ENDPOINT_NULL;
  u32 table_index, ll_index, server_index;
  app_listener_t *app_listener;
  app_worker_t *server_wrk;
  stream_session_t *sl = 0;
  local_session_t *ll, *ls;
  application_t *server;

  server = application_get (app_index);
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
	return -1;
    }

  local_session_parse_handle (lh, &server_index, &ll_index);
  if (PREDICT_FALSE (server_index != app_index))
    {
      clib_warning ("app %u does not own local handle 0x%lx", app_index, lh);
      return -1;
    }

  ll = application_get_local_listen_session (server, ll_index);
  if (PREDICT_FALSE (!ll))
    {
      clib_warning ("no local listener");
      return -1;
    }

  app_listener = app_local_listener_get (server, ll->listener_db_index);
  if (!clib_bitmap_get (app_listener->workers, wrk_map_index))
    {
      clib_warning ("app wrk %u not listening on handle %lu", wrk_map_index,
		    lh);
      return -1;
    }

  server_wrk = application_get_worker (server, wrk_map_index);
  /* *INDENT-OFF* */
  pool_foreach (ls, server_wrk->local_sessions, ({
    if (ls->listener_index == ll->session_index)
      application_local_session_disconnect (server_wrk->app_index, ls);
  }));
  /* *INDENT-ON* */

  clib_bitmap_set_no_check (app_listener->workers, wrk_map_index, 0);
  if (clib_bitmap_is_zero (app_listener->workers))
    {
      app_local_listener_free (server, app_listener);
      application_local_listener_session_endpoint (ll, &sep);
      session_lookup_del_session_endpoint (table_index, &sep);
      application_local_listen_session_free (server, ll);
    }

  return 0;
}

static void
application_local_session_fix_eventds (svm_msg_q_t * sq, svm_msg_q_t * cq)
{
  int fd;

  /*
   * segment manager initializes only the producer eventds, since vpp is
   * typically the producer. But for local sessions, we also pass to the
   * apps the mqs they listen on for events from peer apps, so they are also
   * consumer fds.
   */
  fd = svm_msg_q_get_producer_eventfd (sq);
  svm_msg_q_set_consumer_eventfd (sq, fd);
  fd = svm_msg_q_get_producer_eventfd (cq);
  svm_msg_q_set_consumer_eventfd (cq, fd);
}

int
application_local_session_connect (app_worker_t * client_wrk,
				   app_worker_t * server_wrk,
				   local_session_t * ll, u32 opaque)
{
  u32 seg_size, evt_q_sz, evt_q_elts, margin = 16 << 10;
  u32 round_rx_fifo_sz, round_tx_fifo_sz, sm_index;
  segment_manager_properties_t *props, *cprops;
  int rv, has_transport, seg_index;
  svm_fifo_segment_private_t *seg;
  application_t *server, *client;
  segment_manager_t *sm;
  local_session_t *ls;
  svm_msg_q_t *sq, *cq;
  u64 segment_handle;

  ls = application_local_session_alloc (server_wrk);
  server = application_get (server_wrk->app_index);
  client = application_get (client_wrk->app_index);

  props = application_segment_manager_properties (server);
  cprops = application_segment_manager_properties (client);
  evt_q_elts = props->evt_q_size + cprops->evt_q_size;
  evt_q_sz = segment_manager_evt_q_expected_size (evt_q_elts);
  round_rx_fifo_sz = 1 << max_log2 (props->rx_fifo_size);
  round_tx_fifo_sz = 1 << max_log2 (props->tx_fifo_size);
  seg_size = round_rx_fifo_sz + round_tx_fifo_sz + evt_q_sz + margin;

  has_transport = session_has_transport ((stream_session_t *) ll);
  if (!has_transport)
    {
      /* Local sessions don't have backing transport */
      ls->port = ll->port;
      sm = application_get_local_segment_manager (server_wrk);
    }
  else
    {
      stream_session_t *sl = (stream_session_t *) ll;
      transport_connection_t *tc;
      tc = listen_session_get_transport (sl);
      ls->port = tc->lcl_port;
      sm = app_worker_get_listen_segment_manager (server_wrk, sl);
    }

  seg_index = segment_manager_add_segment (sm, seg_size);
  if (seg_index < 0)
    {
      clib_warning ("failed to add new cut-through segment");
      return seg_index;
    }
  seg = segment_manager_get_segment_w_lock (sm, seg_index);
  sq = segment_manager_alloc_queue (seg, props);
  cq = segment_manager_alloc_queue (seg, cprops);

  if (props->use_mq_eventfd)
    application_local_session_fix_eventds (sq, cq);

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
  sm_index = segment_manager_index (sm);
  ls->server_rx_fifo->ct_session_index = ls->session_index;
  ls->server_tx_fifo->ct_session_index = ls->session_index;
  ls->server_rx_fifo->segment_manager = sm_index;
  ls->server_tx_fifo->segment_manager = sm_index;
  ls->server_rx_fifo->segment_index = seg_index;
  ls->server_tx_fifo->segment_index = seg_index;
  ls->svm_segment_index = seg_index;
  ls->listener_index = ll->session_index;
  ls->client_wrk_index = client_wrk->wrk_index;
  ls->client_opaque = opaque;
  ls->listener_session_type = ll->session_type;
  ls->session_state = SESSION_STATE_READY;

  segment_handle = segment_manager_segment_handle (sm, seg);
  if ((rv = server->cb_fns.add_segment_callback (server_wrk->api_client_index,
						 segment_handle)))
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
  if (server->flags & APP_OPTIONS_FLAGS_IS_BUILTIN)
    application_local_session_connect_notify (ls);

  return 0;

failed:
  if (!has_transport)
    segment_manager_del_segment (sm, seg);
  return rv;
}

static u64
application_client_local_connect_key (local_session_t * ls)
{
  return (((u64) ls->app_wrk_index) << 32 | (u64) ls->session_index);
}

static void
application_client_local_connect_key_parse (u64 key, u32 * app_wrk_index,
					    u32 * session_index)
{
  *app_wrk_index = key >> 32;
  *session_index = key & 0xFFFFFFFF;
}

int
application_local_session_connect_notify (local_session_t * ls)
{
  svm_fifo_segment_private_t *seg;
  app_worker_t *client_wrk, *server_wrk;
  segment_manager_t *sm;
  application_t *client;
  int rv, is_fail = 0;
  u64 segment_handle;
  u64 client_key;

  client_wrk = app_worker_get (ls->client_wrk_index);
  server_wrk = app_worker_get (ls->app_wrk_index);
  client = application_get (client_wrk->app_index);

  sm = application_get_local_segment_manager_w_session (server_wrk, ls);
  seg = segment_manager_get_segment_w_lock (sm, ls->svm_segment_index);
  segment_handle = segment_manager_segment_handle (sm, seg);
  if ((rv = client->cb_fns.add_segment_callback (client_wrk->api_client_index,
						 segment_handle)))
    {
      clib_warning ("failed to notify client %u of new segment",
		    ls->client_wrk_index);
      segment_manager_segment_reader_unlock (sm);
      application_local_session_disconnect (ls->client_wrk_index, ls);
      is_fail = 1;
    }
  else
    {
      segment_manager_segment_reader_unlock (sm);
    }

  client->cb_fns.session_connected_callback (client_wrk->wrk_index,
					     ls->client_opaque,
					     (stream_session_t *) ls,
					     is_fail);

  client_key = application_client_local_connect_key (ls);
  hash_set (client_wrk->local_connects, client_key, client_key);
  return 0;
}

int
application_local_session_cleanup (app_worker_t * client_wrk,
				   app_worker_t * server_wrk,
				   local_session_t * ls)
{
  svm_fifo_segment_private_t *seg;
  stream_session_t *listener;
  segment_manager_t *sm;
  u64 client_key;
  u8 has_transport;

  /* Retrieve listener transport type as it is the one that decides where
   * the fifos are allocated */
  has_transport = application_local_session_listener_has_transport (ls);
  if (!has_transport)
    sm = application_get_local_segment_manager_w_session (server_wrk, ls);
  else
    {
      listener = listen_session_get (ls->listener_index);
      sm = app_worker_get_listen_segment_manager (server_wrk, listener);
    }

  seg = segment_manager_get_segment (sm, ls->svm_segment_index);
  if (client_wrk)
    {
      client_key = application_client_local_connect_key (ls);
      hash_unset (client_wrk->local_connects, client_key);
    }

  if (!has_transport)
    {
      application_t *server = application_get (server_wrk->app_index);
      u64 segment_handle = segment_manager_segment_handle (sm, seg);
      server->cb_fns.del_segment_callback (server_wrk->api_client_index,
					   segment_handle);
      if (client_wrk)
	{
	  application_t *client = application_get (client_wrk->app_index);
	  client->cb_fns.del_segment_callback (client_wrk->api_client_index,
					       segment_handle);
	}
      segment_manager_del_segment (sm, seg);
    }

  application_local_session_free (server_wrk, ls);

  return 0;
}

int
application_local_session_disconnect (u32 app_index, local_session_t * ls)
{
  app_worker_t *client_wrk, *server_wrk;
  u8 is_server = 0, is_client = 0;
  application_t *app;

  app = application_get_if_valid (app_index);
  if (!app)
    return 0;

  client_wrk = app_worker_get_if_valid (ls->client_wrk_index);
  server_wrk = app_worker_get (ls->app_wrk_index);

  if (server_wrk->app_index == app_index)
    is_server = 1;
  else if (client_wrk && client_wrk->app_index == app_index)
    is_client = 1;

  if (!is_server && !is_client)
    {
      clib_warning ("app %u is neither client nor server for session 0x%lx",
		    app_index, application_local_session_handle (ls));
      return VNET_API_ERROR_INVALID_VALUE;
    }

  if (ls->session_state == SESSION_STATE_CLOSED)
    return application_local_session_cleanup (client_wrk, server_wrk, ls);

  if (app_index == ls->client_wrk_index)
    {
      mq_send_local_session_disconnected_cb (ls->app_wrk_index, ls);
    }
  else
    {
      if (!client_wrk)
	{
	  return application_local_session_cleanup (client_wrk, server_wrk,
						    ls);
	}
      else if (ls->session_state < SESSION_STATE_READY)
	{
	  application_t *client = application_get (client_wrk->app_index);
	  client->cb_fns.session_connected_callback (client_wrk->wrk_index,
						     ls->client_opaque,
						     (stream_session_t *) ls,
						     1 /* is_fail */ );
	  ls->session_state = SESSION_STATE_CLOSED;
	  return application_local_session_cleanup (client_wrk, server_wrk,
						    ls);
	}
      else
	{
	  mq_send_local_session_disconnected_cb (client_wrk->wrk_index, ls);
	}
    }

  ls->session_state = SESSION_STATE_CLOSED;

  return 0;
}

int
application_local_session_disconnect_w_index (u32 app_wrk_index, u32 ls_index)
{
  app_worker_t *app_wrk;
  local_session_t *ls;
  app_wrk = app_worker_get (app_wrk_index);
  ls = application_get_local_session (app_wrk, ls_index);
  return application_local_session_disconnect (app_wrk_index, ls);
}

void
app_worker_local_sessions_free (app_worker_t * app_wrk)
{
  u32 index, server_wrk_index, session_index;
  u64 handle, *handles = 0;
  app_worker_t *server_wrk;
  segment_manager_t *sm;
  local_session_t *ls;
  int i;

  /*
   * Local sessions
   */
  if (app_wrk->local_sessions)
    {
      /* *INDENT-OFF* */
      pool_foreach (ls, app_wrk->local_sessions, ({
	application_local_session_disconnect (app_wrk->wrk_index, ls);
      }));
      /* *INDENT-ON* */
    }

  /*
   * Local connects
   */
  vec_reset_length (handles);
  /* *INDENT-OFF* */
  hash_foreach (handle, index, app_wrk->local_connects, ({
    vec_add1 (handles, handle);
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (handles); i++)
    {
      application_client_local_connect_key_parse (handles[i],
						  &server_wrk_index,
						  &session_index);
      server_wrk = app_worker_get_if_valid (server_wrk_index);
      if (server_wrk)
	{
	  ls = application_get_local_session (server_wrk, session_index);
	  application_local_session_disconnect (app_wrk->wrk_index, ls);
	}
    }

  sm = segment_manager_get (app_wrk->local_segment_manager);
  sm->app_wrk_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
  segment_manager_del (sm);
}

clib_error_t *
vnet_app_add_tls_cert (vnet_app_add_tls_cert_args_t * a)
{
  application_t *app;
  app = application_get (a->app_index);
  if (!app)
    return clib_error_return_code (0, VNET_API_ERROR_APPLICATION_NOT_ATTACHED,
				   0, "app %u doesn't exist", a->app_index);
  app->tls_cert = vec_dup (a->cert);
  return 0;
}

clib_error_t *
vnet_app_add_tls_key (vnet_app_add_tls_key_args_t * a)
{
  application_t *app;
  app = application_get (a->app_index);
  if (!app)
    return clib_error_return_code (0, VNET_API_ERROR_APPLICATION_NOT_ATTACHED,
				   0, "app %u doesn't exist", a->app_index);
  app->tls_key = vec_dup (a->key);
  return 0;
}

u8 *
format_app_worker_listener (u8 * s, va_list * args)
{
  app_worker_t *app_wrk = va_arg (*args, app_worker_t *);
  u64 handle = va_arg (*args, u64);
  u32 sm_index = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  stream_session_t *listener;
  const u8 *app_name;
  u8 *str;

  if (!app_wrk)
    {
      if (verbose)
	s = format (s, "%-40s%-25s%=10s%-15s%-15s%-10s", "Connection", "App",
		    "Wrk", "API Client", "ListenerID", "SegManager");
      else
	s = format (s, "%-40s%-25s%=10s", "Connection", "App", "Wrk");

      return s;
    }

  app_name = application_name_from_index (app_wrk->app_index);
  listener = listen_session_get_from_handle (handle);
  str = format (0, "%U", format_stream_session, listener, verbose);

  if (verbose)
    {
      char buf[32];
      sprintf (buf, "%u(%u)", app_wrk->wrk_map_index, app_wrk->wrk_index);
      s = format (s, "%-40s%-25s%=10s%-15u%-15u%-10u", str, app_name,
		  buf, app_wrk->api_client_index, handle, sm_index);
    }
  else
    s = format (s, "%-40s%-25s%=10u", str, app_name, app_wrk->wrk_map_index);

  return s;
}

static void
application_format_listeners (application_t * app, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;
  u32 sm_index;
  u64 handle;

  if (!app)
    {
      vlib_cli_output (vm, "%U", format_app_worker_listener, 0 /* header */ ,
		       0, 0, verbose);
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach (wrk_map, app->worker_maps, ({
    app_wrk = app_worker_get (wrk_map->wrk_index);
    if (hash_elts (app_wrk->listeners_table) == 0)
      continue;
    hash_foreach (handle, sm_index, app_wrk->listeners_table, ({
      vlib_cli_output (vm, "%U", format_app_worker_listener, app_wrk,
                       handle, sm_index, verbose);
    }));
  }));
  /* *INDENT-ON* */
}

static void
app_worker_format_connects (app_worker_t * app_wrk, int verbose)
{
  svm_fifo_segment_private_t *fifo_segment;
  vlib_main_t *vm = vlib_get_main ();
  segment_manager_t *sm;
  const u8 *app_name;
  u8 *s = 0;

  /* Header */
  if (!app_wrk)
    {
      if (verbose)
	vlib_cli_output (vm, "%-40s%-20s%-15s%-10s", "Connection", "App",
			 "API Client", "SegManager");
      else
	vlib_cli_output (vm, "%-40s%-20s", "Connection", "App");
      return;
    }

  if (app_wrk->connects_seg_manager == (u32) ~ 0)
    return;

  app_name = application_name_from_index (app_wrk->app_index);

  /* Across all fifo segments */
  sm = segment_manager_get (app_wrk->connects_seg_manager);

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
                      app_wrk->api_client_index, app_wrk->connects_seg_manager);
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

}

static void
application_format_connects (application_t * app, int verbose)
{
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;

  if (!app)
    {
      app_worker_format_connects (0, verbose);
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach (wrk_map, app->worker_maps, ({
    app_wrk = app_worker_get (wrk_map->wrk_index);
    app_worker_format_connects (app_wrk, verbose);
  }));
  /* *INDENT-ON* */
}

static void
app_worker_format_local_sessions (app_worker_t * app_wrk, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  local_session_t *ls;
  transport_proto_t tp;
  u8 *conn = 0;

  /* Header */
  if (app_wrk == 0)
    {
      vlib_cli_output (vm, "%-40s%-15s%-20s", "Connection", "ServerApp",
		       "ClientApp");
      return;
    }

  if (!pool_elts (app_wrk->local_sessions)
      && !pool_elts (app_wrk->local_connects))
    return;

  /* *INDENT-OFF* */
  pool_foreach (ls, app_wrk->local_sessions, ({
    tp = session_type_transport_proto(ls->listener_session_type);
    conn = format (0, "[L][%U] *:%u", format_transport_proto_short, tp,
                   ls->port);
    vlib_cli_output (vm, "%-40v%-15u%-20u", conn, ls->app_wrk_index,
                     ls->client_wrk_index);
    vec_reset_length (conn);
  }));
  /* *INDENT-ON* */

  vec_free (conn);
}

static void
application_format_local_sessions (application_t * app, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;
  transport_proto_t tp;
  local_session_t *ls;
  u8 *conn = 0;

  if (!app)
    {
      app_worker_format_local_sessions (0, verbose);
      return;
    }

  /*
   * Format local listeners
   */

  /* *INDENT-OFF* */
  pool_foreach (ls, app->local_listen_sessions, ({
    tp = session_type_transport_proto (ls->listener_session_type);
    conn = format (0, "[L][%U] *:%u", format_transport_proto_short, tp,
                   ls->port);
    vlib_cli_output (vm, "%-40v%-15u%-20s", conn, ls->app_wrk_index, "*");
    vec_reset_length (conn);
  }));
  /* *INDENT-ON* */

  /*
   * Format local accepted/connected sessions
   */
  /* *INDENT-OFF* */
  pool_foreach (wrk_map, app->worker_maps, ({
    app_wrk = app_worker_get (wrk_map->wrk_index);
    app_worker_format_local_sessions (app_wrk, verbose);
  }));
  /* *INDENT-ON* */
}

static void
app_worker_format_local_connects (app_worker_t * app, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 app_wrk_index, session_index;
  app_worker_t *server_wrk;
  local_session_t *ls;
  u64 client_key;
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

  if (!app->local_connects)
    return;

  /* *INDENT-OFF* */
  hash_foreach (client_key, value, app->local_connects, ({
    application_client_local_connect_key_parse (client_key, &app_wrk_index,
                                                &session_index);
    server_wrk = app_worker_get (app_wrk_index);
    ls = application_get_local_session (server_wrk, session_index);
    vlib_cli_output (vm, "%-40s%-15s%-20s", "TODO", ls->app_wrk_index,
                     ls->client_wrk_index);
  }));
  /* *INDENT-ON* */
}

static void
application_format_local_connects (application_t * app, int verbose)
{
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;

  if (!app)
    {
      app_worker_format_local_connects (0, verbose);
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach (wrk_map, app->worker_maps, ({
    app_wrk = app_worker_get (wrk_map->wrk_index);
    app_worker_format_local_connects (app_wrk, verbose);
  }));
  /* *INDENT-ON* */
}

u8 *
format_application_worker (u8 * s, va_list * args)
{
  app_worker_t *app_wrk = va_arg (*args, app_worker_t *);
  u32 indent = 1;

  s = format (s, "%U wrk-index %u app-index %u map-index %u "
	      "api-client-index %d\n", format_white_space, indent,
	      app_wrk->wrk_index, app_wrk->app_index, app_wrk->wrk_map_index,
	      app_wrk->api_client_index);
  return s;
}

u8 *
format_application (u8 * s, va_list * args)
{
  application_t *app = va_arg (*args, application_t *);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);
  segment_manager_properties_t *props;
  const u8 *app_ns_name, *app_name;
  app_worker_map_t *wrk_map;
  app_worker_t *app_wrk;

  if (app == 0)
    {
      if (!verbose)
	s = format (s, "%-10s%-20s%-40s", "Index", "Name", "Namespace");
      return s;
    }

  app_name = app_get_name (app);
  app_ns_name = app_namespace_id_from_index (app->ns_index);
  props = application_segment_manager_properties (app);
  if (!verbose)
    {
      s = format (s, "%-10u%-20s%-40s", app->app_index, app_name,
		  app_ns_name);
      return s;
    }

  s = format (s, "app-name %s app-index %u ns-index %u seg-size %U\n",
	      app_name, app->app_index, app->ns_index,
	      format_memory_size, props->add_segment_size);
  s = format (s, "rx-fifo-size %U tx-fifo-size %U workers:\n",
	      format_memory_size, props->rx_fifo_size,
	      format_memory_size, props->tx_fifo_size);

  /* *INDENT-OFF* */
  pool_foreach (wrk_map, app->worker_maps, ({
      app_wrk = app_worker_get (wrk_map->wrk_index);
      s = format (s, "%U", format_application_worker, app_wrk);
  }));
  /* *INDENT-ON* */

  return s;
}

void
application_format_all_listeners (vlib_main_t * vm, int do_local, int verbose)
{
  application_t *app;

  if (!pool_elts (app_main.app_pool))
    {
      vlib_cli_output (vm, "No active server bindings");
      return;
    }

  if (do_local)
    {
      application_format_local_sessions (0, verbose);
      /* *INDENT-OFF* */
      pool_foreach (app, app_main.app_pool, ({
        application_format_local_sessions (app, verbose);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      application_format_listeners (0, verbose);

      /* *INDENT-OFF* */
      pool_foreach (app, app_main.app_pool, ({
        application_format_listeners (app, verbose);
      }));
      /* *INDENT-ON* */
    }
}

void
application_format_all_clients (vlib_main_t * vm, int do_local, int verbose)
{
  application_t *app;

  if (!pool_elts (app_main.app_pool))
    {
      vlib_cli_output (vm, "No active apps");
      return;
    }

  if (do_local)
    {
      application_format_local_connects (0, verbose);

      /* *INDENT-OFF* */
      pool_foreach (app, app_main.app_pool, ({
	application_format_local_connects (app, verbose);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      application_format_connects (0, verbose);

      /* *INDENT-OFF* */
      pool_foreach (app, app_main.app_pool, ({
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
  u32 app_index = ~0;
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
      else if (unformat (input, "%u", &app_index))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (do_server)
    {
      application_format_all_listeners (vm, do_local, verbose);
      return 0;
    }

  if (do_client)
    {
      application_format_all_clients (vm, do_local, verbose);
      return 0;
    }

  if (app_index != ~0)
    {
      app = application_get_if_valid (app_index);
      if (!app)
	return clib_error_return (0, "No app with index %u", app_index);

      vlib_cli_output (vm, "%U", format_application, app, /* verbose */ 1);
      return 0;
    }

  /* Print app related info */
  if (!do_server && !do_client)
    {
      vlib_cli_output (vm, "%U", format_application, 0, 0);
      /* *INDENT-OFF* */
      pool_foreach (app, app_main.app_pool, ({
	vlib_cli_output (vm, "%U", format_application, app, 0);
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
