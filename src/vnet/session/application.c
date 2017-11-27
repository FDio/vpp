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

/**
 * Default application event queue size
 */
static u32 default_app_evt_queue_size = 128;

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
  unix_shared_memory_queue_t *q;

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
  if (CLIB_DEBUG > 1)
    clib_warning ("[%d] New app (%d)", getpid (), app->index);
  return app;
}

void
application_del (application_t * app)
{
  segment_manager_properties_t *props;
  vnet_unbind_args_t _a, *a = &_a;
  segment_manager_t *sm;
  u64 handle, *handles = 0;
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
  props = segment_manager_properties_get (app->sm_properties);
  segment_manager_properties_free (props);
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

int
application_init (application_t * app, u32 api_client_index, u64 * options,
		  session_cb_vft_t * cb_fns)
{
  segment_manager_t *sm;
  segment_manager_properties_t *props;
  u32 app_evt_queue_size, first_seg_size;
  u32 default_rx_fifo_size = 16 << 10, default_tx_fifo_size = 16 << 10;
  int rv;

  app_evt_queue_size = options[APP_EVT_QUEUE_SIZE] > 0 ?
    options[APP_EVT_QUEUE_SIZE] : default_app_evt_queue_size;

  /*
   * Setup segment manager
   */
  sm = segment_manager_new ();
  sm->app_index = app->index;
  props = segment_manager_properties_alloc ();
  app->sm_properties = segment_manager_properties_index (props);
  props->add_segment_size = options[SESSION_OPTIONS_ADD_SEGMENT_SIZE];
  props->rx_fifo_size = options[SESSION_OPTIONS_RX_FIFO_SIZE];
  props->rx_fifo_size =
    props->rx_fifo_size ? props->rx_fifo_size : default_rx_fifo_size;
  props->tx_fifo_size = options[SESSION_OPTIONS_TX_FIFO_SIZE];
  props->tx_fifo_size =
    props->tx_fifo_size ? props->tx_fifo_size : default_tx_fifo_size;
  props->add_segment = props->add_segment_size != 0;
  props->preallocated_fifo_pairs = options[APP_OPTIONS_PREALLOC_FIFO_PAIRS];
  props->use_private_segment = options[APP_OPTIONS_FLAGS]
    & APP_OPTIONS_FLAGS_IS_BUILTIN;
  props->private_segment_count = options[APP_OPTIONS_PRIVATE_SEGMENT_COUNT];
  props->private_segment_size = options[APP_OPTIONS_PRIVATE_SEGMENT_SIZE];

  first_seg_size = options[SESSION_OPTIONS_SEGMENT_SIZE];
  if ((rv = segment_manager_init (sm, app->sm_properties, first_seg_size)))
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
  app->proxied_transports = options[APP_OPTIONS_PROXY_TRANSPORT];

  /* If no scope enabled, default to global */
  if (!application_has_global_scope (app)
      && !application_has_local_scope (app))
    app->flags |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;

  /* Allocate app event queue in the first shared-memory segment */
  app->event_queue = segment_manager_alloc_queue (sm, app_evt_queue_size);

  /* Check that the obvious things are properly set up */
  application_verify_cb_fns (cb_fns);

  /* Add app to lookup by api_client_index table */
  application_table_add (app);

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
  sm->properties_index = app->sm_properties;

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
			  u64 * res)
{
  segment_manager_t *sm;
  stream_session_t *s;
  u64 handle;
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
application_stop_listen (application_t * srv, u64 handle)
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

int
application_add_segment_notify (u32 app_index, u32 fifo_segment_index)
{
  application_t *app = application_get (app_index);
  u32 seg_size = 0;
  u8 *seg_name;

  /* Send an API message to the external app, to map new segment */
  ASSERT (app->cb_fns.add_segment_callback);

  segment_manager_get_segment_info (fifo_segment_index, &seg_name, &seg_size);
  return app->cb_fns.add_segment_callback (app->api_client_index, seg_name,
					   seg_size);
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
      sep.is_ip4 = is_ip4;
      sep.fib_index = app_namespace_get_fib_index (app_ns, fib_proto);
      sep.sw_if_index = app_ns->sw_if_index;
      sep.transport_proto = transport_proto;
      application_start_listen (app, &sep, &handle);
      s = listen_session_get_from_handle (handle);
      s->listener_index = SESSION_PROXY_LISTENER_INDEX;
    }
  else
    {
      s = application_first_listener (app, fib_proto, transport_proto);
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
      session_lookup_add_session_endpoint (sti, &sep, s->session_index);
    }
  return 0;
}

void
application_start_stop_proxy (application_t * app, u8 transport_proto,
			      u8 is_start)
{
  if (application_has_local_scope (app))
    {
      session_endpoint_t sep = SESSION_ENDPOINT_NULL;
      app_namespace_t *app_ns;
      app_ns = app_namespace_get (app->ns_index);
      sep.is_ip4 = 1;
      sep.transport_proto = transport_proto;
      sep.port = 0;
      session_lookup_add_session_endpoint (app_ns->local_table_index, &sep,
					   app->index);

      sep.is_ip4 = 0;
      session_lookup_add_session_endpoint (app_ns->local_table_index, &sep,
					   app->index);
    }

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
  ASSERT (application_is_proxy (app));
  if (application_is_builtin (app))
    return;
  if (transports & (1 << TRANSPORT_PROTO_TCP))
    application_start_stop_proxy (app, TRANSPORT_PROTO_TCP, 1);
  if (transports & (1 << TRANSPORT_PROTO_UDP))
    application_start_stop_proxy (app, TRANSPORT_PROTO_UDP, 1);
}

void
application_remove_proxy (application_t * app)
{
  u16 transports = app->proxied_transports;
  ASSERT (application_is_proxy (app));
  if (transports & (1 << TRANSPORT_PROTO_TCP))
    application_start_stop_proxy (app, TRANSPORT_PROTO_TCP, 0);
  if (transports & (1 << TRANSPORT_PROTO_UDP))
    application_start_stop_proxy (app, TRANSPORT_PROTO_UDP, 0);
}

u8 *
format_application_listener (u8 * s, va_list * args)
{
  application_t *app = va_arg (*args, application_t *);
  u64 handle = va_arg (*args, u64);
  u32 index = va_arg (*args, u32);
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
		  app->api_client_index, handle, index);
    }
  else
    s = format (s, "%-40s%-20s", str, app_name);

  vec_free (app_name);
  return s;
}

void
application_format_connects (application_t * app, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  segment_manager_t *sm;
  u8 *app_name, *s = 0;
  int j;

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
  for (j = 0; j < vec_len (sm->segment_indices); j++)
    {
      svm_fifo_segment_private_t *fifo_segment;
      svm_fifo_t *fifo;
      u8 *str;

      fifo_segment = svm_fifo_segment_get_segment (sm->segment_indices[j]);
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
    }

  vec_free (app_name);
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
  props = segment_manager_properties_get (app->sm_properties);
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

static clib_error_t *
show_app_command_fn (vlib_main_t * vm, unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  application_t *app;
  int do_server = 0;
  int do_client = 0;
  int verbose = 0;

  session_cli_return_if_not_enabled ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "server"))
	do_server = 1;
      else if (unformat (input, "client"))
	do_client = 1;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else
	break;
    }

  if (do_server)
    {
      u64 handle;
      u32 index;
      if (pool_elts (app_pool))
	{
	  vlib_cli_output (vm, "%U", format_application_listener,
			   0 /* header */ , 0, 0,
			   verbose);
	  /* *INDENT-OFF* */
          pool_foreach (app, app_pool,
          ({
            /* App's listener sessions */
            if (hash_elts (app->listeners_table) == 0)
              continue;
            hash_foreach (handle, index, app->listeners_table,
	    ({
              vlib_cli_output (vm, "%U", format_application_listener, app,
              			       handle, index, verbose);
            }));
          }));
          /* *INDENT-ON* */
	}
      else
	vlib_cli_output (vm, "No active server bindings");
    }

  if (do_client)
    {
      if (pool_elts (app_pool))
	{
	  application_format_connects (0, verbose);

          /* *INDENT-OFF* */
          pool_foreach (app, app_pool,
          ({
            if (app->connects_seg_manager == (u32)~0)
              continue;
            application_format_connects (app, verbose);
          }));
          /* *INDENT-ON* */
	}
      else
	vlib_cli_output (vm, "No active client bindings");
    }

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
