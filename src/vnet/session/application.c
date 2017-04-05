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
  memset (app, 0, sizeof(*app));
  app->index = application_get_index (app);
  app->connects_seg_manager = ~0;
  return app;
}

void
application_del (application_t * app)
{
  api_main_t *am = &api_main;
  void *oldheap;
  segment_manager_t *sm;
  u32 handle, index;

  /*
   * Cleanup segment managers
   */
  if (app->connects_seg_manager != (u32)~0)
    {
      sm = segment_manager_get (app->connects_seg_manager);
      segment_manager_del (sm);
    }

  /* *INDENT-OFF* */
  hash_foreach (handle, index, app->listeners_table,
  ({
    sm = segment_manager_get (index);
    segment_manager_del (sm);
  }));
  /* *INDENT-ON* */

  /*
   * Free the event fifo in the /vpe-api shared-memory segment
   */
  oldheap = svm_push_data_heap (am->vlib_rp);
  if (app->event_queue)
    unix_shared_memory_queue_free (app->event_queue);
  svm_pop_heap (oldheap);

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
application_init (application_t *app, u32 api_client_index, u64 *options,
		  session_cb_vft_t * cb_fns)
{
  api_main_t *am = &api_main;
  segment_manager_t *sm;
  segment_manager_properties_t *props;
  void *oldheap;
  u32 app_evt_queue_size;
  int rv;

  app_evt_queue_size = options[APP_EVT_QUEUE_SIZE] > 0 ?
      options[APP_EVT_QUEUE_SIZE] : default_app_evt_queue_size;

  /* Allocate event fifo in the /vpe-api shared-memory segment */
  oldheap = svm_push_data_heap (am->vlib_rp);

  /* Allocate server event queue */
  app->event_queue =
    unix_shared_memory_queue_init (app_evt_queue_size,
				   sizeof (session_fifo_event_t),
				   0 /* consumer pid */ ,
				   0
				   /* (do not) signal when queue non-empty */
    );

  svm_pop_heap (oldheap);

  /* Setup segment manager */
  sm = segment_manager_new ();
  props = &app->sm_properties;
  props->add_segment_size = options[SESSION_OPTIONS_ADD_SEGMENT_SIZE];
  props->rx_fifo_size = options[SESSION_OPTIONS_RX_FIFO_SIZE];
  props->tx_fifo_size = options[SESSION_OPTIONS_TX_FIFO_SIZE];
  props->add_segment = props->add_segment_size != 0;

  if ((rv = segment_manager_init (sm, props,
				  options[SESSION_OPTIONS_SEGMENT_SIZE])))
    return rv;

  app->first_segment_manager = segment_manager_index (sm);
  app->api_client_index = api_client_index;
  app->flags = options[SESSION_OPTIONS_FLAGS];
  app->cb_fns = *cb_fns;

  /* Check that the obvious things are properly set up */
  application_verify_cb_fns (cb_fns);

  /* Add app to lookup by api_client_index table */
  application_table_add (app);

  return 0;
}

application_t *
application_get (u32 index)
{
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
application_alloc_segment_manager (application_t *app)
{
  segment_manager_t *sm = 0;

  if (app->first_segment_manager != (u32) ~0)
    {
      sm = segment_manager_get (app->first_segment_manager);
      app->first_segment_manager = ~0;
      return sm;
    }

  sm = segment_manager_new ();
  if (segment_manager_init (sm, &app->sm_properties, 0))
    return 0;
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
application_start_listen (application_t *srv, session_type_t session_type,
			  transport_endpoint_t *tep, u64 *res)
{
  segment_manager_t *sm;
  stream_session_t *s;
  u64 handle;

  s = listen_session_new (session_type);
  s->app_index = srv->index;

  if (stream_session_listen (s, tep))
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
 * Stop listening session associated to handle
 */
int
application_stop_listen (application_t *srv, u64 handle)
{
  stream_session_t *listener;

  if (srv && hash_get (srv->listeners_table, handle) == 0)
    {
      clib_warning ("app doesn't own handle %llu!", handle);
      return -1;
    }

  listener = listen_session_get_from_handle (handle);
  stream_session_stop_listen (listener);

  /* Might be that internal servers have no associated app */
  if (srv)
    hash_unset (srv->listeners_table, handle);
  listen_session_del (listener);

  return 0;
}

int
application_open_session (application_t *app, session_type_t sst,
			  transport_endpoint_t *tep, u32 api_context)
{
  segment_manager_t *sm;
  transport_connection_t *tc=0;
  int rv;

  /* Make sure we have a segment manager for connects */
  if (app->connects_seg_manager == (u32) ~0)
    {
      sm = application_alloc_segment_manager (app);
      if (sm == 0)
	return -1;
      app->connects_seg_manager = segment_manager_index (sm);
    }

  if ((rv = stream_session_open (app->index, sst, tep, &tc)))
    return rv;

  /* Store api_context for when the reply comes. Not the nicest thing
   * but better allocating a separate half-open pool.  */
  tc->s_index = api_context;

  return 0;
}

segment_manager_t *
application_get_connect_segment_manager (application_t *app)
{
  ASSERT (app->connects_seg_manager != (u32)~0);
  return segment_manager_get (app->connects_seg_manager);
}

segment_manager_t *
application_get_listen_segment_manager (application_t *app,
					stream_session_t *s)
{
  uword *smp;
  smp = hash_get(app->listeners_table, listen_session_get_handle (s));
  ASSERT(smp != 0);
  return segment_manager_get (*smp);
}

u8 *
format_application_server (u8 * s, va_list * args)
{
  application_t *srv = va_arg (*args, application_t *);
  int verbose = va_arg (*args, int);
  vl_api_registration_t *regp;
  stream_session_t *listener;
  u8 *server_name, *str, *seg_name;
  u32 segment_size;

  if (srv == 0)
    {
      if (verbose)
	s = format (s, "%-40s%-20s%-15s%-15s%-10s", "Connection", "Server",
		    "Segment", "API Client", "Cookie");
      else
	s = format (s, "%-40s%-20s", "Connection", "Server");

      return s;
    }

  regp = vl_api_client_index_to_registration (srv->api_client_index);
  if (!regp)
    server_name = format (0, "builtin-%d%c", srv->index, 0);
  else
    server_name = regp->name;

  listener = stream_session_listener_get (srv->session_type,
					  srv->session_index);
  str = format (0, "%U", format_stream_session, listener, verbose);

  segment_manager_get_segment_info (listener->svm_segment_index, &seg_name,
				    &segment_size);
  if (verbose)
    {
      s = format (s, "%-40s%-20s%-20s%-10d%-10d", str, server_name,
		  seg_name, srv->api_client_index, srv->accept_cookie);
    }
  else
    s = format (s, "%-40s%-20s", str, server_name);
  return s;
}

u8 *
format_application_client (u8 * s, va_list * args)
{
  application_t *client = va_arg (*args, application_t *);
  int verbose = va_arg (*args, int);
  stream_session_t *session;
  u8 *str, *seg_name;
  u32 segment_size;

  if (client == 0)
    {
      if (verbose)
	s =
	  format (s, "%-40s%-20s%-10s", "Connection", "Segment",
		  "API Client");
      else
	s = format (s, "%-40s", "Connection");

      return s;
    }

  session = stream_session_get (client->session_index, client->thread_index);
  str = format (0, "%U", format_stream_session, session, verbose);

  segment_manager_get_segment_info (session->svm_segment_index, &seg_name,
				    &segment_size);
  if (verbose)
    {
      s = format (s, "%-40s%-20s%-10d%", str, seg_name,
		  client->api_client_index);
    }
  else
    s = format (s, "%-40s", str);
  return s;
}

static clib_error_t *
show_app_command_fn (vlib_main_t * vm, unformat_input_t * input,
		     vlib_cli_command_t * cmd)
{
  session_manager_main_t *smm = &session_manager_main;
  application_t *app;
  int do_server = 0;
  int do_client = 0;
  int verbose = 0;

  if (!smm->is_enabled)
    {
      clib_error_return (0, "session layer is not enabled");
    }

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
      if (pool_elts (app_pool))
	{
	  vlib_cli_output (vm, "%U", format_application_server,
			   0 /* header */ ,
			   verbose);
          /* *INDENT-OFF* */
          pool_foreach (app, app_pool,
          ({
            if (app->mode == APP_SERVER)
              vlib_cli_output (vm, "%U", format_application_server, app,
                               verbose);
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
	  vlib_cli_output (vm, "%U", format_application_client,
			   0 /* header */ ,
			   verbose);
          /* *INDENT-OFF* */
          pool_foreach (app, app_pool,
          ({
            if (app->mode == APP_CLIENT)
              vlib_cli_output (vm, "%U", format_application_client, app,
                               verbose);
          }));
          /* *INDENT-ON* */
	}
      else
	vlib_cli_output (vm, "No active client bindings");
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
