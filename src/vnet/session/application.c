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
#include <vnet/session/session.h>

/*
 * Pool from which we allocate all applications
 */
static application_t *app_pool;

/*
 * Hash table of apps by api client index
 */
static uword *app_by_api_client_index;

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

void
application_del (application_t * app)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  api_main_t *am = &api_main;
  void *oldheap;
  session_manager_t *sm;

  if (app->mode == APP_SERVER)
    {
      sm = session_manager_get (app->session_manager_index);
      session_manager_del (smm, sm);
    }

  /* Free the event fifo in the /vpe-api shared-memory segment */
  oldheap = svm_push_data_heap (am->vlib_rp);
  if (app->event_queue)
    unix_shared_memory_queue_free (app->event_queue);
  svm_pop_heap (oldheap);

  application_table_del (app);

  pool_put (app_pool, app);
}

application_t *
application_new (application_type_t type, session_type_t sst,
		 u32 api_client_index, u32 flags, session_cb_vft_t * cb_fns)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  api_main_t *am = &api_main;
  application_t *app;
  void *oldheap;
  session_manager_t *sm;

  pool_get (app_pool, app);
  memset (app, 0, sizeof (*app));

  /* Allocate event fifo in the /vpe-api shared-memory segment */
  oldheap = svm_push_data_heap (am->vlib_rp);

  /* Allocate server event queue */
  app->event_queue =
    unix_shared_memory_queue_init (128 /* nels $$$$ config */ ,
				   sizeof (session_fifo_event_t),
				   0 /* consumer pid */ ,
				   0
				   /* (do not) signal when queue non-empty */
    );

  svm_pop_heap (oldheap);

  /* If a server, allocate session manager */
  if (type == APP_SERVER)
    {
      pool_get (smm->session_managers, sm);
      memset (sm, 0, sizeof (*sm));

      app->session_manager_index = sm - smm->session_managers;
    }
  else if (type == APP_CLIENT)
    {
      /* Allocate connect session manager if needed */
      if (smm->connect_manager_index[sst] == INVALID_INDEX)
	connects_session_manager_init (smm, sst);
      app->session_manager_index = smm->connect_manager_index[sst];
    }

  app->mode = type;
  app->index = application_get_index (app);
  app->session_type = sst;
  app->api_client_index = api_client_index;
  app->flags = flags;
  app->cb_fns = *cb_fns;

  /* Add app to lookup by api_client_index table */
  application_table_add (app);

  return app;
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

int
application_server_init (application_t * server, u32 segment_size,
			 u32 add_segment_size, u32 rx_fifo_size,
			 u32 tx_fifo_size, u8 ** segment_name)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  session_manager_t *sm;
  int rv;

  sm = session_manager_get (server->session_manager_index);

  /* Add first segment */
  if ((rv = session_manager_add_first_segment (smm, sm, segment_size,
					       segment_name)))
    {
      return rv;
    }

  /* Setup session manager */
  sm->add_segment_size = add_segment_size;
  sm->rx_fifo_size = rx_fifo_size;
  sm->tx_fifo_size = tx_fifo_size;
  sm->add_segment = sm->add_segment_size != 0;
  return 0;
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

  session_manager_get_segment_info (listener->server_segment_index, &seg_name,
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

  session_manager_get_segment_info (session->server_segment_index, &seg_name,
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
