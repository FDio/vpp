/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/session/application_interface.h>

#include <vnet/session/session.h>
#include <vlibmemory/api.h>
#include <vnet/dpo/load_balance.h>

/** @file
    VPP's application/session API bind/unbind/connect/disconnect calls
*/

static u8
session_endpoint_is_local (session_endpoint_t * sep)
{
  return (ip_is_zero (&sep->ip, sep->is_ip4)
	  || ip_is_local_host (&sep->ip, sep->is_ip4));
}

static u8
session_endpoint_is_zero (session_endpoint_t * sep)
{
  return ip_is_zero (&sep->ip, sep->is_ip4);
}

u8
session_endpoint_in_ns (session_endpoint_t * sep)
{
  u8 is_zero = ip_is_zero (&sep->ip, sep->is_ip4);
  if (!is_zero && sep->sw_if_index != ENDPOINT_INVALID_INDEX
      && !ip_interface_has_address (sep->sw_if_index, &sep->ip, sep->is_ip4))
    {
      clib_warning ("sw_if_index %u not configured with ip %U",
		    sep->sw_if_index, format_ip46_address, &sep->ip,
		    sep->is_ip4);
      return 0;
    }
  return (is_zero || ip_is_local (sep->fib_index, &sep->ip, sep->is_ip4));
}

int
api_parse_session_handle (u64 handle, u32 * session_index, u32 * thread_index)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  stream_session_t *pool;

  *thread_index = handle & 0xFFFFFFFF;
  *session_index = handle >> 32;

  if (*thread_index >= vec_len (smm->sessions))
    return VNET_API_ERROR_INVALID_VALUE;

  pool = smm->sessions[*thread_index];

  if (pool_is_free_index (pool, *session_index))
    return VNET_API_ERROR_INVALID_VALUE_2;

  return 0;
}

static void
session_endpoint_update_for_app (session_endpoint_t * sep,
				 application_t * app)
{
  app_namespace_t *app_ns;
  app_ns = app_namespace_get (app->ns_index);
  if (app_ns)
    {
      /* Ask transport and network to bind to/connect using local interface
       * that "supports" app's namespace. This will fix our local connection
       * endpoint.
       */
      sep->sw_if_index = app_ns->sw_if_index;
      sep->fib_index =
	sep->is_ip4 ? app_ns->ip4_fib_index : app_ns->ip6_fib_index;
    }
}

static int
vnet_bind_i (u32 app_index, session_endpoint_t * sep, u64 * handle)
{
  application_t *app;
  u32 table_index;
  u64 listener;
  int rv, have_local = 0;

  app = application_get_if_valid (app_index);
  if (!app)
    {
      SESSION_DBG ("app not attached");
      return VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  session_endpoint_update_for_app (sep, app);
  if (!session_endpoint_in_ns (sep))
    return VNET_API_ERROR_INVALID_VALUE_2;

  table_index = application_session_table (app,
					   session_endpoint_fib_proto (sep));
  listener = session_lookup_endpoint_listener (table_index, sep, 1);
  if (listener != SESSION_INVALID_HANDLE)
    return VNET_API_ERROR_ADDRESS_IN_USE;

  /*
   * Add session endpoint to local session table. Only binds to "inaddr_any"
   * (i.e., zero address) are added to local scope table.
   */
  if (application_has_local_scope (app) && session_endpoint_is_zero (sep))
    {
      if ((rv = application_start_local_listen (app, sep, handle)))
	return rv;
      have_local = 1;
    }

  if (!application_has_global_scope (app))
    return (have_local - 1);

  /*
   * Add session endpoint to global session table
   */

  /* Setup listen path down to transport */
  rv = application_start_listen (app, sep, handle);
  if (rv && have_local)
    session_lookup_del_session_endpoint (table_index, sep);
  return rv;
}

int
vnet_unbind_i (u32 app_index, session_handle_t handle)
{
  application_t *app;
  int rv;

  if (!(app = application_get_if_valid (app_index)))
    {
      SESSION_DBG ("app (%d) not attached", app_index);
      return VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  if (application_has_local_scope (app))
    {
      if ((rv = application_stop_local_listen (app, handle)))
	return rv;
    }

  /*
   * Clear the global scope table of the listener
   */
  if (application_has_global_scope (app))
    return application_stop_listen (app, handle);
  return 0;
}

int
vnet_connect_i (u32 client_index, u32 api_context, session_endpoint_t * sep,
		void *mp)
{
  application_t *server, *client;
  u32 table_index, server_index;
  stream_session_t *listener;

  if (session_endpoint_is_zero (sep))
    return VNET_API_ERROR_INVALID_VALUE;

  client = application_get (client_index);
  session_endpoint_update_for_app (sep, client);

  /*
   * First check the local scope for locally attached destinations.
   * If we have local scope, we pass *all* connects through it since we may
   * have special policy rules even for non-local destinations, think proxy.
   */
  if (application_has_local_scope (client))
    {
      table_index = application_local_session_table (client);
      server_index = session_lookup_local_endpoint (table_index, sep);
      if (server_index == APP_DROP_INDEX)
	return VNET_API_ERROR_APP_CONNECT_FILTERED;

      /*
       * Break loop if rule in local table points to connecting app. This
       * can happen if client is a generic proxy. Route connect through
       * global table instead.
       */
      if (server_index != client_index)
	{
	  if ((server = application_get (server_index)))
	    return application_local_session_connect (table_index, client,
		                                      server, sep, 0,
		                                      api_context);
	}
    }

  /*
   * If nothing found, check the global scope for locally attached
   * destinations. Make sure first that we're allowed to.
   */
  if (session_endpoint_is_local (sep))
    return VNET_API_ERROR_SESSION_CONNECT;

  if (!application_has_global_scope (client))
    return VNET_API_ERROR_APP_CONNECT_SCOPE;

  table_index = application_session_table (client,
	                                   session_endpoint_fib_proto (sep));
  listener = session_lookup_listener (table_index, sep);
  if (listener)
    {
      server = application_get (listener->app_index);
      if (server)
	return application_local_session_connect (table_index, client, server,
	                                          sep, listener, api_context);
    }

  /*
   * Not connecting to a local server, propagate to transport
   */
  if (application_open_session (client, sep, api_context))
    return VNET_API_ERROR_SESSION_CONNECT;
  return 0;
}

/**
 * unformat a vnet URI
 *
 * transport-proto://ip46-addr:port
 * eg. tcp://ip46-addr:port
 *
 * u8 ip46_address[16];
 * u16  port_in_host_byte_order;
 * stream_session_type_t sst;
 * u8 *fifo_name;
 *
 * if (unformat (input, "%U", unformat_vnet_uri, &ip46_address,
 *              &sst, &port, &fifo_name))
 *  etc...
 *
 */
uword
unformat_vnet_uri (unformat_input_t * input, va_list * args)
{
  session_endpoint_t *sep = va_arg (*args, session_endpoint_t *);
  u32 transport_proto = 0;
  if (unformat (input, "%U://%U/%d", unformat_transport_proto,
		&transport_proto, unformat_ip4_address, &sep->ip.ip4,
		&sep->port))
    {
      sep->transport_proto = transport_proto;
      sep->port = clib_host_to_net_u16 (sep->port);
      sep->is_ip4 = 1;
      return 1;
    }
  if (unformat (input, "%U://%U/%d", unformat_transport_proto,
		&transport_proto, unformat_ip6_address, &sep->ip.ip6,
		&sep->port))
    {
      sep->transport_proto = transport_proto;
      sep->port = clib_host_to_net_u16 (sep->port);
      sep->is_ip4 = 0;
      return 1;
    }
  return 0;
}

static u8 *cache_uri;
static session_endpoint_t *cache_sep;

int
parse_uri (char *uri, session_endpoint_t * sep)
{
  unformat_input_t _input, *input = &_input;

  if (cache_uri && !strncmp (uri, (char *) cache_uri, vec_len (cache_uri)))
    {
      *sep = *cache_sep;
      return 0;
    }

  /* Make sure */
  uri = (char *) format (0, "%s%c", uri, 0);

  /* Parse uri */
  unformat_init_string (input, uri, strlen (uri));
  if (!unformat (input, "%U", unformat_vnet_uri, sep))
    {
      unformat_free (input);
      return VNET_API_ERROR_INVALID_VALUE;
    }
  unformat_free (input);

  vec_free (cache_uri);
  cache_uri = (u8 *) uri;
  if (cache_sep)
    clib_mem_free (cache_sep);
  cache_sep = clib_mem_alloc (sizeof (*sep));
  *cache_sep = *sep;

  return 0;
}

static int
session_validate_namespace (u8 * namespace_id, u64 secret, u32 * app_ns_index)
{
  app_namespace_t *app_ns;
  if (vec_len (namespace_id) == 0)
    {
      /* Use default namespace */
      *app_ns_index = 0;
      return 0;
    }

  *app_ns_index = app_namespace_index_from_id (namespace_id);
  if (*app_ns_index == APP_NAMESPACE_INVALID_INDEX)
    return VNET_API_ERROR_APP_INVALID_NS;
  app_ns = app_namespace_get (*app_ns_index);
  if (!app_ns)
    return VNET_API_ERROR_APP_INVALID_NS;
  if (app_ns->ns_secret != secret)
    return VNET_API_ERROR_APP_WRONG_NS_SECRET;
  return 0;
}

/**
 * Attach application to vpp
 *
 * Allocates a vpp app, i.e., a structure that keeps back pointers
 * to external app and a segment manager for shared memory fifo based
 * communication with the external app.
 */
clib_error_t *
vnet_application_attach (vnet_app_attach_args_t * a)
{
  svm_fifo_segment_private_t *fs;
  application_t *app = 0;
  segment_manager_t *sm;
  u32 app_ns_index = 0;
  u64 secret;
  int rv;

  app = application_lookup (a->api_client_index);
  if (app)
    return clib_error_return_code (0, VNET_API_ERROR_APP_ALREADY_ATTACHED,
				   0, "app already attached");

  secret = a->options[APP_OPTIONS_NAMESPACE_SECRET];
  if ((rv = session_validate_namespace (a->namespace_id, secret,
					&app_ns_index)))
    return clib_error_return_code (0, rv, 0, "namespace validation: %d", rv);
  a->options[APP_OPTIONS_NAMESPACE] = app_ns_index;
  app = application_new ();
  if ((rv = application_init (app, a->api_client_index, a->options,
			      a->session_cb_vft)))
    return clib_error_return_code (0, rv, 0, "app init: %d", rv);

  a->app_event_queue_address = pointer_to_uword (app->event_queue);
  sm = segment_manager_get (app->first_segment_manager);
  fs = segment_manager_get_segment_w_lock (sm, 0);

  if (application_is_proxy (app))
    application_setup_proxy (app);

  ASSERT (vec_len (fs->ssvm.name) <= 128);
  a->segment = &fs->ssvm;
  a->app_index = app->index;

  segment_manager_segment_reader_unlock (sm);

  return 0;
}

/**
 * Detach application from vpp
 */
int
vnet_application_detach (vnet_app_detach_args_t * a)
{
  application_t *app;
  app = application_get_if_valid (a->app_index);

  if (!app)
    {
      clib_warning ("app not attached");
      return VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  application_del (app);
  return 0;
}

int
vnet_bind_uri (vnet_bind_args_t * a)
{
  session_endpoint_t sep = SESSION_ENDPOINT_NULL;
  int rv;

  rv = parse_uri (a->uri, &sep);
  if (rv)
    return rv;

  return vnet_bind_i (a->app_index, &sep, &a->handle);
}

int
vnet_unbind_uri (vnet_unbind_args_t * a)
{
  stream_session_t *listener;
  session_endpoint_t sep = SESSION_ENDPOINT_NULL;
  int rv;

  rv = parse_uri (a->uri, &sep);
  if (rv)
    return rv;

  /* NOTE: only default table supported for uri */
  listener = session_lookup_listener (0, &sep);
  if (!listener)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  return vnet_unbind_i (a->app_index, listen_session_get_handle (listener));
}

clib_error_t *
vnet_connect_uri (vnet_connect_args_t * a)
{
  session_endpoint_t sep_null = SESSION_ENDPOINT_NULL;
  int rv;

  /* Parse uri */
  a->sep = sep_null;
  rv = parse_uri (a->uri, &a->sep);
  if (rv)
    return clib_error_return_code (0, rv, 0, "app init: %d", rv);
  if ((rv = vnet_connect_i (a->app_index, a->api_context, &a->sep, a->mp)))
    return clib_error_return_code (0, rv, 0, "connect failed");
  return 0;
}

int
vnet_disconnect_session (vnet_disconnect_args_t * a)
{
  if (session_handle_is_local (a->handle))
    {
      local_session_t *ls;
      ls = application_get_local_session_from_handle (a->handle);
      if (ls->app_index != a->app_index && ls->client_index != a->app_index)
	{
	  clib_warning("app %u is neither client nor server for session %u",
		       a->app_index, a->app_index);
	  return VNET_API_ERROR_INVALID_VALUE;
	}
      return application_local_session_disconnect (a->app_index, ls);
    }
  else
    {
      stream_session_t *s;
      s = session_get_from_handle_if_valid (a->handle);
      if (!s || s->app_index != a->app_index)
	return VNET_API_ERROR_INVALID_VALUE;

      /* We're peeking into another's thread pool. Make sure */
      ASSERT(s->session_index == session_thread_from_handle (a->handle));

      stream_session_disconnect (s);
    }
  return 0;
}

clib_error_t *
vnet_bind (vnet_bind_args_t * a)
{
  int rv;
  if ((rv = vnet_bind_i (a->app_index, &a->sep, &a->handle)))
    return clib_error_return_code (0, rv, 0, "bind failed");
  return 0;
}

clib_error_t *
vnet_unbind (vnet_unbind_args_t * a)
{
  int rv;
  if ((rv = vnet_unbind_i (a->app_index, a->handle)))
    return clib_error_return_code (0, rv, 0, "unbind failed");
  return 0;
}

clib_error_t *
vnet_connect (vnet_connect_args_t * a)
{
  int rv;
  if ((rv = vnet_connect_i (a->app_index, a->api_context, &a->sep, a->mp)))
    return clib_error_return_code (0, rv, 0, "connect failed");
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
