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
#include <vnet/fib/ip4_fib.h>

/** @file
    VPP's application/session API bind/unbind/connect/disconnect calls
*/

static u8
ip_is_zero (ip46_address_t * ip46_address, u8 is_ip4)
{
  if (is_ip4)
    return (ip46_address->ip4.as_u32 == 0);
  else
    return (ip46_address->as_u64[0] == 0 && ip46_address->as_u64[1] == 0);
}

static u8
ip_is_local_host (ip46_address_t * ip46_address, u8 is_ip4)
{
  if (is_ip4)
    return (ip46_address->ip4.as_u8[0] == 127);
  else
    return (ip46_address->as_u64[0] == 0 && ip46_address->as_u64[1] == 1);
}

/**
 * Checks that an ip is local to the requested fib
 */
u8
ip_is_local (u32 fib_index, ip46_address_t * ip46_address, u8 is_ip4)
{
  fib_node_index_t fei;
  fib_entry_flag_t flags;
  fib_prefix_t prefix;

  /* Check if requester is local */
  if (is_ip4)
    {
      prefix.fp_len = 32;
      prefix.fp_proto = FIB_PROTOCOL_IP4;
    }
  else
    {
      prefix.fp_len = 128;
      prefix.fp_proto = FIB_PROTOCOL_IP6;
    }

  clib_memcpy (&prefix.fp_addr, ip46_address, sizeof (ip46_address_t));
  fei = fib_table_lookup (0, &prefix);
  flags = fib_entry_get_flags (fei);

  return (flags & FIB_ENTRY_FLAG_LOCAL);
}

u8
ip_interface_has_address (u32 sw_if_index, ip46_address_t *ip, u8 is_ip4)
{
  ip_interface_address_t *ia = 0;

  if (is_ip4)
    {
      ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
      ip4_address_t *ip4;
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm4, ia, sw_if_index, 1 /* unnumbered */ ,
      ({
        ip4 = ip_interface_address_get_address (lm4, ia);
        if (ip4_address_compare (ip4, ip->ip4) == 0)
          return 1;
      }));
      /* *INDENT-ON* */
    }
  else
    {
      ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
      ip6_address_t *ip6;
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm6, ia, sw_if_index, 1 /* unnumbered */ ,
      ({
        ip6 = ip_interface_address_get_address (lm6, ia);
        if (ip6_address_compare (ip6, ip->ip6) == 0)
          return 1;
      }));
      /* *INDENT-ON* */
    }
  return 0;
}

static u8
session_endpoint_is_local (session_endpoint_t *sep)
{
  return (ip_is_zero (sep->ip, sep->is_ip4)
      || ip_is_local_host (sep->fib_index, sep->ip, sep->is_ip4));
}

static u8
session_endpoint_is_zero (session_endpoint_t *sep)
{
  return ip_is_zero (sep->ip, sep->is_ip4);
}

u8
session_endpoint_in_ns (session_endpoint_t *sep)
{
  if (sep->fib_index != SEP_INVALID_INDEX
      && ip_interface_has_address (sep->sw_if_index, &sep->ip, sep->is_ip4))
    {
      clib_warning ("sw_if_index %u not configured with ip %U",
                    sep->sw_if_index, format_ip46_address, &sep->ip,
                    sep->is_ip4);
      return 0;
    }
  return (ip_is_zero (sep->ip, sep->is_ip4)
      || ip_is_local (sep->fib_index, sep->ip, sep->is_ip4));
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
session_endpoint_update_for_app (session_endpoint_t *sep, application_t *app)
{
  app_namespace_t *app_ns;
  app_ns = app_namespace_get (app);
  if (app_ns)
    {
      /* Ask transport and network to bind to/connect using local interface
       * that "supports" app's namespace. This will fix our local connection
       * endpoint.
       */
      sep->sw_if_index = app_ns->sw_if_index;
      sep->fib_index = app_ns->nns_index;
    }
}

static int
vnet_bind_i (u32 app_index, session_endpoint_t * sep, u64 * handle)
{
  application_t *app;
  u32 table_index, listener_index;
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

  table_index = application_session_table (app);
  listener_index = session_lookup_session_endpoint (table_index, sep);
  if (listener_index != SESSION_INVALID_INDEX)
    return VNET_API_ERROR_ADDRESS_IN_USE;

  /*
   * Add session endpoint to local session table. Only binds to "inaddr_any"
   * (i.e., zero address) are added to local scope table.
   */
  if (application_has_local_scope (app) && session_endpoint_is_zero (sep))
    {
      table_index = application_local_session_table (app);
      listener_index = session_lookup_session_endpoint (table_index, sep);
      if (listener_index != SESSION_INVALID_INDEX)
	return VNET_API_ERROR_ADDRESS_IN_USE;
      session_table_add_session_endpoint (table_index, sep, app->index);
      *handle = SESSION_LOCAL_TABLE_PREFIX << 32 | (u32) sep->port << 8;
      *handle |= sep->transport_proto;
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
    session_local_table_del (table_index, handle);
  return rv;
}

int
vnet_unbind_i (u32 app_index, u64 handle)
{
  application_t *app = application_get_if_valid (app_index);
  stream_session_t *listener;
  u32 port_and_proto, table_index, have_local = 0;
  int rv;

  if (!app)
    {
      SESSION_DBG ("app (%d) not attached", app_index);
      return VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  /*
   * Clean up local session table. If we have a listener session use it to
   * find the port and proto. If not, the handle must be a local table handle
   * so parse it.
   */
  listener = listen_session_get_from_handle (handle);
  if (application_has_local_scope (app))
    {
      session_endpoint_t sep = SESSION_ENDPOINT_NULL;

      if (listener)
	{
	  port_and_proto = listen_session_get_port_and_proto (listener);
	  sep.transport_proto = port_and_proto & 0xff;
	  sep.port = port_and_proto >> 8;
	}
      else if (handle >> 32 == SESSION_LOCAL_TABLE_PREFIX)
	{
	  u32 local_table_handle = handle & 0xFFFFFFFFULL;
	  sep.transport_proto = local_table_handle & 0xff;
	  sep.port = local_table_handle >> 8;
	}
      else
	{
	  return -1;
	}
      table_index = application_session_table (app);
      session_table_del_session_endpoint (table_index, sep);
      have_local = 1;
    }

  /*
   * Clear the global scope table of the listener
   */
  if (application_has_global_scope (app))
    return application_stop_listen (app, handle);
  return 0;
}

int
vnet_connect_i (u32 app_index, u32 api_context, session_endpoint_t * sep,
                void *mp)
{
  stream_session_t *listener;
  application_t *server, *app;
  u32 table_index;

  if (session_endpoint_is_zero (sep))
    return VNET_API_ERROR_INVALID_VALUE;

  app = application_get (app_index);
  session_endpoint_update_for_app (sep, app);

  /*
   * First check the the local scope for locally attached destinations.
   * If we have local scope, we pass *all* connects through it since we may
   * have special policy rules even for non local destinations, think proxy.
   */
  if (application_has_local_scope (app))
    {
      table_index = application_local_session_table (app);
      app_index = session_lookup_session_endpoint (table_index, sep);
      server = application_get (app_index);
      /*
       * Server is willing to have a direct fifo connection created
       * instead of going through the state machine, etc.
       */
      if (server->flags & APP_OPTIONS_FLAGS_ACCEPT_REDIRECT)
	return server->cb_fns.
	  redirect_connect_callback (server->api_client_index, mp);
    }

  /*
   * If nothing found, check the global scope for locally attached
   * destinations. Make sure first that we're allowed to.
   */
  if (session_endpoint_is_local (sep) || !application_has_global_scope (app))
    {
      clib_warning ("connect out of scope");
      return VNET_API_ERROR_INVALID_VALUE_2;
    }

  table_index = application_session_table (app);
  app_index = session_lookup_session_endpoint (table_index, sep);
  server = application_get (app_index);
  if (server->flags & APP_OPTIONS_FLAGS_ACCEPT_REDIRECT)
    return server->cb_fns.redirect_connect_callback (server->api_client_index,
	                                             mp);

  /*
   * Not connecting to a local server, propagate to transport
   */
  return application_open_session (app, sep, api_context);
}

/**
 * unformat a vnet URI
 *
 * fifo://name
 * tcp://ip46-addr:port
 * udp://ip46-addr:port
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

  if (unformat (input, "tcp://%U/%d", unformat_ip4_address, &sep->ip.ip4,
		&sep->port))
    {
      sep->transport_proto = TRANSPORT_PROTO_TCP;
      sep->port = clib_host_to_net_u16 (sep->port);
      sep->is_ip4 = 1;
      return 1;
    }
  if (unformat (input, "udp://%U/%d", unformat_ip4_address, &sep->ip.ip4,
		&sep->port))
    {
      sep->transport_proto = TRANSPORT_PROTO_UDP;
      sep->port = clib_host_to_net_u16 (sep->port);
      sep->is_ip4 = 1;
      return 1;
    }
  if (unformat (input, "udp://%U/%d", unformat_ip6_address, &sep->ip.ip6,
		&sep->port))
    {
      sep->transport_proto = TRANSPORT_PROTO_UDP;
      sep->port = clib_host_to_net_u16 (sep->port);
      return 1;
    }
  if (unformat (input, "tcp://%U/%d", unformat_ip6_address, &sep->ip.ip6,
		&sep->port))
    {
      sep->transport_proto = TRANSPORT_PROTO_TCP;
      sep->port = clib_host_to_net_u16 (sep->port);
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
session_validate_namespace (u8 *namespace_id, u64 secret, u32 *app_ns_index)
{
  app_namespace_t *app_ns;
  if (vec_len(namespace_id) == 0)
    {
      *app_ns_index = 0;
      return 0;
    }

  namespace_id[vec_len(namespace_id) - 1] = 0;
  app_ns_index = app_namespace_index_from_id (namespace_id);
  app_ns = app_namespace_get (app_ns_index);
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
int
vnet_application_attach (vnet_app_attach_args_t * a)
{
  application_t *app = 0;
  segment_manager_t *sm;
  u8 *seg_name;
  u64 secret;
  int rv;

  secret = a->options[APP_OPTIONS_NAMESPACE_SECRET];
  if ((rv = session_validate_namespace (a->namespace_id, secret,
	                                &a->options[APP_OPTIONS_NAMESPACE])))
    return rv;

  app = application_new ();
  if ((rv = application_init (app, a->api_client_index, a->options,
			      a->session_cb_vft)))
    return rv;

  a->app_event_queue_address = pointer_to_uword (app->event_queue);
  sm = segment_manager_get (app->first_segment_manager);
  segment_manager_get_segment_info (sm->segment_indices[0],
				    &seg_name, &a->segment_size);

  a->segment_name_length = vec_len (seg_name);
  a->segment_name = seg_name;
  ASSERT (vec_len (a->segment_name) <= 128);
  a->app_index = app->index;
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

  memset (&sep, 0, sizeof (sep));
  rv = parse_uri (a->uri, &sep);
  if (rv)
    return rv;

  if ((rv = vnet_bind_i (a->app_index, &sep, &a->handle)))
    return rv;

  return 0;
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

  listener = session_lookup_listener (&sep);
  if (!listener)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  return vnet_unbind_i (a->app_index, listen_session_get_handle (listener));
}

int
vnet_connect_uri (vnet_connect_args_t * a)
{
  session_endpoint_t sep = SESSION_ENDPOINT_NULL;
  int rv;

  /* Parse uri */
  memset (&sep, 0, sizeof (sep));
  rv = parse_uri (a->uri, &sep);
  if (rv)
    return rv;

  return vnet_connect_i (a->app_index, a->api_context, &sep, a->mp);
}

int
vnet_disconnect_session (vnet_disconnect_args_t * a)
{
  u32 index, thread_index;
  stream_session_t *s;

  session_parse_handle (a->handle, &index, &thread_index);
  s = stream_session_get_if_valid (index, thread_index);

  if (!s || s->app_index != a->app_index)
    return VNET_API_ERROR_INVALID_VALUE;

  /* We're peeking into another's thread pool. Make sure */
  ASSERT (s->session_index == index);

  session_send_session_evt_to_thread (a->handle, FIFO_EVENT_DISCONNECT,
				      thread_index);
  return 0;
}

int
vnet_bind (vnet_bind_args_t * a)
{
  int rv;

  if ((rv = vnet_bind_i (a->app_index, &a->sep, &a->handle)))
    return rv;

  return 0;
}

int
vnet_unbind (vnet_unbind_args_t * a)
{
  return vnet_unbind_i (a->app_index, a->handle);
}

int
vnet_connect (vnet_connect_args_t * a)
{
  return vnet_connect_i (a->app_index, a->api_context, &a->sep, a->mp);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
