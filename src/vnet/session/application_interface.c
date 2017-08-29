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
ip_is_local (ip46_address_t * ip46_address, u8 is_ip4)
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

int
vnet_bind_i (u32 app_index, session_type_t sst,
	     transport_endpoint_t * tep, u64 * handle)
{
  application_t *app;
  stream_session_t *listener;

  app = application_get_if_valid (app_index);
  if (!app)
    {
      clib_warning ("app not attached");
      return VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  listener = stream_session_lookup_listener (&tep->ip,
					     clib_host_to_net_u16 (tep->port),
					     sst);
  if (listener)
    return VNET_API_ERROR_ADDRESS_IN_USE;

  if (!ip_is_zero (&tep->ip, tep->is_ip4)
      && !ip_is_local (&tep->ip, tep->is_ip4))
    return VNET_API_ERROR_INVALID_VALUE_2;

  /* Setup listen path down to transport */
  return application_start_listen (app, sst, tep, handle);
}

int
vnet_unbind_i (u32 app_index, u64 handle)
{
  application_t *app = application_get_if_valid (app_index);

  if (!app)
    {
      clib_warning ("app (%d) not attached", app_index);
      return VNET_API_ERROR_APPLICATION_NOT_ATTACHED;
    }

  /* Clear the listener */
  return application_stop_listen (app, handle);
}

int
vnet_connect_i (u32 app_index, u32 api_context, session_type_t sst,
		transport_endpoint_t * tep, void *mp)
{
  stream_session_t *listener;
  application_t *server, *app;

  /*
   * Figure out if connecting to a local server
   */
  listener = stream_session_lookup_listener (&tep->ip,
					     clib_host_to_net_u16 (tep->port),
					     sst);
  if (listener)
    {
      server = application_get (listener->app_index);

      /*
       * Server is willing to have a direct fifo connection created
       * instead of going through the state machine, etc.
       */
      if (server->flags & APP_OPTIONS_FLAGS_USE_FIFO)
	return server->cb_fns.
	  redirect_connect_callback (server->api_client_index, mp);
    }

  /*
   * Not connecting to a local server. Create regular session
   */
  app = application_get (app_index);
  return application_open_session (app, sst, tep, api_context);
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
  session_type_t *sst = va_arg (*args, session_type_t *);
  transport_endpoint_t *tep = va_arg (*args, transport_endpoint_t *);

  if (unformat (input, "tcp://%U/%d", unformat_ip4_address, &tep->ip.ip4,
		&tep->port))
    {
      *sst = SESSION_TYPE_IP4_TCP;
      tep->is_ip4 = 1;
      return 1;
    }
  if (unformat (input, "udp://%U/%d", unformat_ip4_address, &tep->ip.ip4,
		&tep->port))
    {
      *sst = SESSION_TYPE_IP4_UDP;
      tep->is_ip4 = 1;
      return 1;
    }
  if (unformat (input, "udp://%U/%d", unformat_ip6_address, &tep->ip.ip6,
		&tep->port))
    {
      *sst = SESSION_TYPE_IP6_UDP;
      return 1;
    }
  if (unformat (input, "tcp://%U/%d", unformat_ip6_address, &tep->ip.ip6,
		&tep->port))
    {
      *sst = SESSION_TYPE_IP6_TCP;
      return 1;
    }

  return 0;
}

static u8 *cache_uri;
static session_type_t cache_sst;
static transport_endpoint_t *cache_tep;

int
parse_uri (char *uri, session_type_t * sst, transport_endpoint_t * tep)
{
  unformat_input_t _input, *input = &_input;

  if (cache_uri && !strncmp (uri, (char *) cache_uri, vec_len (cache_uri)))
    {
      *sst = cache_sst;
      *tep = *cache_tep;
      return 0;
    }

  /* Make sure */
  uri = (char *) format (0, "%s%c", uri, 0);

  /* Parse uri */
  unformat_init_string (input, uri, strlen (uri));
  if (!unformat (input, "%U", unformat_vnet_uri, sst, tep))
    {
      unformat_free (input);
      return VNET_API_ERROR_INVALID_VALUE;
    }
  unformat_free (input);

  vec_free (cache_uri);
  cache_uri = (u8 *) uri;
  cache_sst = *sst;
  if (cache_tep)
    clib_mem_free (cache_tep);
  cache_tep = clib_mem_alloc (sizeof (*tep));
  *cache_tep = *tep;

  return 0;
}

/**
 * Attaches application.
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
  int rv;

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
  session_type_t sst = SESSION_N_TYPES;
  transport_endpoint_t tep;
  int rv;

  memset (&tep, 0, sizeof (tep));
  rv = parse_uri (a->uri, &sst, &tep);
  if (rv)
    return rv;

  if ((rv = vnet_bind_i (a->app_index, sst, &tep, &a->handle)))
    return rv;

  return 0;
}

int
vnet_unbind_uri (vnet_unbind_args_t * a)
{
  session_type_t sst = SESSION_N_TYPES;
  stream_session_t *listener;
  transport_endpoint_t tep;
  int rv;

  rv = parse_uri (a->uri, &sst, &tep);
  if (rv)
    return rv;

  listener = stream_session_lookup_listener (&tep.ip,
					     clib_host_to_net_u16 (tep.port),
					     sst);
  if (!listener)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  return vnet_unbind_i (a->app_index, listen_session_get_handle (listener));
}

int
vnet_connect_uri (vnet_connect_args_t * a)
{
  transport_endpoint_t tep;
  session_type_t sst;
  int rv;

  /* Parse uri */
  memset (&tep, 0, sizeof (tep));
  rv = parse_uri (a->uri, &sst, &tep);
  if (rv)
    return rv;

  return vnet_connect_i (a->app_index, a->api_context, sst, &tep, a->mp);
}

int
vnet_disconnect_session (vnet_disconnect_args_t * a)
{
  u32 index, thread_index;
  stream_session_t *s;

  stream_session_parse_handle (a->handle, &index, &thread_index);
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
  session_type_t sst = SESSION_N_TYPES;
  int rv;

  sst = session_type_from_proto_and_ip (a->proto, a->tep.is_ip4);
  if ((rv = vnet_bind_i (a->app_index, sst, &a->tep, &a->handle)))
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
  session_type_t sst;

  sst = session_type_from_proto_and_ip (a->proto, a->tep.is_ip4);
  return vnet_connect_i (a->app_index, a->api_context, sst, &a->tep, a->mp);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
