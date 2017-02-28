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

  clib_memcpy (&prefix.fp_addr, ip46_address, sizeof (ip46_address));
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
vnet_bind_i (u32 api_client_index, ip46_address_t * ip46, u16 port_host_order,
	     session_type_t sst, u64 * options, session_cb_vft_t * cb_fns,
	     application_t ** app, u32 * len_seg_name, char *seg_name)
{
  u8 *segment_name = 0;
  application_t *server = 0;
  stream_session_t *listener;
  u8 is_ip4;

  listener =
    stream_session_lookup_listener (ip46,
				    clib_host_to_net_u16 (port_host_order),
				    sst);

  if (listener)
    return VNET_API_ERROR_ADDRESS_IN_USE;

  if (application_lookup (api_client_index))
    {
      clib_warning ("Only one bind supported for now");
      return VNET_API_ERROR_ADDRESS_IN_USE;
    }

  is_ip4 = SESSION_TYPE_IP4_UDP == sst || SESSION_TYPE_IP4_TCP == sst;
  if (!ip_is_zero (ip46, is_ip4) && !ip_is_local (ip46, is_ip4))
    return VNET_API_ERROR_INVALID_VALUE;

  /* Allocate and initialize stream server */
  server = application_new (APP_SERVER, sst, api_client_index,
			    options[SESSION_OPTIONS_FLAGS], cb_fns);

  application_server_init (server, options[SESSION_OPTIONS_SEGMENT_SIZE],
			   options[SESSION_OPTIONS_ADD_SEGMENT_SIZE],
			   options[SESSION_OPTIONS_RX_FIFO_SIZE],
			   options[SESSION_OPTIONS_TX_FIFO_SIZE],
			   &segment_name);

  /* Setup listen path down to transport */
  stream_session_start_listen (server->index, ip46, port_host_order);

  /*
   * Return values
   */

  ASSERT (vec_len (segment_name) <= 128);
  *len_seg_name = vec_len (segment_name);
  memcpy (seg_name, segment_name, *len_seg_name);
  *app = server;

  return 0;
}

int
vnet_unbind_i (u32 api_client_index)
{
  application_t *server;

  /*
   * Find the stream_server_t corresponding to the api client
   */
  server = application_lookup (api_client_index);
  if (!server)
    return VNET_API_ERROR_INVALID_VALUE_2;

  /* Clear the listener */
  stream_session_stop_listen (server->index);
  application_del (server);

  return 0;
}

int
vnet_connect_i (u32 api_client_index, u32 api_context, session_type_t sst,
		ip46_address_t * ip46, u16 port, u64 * options, void *mp,
		session_cb_vft_t * cb_fns)
{
  stream_session_t *listener;
  application_t *server, *app;

  /*
   * Figure out if connecting to a local server
   */
  listener = stream_session_lookup_listener (ip46,
					     clib_host_to_net_u16 (port),
					     sst);
  if (listener)
    {
      server = application_get (listener->app_index);

      /*
       * Server is willing to have a direct fifo connection created
       * instead of going through the state machine, etc.
       */
      if (server->flags & SESSION_OPTIONS_FLAGS_USE_FIFO)
	return server->cb_fns.
	  redirect_connect_callback (server->api_client_index, mp);
    }

  /* Create client app */
  app = application_new (APP_CLIENT, sst, api_client_index,
			 options[SESSION_OPTIONS_FLAGS], cb_fns);

  app->api_context = api_context;

  /*
   * Not connecting to a local server. Create regular session
   */
  stream_session_open (sst, ip46, port, app->index);

  return 0;
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
  ip46_address_t *address = va_arg (*args, ip46_address_t *);
  session_type_t *sst = va_arg (*args, session_type_t *);
  u16 *port = va_arg (*args, u16 *);

  if (unformat (input, "tcp://%U/%d", unformat_ip4_address, &address->ip4,
		port))
    {
      *sst = SESSION_TYPE_IP4_TCP;
      return 1;
    }
  if (unformat (input, "udp://%U/%d", unformat_ip4_address, &address->ip4,
		port))
    {
      *sst = SESSION_TYPE_IP4_UDP;
      return 1;
    }
  if (unformat (input, "udp://%U/%d", unformat_ip6_address, &address->ip6,
		port))
    {
      *sst = SESSION_TYPE_IP6_UDP;
      return 1;
    }
  if (unformat (input, "tcp://%U/%d", unformat_ip6_address, &address->ip6,
		port))
    {
      *sst = SESSION_TYPE_IP6_TCP;
      return 1;
    }

  return 0;
}

int
parse_uri (char *uri, session_type_t * sst, ip46_address_t * addr,
	   u16 * port_number_host_byte_order)
{
  unformat_input_t _input, *input = &_input;

  /* Make sure */
  uri = (char *) format (0, "%s%c", uri, 0);

  /* Parse uri */
  unformat_init_string (input, uri, strlen (uri));
  if (!unformat (input, "%U", unformat_vnet_uri, addr, sst,
		 port_number_host_byte_order))
    {
      unformat_free (input);
      return VNET_API_ERROR_INVALID_VALUE;
    }
  unformat_free (input);

  return 0;
}

int
vnet_bind_uri (vnet_bind_args_t * a)
{
  application_t *server = 0;
  u16 port_host_order;
  session_type_t sst = SESSION_N_TYPES;
  ip46_address_t ip46;
  int rv;

  memset (&ip46, 0, sizeof (ip46));
  rv = parse_uri (a->uri, &sst, &ip46, &port_host_order);
  if (rv)
    return rv;

  if ((rv = vnet_bind_i (a->api_client_index, &ip46, port_host_order, sst,
			 a->options, a->session_cb_vft, &server,
			 &a->segment_name_length, a->segment_name)))
    return rv;

  a->server_event_queue_address = (u64) server->event_queue;
  return 0;
}

session_type_t
session_type_from_proto_and_ip (session_api_proto_t proto, u8 is_ip4)
{
  if (proto == SESSION_PROTO_TCP)
    {
      if (is_ip4)
	return SESSION_TYPE_IP4_TCP;
      else
	return SESSION_TYPE_IP6_TCP;
    }
  else
    {
      if (is_ip4)
	return SESSION_TYPE_IP4_UDP;
      else
	return SESSION_TYPE_IP6_UDP;
    }

  return SESSION_N_TYPES;
}

int
vnet_unbind_uri (char *uri, u32 api_client_index)
{
  u16 port_number_host_byte_order;
  session_type_t sst = SESSION_N_TYPES;
  ip46_address_t ip46_address;
  stream_session_t *listener;
  int rv;

  rv = parse_uri (uri, &sst, &ip46_address, &port_number_host_byte_order);
  if (rv)
    return rv;

  listener =
    stream_session_lookup_listener (&ip46_address,
				    clib_host_to_net_u16
				    (port_number_host_byte_order), sst);

  if (!listener)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  /* External client? */
  if (api_client_index != ~0)
    {
      ASSERT (vl_api_client_index_to_registration (api_client_index));
    }

  return vnet_unbind_i (api_client_index);
}

int
vnet_connect_uri (vnet_connect_args_t * a)
{
  ip46_address_t ip46_address;
  u16 port;
  session_type_t sst;
  application_t *app;
  int rv;

  app = application_lookup (a->api_client_index);
  if (app)
    {
      clib_warning ("Already have a connect from this app");
      return VNET_API_ERROR_INVALID_VALUE_2;
    }

  /* Parse uri */
  rv = parse_uri (a->uri, &sst, &ip46_address, &port);
  if (rv)
    return rv;

  return vnet_connect_i (a->api_client_index, a->api_context, sst,
			 &ip46_address, port, a->options, a->mp,
			 a->session_cb_vft);
}

int
vnet_disconnect_session (u32 client_index, u32 session_index,
			 u32 thread_index)
{
  stream_session_t *session;

  session = stream_session_get (session_index, thread_index);
  stream_session_disconnect (session);

  return 0;
}


int
vnet_bind (vnet_bind_args_t * a)
{
  application_t *server = 0;
  session_type_t sst = SESSION_N_TYPES;
  int rv;

  sst = session_type_from_proto_and_ip (a->proto, a->tep.is_ip4);
  if ((rv = vnet_bind_i (a->api_client_index, &a->tep.ip, a->tep.port, sst,
			 a->options, a->session_cb_vft, &server,
			 &a->segment_name_length, a->segment_name)))
    return rv;

  a->server_event_queue_address = (u64) server->event_queue;
  a->handle = (u64) a->tep.vrf << 32 | (u64) server->session_index;
  return 0;
}

int
vnet_unbind (vnet_unbind_args_t * a)
{
  application_t *server;

  if (a->api_client_index != ~0)
    {
      ASSERT (vl_api_client_index_to_registration (a->api_client_index));
    }

  /* Make sure this is the right one */
  server = application_lookup (a->api_client_index);
  ASSERT (server->session_index == (0xFFFFFFFF & a->handle));

  /* TODO use handle to disambiguate namespaces/vrfs */
  return vnet_unbind_i (a->api_client_index);
}

int
vnet_connect (vnet_connect_args_t * a)
{
  session_type_t sst;
  application_t *app;

  app = application_lookup (a->api_client_index);
  if (app)
    {
      clib_warning ("Already have a connect from this app");
      return VNET_API_ERROR_INVALID_VALUE_2;
    }

  sst = session_type_from_proto_and_ip (a->proto, a->tep.is_ip4);
  return vnet_connect_i (a->api_client_index, a->api_context, sst, &a->tep.ip,
			 a->tep.port, a->options, a->mp, a->session_cb_vft);
}

int
vnet_disconnect (vnet_disconnect_args_t * a)
{
  stream_session_t *session;
  u32 session_index, thread_index;

  if (api_parse_session_handle (a->handle, &session_index, &thread_index))
    {
      clib_warning ("Invalid handle");
      return -1;
    }

  session = stream_session_get (session_index, thread_index);
  stream_session_disconnect (session);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
