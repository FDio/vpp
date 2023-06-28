/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
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
#include <vnet/session/application.h>
#include <vnet/session/session.h>

/** @file
    VPP's application/session API bind/unbind/connect/disconnect calls
*/

/**
 * unformat a vnet URI
 *
 * transport-proto://[hostname]ip46-addr:port
 * eg. 	tcp://ip46-addr:port
 * 	tls://[testtsl.fd.io]ip46-addr:port
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
  session_endpoint_cfg_t *sep = va_arg (*args, session_endpoint_cfg_t *);
  u32 transport_proto = 0, port;

  if (unformat (input, "%U://%U/%d", unformat_transport_proto,
		&transport_proto, unformat_ip4_address, &sep->ip.ip4, &port))
    {
      sep->transport_proto = transport_proto;
      sep->port = clib_host_to_net_u16 (port);
      sep->is_ip4 = 1;
      return 1;
    }
  else if (unformat (input, "%U://%U/%d", unformat_transport_proto,
		     &transport_proto, unformat_ip6_address, &sep->ip.ip6,
		     &port))
    {
      sep->transport_proto = transport_proto;
      sep->port = clib_host_to_net_u16 (port);
      sep->is_ip4 = 0;
      return 1;
    }
  else if (unformat (input, "%U://session/%lu", unformat_transport_proto,
		     &transport_proto, &sep->parent_handle))
    {
      sep->transport_proto = transport_proto;
      sep->ip.ip4.as_u32 = 1;	/* ip need to be non zero in vnet */
      return 1;
    }
  return 0;
}

static u8 *cache_uri;
static session_endpoint_cfg_t *cache_sep;

session_error_t
parse_uri (char *uri, session_endpoint_cfg_t *sep)
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
      return SESSION_E_INVALID;
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

int
vnet_bind_uri (vnet_listen_args_t * a)
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  int rv;

  rv = parse_uri (a->uri, &sep);
  if (rv)
    return rv;
  sep.app_wrk_index = 0;
  clib_memcpy (&a->sep_ext, &sep, sizeof (sep));
  return vnet_listen (a);
}

session_error_t
vnet_unbind_uri (vnet_unlisten_args_t *a)
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  application_t *app;
  session_t *listener;
  u32 table_index;
  session_error_t rv;

  if ((rv = parse_uri (a->uri, &sep)))
    return rv;

  app = application_get (a->app_index);
  if (!app)
    return SESSION_E_INVALID;

  table_index = application_session_table (app, fib_ip_proto (!sep.is_ip4));
  listener = session_lookup_listener (table_index,
				      (session_endpoint_t *) & sep);
  if (!listener)
    return SESSION_E_ADDR_NOT_IN_USE;
  a->handle = listen_session_get_handle (listener);
  return vnet_unlisten (a);
}

session_error_t
vnet_connect_uri (vnet_connect_args_t *a)
{
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  session_error_t rv;

  if ((rv = parse_uri (a->uri, &sep)))
    return rv;

  clib_memcpy (&a->sep_ext, &sep, sizeof (sep));
  if ((rv = vnet_connect (a)))
    return rv;
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
