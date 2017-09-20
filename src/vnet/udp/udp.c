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

/** @file
    udp state machine, etc.
*/

#include <vnet/udp/udp.h>
#include <vnet/session/session.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>

udp_uri_main_t udp_uri_main;

u32
udp_session_bind_ip4 (u32 session_index, transport_endpoint_t * lcl)
{
  udp_uri_main_t *um = vnet_get_udp_main ();
  udp_connection_t *listener;

  pool_get (um->udp_listeners, listener);
  memset (listener, 0, sizeof (udp_connection_t));
  listener->c_lcl_port = lcl->port;
  listener->c_lcl_ip4.as_u32 = lcl->ip.ip4.as_u32;
  listener->c_transport_proto = TRANSPORT_PROTO_UDP;
  udp_register_dst_port (um->vlib_main, clib_net_to_host_u16 (lcl->port),
			 udp4_uri_input_node.index, 1 /* is_ipv4 */ );
  return 0;
}

u32
udp_session_bind_ip6 (u32 session_index, transport_endpoint_t * lcl)
{
  udp_uri_main_t *um = vnet_get_udp_main ();
  udp_connection_t *listener;

  pool_get (um->udp_listeners, listener);
  listener->c_lcl_port = lcl->port;
  clib_memcpy (&listener->c_lcl_ip6, &lcl->ip.ip6, sizeof (ip6_address_t));
  listener->c_transport_proto = TRANSPORT_PROTO_UDP;
  udp_register_dst_port (um->vlib_main, clib_net_to_host_u16 (lcl->port),
			 udp4_uri_input_node.index, 0 /* is_ipv4 */ );
  return 0;
}

u32
udp_session_unbind_ip4 (u32 listener_index)
{
  vlib_main_t *vm = vlib_get_main ();
  udp_connection_t *listener;
  listener = udp_listener_get (listener_index);

  /* deregister the udp_local mapping */
  udp_unregister_dst_port (vm, listener->c_lcl_port, 1 /* is_ipv4 */ );
  return 0;
}

u32
udp_session_unbind_ip6 (u32 listener_index)
{
  vlib_main_t *vm = vlib_get_main ();
  udp_connection_t *listener;

  listener = udp_listener_get (listener_index);

  /* deregister the udp_local mapping */
  udp_unregister_dst_port (vm, listener->c_lcl_port, 0 /* is_ipv4 */ );
  return 0;
}

transport_connection_t *
udp_session_get_listener (u32 listener_index)
{
  udp_connection_t *us;

  us = udp_listener_get (listener_index);
  return &us->connection;
}

u32
udp_push_header (transport_connection_t * tconn, vlib_buffer_t * b)
{
  udp_connection_t *us;
  u8 *data;
  udp_header_t *udp;

  us = (udp_connection_t *) tconn;

  if (tconn->is_ip4)
    {
      ip4_header_t *ip;

      data = vlib_buffer_get_current (b);
      udp = (udp_header_t *) (data - sizeof (udp_header_t));
      ip = (ip4_header_t *) ((u8 *) udp - sizeof (ip4_header_t));

      /* Build packet header, swap rx key src + dst fields */
      ip->src_address.as_u32 = us->c_lcl_ip4.as_u32;
      ip->dst_address.as_u32 = us->c_rmt_ip4.as_u32;
      ip->ip_version_and_header_length = 0x45;
      ip->ttl = 254;
      ip->protocol = IP_PROTOCOL_UDP;
      ip->length = clib_host_to_net_u16 (b->current_length + sizeof (*udp));
      ip->checksum = ip4_header_checksum (ip);

      udp->src_port = us->c_lcl_port;
      udp->dst_port = us->c_rmt_port;
      udp->length = clib_host_to_net_u16 (b->current_length);
      udp->checksum = 0;

      b->current_length = sizeof (*ip) + sizeof (*udp);
      return SESSION_QUEUE_NEXT_IP4_LOOKUP;
    }
  else
    {
      vlib_main_t *vm = vlib_get_main ();
      ip6_header_t *ip;
      u16 payload_length;
      int bogus = ~0;

      data = vlib_buffer_get_current (b);
      udp = (udp_header_t *) (data - sizeof (udp_header_t));
      ip = (ip6_header_t *) ((u8 *) udp - sizeof (ip6_header_t));

      /* Build packet header, swap rx key src + dst fields */
      clib_memcpy (&ip->src_address, &us->c_lcl_ip6, sizeof (ip6_address_t));
      clib_memcpy (&ip->dst_address, &us->c_rmt_ip6, sizeof (ip6_address_t));

      ip->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (0x6 << 28);

      ip->hop_limit = 0xff;
      ip->protocol = IP_PROTOCOL_UDP;

      payload_length = vlib_buffer_length_in_chain (vm, b);
      payload_length -= sizeof (*ip);

      ip->payload_length = clib_host_to_net_u16 (payload_length);

      udp->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip, &bogus);
      ASSERT (!bogus);

      udp->src_port = us->c_lcl_port;
      udp->dst_port = us->c_rmt_port;
      udp->length = clib_host_to_net_u16 (b->current_length);
      udp->checksum = 0;

      b->current_length = sizeof (*ip) + sizeof (*udp);

      return SESSION_QUEUE_NEXT_IP6_LOOKUP;
    }
}

transport_connection_t *
udp_session_get (u32 connection_index, u32 my_thread_index)
{
  udp_uri_main_t *um = vnet_get_udp_main ();

  udp_connection_t *us;
  us =
    pool_elt_at_index (um->udp_sessions[my_thread_index], connection_index);
  return &us->connection;
}

void
udp_session_close (u32 connection_index, u32 my_thread_index)
{
  udp_uri_main_t *um = vnet_get_udp_main ();
  pool_put_index (um->udp_sessions[my_thread_index], connection_index);
}

u8 *
format_udp_session_ip4 (u8 * s, va_list * args)
{
  u32 uci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  udp_connection_t *u4;

  u4 = udp_connection_get (uci, thread_index);

  s = format (s, "[%s] %U:%d->%U:%d", "udp", format_ip4_address,
	      &u4->c_lcl_ip4, clib_net_to_host_u16 (u4->c_lcl_port),
	      format_ip4_address, &u4->c_rmt_ip4,
	      clib_net_to_host_u16 (u4->c_rmt_port));
  return s;
}

u8 *
format_udp_session_ip6 (u8 * s, va_list * args)
{
  u32 uci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  udp_connection_t *tc = udp_connection_get (uci, thread_index);
  s = format (s, "[%s] %U:%d->%U:%d", "udp", format_ip6_address,
	      &tc->c_lcl_ip6, clib_net_to_host_u16 (tc->c_lcl_port),
	      format_ip6_address, &tc->c_rmt_ip6,
	      clib_net_to_host_u16 (tc->c_rmt_port));
  return s;
}

u8 *
format_udp_listener_session_ip4 (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  udp_connection_t *tc = udp_listener_get (tci);
  s = format (s, "[%s] %U:%d->%U:%d", "udp", format_ip4_address,
	      &tc->c_lcl_ip4, clib_net_to_host_u16 (tc->c_lcl_port),
	      format_ip4_address, &tc->c_rmt_ip4,
	      clib_net_to_host_u16 (tc->c_rmt_port));
  return s;
}

u8 *
format_udp_listener_session_ip6 (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  udp_connection_t *tc = udp_listener_get (tci);
  s = format (s, "[%s] %U:%d->%U:%d", "udp", format_ip6_address,
	      &tc->c_lcl_ip6, clib_net_to_host_u16 (tc->c_lcl_port),
	      format_ip6_address, &tc->c_rmt_ip6,
	      clib_net_to_host_u16 (tc->c_rmt_port));
  return s;
}

u16
udp_send_mss_uri (transport_connection_t * t)
{
  /* TODO figure out MTU of output interface */
  return 400;
}

u32
udp_send_space_uri (transport_connection_t * t)
{
  /* No constraint on TX window */
  return ~0;
}

int
udp_open_connection (transport_endpoint_t * tep)
{
  clib_warning ("Not implemented");
  return 0;
}

/* *INDENT-OFF* */
const static transport_proto_vft_t udp4_proto = {
  .bind = udp_session_bind_ip4,
  .open = udp_open_connection,
  .unbind = udp_session_unbind_ip4,
  .push_header = udp_push_header,
  .get_connection = udp_session_get,
  .get_listener = udp_session_get_listener,
  .close = udp_session_close,
  .send_mss = udp_send_mss_uri,
  .send_space = udp_send_space_uri,
  .format_connection = format_udp_session_ip4,
  .format_listener = format_udp_listener_session_ip4
};

const static transport_proto_vft_t udp6_proto = {
  .bind = udp_session_bind_ip6,
  .open = udp_open_connection,
  .unbind = udp_session_unbind_ip6,
  .push_header = udp_push_header,
  .get_connection = udp_session_get,
  .get_listener = udp_session_get_listener,
  .close = udp_session_close,
  .send_mss = udp_send_mss_uri,
  .send_space = udp_send_space_uri,
  .format_connection = format_udp_session_ip6,
  .format_listener = format_udp_listener_session_ip6
};
/* *INDENT-ON* */

static clib_error_t *
udp_init (vlib_main_t * vm)
{
  udp_uri_main_t *um = vnet_get_udp_main ();
  ip_main_t *im = &ip_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 num_threads;
  clib_error_t *error = 0;
  ip_protocol_info_t *pi;

  um->vlib_main = vm;
  um->vnet_main = vnet_get_main ();

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;
  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;
  if ((error = vlib_call_init_function (vm, ip6_lookup_init)))
    return error;

  /*
   * Registrations
   */

  /* IP registration */
  pi = ip_get_protocol_info (im, IP_PROTOCOL_UDP);
  if (pi == 0)
    return clib_error_return (0, "UDP protocol info AWOL");
  pi->format_header = format_udp_header;
  pi->unformat_pg_edit = unformat_pg_udp_header;


  /* Register as transport with URI */
  session_register_transport (TRANSPORT_PROTO_UDP, 1, &udp4_proto);
  session_register_transport (TRANSPORT_PROTO_UDP, 0, &udp6_proto);

  /*
   * Initialize data structures
   */

  num_threads = 1 /* main thread */  + tm->n_threads;
  vec_validate (um->udp_sessions, num_threads - 1);

  return error;
}

VLIB_INIT_FUNCTION (udp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
