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

#include <vnet/uri/uri.h>
#include <vnet/ip/udp.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>

/* Per-worker thread udp connection pools */
udp_session_t **udp_sessions;
udp_session_t *udp_listeners;

u32
vnet_bind_ip4_udp_uri (vlib_main_t *vm, u32 session_index, ip46_address_t *ip,
                       u16 port_number_host_byte_order)
{
  udp_session_t *listener;
  pool_get(udp_listeners, listener);
  memset (listener, 0, sizeof (udp_session_t));
  listener->c_lcl_port = clib_host_to_net_u16 (port_number_host_byte_order);
  listener->c_lcl_ip4.as_u32 = ip->ip4.as_u32;
  listener->c_proto = SESSION_TYPE_IP4_UDP;
  udp_register_dst_port (vm, port_number_host_byte_order,
                         udp4_uri_input_node.index, 1 /* is_ipv4 */);
  return 0;
}

u32
vnet_bind_ip6_udp_uri (vlib_main_t *vm, u32 session_index, ip46_address_t *ip,
                       u16 port_number_host_byte_order)
{
  udp_session_t *listener;
  pool_get(udp_listeners, listener);
  listener->c_lcl_port = clib_host_to_net_u16 (port_number_host_byte_order);
  clib_memcpy (&listener->c_lcl_ip6, &ip->ip6, sizeof(ip6_address_t));
  listener->c_proto = SESSION_TYPE_IP6_UDP;
  udp_register_dst_port (vm, port_number_host_byte_order,
                         udp4_uri_input_node.index, 0 /* is_ipv4 */);
  return 0;
}

u32
vnet_unbind_ip4_udp_uri (vlib_main_t *vm, u32 listener_index)
{
  udp_session_t *listener = pool_elt_at_index(udp_listeners, listener_index);
  /* deregister the udp_local mapping */
  udp_unregister_dst_port (vm, listener->c_lcl_port, 1 /* is_ipv4 */);
  return 0;
}

u32
vnet_unbind_ip6_udp_uri (vlib_main_t *vm, u32 listener_index)
{
  udp_session_t *listener = pool_elt_at_index(udp_listeners, listener_index);
  /* deregister the udp_local mapping */
  udp_unregister_dst_port (vm, listener->c_lcl_port, 0 /* is_ipv4 */);
  return 0;
}

transport_connection_t *
uri_udp_session_get_listener (u32 listener_index)
{
  udp_session_t *us;
  us = pool_elt_at_index (udp_listeners, listener_index);
  return &us->connection;
}

u32
uri_tx_ip4_udp (transport_connection_t *tconn, vlib_buffer_t *b)
{
  ip4_header_t * ip;
  udp_header_t * udp;
  udp_session_t *us;
  u8 * data;

  us = (udp_session_t *)tconn;

  data = vlib_buffer_get_current (b);
  udp = (udp_header_t *) (data - sizeof(udp_header_t));
  ip = (ip4_header_t *) ((u8 *) udp - sizeof(ip4_header_t));

  /* Build packet header, swap rx key src + dst fields */
  ip->src_address.as_u32 = us->c_lcl_ip4.as_u32;
  ip->dst_address.as_u32 = us->c_rmt_ip4.as_u32;
  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->length = clib_host_to_net_u16 (b->current_length + sizeof (*udp));
  ip->checksum = ip4_header_checksum(ip);

  udp->src_port = us->c_lcl_port;
  udp->dst_port = us->c_rmt_port;
  udp->length = clib_host_to_net_u16 (b->current_length);
  udp->checksum = 0;

  b->current_length = sizeof (*ip) + sizeof (*udp);

  return URI_QUEUE_NEXT_IP4_LOOKUP;
}

transport_connection_t *
uri_udp_session_get (u32 connection_index, u32 my_thread_index)
{
  udp_session_t * us;
  us = pool_elt_at_index (udp_sessions[my_thread_index], connection_index);
  return &us->connection;
}

void
uri_udp_session_delete (u32 connection_index, u32 my_thread_index)
{
  pool_put_index (udp_sessions[my_thread_index], connection_index);
}

u8 *
format_ip4_udp_stream_session (u8 * s, va_list * args)
{
  u32 tsi = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  udp_session_t *u4;

  u4 = pool_elt_at_index(udp_sessions[thread_index], tsi);

  s = format (s, "%-20U%-20U%-10d%-10d%-8s", format_ip4_address,
              &u4->c_lcl_ip4, format_ip4_address, &u4->c_rmt_ip4,
              clib_net_to_host_u16 (u4->c_lcl_port),
              clib_net_to_host_u16 (u4->c_rmt_port), "udp");

  return s;
}

u8*
format_stream_session_ip6_udp (u8 *s, va_list *args)
{
  clib_warning ("unimplmented");
  return 0;
}

u8*
format_stream_session_fifo (u8 *s, va_list *args)
{
  clib_warning ("unimplmented");
  return 0;
}

u32 uri_tx_ip6_udp (vlib_main_t *vm, stream_session_t *s, vlib_buffer_t *b)
{
  clib_warning ("unimplmented");
  return 0;
}
u32 uri_tx_fifo (vlib_main_t *vm, stream_session_t *s, vlib_buffer_t *b)
{
  clib_warning ("unimplmented");
  return 0;
}

u16
udp_send_mss_uri (transport_connection_t *t)
{
  /* TODO figure out MTU of output interface */
  return 400;
}

const static transport_proto_vft_t udp4_proto = {
  .bind = vnet_bind_ip4_udp_uri,
  .unbind = vnet_unbind_ip4_udp_uri,
  .push_header = uri_tx_ip4_udp,
  .get_connection = uri_udp_session_get,
  .get_listener = uri_udp_session_get_listener,
  .delete = uri_udp_session_delete,
  .send_mss = udp_send_mss_uri,
  .format_connection = format_ip4_udp_stream_session
};

static clib_error_t *
uri_udp4_module_init (vlib_main_t * vm)
{
  u32 num_threads;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  num_threads = 1 /* main thread */ + tm->n_threads;

  uri_register_transport (SESSION_TYPE_IP4_UDP, &udp4_proto);

  /** FIXME move to udp main */
  vec_validate (udp_sessions, num_threads - 1);
  return 0;
}

VLIB_INIT_FUNCTION (uri_udp4_module_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
