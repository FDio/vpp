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

u32
udp_session_bind (u32 session_index, transport_endpoint_t * lcl)
{
  udp_main_t *um = vnet_get_udp_main ();
  vlib_main_t *vm = vlib_get_main ();
  udp_connection_t *listener;
  u32 node_index;
  void *iface_ip;
  udp_dst_port_info_t *pi;

  pi = udp_get_dst_port_info (um, lcl->port, lcl->is_ip4);
  if (pi)
    return -1;

  pool_get (um->listener_pool, listener);
  memset (listener, 0, sizeof (udp_connection_t));

  listener->c_lcl_port = lcl->port;
  listener->c_c_index = listener - um->listener_pool;

  /* If we are provided a sw_if_index, bind using one of its ips */
  if (ip_is_zero (&lcl->ip, 1) && lcl->sw_if_index != ENDPOINT_INVALID_INDEX)
    {
      if ((iface_ip = ip_interface_get_first_ip (lcl->sw_if_index,
						 lcl->is_ip4)))
	ip_set (&lcl->ip, iface_ip, lcl->is_ip4);
    }
  ip_copy (&listener->c_lcl_ip, &lcl->ip, lcl->is_ip4);
  listener->c_is_ip4 = lcl->is_ip4;
  listener->c_proto = TRANSPORT_PROTO_UDP;
  listener->c_s_index = session_index;
  listener->c_fib_index = lcl->fib_index;

  node_index = lcl->is_ip4 ? udp4_input_node.index : udp6_input_node.index;
  udp_register_dst_port (vm, clib_net_to_host_u16 (lcl->port), node_index,
			 1 /* is_ipv4 */ );
  return listener->c_c_index;
}

u32
udp_session_unbind (u32 listener_index)
{
  vlib_main_t *vm = vlib_get_main ();

  udp_connection_t *listener;
  listener = udp_listener_get (listener_index);
  udp_unregister_dst_port (vm, listener->c_lcl_port, listener->c_is_ip4);
  return 0;
}

transport_connection_t *
udp_session_get_listener (u32 listener_index)
{
  udp_connection_t *us;

  us = udp_listener_get (listener_index);
  return &us->connection;
}

udp_connection_t *
udp_half_open_get (u32 conn_index)
{
  udp_connection_t *uc = 0;
  clib_spinlock_lock_if_init (&udp_main.half_open_lock);
  if (!pool_is_free_index (udp_main.half_open_connections, conn_index))
    uc = pool_elt_at_index (udp_main.half_open_connections, conn_index);
  clib_spinlock_unlock_if_init (&udp_main.half_open_lock);
  return uc;
}

void
udp_half_open_del (udp_connection_t * uc)
{
  udp_main_t *um = vnet_get_udp_main ();
  clib_spinlock_lock_if_init (&um->half_open_lock);
  pool_put_index (um->half_open_connections, uc->c_c_index);
  if (CLIB_DEBUG)
    memset (uc, 0xFA, sizeof (*uc));
  clib_spinlock_unlock_if_init (&um->half_open_lock);
}

u32
udp_push_header (transport_connection_t * tc, vlib_buffer_t * b)
{
  udp_connection_t *uc;
  vlib_main_t *vm = vlib_get_main ();

  uc = udp_get_connection_from_transport (tc);

  vlib_buffer_push_udp (b, uc->c_lcl_port, uc->c_rmt_port, 1);
  if (tc->is_ip4)
    vlib_buffer_push_ip4 (vm, b, &uc->c_lcl_ip4, &uc->c_rmt_ip4,
	                  IP_PROTOCOL_UDP, 1);
  else
    {
      ip6_header_t *ih;
      ih = vlib_buffer_push_ip6 (vm, b, &uc->c_lcl_ip6, &uc->c_rmt_ip6,
	                  IP_PROTOCOL_UDP);
      vnet_buffer (b)->l3_hdr_offset = (u8 *) ih - b->data;
    }
  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  return 0;
}

transport_connection_t *
udp_session_get (u32 connection_index, u32 thread_index)
{
  udp_main_t *um = vnet_get_udp_main ();
  udp_connection_t *us;
  if (!pool_is_free_index(um->connections[thread_index], connection_index))
    {
      us = pool_elt_at_index(um->connections[thread_index],
	                     connection_index);
      return &us->connection;
    }
  else if (thread_index == 0)
    {
      us = udp_half_open_get(connection_index);
      if (us)
	return &us->connection;
    }
  return 0;
}

void
udp_session_close (u32 connection_index, u32 my_thread_index)
{
  udp_main_t *um = vnet_get_udp_main ();
  udp_connection_t *uc;
  if (!pool_is_free_index (um->connections[my_thread_index],
                           connection_index))
    {
      uc = udp_half_open_get (connection_index);
      stream_session_delete_notify(&uc->connection);
      pool_put_index (um->connections[my_thread_index], connection_index);
    }
  else if ((uc = udp_half_open_get (connection_index)))
    {
      stream_session_delete_notify(&uc->connection);
      udp_half_open_del (uc);
    }
}

u8 *
format_udp_connection (u8 *s, va_list *args)
{
  udp_connection_t *uc = va_arg (*args, udp_connection_t *);
  if (uc->c_is_ip4)
    s = format (s, "[%s] %U:%d->%U:%d", "U", format_ip4_address,
		&uc->c_lcl_ip4, clib_net_to_host_u16 (uc->c_lcl_port),
		format_ip4_address, &uc->c_rmt_ip4,
		clib_net_to_host_u16 (uc->c_rmt_port));
  else
    s = format (s, "[%s] %U:%d->%U:%d", "U", format_ip6_address,
		&uc->c_lcl_ip6, clib_net_to_host_u16 (uc->c_lcl_port),
		format_ip6_address, &uc->c_rmt_ip6,
		clib_net_to_host_u16 (uc->c_rmt_port));
  return s;
}

u8 *
format_udp_session (u8 * s, va_list * args)
{
  u32 uci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  udp_connection_t *uc;

  uc = udp_connection_get (uci, thread_index);
  return format (s, "%U", format_udp_connection, uc);
}

u8 *
format_udp_listener_session (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  udp_connection_t *uc = udp_listener_get (tci);
  return format (s, "%U", format_udp_connection, uc);
}

u8 *
format_udp_half_open_session (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  udp_connection_t *uc = udp_half_open_get (tci);
  return format (s, "%U", format_udp_connection, uc);
}

u16
udp_send_mss (transport_connection_t * t)
{
  /* TODO figure out MTU of output interface */
  return 1460;
}

u32
udp_send_space (transport_connection_t * t)
{
  /* No constraint on TX window */
  return ~0;
}

udp_connection_t *
udp_half_open_connection_new (void)
{
  udp_main_t *um = vnet_get_udp_main ();
  udp_connection_t *tc = 0;
  ASSERT (vlib_get_thread_index () == 0);
  pool_get (um->half_open_connections, tc);
  memset (tc, 0, sizeof (*tc));
  tc->c_c_index = tc - um->half_open_connections;
  return tc;
}

int
udp_open_connection (transport_endpoint_t * rmt)
{
  udp_main_t *um = vnet_get_udp_main ();
  udp_connection_t *uc;
  ip46_address_t lcl_addr;
  u16 lcl_port;

  if (transport_alloc_local_endpoint (TRANSPORT_PROTO_UDP, rmt, &lcl_addr,
				      &lcl_port))
    return -1;

  clib_spinlock_lock_if_init (&um->half_open_lock);
  uc = udp_half_open_connection_new ();
  ip_copy (&uc->c_rmt_ip, &rmt->ip, rmt->is_ip4);
  ip_copy (&uc->c_lcl_ip, &lcl_addr, rmt->is_ip4);
  uc->c_rmt_port = rmt->port;
  uc->c_lcl_port = clib_host_to_net_u16 (lcl_port);
  uc->c_is_ip4 = rmt->is_ip4;
  uc->c_proto = TRANSPORT_PROTO_UDP;
  uc->c_fib_index = rmt->fib_index;
  clib_spinlock_unlock_if_init (&um->half_open_lock);

  /*
   * Ask session to allocate a session and fifos
   */
  return 0;
}

transport_connection_t *
udp_half_open_session_get_transport (u32 conn_index)
{
  udp_connection_t *uc = udp_half_open_get (conn_index);
  return &uc->connection;
}

/* *INDENT-OFF* */
const static transport_proto_vft_t udp_proto = {
  .bind = udp_session_bind,
  .open = udp_open_connection,
  .unbind = udp_session_unbind,
  .push_header = udp_push_header,
  .get_connection = udp_session_get,
  .get_listener = udp_session_get_listener,
  .get_half_open = udp_half_open_session_get_transport,
  .close = udp_session_close,
  .send_mss = udp_send_mss,
  .send_space = udp_send_space,
  .format_connection = format_udp_session,
  .format_half_open = format_udp_half_open_session,
  .format_listener = format_udp_listener_session
};
/* *INDENT-ON* */

static clib_error_t *
udp_init (vlib_main_t * vm)
{
  udp_main_t *um = vnet_get_udp_main ();
  ip_main_t *im = &ip_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 num_threads;
  clib_error_t *error = 0;
  ip_protocol_info_t *pi;

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
  transport_register_protocol (TRANSPORT_PROTO_UDP, 1, &udp_proto);
  transport_register_protocol (TRANSPORT_PROTO_UDP, 0, &udp_proto);

  /*
   * Initialize data structures
   */

  num_threads = 1 /* main thread */  + tm->n_threads;
  vec_validate (um->connections, num_threads - 1);

  if (num_threads > 1)
    clib_spinlock_init (&um->half_open_lock);
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
