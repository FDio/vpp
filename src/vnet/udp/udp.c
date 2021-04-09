/*
 * Copyright (c) 2016-2020 Cisco and/or its affiliates.
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

#include <vnet/udp/udp.h>
#include <vnet/session/session.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>
#include <vppinfra/sparse_vec.h>

udp_main_t udp_main;

static void
udp_connection_register_port (vlib_main_t * vm, u16 lcl_port, u8 is_ip4)
{
  udp_main_t *um = &udp_main;
  udp_dst_port_info_t *pi;
  u16 *n;

  pi = udp_get_dst_port_info (um, lcl_port, is_ip4);
  if (!pi)
    {
      udp_add_dst_port (um, lcl_port, 0, is_ip4);
      pi = udp_get_dst_port_info (um, lcl_port, is_ip4);
      pi->n_connections = 1;
    }
  else
    {
      pi->n_connections += 1;
      /* Do not return. The fact that the pi is valid does not mean
       * it's up to date */
    }

  pi->node_index = is_ip4 ? udp4_input_node.index : udp6_input_node.index;
  pi->next_index = um->local_to_input_edge[is_ip4];

  /* Setup udp protocol -> next index sparse vector mapping. */
  if (is_ip4)
    n = sparse_vec_validate (um->next_by_dst_port4,
			     clib_host_to_net_u16 (lcl_port));
  else
    n = sparse_vec_validate (um->next_by_dst_port6,
			     clib_host_to_net_u16 (lcl_port));

  n[0] = pi->next_index;
}

static void
udp_connection_unregister_port (u16 lcl_port, u8 is_ip4)
{
  udp_main_t *um = &udp_main;
  udp_dst_port_info_t *pi;

  pi = udp_get_dst_port_info (um, lcl_port, is_ip4);
  if (!pi)
    return;

  if (!pi->n_connections)
    {
      clib_warning ("no connections using port %u", lcl_port);
      return;
    }

  if (!clib_atomic_sub_fetch (&pi->n_connections, 1))
    udp_unregister_dst_port (0, lcl_port, is_ip4);
}

void
udp_connection_share_port (u16 lcl_port, u8 is_ip4)
{
  udp_main_t *um = &udp_main;
  udp_dst_port_info_t *pi;

  /* Done without a lock but the operation is atomic. Writers to pi hash
   * table and vector should be guarded by a barrier sync */
  pi = udp_get_dst_port_info (um, lcl_port, is_ip4);
  clib_atomic_fetch_add_rel (&pi->n_connections, 1);
}

udp_connection_t *
udp_connection_alloc (u32 thread_index)
{
  udp_main_t *um = &udp_main;
  udp_connection_t *uc;
  u32 will_expand = 0;
  pool_get_aligned_will_expand (um->connections[thread_index], will_expand,
				CLIB_CACHE_LINE_BYTES);

  if (PREDICT_FALSE (will_expand))
    {
      clib_spinlock_lock_if_init (&udp_main.peekers_write_locks
				  [thread_index]);
      pool_get_aligned (udp_main.connections[thread_index], uc,
			CLIB_CACHE_LINE_BYTES);
      clib_spinlock_unlock_if_init (&udp_main.peekers_write_locks
				    [thread_index]);
    }
  else
    {
      pool_get_aligned (um->connections[thread_index], uc,
			CLIB_CACHE_LINE_BYTES);
    }
  clib_memset (uc, 0, sizeof (*uc));
  uc->c_c_index = uc - um->connections[thread_index];
  uc->c_thread_index = thread_index;
  uc->c_proto = TRANSPORT_PROTO_UDP;
  return uc;
}

void
udp_connection_free (udp_connection_t * uc)
{
  u32 thread_index = uc->c_thread_index;
  clib_spinlock_free (&uc->rx_lock);
  if (CLIB_DEBUG)
    clib_memset (uc, 0xFA, sizeof (*uc));
  pool_put (udp_main.connections[thread_index], uc);
}

static void
udp_connection_cleanup (udp_connection_t * uc)
{
  transport_endpoint_cleanup (TRANSPORT_PROTO_UDP, &uc->c_lcl_ip,
			      uc->c_lcl_port);
  udp_connection_unregister_port (clib_net_to_host_u16 (uc->c_lcl_port),
				  uc->c_is_ip4);
  udp_connection_free (uc);
}

void
udp_connection_delete (udp_connection_t * uc)
{
  session_transport_delete_notify (&uc->connection);
  udp_connection_cleanup (uc);
}

static u8
udp_connection_port_used_extern (u16 lcl_port, u8 is_ip4)
{
  udp_main_t *um = vnet_get_udp_main ();
  udp_dst_port_info_t *pi;

  pi = udp_get_dst_port_info (um, lcl_port, is_ip4);
  return (pi && !pi->n_connections
	  && udp_is_valid_dst_port (lcl_port, is_ip4));
}

static u16
udp_default_mtu (udp_main_t * um, u8 is_ip4)
{
  u16 ip_hlen = is_ip4 ? sizeof (ip4_header_t) : sizeof (ip6_header_t);
  return (um->default_mtu - sizeof (udp_header_t) - ip_hlen);
}

static u32
udp_session_bind (u32 session_index, transport_endpoint_t * lcl)
{
  udp_main_t *um = vnet_get_udp_main ();
  vlib_main_t *vm = vlib_get_main ();
  transport_endpoint_cfg_t *lcl_ext;
  udp_connection_t *listener;
  u16 lcl_port_ho;
  void *iface_ip;

  lcl_port_ho = clib_net_to_host_u16 (lcl->port);

  if (udp_connection_port_used_extern (lcl_port_ho, lcl->is_ip4))
    {
      clib_warning ("port already used");
      return SESSION_E_PORTINUSE;
    }

  pool_get (um->listener_pool, listener);
  clib_memset (listener, 0, sizeof (udp_connection_t));

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
  listener->mss = udp_default_mtu (um, listener->c_is_ip4);
  listener->flags |= UDP_CONN_F_OWNS_PORT | UDP_CONN_F_LISTEN;
  lcl_ext = (transport_endpoint_cfg_t *) lcl;
  if (lcl_ext->transport_flags & TRANSPORT_CFG_F_CONNECTED)
    listener->flags |= UDP_CONN_F_CONNECTED;
  else
    listener->c_flags |= TRANSPORT_CONNECTION_F_CLESS;
  clib_spinlock_init (&listener->rx_lock);

  udp_connection_register_port (vm, lcl_port_ho, lcl->is_ip4);
  return listener->c_c_index;
}

static u32
udp_session_unbind (u32 listener_index)
{
  udp_main_t *um = &udp_main;
  udp_connection_t *listener;

  listener = udp_listener_get (listener_index);
  udp_connection_unregister_port (clib_net_to_host_u16 (listener->c_lcl_port),
				  listener->c_is_ip4);
  clib_spinlock_free (&listener->rx_lock);
  pool_put (um->listener_pool, listener);
  return 0;
}

static transport_connection_t *
udp_session_get_listener (u32 listener_index)
{
  udp_connection_t *us;

  us = udp_listener_get (listener_index);
  return &us->connection;
}

always_inline u32
udp_push_one_header (vlib_main_t *vm, udp_connection_t *uc, vlib_buffer_t *b)
{
  vlib_buffer_push_udp (b, uc->c_lcl_port, uc->c_rmt_port, 1);
  if (uc->c_is_ip4)
    vlib_buffer_push_ip4_custom (vm, b, &uc->c_lcl_ip4, &uc->c_rmt_ip4,
				 IP_PROTOCOL_UDP, 1 /* csum offload */,
				 0 /* is_df */, uc->c_dscp);
  else
    vlib_buffer_push_ip6 (vm, b, &uc->c_lcl_ip6, &uc->c_rmt_ip6,
			  IP_PROTOCOL_UDP);
  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = uc->c_fib_index;
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  return 0;
}

static u32
udp_push_header (transport_connection_t *tc, vlib_buffer_t **bs, u32 n_bufs)
{
  vlib_main_t *vm = vlib_get_main ();
  udp_connection_t *uc;

  uc = udp_connection_from_transport (tc);

  while (n_bufs >= 4)
    {
      vlib_prefetch_buffer_header (bs[2], STORE);
      vlib_prefetch_buffer_header (bs[3], STORE);

      udp_push_one_header (vm, uc, bs[0]);
      udp_push_one_header (vm, uc, bs[1]);

      n_bufs -= 2;
      bs += 2;
    }
  while (n_bufs)
    {
      if (n_bufs > 1)
	vlib_prefetch_buffer_header (bs[1], STORE);

      udp_push_one_header (vm, uc, bs[0]);

      n_bufs -= 1;
      bs += 1;
    }

  if (PREDICT_FALSE (uc->flags & UDP_CONN_F_CLOSING))
    {
      if (!transport_max_tx_dequeue (&uc->connection))
	udp_connection_delete (uc);
    }

  return 0;
}

static transport_connection_t *
udp_session_get (u32 connection_index, u32 thread_index)
{
  udp_connection_t *uc;
  uc = udp_connection_get (connection_index, thread_index);
  if (uc)
    return &uc->connection;
  return 0;
}

static void
udp_session_close (u32 connection_index, u32 thread_index)
{
  udp_connection_t *uc;

  uc = udp_connection_get (connection_index, thread_index);
  if (!uc || (uc->flags & UDP_CONN_F_MIGRATED))
    return;

  if (!transport_max_tx_dequeue (&uc->connection))
    udp_connection_delete (uc);
  else
    uc->flags |= UDP_CONN_F_CLOSING;
}

static void
udp_session_cleanup (u32 connection_index, u32 thread_index)
{
  udp_connection_t *uc;
  uc = udp_connection_get (connection_index, thread_index);
  if (!uc)
    return;
  if (uc->flags & UDP_CONN_F_MIGRATED)
    udp_connection_free (uc);
  else
    udp_connection_cleanup (uc);
}

static int
udp_session_send_params (transport_connection_t * tconn,
			 transport_send_params_t * sp)
{
  udp_connection_t *uc;

  uc = udp_connection_from_transport (tconn);

  /* No constraint on TX window */
  sp->snd_space = ~0;
  /* TODO figure out MTU of output interface */
  sp->snd_mss = uc->mss;
  sp->tx_offset = 0;
  sp->flags = 0;
  return 0;
}

static int
udp_open_connection (transport_endpoint_cfg_t * rmt)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 thread_index = vm->thread_index;
  udp_main_t *um = &udp_main;
  ip46_address_t lcl_addr;
  udp_connection_t *uc;
  u16 lcl_port;
  int rv;

  rv = transport_alloc_local_endpoint (TRANSPORT_PROTO_UDP, rmt, &lcl_addr,
				       &lcl_port);
  if (rv)
    {
      if (rv != SESSION_E_PORTINUSE)
	return rv;

      if (udp_connection_port_used_extern (lcl_port, rmt->is_ip4))
	return SESSION_E_PORTINUSE;

      /* If port in use, check if 5-tuple is also in use */
      if (session_lookup_connection (rmt->fib_index, &lcl_addr, &rmt->ip,
				     lcl_port, rmt->port, TRANSPORT_PROTO_UDP,
				     rmt->is_ip4))
	return SESSION_E_PORTINUSE;

      /* 5-tuple is available so increase lcl endpoint refcount and proceed
       * with connection allocation */
      transport_share_local_endpoint (TRANSPORT_PROTO_UDP, &lcl_addr,
				      lcl_port);
      goto conn_alloc;
    }

  if (udp_is_valid_dst_port (lcl_port, rmt->is_ip4))
    {
      /* If specific source port was requested abort */
      if (rmt->peer.port)
	return SESSION_E_PORTINUSE;

      /* Try to find a port that's not used */
      while (udp_is_valid_dst_port (lcl_port, rmt->is_ip4))
	{
	  lcl_port = transport_alloc_local_port (TRANSPORT_PROTO_UDP,
						 &lcl_addr);
	  if (lcl_port < 1)
	    return SESSION_E_PORTINUSE;
	}
    }

conn_alloc:

  udp_connection_register_port (vm, lcl_port, rmt->is_ip4);

  /* We don't poll main thread if we have workers */
  thread_index = transport_cl_thread ();

  uc = udp_connection_alloc (thread_index);
  ip_copy (&uc->c_rmt_ip, &rmt->ip, rmt->is_ip4);
  ip_copy (&uc->c_lcl_ip, &lcl_addr, rmt->is_ip4);
  uc->c_rmt_port = rmt->port;
  uc->c_lcl_port = clib_host_to_net_u16 (lcl_port);
  uc->c_is_ip4 = rmt->is_ip4;
  uc->c_proto = TRANSPORT_PROTO_UDP;
  uc->c_fib_index = rmt->fib_index;
  uc->c_dscp = rmt->dscp;
  uc->mss = rmt->mss ? rmt->mss : udp_default_mtu (um, uc->c_is_ip4);
  uc->flags |= UDP_CONN_F_OWNS_PORT;
  if (rmt->transport_flags & TRANSPORT_CFG_F_CONNECTED)
    {
      uc->flags |= UDP_CONN_F_CONNECTED;
    }
  else
    {
      clib_spinlock_init (&uc->rx_lock);
      uc->c_flags |= TRANSPORT_CONNECTION_F_CLESS;
    }

  return uc->c_c_index;
}

static transport_connection_t *
udp_session_get_half_open (u32 conn_index)
{
  udp_connection_t *uc;
  u32 thread_index;

  /* We don't poll main thread if we have workers */
  thread_index = transport_cl_thread ();
  uc = udp_connection_get (conn_index, thread_index);
  if (!uc)
    return 0;
  return &uc->connection;
}

static u8 *
format_udp_session (u8 * s, va_list * args)
{
  u32 uci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  udp_connection_t *uc;

  uc = udp_connection_get (uci, thread_index);
  return format (s, "%U", format_udp_connection, uc, verbose);
}

static u8 *
format_udp_half_open_session (u8 * s, va_list * args)
{
  u32 __clib_unused tci = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  clib_warning ("BUG");
  return 0;
}

static u8 *
format_udp_listener_session (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  udp_connection_t *uc = udp_listener_get (tci);
  return format (s, "%U", format_udp_connection, uc, verbose);
}

/* *INDENT-OFF* */
static const transport_proto_vft_t udp_proto = {
  .start_listen = udp_session_bind,
  .connect = udp_open_connection,
  .stop_listen = udp_session_unbind,
  .push_header = udp_push_header,
  .get_connection = udp_session_get,
  .get_listener = udp_session_get_listener,
  .get_half_open = udp_session_get_half_open,
  .close = udp_session_close,
  .cleanup = udp_session_cleanup,
  .send_params = udp_session_send_params,
  .format_connection = format_udp_session,
  .format_half_open = format_udp_half_open_session,
  .format_listener = format_udp_listener_session,
  .transport_options = {
    .name = "udp",
    .short_name = "U",
    .tx_type = TRANSPORT_TX_DGRAM,
    .service_type = TRANSPORT_SERVICE_CL,
  },
};
/* *INDENT-ON* */

static clib_error_t *
udp_init (vlib_main_t * vm)
{
  udp_main_t *um = vnet_get_udp_main ();
  ip_main_t *im = &ip_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 num_threads;
  ip_protocol_info_t *pi;
  int i;

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
  transport_register_protocol (TRANSPORT_PROTO_UDP, &udp_proto,
			       FIB_PROTOCOL_IP4, ip4_lookup_node.index);
  transport_register_protocol (TRANSPORT_PROTO_UDP, &udp_proto,
			       FIB_PROTOCOL_IP6, ip6_lookup_node.index);

  /*
   * Initialize data structures
   */

  num_threads = 1 /* main thread */  + tm->n_threads;
  vec_validate (um->connections, num_threads - 1);
  vec_validate (um->connection_peekers, num_threads - 1);
  vec_validate (um->peekers_readers_locks, num_threads - 1);
  vec_validate (um->peekers_write_locks, num_threads - 1);

  if (num_threads > 1)
    for (i = 0; i < num_threads; i++)
      {
	clib_spinlock_init (&um->peekers_readers_locks[i]);
	clib_spinlock_init (&um->peekers_write_locks[i]);
      }

  um->local_to_input_edge[UDP_IP4] =
    vlib_node_add_next (vm, udp4_local_node.index, udp4_input_node.index);
  um->local_to_input_edge[UDP_IP6] =
    vlib_node_add_next (vm, udp6_local_node.index, udp6_input_node.index);

  um->default_mtu = 1500;
  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (udp_init) =
{
  .runs_after = VLIB_INITS("ip_main_init", "ip4_lookup_init",
                           "ip6_lookup_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
