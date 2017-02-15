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

#include <vnet/tcp/tcp.h>
#include <vnet/uri/uri_db.h>
#include <vnet/fib/fib.h>
#include <math.h>

tcp_main_t tcp_main;

static u32
tcp_uri_bind (vlib_main_t *vm, u32 session_index, ip46_address_t *ip,
              u16 port_host_byte_order, u8 is_ip4)
{
  tcp_main_t * tm = vnet_get_tcp_main ();
  tcp_connection_t * l;

  pool_get(tm->listener_pool, l);
  memset(l, 0, sizeof(*l));

  l->c_c_index = l - tm->listener_pool;
  l->c_lcl_port = clib_host_to_net_u16 (port_host_byte_order);

  if (is_ip4)
    l->c_lcl_ip4.as_u32 = ip->ip4.as_u32;
  else
    clib_memcpy (&l->c_lcl_ip6, &ip->ip6, sizeof(ip6_address_t));

  l->c_s_index = session_index;
  l->c_proto = SESSION_TYPE_IP4_TCP;
  l->state = TCP_CONNECTION_STATE_LISTEN;
  l->c_is_ip4 = 1;

  return l->c_c_index;
}

u32
tcp_uri_bind_ip4 (vlib_main_t * vm, u32 session_index, ip46_address_t *ip,
                  u16 port_host_byte_order)
{
  return tcp_uri_bind (vm, session_index, ip, port_host_byte_order, 1);
}

u32
tcp_uri_bind_ip6 (vlib_main_t * vm, u32 session_index, ip46_address_t *ip,
                  u16 port_host_byte_order)
{
  return tcp_uri_bind (vm, session_index, ip, port_host_byte_order, 0);

}

static void
tcp_uri_unbind (u32 listener_index)
{
  tcp_main_t * tm = vnet_get_tcp_main ();
  pool_put_index (tm->listener_pool, listener_index);
}

u32
tcp_uri_unbind_ip4 (vlib_main_t * vm, u32 listener_index)
{
  tcp_uri_unbind (listener_index);
  return 0;
}

u32
tcp_uri_unbind_ip6 (vlib_main_t * vm, u32 listener_index)
{
  tcp_uri_unbind (listener_index);
  return 0;
}

transport_connection_t *
tcp_uri_session_get_listener (u32 listener_index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc;
  tc = pool_elt_at_index (tm->listener_pool, listener_index);
  return &tc->connection;
}

/**
 * Actively close a connection
 */
void
tcp_connection_close (tcp_main_t *tm, tcp_connection_t *tc)
{
  u32 tepi;
  transport_endpoint_t *tep;

  /* Send FIN if needed */
  if (tc->state == TCP_CONNECTION_STATE_ESTABLISHED
      || tc->state == TCP_CONNECTION_STATE_SYN_RCVD
      || TCP_CONNECTION_STATE_CLOSE_WAIT)
    tcp_send_fin (tc);

  /* Switch state */
  if (tc->state == TCP_CONNECTION_STATE_ESTABLISHED
      || tc->state == TCP_CONNECTION_STATE_SYN_RCVD)
    tc->state = TCP_CONNECTION_STATE_FIN_WAIT_1;
  else if (tc->state == TCP_CONNECTION_STATE_SYN_SENT)
    tc->state = TCP_CONNECTION_STATE_CLOSED;
  else if (tc->state == TCP_CONNECTION_STATE_CLOSE_WAIT)
    tc->state = TCP_CONNECTION_STATE_LAST_ACK;

  /* Half-close connections are not supported XXX */

  /* Cleanup local endpoint if this was an active connect */
  tepi = transport_endpoint_lookup (&tm->local_endpoints_table, &tc->c_lcl_ip,
                                   tc->c_lcl_port);

  /*XXX lock */
  if (tepi != TRANSPORT_ENDPOINT_INVALID_INDEX)
    {
      tep = pool_elt_at_index (tm->local_endpoints, tepi);
      transport_endpoint_table_del (&tm->local_endpoints_table, tep);
      pool_put (tm->local_endpoints, tep);
    }

  /* If half-open, deallocate temporary connection XXX*/

  /* Deallocate connection */
  pool_put (tm->connections[tc->c_thread_index], tc);
}

/**
 * Close a connection due to an error (e.g., too many retransmits)
 */
void
tcp_connection_drop (tcp_main_t *tm, tcp_connection_t *tc)
{
  clib_warning ("TODO");
}

void
tcp_connection_delete_uri (u32 conn_index, u32 thread_index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc;
  tc = tcp_connection_get (conn_index, thread_index);
  tcp_connection_close (tm, tc);
}

void *
ip_interface_get_first_ip (u32 sw_if_index, u8 is_ip4)
{
  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
  ip_interface_address_t *ia = 0;

  if (is_ip4)
    {
      foreach_ip_interface_address (lm4, ia, sw_if_index, 1 /* unnumbered */,
        ({
          return ip_interface_address_get_address (lm4, ia);
        }));
    }
  else
    {
      foreach_ip_interface_address (lm6, ia, sw_if_index, 1 /* unnumbered */,
        ({
          return ip_interface_address_get_address (lm6, ia);
        }));
    }

  return 0;
}

/**
 * Allocate local port and add if successful add entry to local endpoint
 * table to mark the pair as used.
 */
u16
tcp_allocate_local_port (tcp_main_t *tm, ip46_address_t *ip)
{
  u8 unique = 0;
  transport_endpoint_t *tep;
  u32 time_now, tei;
  u16 min = 1024, max = 65535, tries; /* XXX configurable ?*/

  tries = max - min;
  time_now = tcp_time_now ();

  /* Start at random point or max */
  pool_get (tm->local_endpoints, tep);
  clib_memcpy (&tep->ip, ip, sizeof (*ip));
  tep->port = random_u32 (&time_now) << 16;
  tep->port = tep->port < min ? max : tep->port;

  /* Search for first free slot */
  while (tries)
    {
      tei = transport_endpoint_lookup (&tm->local_endpoints_table, &tep->ip,
                                       tep->port);
      if (tei == TRANSPORT_ENDPOINT_INVALID_INDEX)
        {
          unique = 1;
          break;
        }

      tep->port--;

      if (tep->port < min)
        tep->port = max;

      tries--;
    }

  if (unique)
    {
      transport_endpoint_table_add (&tm->local_endpoints_table, tep,
                                    tep - tm->local_endpoints);

      return tep->port;
    }

  /* Failed */
  pool_put (tm->local_endpoints, tep);
  return -1;
}

void
tcp_timers_init (tcp_connection_t *tc)
{
  int i;

  /* Set all to invalid */
  for (i = 0; i < TCP_N_TIMERS; i++)
    {
      tc->timers[i] = TCP_TIMER_HANDLE_INVALID;
    }

  tc->rto = TCP_RTO_INIT;
}

void
tcp_connection_init_vars (tcp_connection_t *tc)
{
  tcp_timers_init (tc);

  tc->sack_sb.head = TCP_INVALID_SACK_HOLE_INDEX;
}

int
tcp_connection_open (ip46_address_t *rmt_addr, u16 rmt_port, u8 is_ip4)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc;
  fib_prefix_t prefix;
  u32 fei, sw_if_index;
  ip46_address_t lcl_addr;
  u16 lcl_port;

  /*
   * Find the local address and allocate port
   */
  memset (&lcl_addr, 0, sizeof(lcl_addr));

  /* Find a FIB path to the destination */
  clib_memcpy (&prefix.fp_addr, rmt_addr, sizeof(*rmt_addr));
  prefix.fp_proto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  prefix.fp_len = is_ip4 ? 32: 128;

  fei = fib_table_lookup (0, &prefix);

  /* Couldn't find route to destination. Bail out. */
  if (fei == FIB_NODE_INDEX_INVALID)
    return -1;

  sw_if_index = fib_entry_get_resolving_interface (fei);

  if (sw_if_index == (u32)~0)
    return -1;

  if (is_ip4)
    {
      ip4_address_t *ip4;
      ip4 = ip_interface_get_first_ip (sw_if_index, 1);
      lcl_addr.ip4.as_u32 = ip4->as_u32;
    }
  else
    {
      ip6_address_t *ip6;
      ip6 = ip_interface_get_first_ip (sw_if_index, 0);
      clib_memcpy (&lcl_addr.ip6, ip6, sizeof (*ip6));
    }

  /* Allocate source port */
  lcl_port = tcp_allocate_local_port (tm, &lcl_addr);
  if (lcl_port < 1)
    return -1;

  /*
   * Create connection and send SYN
   */

  pool_get (tm->half_open_connections, tc);
  memset (tc, 0, sizeof (*tc));

  clib_memcpy (&tc->c_rmt_ip, rmt_addr, sizeof (ip46_address_t));
  clib_memcpy (&tc->c_lcl_ip, &lcl_addr, sizeof (ip46_address_t));
  tc->c_rmt_port = clib_host_to_net_u16 (rmt_port);
  tc->c_lcl_port = clib_host_to_net_u16 (lcl_port);
  tc->c_c_index = tc - tm->half_open_connections;
  tc->c_is_ip4 = is_ip4;

  tcp_connection_init_vars (tc);

  tcp_send_syn (tc);

  tc->state = TCP_CONNECTION_STATE_SYN_SENT;

  return tc->c_c_index;
}

int
tcp_connection_open_ip4 (ip46_address_t *addr, u16 port)
{
  return tcp_connection_open (addr, port, 1);
}

int
tcp_connection_open_ip6 (ip46_address_t *addr, u16 port)
{
  return tcp_connection_open (addr, port, 0);
}

u8*
format_tcp_stream_session_ip4 (u8 *s, va_list *args)
{
  u32 tci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  tcp_connection_t *tc;

  tc = tcp_connection_get (tci, thread_index);

  s = format (s, "%-20U%-20U%-10d%-10d%-8s", format_ip4_address,
              &tc->c_lcl_ip4, format_ip4_address, &tc->c_rmt_ip4,
              clib_net_to_host_u16 (tc->c_lcl_port),
              clib_net_to_host_u16 (tc->c_rmt_port), "tcp");

  return s;
}

u8*
format_tcp_stream_session_ip6 (u8 *s, va_list *args)
{
  u32 tci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  tcp_connection_t *tc;

  tc = tcp_connection_get (tci, thread_index);

  s = format (s, "%-20U%-20U%-10d%-10d%-8s", format_ip6_address,
              &tc->c_lcl_ip6, format_ip6_address, &tc->c_rmt_ip6,
              clib_net_to_host_u16 (tc->c_lcl_port),
              clib_net_to_host_u16 (tc->c_rmt_port), "tcp");

  return s;
}

transport_connection_t *
tcp_uri_connection_get (u32 conn_index, u32 thread_index)
{
  tcp_connection_t *tc = tcp_connection_get (conn_index, thread_index);
  return &tc->connection;
}

transport_connection_t *
tcp_half_open_connection_get_uri (u32 conn_index)
{
  tcp_connection_t *tc = tcp_half_open_connection_get (conn_index);
  return &tc->connection;
}

u16
tcp_send_mss_uri (transport_connection_t *trans_conn)
{
  tcp_connection_t *tc = (tcp_connection_t *)trans_conn;
  return tcp_snd_mss (tc);
}

u32
tcp_rx_fifo_offset_uri (transport_connection_t *trans_conn)
{
  tcp_connection_t *tc = (tcp_connection_t *)trans_conn;
  return (tc->snd_una_max - tc->snd_una);
}

const static transport_proto_vft_t tcp4_proto = {
  .bind = tcp_uri_bind_ip4,
  .unbind = tcp_uri_unbind_ip4,
  .push_header = tcp_push_header_uri,
  .get_connection = tcp_uri_connection_get,
  .get_listener = tcp_uri_session_get_listener,
  .get_half_open = tcp_half_open_connection_get_uri,
  .delete = tcp_connection_delete_uri,
  .open = tcp_connection_open_ip4,
  .send_mss = tcp_send_mss_uri,
  .rx_fifo_offset = tcp_rx_fifo_offset_uri,
  .format_connection = format_tcp_stream_session_ip4
};

const static transport_proto_vft_t tcp6_proto = {
  .bind = tcp_uri_bind_ip6,
  .unbind = tcp_uri_unbind_ip6,
  .push_header = tcp_push_header_uri,
  .get_connection = tcp_uri_connection_get,
  .get_listener = tcp_uri_session_get_listener,
  .get_half_open = tcp_half_open_connection_get_uri,
  .open = tcp_connection_open_ip6,
  .delete = tcp_connection_delete_uri,
  .send_mss = tcp_send_mss_uri,
  .rx_fifo_offset = tcp_rx_fifo_offset_uri,
  .format_connection = format_tcp_stream_session_ip6
};

void
tcp_timer_keep_handler (u32 conn_index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t * tc;
  u32 thread_index = tm->vlib_main->cpu_index;

  tc = tcp_connection_get (conn_index, thread_index);

  /* If SYN-SENT cleanup connection */
  if (tc->state == TCP_CONNECTION_STATE_SYN_SENT)
    {
      tcp_connection_close (tm, tc);
    }
}

/* *INDENT-OFF* */
static timer_expiration_handler *timer_expiration_handlers[TCP_N_TIMERS] =
{
    tcp_timer_retransmit_handler,
    tcp_timer_delack_handler,
    0,
    tcp_timer_keep_handler,
    0,
    tcp_timer_retransmit_syn_handler
};
/* *INDENT-ON* */

static void
tcp_expired_timers_dispatch (u32 *expired_timers)
{
  int i;
  u32 connection_index, timer_id;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      /* Get session index and timer id */
      connection_index = expired_timers[i] & 0x0FFFFFFF;
      timer_id = expired_timers[i] >> 28;

      /* Handle expiration */
      (*timer_expiration_handlers[timer_id]) (connection_index);
    }
}

void
tcp_initialize_timer_wheels (tcp_main_t *tm)
{
  tw_timer_wheel_16t_2w_512sl_t *tw;
  vec_foreach (tw, tm->timer_wheels)
  {
    tw_timer_wheel_init_16t_2w_512sl (tw, tcp_expired_timers_dispatch, 
                                       100e-3 /* timer period 100ms */);
    tw->last_run_time = vlib_time_now (tm->vlib_main);
  }
}

clib_error_t *
tcp_init (vlib_main_t * vm)
{
  ip_main_t * im = &ip_main;
  ip_protocol_info_t * pi;
  tcp_main_t *tm = vnet_get_tcp_main ();
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  clib_error_t * error = 0;
  f64 log2 = .69314718055994530941;
  u32 num_threads;

  tm->vlib_main = vm;
  tm->vnet_main = vnet_get_main ();
  tm->sm_main = vnet_get_session_manager_main ();

  if ((error = vlib_call_init_function(vm, ip_main_init)))
    return error;
  if ((error = vlib_call_init_function(vm, ip4_lookup_init)))
    return error;
  if ((error = vlib_call_init_function(vm, ip6_lookup_init)))
    return error;

  /*
   * Registrations
   */

  /* Register with IP */
  pi = ip_get_protocol_info (im, IP_PROTOCOL_TCP);
  if (pi == 0)
      return clib_error_return (0, "TCP protocol info AWOL");
  pi->format_header = format_tcp_header;
  pi->unformat_pg_edit = unformat_pg_tcp_header;

  ip4_register_protocol (IP_PROTOCOL_TCP, tcp4_input_node.index);

  /* Register as transport with URI */
  uri_register_transport (SESSION_TYPE_IP4_TCP, &tcp4_proto);
  uri_register_transport (SESSION_TYPE_IP6_TCP, &tcp6_proto);

  /*
   * Initialize data structures
   */

  num_threads = 1 /* main thread */ + vtm->n_threads;
  vec_validate (tm->connections, num_threads - 1);

  /* Initialize per worker thread tx buffers (used for control messages) */
  vec_validate (tm->tx_buffers, num_threads - 1);

  /* Initialize timer wheels */
  vec_validate (tm->timer_wheels, num_threads - 1);
  tcp_initialize_timer_wheels (tm);

  vec_validate (tm->delack_connections, num_threads - 1);

  /* Initialize clocks per tick for TCP timestamp. Used to compute
   * monotonically increasing timestamps. */
  tm->log2_tstamp_clocks_per_tick = flt_round_nearest (
      log (TCP_TSTAMP_RESOLUTION / vm->clib_time.seconds_per_clock) / log2);

  clib_bihash_init_24_8 (&tm->local_endpoints_table, "local endpoint table",
                         200000 /* $$$$ config parameter nbuckets */,
                         (64<<20) /*$$$ config parameter table size */);

  return error;
}

VLIB_INIT_FUNCTION (tcp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
