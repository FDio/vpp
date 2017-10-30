/*
 * Copyright (c) 2017 SUSE LLC.
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
#include "sctp.h"

sctp_main_t sctp_main;

static u32
sctp_connection_bind (u32 session_index, transport_endpoint_t * tep)
{
  return 0;
}

u32
sctp_session_bind (u32 session_index, transport_endpoint_t * tep)
{
  return sctp_connection_bind (session_index, tep);
}

static void
sctp_connection_unbind (u32 listener_index)
{
  return;
}

u32
sctp_session_unbind (u32 listener_index)
{
  sctp_connection_unbind (listener_index);
  return 0;
}

int
sctp_session_open (transport_endpoint_t * tep)
{
  return 0;
}

void
sctp_session_close (u32 conn_index, u32 thread_index)
{

}

void
sctp_session_cleanup (u32 conn_index, u32 thread_index)
{

}

u16
sctp_session_send_mss (transport_connection_t * trans_conn)
{
  return 0;
}

u32
sctp_session_send_space (transport_connection_t * trans_conn)
{
  return 0;
}

u32
sctp_session_tx_fifo_offset (transport_connection_t * trans_conn)
{
  return 0;
}

transport_connection_t *
sctp_session_get_transport (u32 conn_index, u32 thread_index)
{
  return NULL;
}

transport_connection_t *
sctp_session_get_listener (u32 listener_index)
{
  return NULL;
}

transport_connection_t *
sctp_half_open_session_get_transport (u32 conn_index)
{
  return NULL;
}

u8 *
format_sctp_session (u8 * s, va_list * args)
{
  return NULL;
}

u8 *
format_sctp_listener_session (u8 * s, va_list * args)
{
  return NULL;
}

u8 *
format_sctp_half_open_session (u8 * s, va_list * args)
{
  return NULL;
}

u32
sctp_push_header (transport_connection_t * tconn, vlib_buffer_t * b)
{
  /* TODO: implement logic with congestion avoidance */
  return 0;
}

/* *INDENT OFF* */
const static transport_proto_vft_t sctp_proto = {
  .bind = sctp_session_bind,
  .unbind = sctp_session_unbind,
  .open = sctp_session_open,
  .close = sctp_session_close,
  .cleanup = sctp_session_cleanup,
  .push_header = sctp_push_header,
  .send_mss = sctp_session_send_mss,
  .send_space = sctp_session_send_space,
  .tx_fifo_offset = sctp_session_tx_fifo_offset,
  .get_connection = sctp_session_get_transport,
  .get_listener = sctp_session_get_listener,
  .get_half_open = sctp_half_open_session_get_transport,
  .format_connection = format_sctp_session,
  .format_listener = format_sctp_listener_session,
  .format_half_open = format_sctp_half_open_session,
};

/* *INDENT ON* */

static void
sctp_expired_timers_dispatch (u32 * expired_timers)
{

}

void
sctp_initialize_timer_wheels (sctp_main_t * tm)
{
  tw_timer_wheel_16t_2w_512sl_t *tw;
  /* *INDENT-OFF* */
  foreach_vlib_main (({
    tw = &tm->timer_wheels[ii];
    tw_timer_wheel_init_16t_2w_512sl (tw, sctp_expired_timers_dispatch,
				      100e-3 /* timer period 100ms */ , ~0);
    tw->last_run_time = vlib_time_now (this_vlib_main);
  }));
  /* *INDENT-ON* */
}

clib_error_t *
sctp_main_enable (vlib_main_t * vm)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  ip_protocol_info_t *pi;
  ip_main_t *im = &ip_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  clib_error_t *error = 0;
  u32 num_threads;
  int thread;
  sctp_connection_t *tc __attribute__ ((unused));
  u32 preallocated_connections_per_thread;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;
  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;
  if ((error = vlib_call_init_function (vm, ip6_lookup_init)))
    return error;

  /*
   * Registrations
   */

  /* Register with IP */
  pi = ip_get_protocol_info (im, IP_PROTOCOL_SCTP);
  if (pi == 0)
    return clib_error_return (0, "SCTP protocol info AWOL");
  pi->format_header = format_tcp_header;
  pi->unformat_pg_edit = unformat_pg_tcp_header;

  ip4_register_protocol (IP_PROTOCOL_SCTP, sctp4_input_node.index);
  ip6_register_protocol (IP_PROTOCOL_SCTP, sctp6_input_node.index);

  /* Register as transport with session layer */
  transport_register_protocol (TRANSPORT_PROTO_TCP, 1, &sctp_proto);
  transport_register_protocol (TRANSPORT_PROTO_TCP, 0, &sctp_proto);

  /*
   * Initialize data structures
   */

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (tm->connections, num_threads - 1);

  /*
   * Preallocate connections. Assume that thread 0 won't
   * use preallocated threads when running multi-core
   */
  if (num_threads == 1)
    {
      thread = 0;
      preallocated_connections_per_thread = tm->preallocated_connections;
    }
  else
    {
      thread = 1;
      preallocated_connections_per_thread =
	tm->preallocated_connections / (num_threads - 1);
    }
  for (; thread < num_threads; thread++)
    {
      if (preallocated_connections_per_thread)
	pool_init_fixed (tm->connections[thread],
			 preallocated_connections_per_thread);
    }

  /*
   * Use a preallocated half-open connection pool?
   */
  if (tm->preallocated_half_open_connections)
    pool_init_fixed (tm->half_open_connections,
		     tm->preallocated_half_open_connections);

  /* Initialize per worker thread tx buffers (used for control messages) */
  vec_validate (tm->tx_buffers, num_threads - 1);

  /* Initialize timer wheels */
  vec_validate (tm->timer_wheels, num_threads - 1);
  sctp_initialize_timer_wheels (tm);

  /* Initialize clocks per tick for TCP timestamp. Used to compute
   * monotonically increasing timestamps. */
  tm->tstamp_ticks_per_clock = vm->clib_time.seconds_per_clock
    / SCTP_TSTAMP_RESOLUTION;

  if (num_threads > 1)
    {
      clib_spinlock_init (&tm->half_open_lock);
    }

  vec_validate (tm->tx_frames[0], num_threads - 1);
  vec_validate (tm->tx_frames[1], num_threads - 1);
  vec_validate (tm->ip_lookup_tx_frames[0], num_threads - 1);
  vec_validate (tm->ip_lookup_tx_frames[1], num_threads - 1);

  tm->bytes_per_buffer = vlib_buffer_free_list_buffer_size
    (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  vec_validate (tm->time_now, num_threads - 1);
  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
