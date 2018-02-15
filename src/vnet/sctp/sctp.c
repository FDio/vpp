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
#include <vnet/sctp/sctp.h>
#include <vnet/sctp/sctp_debug.h>

sctp_main_t sctp_main;

static u32
sctp_connection_bind (u32 session_index, transport_endpoint_t * tep)
{
  sctp_main_t *tm = &sctp_main;
  sctp_connection_t *listener;
  void *iface_ip;

  pool_get (tm->listener_pool, listener);
  memset (listener, 0, sizeof (*listener));

  listener->sub_conn[MAIN_SCTP_SUB_CONN_IDX].parent = listener;
  listener->sub_conn[MAIN_SCTP_SUB_CONN_IDX].c_c_index =
    listener - tm->listener_pool;
  listener->sub_conn[MAIN_SCTP_SUB_CONN_IDX].connection.lcl_port = tep->port;

  /* If we are provided a sw_if_index, bind using one of its IPs */
  if (ip_is_zero (&tep->ip, 1) && tep->sw_if_index != ENDPOINT_INVALID_INDEX)
    {
      if ((iface_ip = ip_interface_get_first_ip (tep->sw_if_index,
						 tep->is_ip4)))
	ip_set (&tep->ip, iface_ip, tep->is_ip4);
    }
  ip_copy (&listener->sub_conn[MAIN_SCTP_SUB_CONN_IDX].connection.lcl_ip,
	   &tep->ip, tep->is_ip4);

  listener->sub_conn[MAIN_SCTP_SUB_CONN_IDX].connection.is_ip4 = tep->is_ip4;
  listener->sub_conn[MAIN_SCTP_SUB_CONN_IDX].connection.proto =
    TRANSPORT_PROTO_SCTP;
  listener->sub_conn[MAIN_SCTP_SUB_CONN_IDX].c_s_index = session_index;
  listener->sub_conn[MAIN_SCTP_SUB_CONN_IDX].connection.fib_index =
    tep->fib_index;
  listener->state = SCTP_STATE_CLOSED;

  sctp_connection_timers_init (listener);

  return listener->sub_conn[MAIN_SCTP_SUB_CONN_IDX].c_c_index;
}

u32
sctp_session_bind (u32 session_index, transport_endpoint_t * tep)
{
  return sctp_connection_bind (session_index, tep);
}

static void
sctp_connection_unbind (u32 listener_index)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  sctp_connection_t *sctp_conn;

  sctp_conn = pool_elt_at_index (tm->listener_pool, listener_index);

  /* Poison the entry */
  if (CLIB_DEBUG > 0)
    memset (sctp_conn, 0xFA, sizeof (*sctp_conn));

  pool_put_index (tm->listener_pool, listener_index);
}

u32
sctp_session_unbind (u32 listener_index)
{
  sctp_connection_unbind (listener_index);
  return 0;
}

void
sctp_punt_unknown (vlib_main_t * vm, u8 is_ip4, u8 is_add)
{
  sctp_main_t *tm = &sctp_main;
  if (is_ip4)
    tm->punt_unknown4 = is_add;
  else
    tm->punt_unknown6 = is_add;
}

static int
sctp_alloc_custom_local_endpoint (sctp_main_t * tm, ip46_address_t * lcl_addr,
				  u16 * lcl_port, u8 is_ip4)
{
  int index, port;
  if (is_ip4)
    {
      index = tm->last_v4_address_rotor++;
      if (tm->last_v4_address_rotor >= vec_len (tm->ip4_src_addresses))
	tm->last_v4_address_rotor = 0;
      lcl_addr->ip4.as_u32 = tm->ip4_src_addresses[index].as_u32;
    }
  else
    {
      index = tm->last_v6_address_rotor++;
      if (tm->last_v6_address_rotor >= vec_len (tm->ip6_src_addresses))
	tm->last_v6_address_rotor = 0;
      clib_memcpy (&lcl_addr->ip6, &tm->ip6_src_addresses[index],
		   sizeof (ip6_address_t));
    }
  port = transport_alloc_local_port (TRANSPORT_PROTO_SCTP, lcl_addr);
  if (port < 1)
    {
      clib_warning ("Failed to allocate src port");
      return -1;
    }
  *lcl_port = port;
  return 0;
}

/**
 * Initialize all connection timers as invalid
 */
void
sctp_connection_timers_init (sctp_connection_t * sctp_conn)
{
  int i, j;

  /* Set all to invalid */
  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    {
      sctp_conn->sub_conn[i].RTO = SCTP_RTO_INIT;

      for (j = 0; j < SCTP_N_TIMERS; j++)
	{
	  sctp_conn->sub_conn[i].timers[j] = SCTP_TIMER_HANDLE_INVALID;
	}
    }
}

/**
 * Stop all connection timers
 */
void
sctp_connection_timers_reset (sctp_connection_t * sctp_conn)
{
  int i, j;
  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    {
      for (j = 0; j < SCTP_N_TIMERS; j++)
	sctp_timer_reset (sctp_conn, i, j);
    }
}

const char *sctp_fsm_states[] = {
#define _(sym, str) str,
  foreach_sctp_fsm_state
#undef _
};

u8 *
format_sctp_state (u8 * s, va_list * args)
{
  u32 state = va_arg (*args, u32);

  if (state < SCTP_N_STATES)
    s = format (s, "%s", sctp_fsm_states[state]);
  else
    s = format (s, "UNKNOWN (%d (0x%x))", state, state);
  return s;
}

u8 *
format_sctp_connection_id (u8 * s, va_list * args)
{
  /*
     sctp_connection_t *sctp_conn = va_arg (*args, sctp_connection_t *);
     if (!sctp_conn)
     return s;
     if (sctp_conn->c_is_ip4)
     {
     s = format (s, "[#%d][%s] %U:%d->%U:%d", sctp_conn->c_thread_index, "T",
     format_ip4_address, &sctp_conn->c_lcl_ip4,
     clib_net_to_host_u16 (sctp_conn->c_lcl_port), format_ip4_address,
     &sctp_conn->c_rmt_ip4, clib_net_to_host_u16 (sctp_conn->c_rmt_port));
     }
     else
     {
     s = format (s, "[#%d][%s] %U:%d->%U:%d", sctp_conn->c_thread_index, "T",
     format_ip6_address, &sctp_conn->c_lcl_ip6,
     clib_net_to_host_u16 (sctp_conn->c_lcl_port), format_ip6_address,
     &sctp_conn->c_rmt_ip6, clib_net_to_host_u16 (sctp_conn->c_rmt_port));
     }
   */
  return s;
}

u8 *
format_sctp_connection (u8 * s, va_list * args)
{
  sctp_connection_t *sctp_conn = va_arg (*args, sctp_connection_t *);
  u32 verbose = va_arg (*args, u32);

  if (!sctp_conn)
    return s;
  s = format (s, "%-50U", format_sctp_connection_id, sctp_conn);
  if (verbose)
    {
      s = format (s, "%-15U", format_sctp_state, sctp_conn->state);
    }

  return s;
}

/**
 * Initialize connection send variables.
 */
void
sctp_init_snd_vars (sctp_connection_t * sctp_conn)
{
  u32 time_now;
  /*
   * We use the time to randomize iss and for setting up the initial
   * timestamp. Make sure it's updated otherwise syn and ack in the
   * handshake may make it look as if time has flown in the opposite
   * direction for us.
   */

  sctp_set_time_now (vlib_get_thread_index ());
  time_now = sctp_time_now ();

  sctp_conn->local_initial_tsn = random_u32 (&time_now);
  sctp_conn->remote_initial_tsn = 0x0;
  sctp_conn->last_rcvd_tsn = sctp_conn->remote_initial_tsn;
  sctp_conn->next_tsn = sctp_conn->local_initial_tsn + 1;
}

/**
 * Update max segment size we're able to process.
 *
 * The value is constrained by our interface's MTU and IP options. It is
 * also what we advertise to our peer.
 */
void
sctp_update_rcv_mss (sctp_connection_t * sctp_conn)
{
  sctp_conn->smallest_PMTU = DEFAULT_A_RWND;	/* TODO find our iface MTU */
  sctp_conn->a_rwnd = DEFAULT_A_RWND - sizeof (sctp_full_hdr_t);
  sctp_conn->rcv_opts.a_rwnd = sctp_conn->a_rwnd;
  sctp_conn->rcv_a_rwnd = sctp_conn->a_rwnd;	/* This will be updated by our congestion algos */
}

void
sctp_init_mss (sctp_connection_t * sctp_conn)
{
  SCTP_DBG ("CONN_INDEX = %u",
	    sctp_conn->sub_conn[MAIN_SCTP_SUB_CONN_IDX].connection.c_index);

  u16 default_a_rwnd = 536;
  sctp_update_rcv_mss (sctp_conn);

  /* TODO cache mss and consider PMTU discovery */
  sctp_conn->snd_a_rwnd =
    clib_min (sctp_conn->rcv_opts.a_rwnd, sctp_conn->a_rwnd);

  if (sctp_conn->snd_a_rwnd < sizeof (sctp_full_hdr_t))
    {
      SCTP_ADV_DBG ("sctp_conn->snd_a_rwnd < sizeof(sctp_full_hdr_t)");
      /* Assume that at least the min default mss works */
      sctp_conn->snd_a_rwnd = default_a_rwnd;
      sctp_conn->rcv_opts.a_rwnd = default_a_rwnd;
    }

  ASSERT (sctp_conn->snd_a_rwnd > sizeof (sctp_full_hdr_t));
}

always_inline sctp_connection_t *
sctp_sub_connection_add (u8 thread_index)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  sctp_connection_t *sctp_conn = tm->connections[thread_index];

  sctp_conn->sub_conn[sctp_conn->next_avail_sub_conn].connection.c_index =
    sctp_conn->sub_conn[MAIN_SCTP_SUB_CONN_IDX].connection.c_index;
  sctp_conn->sub_conn[sctp_conn->next_avail_sub_conn].
    connection.thread_index = thread_index;
  sctp_conn->sub_conn[sctp_conn->next_avail_sub_conn].parent = sctp_conn;

  sctp_conn->next_avail_sub_conn += 1;

  return sctp_conn;
}

void
sctp_sub_connection_add_ip4 (u8 thread_index,
			     sctp_ipv4_addr_param_t * ipv4_addr)
{
  sctp_connection_t *sctp_conn = sctp_sub_connection_add (thread_index);

  clib_memcpy (&sctp_conn->
	       sub_conn[sctp_conn->next_avail_sub_conn].connection.lcl_ip.ip4,
	       &ipv4_addr->address, sizeof (ipv4_addr->address));
}

void
sctp_sub_connection_add_ip6 (u8 thread_index,
			     sctp_ipv6_addr_param_t * ipv6_addr)
{
  sctp_connection_t *sctp_conn = sctp_sub_connection_add (thread_index);

  clib_memcpy (&sctp_conn->
	       sub_conn[sctp_conn->next_avail_sub_conn].connection.lcl_ip.ip6,
	       &ipv6_addr->address, sizeof (ipv6_addr->address));
}

sctp_connection_t *
sctp_connection_new (u8 thread_index)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  sctp_connection_t *sctp_conn;

  pool_get (tm->connections[thread_index], sctp_conn);
  memset (sctp_conn, 0, sizeof (*sctp_conn));
  sctp_conn->sub_conn[MAIN_SCTP_SUB_CONN_IDX].parent = sctp_conn;
  sctp_conn->sub_conn[MAIN_SCTP_SUB_CONN_IDX].c_c_index =
    sctp_conn - tm->connections[thread_index];
  sctp_conn->sub_conn[MAIN_SCTP_SUB_CONN_IDX].c_thread_index = thread_index;
  sctp_conn->local_tag = 0;
  sctp_conn->next_avail_sub_conn = 1;

  return sctp_conn;
}

sctp_connection_t *
sctp_half_open_connection_new (u8 thread_index)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  sctp_connection_t *sctp_conn = 0;
  ASSERT (vlib_get_thread_index () == 0);
  pool_get (tm->half_open_connections, sctp_conn);
  memset (sctp_conn, 0, sizeof (*sctp_conn));
  sctp_conn->sub_conn[MAIN_SCTP_SUB_CONN_IDX].c_c_index =
    sctp_conn - tm->half_open_connections;
  sctp_conn->sub_conn[MAIN_SCTP_SUB_CONN_IDX].parent = sctp_conn;
  return sctp_conn;
}

static inline int
sctp_connection_open (transport_endpoint_t * rmt)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  sctp_connection_t *sctp_conn;
  ip46_address_t lcl_addr;
  u16 lcl_port;
  uword thread_id;
  int rv;

  u8 idx = MAIN_SCTP_SUB_CONN_IDX;

  /*
   * Allocate local endpoint
   */
  if ((rmt->is_ip4 && vec_len (tm->ip4_src_addresses))
      || (!rmt->is_ip4 && vec_len (tm->ip6_src_addresses)))
    rv = sctp_alloc_custom_local_endpoint (tm, &lcl_addr, &lcl_port,
					   rmt->is_ip4);
  else
    rv = transport_alloc_local_endpoint (TRANSPORT_PROTO_SCTP,
					 rmt, &lcl_addr, &lcl_port);

  if (rv)
    return -1;

  /*
   * Create connection and send INIT CHUNK
   */
  thread_id = vlib_get_thread_index ();
  ASSERT (thread_id == 0);

  clib_spinlock_lock_if_init (&tm->half_open_lock);
  sctp_conn = sctp_half_open_connection_new (thread_id);

  transport_connection_t *trans_conn = &sctp_conn->sub_conn[idx].connection;
  ip_copy (&trans_conn->rmt_ip, &rmt->ip, rmt->is_ip4);
  ip_copy (&trans_conn->lcl_ip, &lcl_addr, rmt->is_ip4);
  sctp_conn->sub_conn[idx].parent = sctp_conn;
  trans_conn->rmt_port = rmt->port;
  trans_conn->lcl_port = clib_host_to_net_u16 (lcl_port);
  trans_conn->is_ip4 = rmt->is_ip4;
  trans_conn->proto = TRANSPORT_PROTO_SCTP;
  trans_conn->fib_index = rmt->fib_index;

  sctp_connection_timers_init (sctp_conn);
  /* The other connection vars will be initialized after INIT_ACK chunk received */
  sctp_init_snd_vars (sctp_conn);

  sctp_send_init (sctp_conn);

  clib_spinlock_unlock_if_init (&tm->half_open_lock);

  return sctp_conn->sub_conn[idx].connection.c_index;
}

/**
 * Cleans up connection state.
 *
 * No notifications.
 */
void
sctp_connection_cleanup (sctp_connection_t * sctp_conn)
{
  sctp_main_t *tm = &sctp_main;
  u8 i;

  /* Cleanup local endpoint if this was an active connect */
  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    transport_endpoint_cleanup (TRANSPORT_PROTO_SCTP,
				&sctp_conn->sub_conn[i].connection.lcl_ip,
				sctp_conn->sub_conn[i].connection.lcl_port);

  /* Check if connection is not yet fully established */
  if (sctp_conn->state == SCTP_STATE_COOKIE_WAIT)
    {

    }
  else
    {
      int thread_index =
	sctp_conn->sub_conn[MAIN_SCTP_SUB_CONN_IDX].connection.thread_index;

      /* Make sure all timers are cleared */
      sctp_connection_timers_reset (sctp_conn);

      /* Poison the entry */
      if (CLIB_DEBUG > 0)
	memset (sctp_conn, 0xFA, sizeof (*sctp_conn));
      pool_put (tm->connections[thread_index], sctp_conn);
    }
}

int
sctp_session_open (transport_endpoint_t * tep)
{
  return sctp_connection_open (tep);
}

u16
sctp_check_outstanding_data_chunks (sctp_connection_t * sctp_conn)
{
  u8 i;
  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    {
      if (sctp_conn->sub_conn[i].state == SCTP_SUBCONN_STATE_DOWN)
	continue;

      if (sctp_conn->sub_conn[i].is_retransmitting == 1 ||
	  sctp_conn->sub_conn[i].enqueue_state != SCTP_ERROR_ENQUEUED)
	{
	  SCTP_DBG_OUTPUT
	    ("Connection %u has still DATA to be enqueued inboud / outboud");
	  return 1;
	}

    }
  return 0;			/* Indicates no more data to be read/sent */
}

void
sctp_connection_close (sctp_connection_t * sctp_conn)
{
  SCTP_DBG ("Closing connection %u...",
	    sctp_conn->sub_conn[MAIN_SCTP_SUB_CONN_IDX].connection.c_index);

  sctp_conn->state = SCTP_STATE_SHUTDOWN_PENDING;

  sctp_send_shutdown (sctp_conn);
}

void
sctp_session_close (u32 conn_index, u32 thread_index)
{
  ASSERT (thread_index == 0);
  sctp_connection_t *sctp_conn;
  sctp_conn = sctp_connection_get (conn_index, thread_index);
  if (sctp_conn != NULL)
    sctp_connection_close (sctp_conn);
}

void
sctp_session_cleanup (u32 conn_index, u32 thread_index)
{
  sctp_connection_t *sctp_conn;
  sctp_conn = sctp_connection_get (conn_index, thread_index);

  if (sctp_conn != NULL)
    {
      sctp_connection_timers_reset (sctp_conn);
      /* Wait for the session tx events to clear */
      sctp_conn->state = SCTP_STATE_CLOSED;
    }
}

/**
 * Update snd_mss to reflect the effective segment size that we can send
 */
void
sctp_update_snd_mss (sctp_connection_t * sctp_conn)
{
  /* The overhead for the sctp_header_t and sctp_chunks_common_hdr_t
   * (the sum equals to sctp_full_hdr_t) is already taken into account
   * for the sctp_conn->a_rwnd computation.
   * So let's not account it again here.
   */
  sctp_conn->snd_hdr_length =
    sizeof (sctp_payload_data_chunk_t) - sizeof (sctp_full_hdr_t);
  sctp_conn->snd_a_rwnd =
    clib_min (sctp_conn->a_rwnd,
	      sctp_conn->rcv_opts.a_rwnd) - sctp_conn->snd_hdr_length;

  SCTP_DBG ("sctp_conn->snd_a_rwnd = %u, sctp_conn->snd_hdr_length = %u ",
	    sctp_conn->snd_a_rwnd, sctp_conn->snd_hdr_length);

  ASSERT (sctp_conn->snd_a_rwnd > 0);
}

u16
sctp_session_send_mss (transport_connection_t * trans_conn)
{
  SCTP_DBG ("CONN_INDEX: %u", trans_conn->c_index);

  sctp_connection_t *sctp_conn =
    sctp_get_connection_from_transport (trans_conn);

  if (trans_conn == NULL)
    {
      SCTP_DBG ("trans_conn == NULL");
      return 0;
    }

  if (sctp_conn == NULL)
    {
      SCTP_DBG ("sctp_conn == NULL");
      return 0;
    }
  /* Ensure snd_mss does accurately reflect the amount of data we can push
   * in a segment. This also makes sure that options are updated according to
   * the current state of the connection. */
  sctp_update_snd_mss (sctp_conn);

  return sctp_conn->snd_a_rwnd;
}

u16
sctp_snd_space (sctp_connection_t * sctp_conn)
{
  /* TODO: This requires a real implementation */
  if (sctp_conn == NULL)
    {
      SCTP_DBG ("sctp_conn == NULL");
      return 0;
    }

  if (sctp_conn->state != SCTP_STATE_ESTABLISHED)
    {
      SCTP_DBG_STATE_MACHINE
	("Trying to send DATA while not in SCTP_STATE_ESTABLISHED");
      return 0;
    }

  return sctp_conn->snd_a_rwnd;
}

u32
sctp_session_send_space (transport_connection_t * trans_conn)
{
  SCTP_DBG ("CONN_INDEX: %u", trans_conn->c_index);

  sctp_connection_t *sctp_conn =
    sctp_get_connection_from_transport (trans_conn);

  return sctp_snd_space (sctp_conn);
}

transport_connection_t *
sctp_session_get_transport (u32 conn_index, u32 thread_index)
{
  sctp_connection_t *sctp_conn =
    sctp_connection_get (conn_index, thread_index);
  return &sctp_conn->sub_conn[MAIN_SCTP_SUB_CONN_IDX].connection;
}

transport_connection_t *
sctp_session_get_listener (u32 listener_index)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  sctp_connection_t *sctp_conn;
  sctp_conn = pool_elt_at_index (tm->listener_pool, listener_index);
  return &sctp_conn->sub_conn[MAIN_SCTP_SUB_CONN_IDX].connection;
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

void
sctp_expired_timers_cb (u32 conn_index, u32 timer_id)
{
  sctp_connection_t *sctp_conn;

  sctp_conn = sctp_connection_get (conn_index, vlib_get_thread_index ());
  /* note: the connection may have already disappeared */
  if (PREDICT_FALSE (sctp_conn == 0))
    return;

  SCTP_DBG ("%s expired", sctp_timer_to_string (timer_id));

  switch (timer_id)
    {
    case SCTP_TIMER_T1_INIT:
    case SCTP_TIMER_T1_COOKIE:
    case SCTP_TIMER_T2_SHUTDOWN:
    case SCTP_TIMER_T3_RXTX:
      sctp_timer_reset (sctp_conn, conn_index, timer_id);
      break;
    case SCTP_TIMER_T4_HEARTBEAT:
      sctp_timer_reset (sctp_conn, conn_index, timer_id);
      goto heartbeat;
    }

  if (sctp_conn->sub_conn[conn_index].unacknowledged_hb >
      SCTP_PATH_MAX_RETRANS)
    {
      // The remote-peer is considered to be unreachable hence shutting down
      u8 i, total_subs_down = 1;
      for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
	{
	  if (sctp_conn->sub_conn[i].state == SCTP_SUBCONN_STATE_DOWN)
	    continue;

	  u32 now = sctp_time_now ();
	  if (now > (sctp_conn->sub_conn[i].last_seen + SCTP_HB_INTERVAL))
	    {
	      total_subs_down += 1;
	      sctp_conn->sub_conn[i].state = SCTP_SUBCONN_STATE_DOWN;
	    }
	}

      if (total_subs_down == MAX_SCTP_CONNECTIONS)
	{
	  /* Start cleanup. App wasn't notified yet so use delete notify as
	   * opposed to delete to cleanup session layer state. */
	  stream_session_delete_notify (&sctp_conn->sub_conn
					[MAIN_SCTP_SUB_CONN_IDX].connection);

	  sctp_connection_timers_reset (sctp_conn);

	  sctp_connection_cleanup (sctp_conn);
	}
    }
  return;

heartbeat:
  sctp_send_heartbeat (sctp_conn);
}

static void
sctp_expired_timers_dispatch (u32 * expired_timers)
{
  int i;
  u32 connection_index, timer_id;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      /* Get session index and timer id */
      connection_index = expired_timers[i] & 0x0FFFFFFF;
      timer_id = expired_timers[i] >> 28;

      SCTP_DBG ("Expired timer ID: %u", timer_id);

      /* Handle expiration */
      sctp_expired_timers_cb (connection_index, timer_id);
    }
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
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  clib_error_t *error = 0;
  u32 num_threads;
  int thread;
  sctp_connection_t *sctp_conn __attribute__ ((unused));
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

  ip4_register_protocol (IP_PROTOCOL_SCTP, sctp4_input_node.index);
  ip6_register_protocol (IP_PROTOCOL_SCTP, sctp6_input_node.index);

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

  /* Initialize per worker thread tx buffers (used for control messages) */
  vec_validate (tm->tx_buffers, num_threads - 1);

  /* Initialize timer wheels */
  vec_validate (tm->timer_wheels, num_threads - 1);
  sctp_initialize_timer_wheels (tm);

  /* Initialize clocks per tick for SCTP timestamp. Used to compute
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

clib_error_t *
sctp_enable_disable (vlib_main_t * vm, u8 is_en)
{
  if (is_en)
    {
      if (sctp_main.is_enabled)
	return 0;

      return sctp_main_enable (vm);
    }
  else
    {
      sctp_main.is_enabled = 0;
    }

  return 0;
}

transport_connection_t *
sctp_half_open_session_get_transport (u32 conn_index)
{
  sctp_connection_t *sctp_conn = sctp_half_open_connection_get (conn_index);
  return &sctp_conn->sub_conn[MAIN_SCTP_SUB_CONN_IDX].connection;
}

u8 *
format_sctp_half_open (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  sctp_connection_t *sctp_conn = sctp_half_open_connection_get (tci);
  return format (s, "%U", format_sctp_connection_id, sctp_conn);
}

void
sctp_update_time (f64 now, u8 thread_index)
{
  sctp_set_time_now (thread_index);
  tw_timer_expire_timers_16t_2w_512sl (&sctp_main.timer_wheels[thread_index],
				       now);
  sctp_flush_frames_to_output (thread_index);
}

/* *INDENT OFF* */
const static transport_proto_vft_t sctp_proto = {
  .enable = sctp_enable_disable,
  .bind = sctp_session_bind,
  .unbind = sctp_session_unbind,
  .open = sctp_session_open,
  .close = sctp_session_close,
  .cleanup = sctp_session_cleanup,
  .push_header = sctp_push_header,
  .send_mss = sctp_session_send_mss,
  .send_space = sctp_session_send_space,
  .tx_fifo_offset = NULL,	//sctp_session_tx_fifo_offset,
  .update_time = sctp_update_time,
  .get_connection = sctp_session_get_transport,
  .get_listener = sctp_session_get_listener,
  .get_half_open = sctp_half_open_session_get_transport,
  .format_connection = format_sctp_session,
  .format_listener = format_sctp_listener_session,
  .format_half_open = format_sctp_half_open,
};

/* *INDENT ON* */

clib_error_t *
sctp_init (vlib_main_t * vm)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  ip_main_t *im = &ip_main;
  ip_protocol_info_t *pi;
  /* Session layer, and by implication SCTP, are disabled by default */
  tm->is_enabled = 0;

  /* Register with IP for header parsing */
  pi = ip_get_protocol_info (im, IP_PROTOCOL_SCTP);
  if (pi == 0)
    return clib_error_return (0, "SCTP protocol info AWOL");
  pi->format_header = format_sctp_header;
  pi->unformat_pg_edit = unformat_pg_sctp_header;

  /* Register as transport with session layer */
  transport_register_protocol (TRANSPORT_PROTO_SCTP, &sctp_proto,
			       FIB_PROTOCOL_IP4, sctp4_output_node.index);
  transport_register_protocol (TRANSPORT_PROTO_SCTP, &sctp_proto,
			       FIB_PROTOCOL_IP6, sctp6_output_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (sctp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
