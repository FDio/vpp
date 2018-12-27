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
  clib_memset (listener, 0, sizeof (*listener));

  listener->sub_conn[SCTP_PRIMARY_PATH_IDX].subconn_idx =
    SCTP_PRIMARY_PATH_IDX;
  listener->sub_conn[SCTP_PRIMARY_PATH_IDX].c_c_index =
    listener - tm->listener_pool;
  listener->sub_conn[SCTP_PRIMARY_PATH_IDX].connection.lcl_port = tep->port;

  /* If we are provided a sw_if_index, bind using one of its IPs */
  if (ip_is_zero (&tep->ip, 1) && tep->sw_if_index != ENDPOINT_INVALID_INDEX)
    {
      if ((iface_ip = ip_interface_get_first_ip (tep->sw_if_index,
						 tep->is_ip4)))
	ip_set (&tep->ip, iface_ip, tep->is_ip4);
    }
  ip_copy (&listener->sub_conn[SCTP_PRIMARY_PATH_IDX].connection.lcl_ip,
	   &tep->ip, tep->is_ip4);

  u32 mtu = tep->is_ip4 ? vnet_sw_interface_get_mtu (vnet_get_main (),
						     tep->sw_if_index,
						     VNET_MTU_IP4) :
    vnet_sw_interface_get_mtu (vnet_get_main (), tep->sw_if_index,
			       VNET_MTU_IP6);
  listener->sub_conn[SCTP_PRIMARY_PATH_IDX].PMTU = mtu;
  listener->sub_conn[SCTP_PRIMARY_PATH_IDX].connection.is_ip4 = tep->is_ip4;
  listener->sub_conn[SCTP_PRIMARY_PATH_IDX].connection.proto =
    TRANSPORT_PROTO_SCTP;
  listener->sub_conn[SCTP_PRIMARY_PATH_IDX].c_s_index = session_index;
  listener->sub_conn[SCTP_PRIMARY_PATH_IDX].connection.fib_index =
    tep->fib_index;
  listener->state = SCTP_STATE_CLOSED;

  sctp_connection_timers_init (listener);

  return listener->sub_conn[SCTP_PRIMARY_PATH_IDX].c_c_index;
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
    clib_memset (sctp_conn, 0xFA, sizeof (*sctp_conn));

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
  sctp_connection_t *sctp_conn = va_arg (*args, sctp_connection_t *);
  if (!sctp_conn)
    return s;

  u8 i;
  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    {
      if (sctp_conn->sub_conn[i].connection.is_ip4)
	{
	  s = format (s, "%U[#%d][%s] %U:%d->%U:%d",
		      s,
		      sctp_conn->sub_conn[i].connection.thread_index,
		      "T",
		      format_ip4_address,
		      &sctp_conn->sub_conn[i].connection.lcl_ip.ip4,
		      clib_net_to_host_u16 (sctp_conn->sub_conn[i].
					    connection.lcl_port),
		      format_ip4_address,
		      &sctp_conn->sub_conn[i].connection.rmt_ip.ip4,
		      clib_net_to_host_u16 (sctp_conn->sub_conn[i].
					    connection.rmt_port));
	}
      else
	{
	  s = format (s, "%U[#%d][%s] %U:%d->%U:%d",
		      s,
		      sctp_conn->sub_conn[i].connection.thread_index,
		      "T",
		      format_ip6_address,
		      &sctp_conn->sub_conn[i].connection.lcl_ip.ip6,
		      clib_net_to_host_u16 (sctp_conn->sub_conn[i].
					    connection.lcl_port),
		      format_ip6_address,
		      &sctp_conn->sub_conn[i].connection.rmt_ip.ip6,
		      clib_net_to_host_u16 (sctp_conn->sub_conn[i].
					    connection.rmt_port));
	}
    }
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
  sctp_conn->last_unacked_tsn = sctp_conn->local_initial_tsn;
  sctp_conn->next_tsn = sctp_conn->local_initial_tsn + 1;

  sctp_conn->remote_initial_tsn = 0x0;
  sctp_conn->last_rcvd_tsn = sctp_conn->remote_initial_tsn;
}

always_inline sctp_connection_t *
sctp_sub_connection_add (u8 thread_index)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  sctp_connection_t *sctp_conn = tm->connections[thread_index];

  u8 subconn_idx = sctp_next_avail_subconn (sctp_conn);

  ASSERT (subconn_idx < MAX_SCTP_CONNECTIONS);

  sctp_conn->sub_conn[subconn_idx].connection.c_index =
    sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].connection.c_index;
  sctp_conn->sub_conn[subconn_idx].connection.thread_index = thread_index;
  sctp_conn->sub_conn[subconn_idx].subconn_idx = subconn_idx;

  return sctp_conn;
}

u8
sctp_sub_connection_add_ip4 (vlib_main_t * vm,
			     ip4_address_t * lcl_addr,
			     ip4_address_t * rmt_addr)
{
  sctp_connection_t *sctp_conn = sctp_sub_connection_add (vm->thread_index);

  u8 subconn_idx = sctp_next_avail_subconn (sctp_conn);

  if (subconn_idx == MAX_SCTP_CONNECTIONS)
    return SCTP_ERROR_MAX_CONNECTIONS;

  clib_memcpy (&sctp_conn->sub_conn[subconn_idx].connection.lcl_ip,
	       &lcl_addr, sizeof (lcl_addr));

  clib_memcpy (&sctp_conn->sub_conn[subconn_idx].connection.rmt_ip,
	       &rmt_addr, sizeof (rmt_addr));

  sctp_conn->forming_association_changed = 1;

  return SCTP_ERROR_NONE;
}

u8
sctp_sub_connection_del_ip4 (ip4_address_t * lcl_addr,
			     ip4_address_t * rmt_addr)
{
  sctp_main_t *sctp_main = vnet_get_sctp_main ();

  u32 thread_idx = vlib_get_thread_index ();
  u8 i;

  ASSERT (thread_idx == 0);

  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    {
      sctp_connection_t *sctp_conn = sctp_main->connections[thread_idx];
      sctp_sub_connection_t *sub_conn =
	&sctp_main->connections[thread_idx]->sub_conn[i];
      ip46_address_t *lcl_ip =
	&sctp_main->connections[thread_idx]->sub_conn[i].connection.lcl_ip;
      ip46_address_t *rmt_ip =
	&sctp_main->connections[thread_idx]->sub_conn[i].connection.rmt_ip;

      if (!sub_conn->connection.is_ip4)
	continue;
      if (lcl_ip->ip4.as_u32 == lcl_addr->as_u32 &&
	  rmt_ip->ip4.as_u32 == rmt_addr->as_u32)
	{
	  sub_conn->state = SCTP_SUBCONN_STATE_DOWN;
	  sctp_conn->forming_association_changed = 1;
	  break;
	}
    }
  return SCTP_ERROR_NONE;
}

u8
sctp_sub_connection_add_ip6 (vlib_main_t * vm,
			     ip6_address_t * lcl_addr,
			     ip6_address_t * rmt_addr)
{
  sctp_connection_t *sctp_conn = sctp_sub_connection_add (vm->thread_index);

  u8 subconn_idx = sctp_next_avail_subconn (sctp_conn);

  if (subconn_idx == MAX_SCTP_CONNECTIONS)
    return SCTP_ERROR_MAX_CONNECTIONS;

  clib_memcpy (&sctp_conn->sub_conn[subconn_idx].connection.lcl_ip,
	       &lcl_addr, sizeof (lcl_addr));

  clib_memcpy (&sctp_conn->sub_conn[subconn_idx].connection.rmt_ip,
	       &rmt_addr, sizeof (rmt_addr));

  sctp_conn->forming_association_changed = 1;

  return SCTP_ERROR_NONE;
}

u8
sctp_sub_connection_del_ip6 (ip6_address_t * lcl_addr,
			     ip6_address_t * rmt_addr)
{
  sctp_main_t *sctp_main = vnet_get_sctp_main ();

  u32 thread_idx = vlib_get_thread_index ();
  u8 i;

  ASSERT (thread_idx == 0);

  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    {
      sctp_connection_t *sctp_conn = sctp_main->connections[thread_idx];
      sctp_sub_connection_t *sub_conn =
	&sctp_main->connections[thread_idx]->sub_conn[i];
      ip46_address_t *lcl_ip =
	&sctp_main->connections[thread_idx]->sub_conn[i].connection.lcl_ip;
      ip46_address_t *rmt_ip =
	&sctp_main->connections[thread_idx]->sub_conn[i].connection.rmt_ip;

      if (!sub_conn->connection.is_ip4)
	continue;
      if ((lcl_ip->ip6.as_u64[0] == lcl_addr->as_u64[0]
	   && lcl_ip->ip6.as_u64[1] == lcl_addr->as_u64[1])
	  && (rmt_ip->ip6.as_u64[0] == rmt_addr->as_u64[0]
	      && rmt_ip->ip6.as_u64[1] == rmt_addr->as_u64[1]))
	{
	  sub_conn->state = SCTP_SUBCONN_STATE_DOWN;
	  sctp_conn->forming_association_changed = 1;
	  break;
	}
    }
  return SCTP_ERROR_NONE;
}

u8
sctp_configure (sctp_user_configuration_t config)
{
  sctp_main_t *sctp_main = vnet_get_sctp_main ();

  u32 thread_idx = vlib_get_thread_index ();

  sctp_main->connections[thread_idx]->conn_config.never_delay_sack =
    config.never_delay_sack;
  sctp_main->connections[thread_idx]->conn_config.never_bundle =
    config.never_bundle;

  return 0;
}

sctp_connection_t *
sctp_connection_new (u8 thread_index)
{
  sctp_main_t *sctp_main = vnet_get_sctp_main ();
  sctp_connection_t *sctp_conn;

  pool_get (sctp_main->connections[thread_index], sctp_conn);
  clib_memset (sctp_conn, 0, sizeof (*sctp_conn));
  sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].subconn_idx =
    SCTP_PRIMARY_PATH_IDX;
  sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].c_c_index =
    sctp_conn - sctp_main->connections[thread_index];
  sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].c_thread_index = thread_index;
  sctp_conn->local_tag = 0;

  return sctp_conn;
}

sctp_connection_t *
sctp_half_open_connection_new (u8 thread_index)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  sctp_connection_t *sctp_conn = 0;
  ASSERT (vlib_get_thread_index () == 0);
  pool_get (tm->half_open_connections, sctp_conn);
  clib_memset (sctp_conn, 0, sizeof (*sctp_conn));
  sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].c_c_index =
    sctp_conn - tm->half_open_connections;
  sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].subconn_idx =
    SCTP_PRIMARY_PATH_IDX;
  return sctp_conn;
}

static inline int
sctp_connection_open (transport_endpoint_cfg_t * rmt)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  sctp_connection_t *sctp_conn;
  ip46_address_t lcl_addr;
  u16 lcl_port;
  uword thread_id;
  int rv;

  u8 idx = SCTP_PRIMARY_PATH_IDX;

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
  u32 mtu = rmt->is_ip4 ? vnet_sw_interface_get_mtu (vnet_get_main (),
						     rmt->peer.sw_if_index,
						     VNET_MTU_IP4) :
    vnet_sw_interface_get_mtu (vnet_get_main (), rmt->peer.sw_if_index,
			       VNET_MTU_IP6);
  sctp_conn->sub_conn[idx].PMTU = mtu;

  transport_connection_t *trans_conn = &sctp_conn->sub_conn[idx].connection;
  ip_copy (&trans_conn->rmt_ip, &rmt->ip, rmt->is_ip4);
  ip_copy (&trans_conn->lcl_ip, &lcl_addr, rmt->is_ip4);
  sctp_conn->sub_conn[idx].subconn_idx = idx;
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

  int thread_index =
    sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].connection.thread_index;

  /* Make sure all timers are cleared */
  sctp_connection_timers_reset (sctp_conn);

  /* Poison the entry */
  if (CLIB_DEBUG > 0)
    clib_memset (sctp_conn, 0xFA, sizeof (*sctp_conn));
  pool_put (tm->connections[thread_index], sctp_conn);
}

int
sctp_session_open (transport_endpoint_cfg_t * tep)
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
	    ("Connection %u has still DATA to be enqueued inboud / outboud",
	     sctp_conn->sub_conn[i].connection.c_index);
	  return 1;
	}

    }
  return 0;			/* Indicates no more data to be read/sent */
}

void
sctp_connection_close (sctp_connection_t * sctp_conn)
{
  SCTP_DBG ("Closing connection %u...",
	    sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].connection.c_index);

  sctp_conn->state = SCTP_STATE_SHUTDOWN_PENDING;

  sctp_send_shutdown (sctp_conn);
}

void
sctp_session_close (u32 conn_index, u32 thread_index)
{
  ASSERT (thread_index == 0);

  sctp_connection_t *sctp_conn =
    sctp_connection_get (conn_index, thread_index);
  if (sctp_conn != NULL)
    sctp_connection_close (sctp_conn);
}

void
sctp_session_cleanup (u32 conn_index, u32 thread_index)
{
  sctp_connection_t *sctp_conn =
    sctp_connection_get (conn_index, thread_index);

  if (sctp_conn != NULL)
    {
      sctp_connection_timers_reset (sctp_conn);
      /* Wait for the session tx events to clear */
      sctp_conn->state = SCTP_STATE_CLOSED;
    }
}

/**
 * Compute maximum segment size for session layer.
 */
u16
sctp_session_send_mss (transport_connection_t * trans_conn)
{
  sctp_connection_t *sctp_conn =
    sctp_get_connection_from_transport (trans_conn);

  if (sctp_conn == NULL)
    {
      SCTP_DBG ("sctp_conn == NULL");
      return 0;
    }

  update_cwnd (sctp_conn);
  update_smallest_pmtu_idx (sctp_conn);

  u8 idx = sctp_data_subconn_select (sctp_conn);
  return sctp_conn->sub_conn[idx].cwnd;
}

u16
sctp_snd_space (sctp_connection_t * sctp_conn)
{
  /* RFC 4096 Section 6.1; point (A) */
  if (sctp_conn->peer_rwnd == 0)
    return 0;

  u8 idx = sctp_data_subconn_select (sctp_conn);

  u32 available_wnd =
    clib_min (sctp_conn->peer_rwnd, sctp_conn->sub_conn[idx].cwnd);
  int flight_size = (int) (sctp_conn->next_tsn - sctp_conn->last_unacked_tsn);

  if (available_wnd <= flight_size)
    return 0;

  /* Finally, let's subtract the DATA chunk headers overhead */
  return available_wnd -
    flight_size -
    sizeof (sctp_payload_data_chunk_t) - sizeof (sctp_full_hdr_t);
}

/**
 * Compute TX window session is allowed to fill.
 */
u32
sctp_session_send_space (transport_connection_t * trans_conn)
{
  sctp_connection_t *sctp_conn =
    sctp_get_connection_from_transport (trans_conn);

  return sctp_snd_space (sctp_conn);
}

transport_connection_t *
sctp_session_get_transport (u32 conn_index, u32 thread_index)
{
  sctp_connection_t *sctp_conn =
    sctp_connection_get (conn_index, thread_index);

  if (PREDICT_TRUE (sctp_conn != NULL))
    return &sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].connection;

  return NULL;
}

transport_connection_t *
sctp_session_get_listener (u32 listener_index)
{
  sctp_main_t *tm = vnet_get_sctp_main ();
  sctp_connection_t *sctp_conn;
  sctp_conn = pool_elt_at_index (tm->listener_pool, listener_index);
  return &sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].connection;
}

u8 *
format_sctp_session (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  sctp_connection_t *tc;

  tc = sctp_connection_get (tci, thread_index);
  if (tc)
    s = format (s, "%U", format_sctp_connection, tc, verbose);
  else
    s = format (s, "empty\n");
  return s;
}

u8 *
format_sctp_listener_session (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  sctp_connection_t *tc = sctp_listener_get (tci);
  return format (s, "%U", format_sctp_connection_id, tc);
}

void
sctp_expired_timers_cb (u32 conn_index, u32 timer_id)
{
  sctp_connection_t *sctp_conn;

  SCTP_DBG ("%s expired", sctp_timer_to_string (timer_id));

  sctp_conn = sctp_connection_get (conn_index, vlib_get_thread_index ());
  /* note: the connection may have already disappeared */
  if (PREDICT_FALSE (sctp_conn == 0))
    return;

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
	  session_transport_delete_notify (&sctp_conn->sub_conn
					   [SCTP_PRIMARY_PATH_IDX].connection);

	  sctp_connection_timers_reset (sctp_conn);

	  sctp_connection_cleanup (sctp_conn);
	}
      return;
    }

  switch (timer_id)
    {
    case SCTP_TIMER_T1_INIT:
      sctp_send_init (sctp_conn);
      break;
    case SCTP_TIMER_T1_COOKIE:
      sctp_send_cookie_echo (sctp_conn);
      break;
    case SCTP_TIMER_T2_SHUTDOWN:
      sctp_send_shutdown (sctp_conn);
      break;
    case SCTP_TIMER_T3_RXTX:
      sctp_timer_reset (sctp_conn, conn_index, timer_id);
      sctp_conn->flags |= SCTP_CONN_RECOVERY;
      sctp_data_retransmit (sctp_conn);
      break;
    case SCTP_TIMER_T4_HEARTBEAT:
      sctp_timer_reset (sctp_conn, conn_index, timer_id);
      goto heartbeat;
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
  return &sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].connection;
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
  .update_time = sctp_update_time,
  .get_connection = sctp_session_get_transport,
  .get_listener = sctp_session_get_listener,
  .get_half_open = sctp_half_open_session_get_transport,
  .format_connection = format_sctp_session,
  .format_listener = format_sctp_listener_session,
  .format_half_open = format_sctp_half_open,
  .tx_type = TRANSPORT_TX_DEQUEUE,
  .service_type = TRANSPORT_SERVICE_VC,
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

  sctp_api_reference ();

  return 0;
}

VLIB_INIT_FUNCTION (sctp_init);

static clib_error_t *
show_sctp_punt_fn (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd_arg)
{
  sctp_main_t *tm = &sctp_main;
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			      input);
  vlib_cli_output (vm, "IPv4 UDP punt: %s",
		   tm->punt_unknown4 ? "enabled" : "disabled");
  vlib_cli_output (vm, "IPv6 UDP punt: %s",
		   tm->punt_unknown6 ? "enabled" : "disabled");
  return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_tcp_punt_command, static) =
{
  .path = "show sctp punt",
  .short_help = "show sctp punt",
  .function = show_sctp_punt_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
