/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vnet/tcp/tcp_inlines.h>
#include <vnet/dpo/receive_dpo.h>
#include <vnet/ip-neighbor/ip_neighbor.h>

const char *tcp_fsm_states[] = {
#define _(sym, str) str,
  foreach_tcp_fsm_state
#undef _
};

u8 *
format_tcp_state (u8 * s, va_list * args)
{
  u32 state = va_arg (*args, u32);

  if (state < TCP_N_STATES)
    s = format (s, "%s", tcp_fsm_states[state]);
  else
    s = format (s, "UNKNOWN (%d (0x%x))", state, state);
  return s;
}

const char *tcp_cfg_flags_str[] = {
#define _(sym, str) str,
  foreach_tcp_cfg_flag
#undef _
};

static u8 *
format_tcp_cfg_flags (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  int i, last = -1;

  for (i = 0; i < TCP_CFG_N_FLAG_BITS; i++)
    if (tc->cfg_flags & (1 << i))
      last = i;
  for (i = 0; i < last; i++)
    {
      if (tc->cfg_flags & (1 << i))
	s = format (s, "%s, ", tcp_cfg_flags_str[i]);
    }
  if (last >= 0)
    s = format (s, "%s", tcp_cfg_flags_str[last]);
  return s;
}

const char *tcp_connection_flags_str[] = {
#define _(sym, str) str,
  foreach_tcp_connection_flag
#undef _
};

static u8 *
format_tcp_connection_flags (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  int i, last = -1;

  for (i = 0; i < TCP_CONN_N_FLAG_BITS; i++)
    if (tc->flags & (1 << i))
      last = i;
  for (i = 0; i < last; i++)
    {
      if (tc->flags & (1 << i))
	s = format (s, "%s, ", tcp_connection_flags_str[i]);
    }
  if (last >= 0)
    s = format (s, "%s", tcp_connection_flags_str[last]);
  return s;
}

const char *tcp_conn_timers[] = {
#define _(sym, str) str,
  foreach_tcp_timer
#undef _
};

static u8 *
format_tcp_timers (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  int i, last = -1;

  for (i = 0; i < TCP_N_TIMERS; i++)
    if (tc->timers[i] != TCP_TIMER_HANDLE_INVALID)
      last = i;

  for (i = 0; i < last; i++)
    {
      if (tc->timers[i] != TCP_TIMER_HANDLE_INVALID)
	s = format (s, "%s,", tcp_conn_timers[i]);
    }

  if (last >= 0)
    s = format (s, "%s", tcp_conn_timers[i]);

  return s;
}

static u8 *
format_tcp_congestion_status (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  if (tcp_in_recovery (tc))
    s = format (s, "recovery");
  else if (tcp_in_fastrecovery (tc))
    s = format (s, "fastrecovery");
  else
    s = format (s, "none");
  return s;
}

static i32
tcp_rcv_wnd_available (tcp_connection_t * tc)
{
  return (i32) tc->rcv_wnd - (tc->rcv_nxt - tc->rcv_las);
}

static u8 *
format_tcp_congestion (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  u32 indent = format_get_indent (s), prr_space = 0;

  s = format (s, "%U ", format_tcp_congestion_status, tc);
  s = format (s, "algo %s cwnd %u ssthresh %u bytes_acked %u\n",
	      tc->cc_algo->name, tc->cwnd, tc->ssthresh, tc->bytes_acked);
  s = format (s, "%Ucc space %u prev_cwnd %u prev_ssthresh %u\n",
	      format_white_space, indent, tcp_available_cc_snd_space (tc),
	      tc->prev_cwnd, tc->prev_ssthresh);
  s = format (s, "%Usnd_cong %u dupack %u limited_tx %u\n",
	      format_white_space, indent, tc->snd_congestion - tc->iss,
	      tc->rcv_dupacks, tc->limited_transmit - tc->iss);
  s = format (s, "%Urxt_bytes %u rxt_delivered %u rxt_head %u rxt_ts %u\n",
	      format_white_space, indent, tc->snd_rxt_bytes,
	      tc->rxt_delivered, tc->rxt_head - tc->iss,
	      tcp_time_now_w_thread (tc->c_thread_index) - tc->snd_rxt_ts);
  if (tcp_in_fastrecovery (tc))
    prr_space = tcp_fastrecovery_prr_snd_space (tc);
  s = format (s, "%Uprr_start %u prr_delivered %u prr space %u\n",
	      format_white_space, indent, tc->prr_start - tc->iss,
	      tc->prr_delivered, prr_space);
  return s;
}

static u8 *
format_tcp_stats (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  u32 indent = format_get_indent (s);
  s = format (s, "in segs %lu dsegs %lu bytes %lu dupacks %u\n",
	      tc->segs_in, tc->data_segs_in, tc->bytes_in, tc->dupacks_in);
  s = format (s, "%Uout segs %lu dsegs %lu bytes %lu dupacks %u\n",
	      format_white_space, indent, tc->segs_out,
	      tc->data_segs_out, tc->bytes_out, tc->dupacks_out);
  s = format (s, "%Ufr %u tr %u rxt segs %lu bytes %lu duration %.3f\n",
	      format_white_space, indent, tc->fr_occurences,
	      tc->tr_occurences, tc->segs_retrans, tc->bytes_retrans,
	      tcp_time_now_us (tc->c_thread_index) - tc->start_ts);
  s = format (s, "%Uerr wnd data below %u above %u ack below %u above %u",
	      format_white_space, indent, tc->errors.below_data_wnd,
	      tc->errors.above_data_wnd, tc->errors.below_ack_wnd,
	      tc->errors.above_ack_wnd);
  return s;
}

static u8 *
format_tcp_vars (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  s = format (s, " index: %u cfg: %U flags: %U timers: %U\n", tc->c_c_index,
	      format_tcp_cfg_flags, tc, format_tcp_connection_flags, tc,
	      format_tcp_timers, tc);
  s = format (s, " snd_una %u snd_nxt %u snd_una_max %u",
	      tc->snd_una - tc->iss, tc->snd_nxt - tc->iss,
	      tc->snd_una_max - tc->iss);
  s = format (s, " rcv_nxt %u rcv_las %u\n",
	      tc->rcv_nxt - tc->irs, tc->rcv_las - tc->irs);
  s = format (s, " snd_wnd %u rcv_wnd %u rcv_wscale %u ",
	      tc->snd_wnd, tc->rcv_wnd, tc->rcv_wscale);
  s = format (s, "snd_wl1 %u snd_wl2 %u\n", tc->snd_wl1 - tc->irs,
	      tc->snd_wl2 - tc->iss);
  s = format (s, " flight size %u out space %u rcv_wnd_av %u",
	      tcp_flight_size (tc), tcp_available_output_snd_space (tc),
	      tcp_rcv_wnd_available (tc));
  s = format (s, " tsval_recent %u\n", tc->tsval_recent);
  s = format (s, " tsecr %u tsecr_last_ack %u tsval_recent_age %u",
	      tc->rcv_opts.tsecr, tc->tsecr_last_ack,
	      tcp_time_now () - tc->tsval_recent_age);
  s = format (s, " snd_mss %u\n", tc->snd_mss);
  s = format (s, " rto %u rto_boff %u srtt %.1f us %.3f rttvar %.1f",
	      tc->rto / 1000, tc->rto_boff, tc->srtt / 1000.0,
	      tc->mrtt_us * 1e3, tc->rttvar / 1000.0);
  s = format (s, " rtt_ts %.4f rtt_seq %u\n", tc->rtt_ts,
	      tc->rtt_seq - tc->iss);
  s = format (s, " next_node %u opaque 0x%x fib_index %u\n",
	      tc->next_node_index, tc->next_node_opaque, tc->c_fib_index);
  s = format (s, " cong:   %U", format_tcp_congestion, tc);

  if (tc->state >= TCP_STATE_ESTABLISHED)
    {
      s = format (s, " sboard: %U\n", format_tcp_scoreboard, &tc->sack_sb,
		  tc);
      s = format (s, " stats: %U\n", format_tcp_stats, tc);
    }
  if (vec_len (tc->snd_sacks))
    s = format (s, " sacks tx: %U\n", format_tcp_sacks, tc);

  return s;
}

u8 *
format_tcp_connection_id (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  if (!tc)
    return s;
  if (tc->c_is_ip4)
    {
      s = format (s, "[%d:%d][%s] %U:%d->%U:%d", tc->c_thread_index,
		  tc->c_s_index, "T", format_ip4_address, &tc->c_lcl_ip4,
		  clib_net_to_host_u16 (tc->c_lcl_port), format_ip4_address,
		  &tc->c_rmt_ip4, clib_net_to_host_u16 (tc->c_rmt_port));
    }
  else
    {
      s = format (s, "[%d:%d][%s] %U:%d->%U:%d", tc->c_thread_index,
		  tc->c_s_index, "T", format_ip6_address, &tc->c_lcl_ip6,
		  clib_net_to_host_u16 (tc->c_lcl_port), format_ip6_address,
		  &tc->c_rmt_ip6, clib_net_to_host_u16 (tc->c_rmt_port));
    }

  return s;
}

u8 *
format_tcp_connection (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  u32 verbose = va_arg (*args, u32);

  if (!tc)
    return s;
  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_tcp_connection_id, tc);
  if (verbose)
    {
      s = format (s, "%-" SESSION_CLI_STATE_LEN "U", format_tcp_state,
		  tc->state);
      if (verbose > 1)
	s = format (s, "\n%U", format_tcp_vars, tc);
    }

  return s;
}

u8 *
format_tcp_sacks (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  sack_block_t *sacks = tc->snd_sacks;
  sack_block_t *block;
  int i, len = 0;

  len = vec_len (sacks);
  for (i = 0; i < len - 1; i++)
    {
      block = &sacks[i];
      s = format (s, " start %u end %u\n", block->start - tc->irs,
		  block->end - tc->irs);
    }
  if (len)
    {
      block = &sacks[len - 1];
      s = format (s, " start %u end %u", block->start - tc->irs,
		  block->end - tc->irs);
    }
  return s;
}

u8 *
format_tcp_rcv_sacks (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  sack_block_t *sacks = tc->rcv_opts.sacks;
  sack_block_t *block;
  int i, len = 0;

  len = vec_len (sacks);
  for (i = 0; i < len - 1; i++)
    {
      block = &sacks[i];
      s = format (s, " start %u end %u\n", block->start - tc->iss,
		  block->end - tc->iss);
    }
  if (len)
    {
      block = &sacks[len - 1];
      s = format (s, " start %u end %u", block->start - tc->iss,
		  block->end - tc->iss);
    }
  return s;
}

static u8 *
format_tcp_sack_hole (u8 * s, va_list * args)
{
  sack_scoreboard_hole_t *hole = va_arg (*args, sack_scoreboard_hole_t *);
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  if (tc)
    s = format (s, "  [%u, %u]", hole->start - tc->iss, hole->end - tc->iss);
  else
    s = format (s, "  [%u, %u]", hole->start, hole->end);
  return s;
}

u8 *
format_tcp_scoreboard (u8 * s, va_list * args)
{
  sack_scoreboard_t *sb = va_arg (*args, sack_scoreboard_t *);
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  sack_scoreboard_hole_t *hole;
  u32 indent = format_get_indent (s);

  s = format (s, "sacked %u last_sacked %u lost %u last_lost %u"
	      " rxt_sacked %u\n",
	      sb->sacked_bytes, sb->last_sacked_bytes, sb->lost_bytes,
	      sb->last_lost_bytes, sb->rxt_sacked);
  s = format (s, "%Ulast_delivered %u high_sacked %u is_reneging %u",
	      format_white_space, indent, sb->last_bytes_delivered,
	      sb->high_sacked - tc->iss, sb->is_reneging);
  s = format (s, " reorder %u\n", sb->reorder);
  s = format (s, "%Ucur_rxt_hole %u high_rxt %u rescue_rxt %u",
	      format_white_space, indent, sb->cur_rxt_hole,
	      sb->high_rxt - tc->iss, sb->rescue_rxt - tc->iss);

  hole = scoreboard_first_hole (sb);
  if (hole)
    s = format (s, "\n%Uhead %u tail %u %u holes:\n%U", format_white_space,
		indent, sb->head, sb->tail, pool_elts (sb->holes),
		format_white_space, indent);

  while (hole)
    {
      s = format (s, "%U", format_tcp_sack_hole, hole, tc);
      hole = scoreboard_next_hole (sb, hole);
    }

  return s;
}

/**
 * \brief Configure an ipv4 source address range
 * @param vm vlib_main_t pointer
 * @param start first ipv4 address in the source address range
 * @param end last ipv4 address in the source address range
 * @param table_id VRF / table ID, 0 for the default FIB
 * @return 0 if all OK, else an error indication from api_errno.h
 */

int
tcp_configure_v4_source_address_range (vlib_main_t * vm,
				       ip4_address_t * start,
				       ip4_address_t * end, u32 table_id)
{
  u32 start_host_byte_order, end_host_byte_order;
  fib_prefix_t prefix;
  fib_node_index_t fei;
  u32 fib_index = 0;
  u32 sw_if_index;
  int rv;

  clib_memset (&prefix, 0, sizeof (prefix));

  fib_index = fib_table_find (FIB_PROTOCOL_IP4, table_id);

  if (fib_index == ~0)
    return VNET_API_ERROR_NO_SUCH_FIB;

  start_host_byte_order = clib_net_to_host_u32 (start->as_u32);
  end_host_byte_order = clib_net_to_host_u32 (end->as_u32);

  /* sanity check for reversed args or some such */
  if ((end_host_byte_order - start_host_byte_order) > (10 << 10))
    return VNET_API_ERROR_INVALID_ARGUMENT;

  /* Lookup the last address, to identify the interface involved */
  prefix.fp_len = 32;
  prefix.fp_proto = FIB_PROTOCOL_IP4;
  memcpy (&prefix.fp_addr.ip4, end, sizeof (ip4_address_t));

  fei = fib_table_lookup (fib_index, &prefix);

  /* Couldn't find route to destination. Bail out. */
  if (fei == FIB_NODE_INDEX_INVALID)
    return VNET_API_ERROR_NEXT_HOP_NOT_IN_FIB;

  sw_if_index = fib_entry_get_resolving_interface (fei);

  /* Configure proxy arp across the range */
  rv = ip4_neighbor_proxy_add (fib_index, start, end);

  if (rv)
    return rv;

  rv = ip4_neighbor_proxy_enable (sw_if_index);

  if (rv)
    return rv;

  do
    {
      dpo_id_t dpo = DPO_INVALID;

      vec_add1 (tcp_cfg.ip4_src_addrs, start[0]);

      /* Add local adjacencies for the range */

      receive_dpo_add_or_lock (DPO_PROTO_IP4, ~0 /* sw_if_index */ ,
			       NULL, &dpo);
      prefix.fp_len = 32;
      prefix.fp_proto = FIB_PROTOCOL_IP4;
      prefix.fp_addr.ip4.as_u32 = start->as_u32;

      fib_table_entry_special_dpo_update (fib_index,
					  &prefix,
					  FIB_SOURCE_API,
					  FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
      dpo_reset (&dpo);

      start_host_byte_order++;
      start->as_u32 = clib_host_to_net_u32 (start_host_byte_order);
    }
  while (start_host_byte_order <= end_host_byte_order);

  return 0;
}

/**
 * \brief Configure an ipv6 source address range
 * @param vm vlib_main_t pointer
 * @param start first ipv6 address in the source address range
 * @param end last ipv6 address in the source address range
 * @param table_id VRF / table ID, 0 for the default FIB
 * @return 0 if all OK, else an error indication from api_errno.h
 */

int
tcp_configure_v6_source_address_range (vlib_main_t * vm,
				       ip6_address_t * start,
				       ip6_address_t * end, u32 table_id)
{
  fib_prefix_t prefix;
  u32 fib_index = 0;
  fib_node_index_t fei;
  u32 sw_if_index;

  clib_memset (&prefix, 0, sizeof (prefix));

  fib_index = fib_table_find (FIB_PROTOCOL_IP6, table_id);

  if (fib_index == ~0)
    return VNET_API_ERROR_NO_SUCH_FIB;

  while (1)
    {
      int i;
      ip6_address_t tmp;
      dpo_id_t dpo = DPO_INVALID;

      /* Remember this address */
      vec_add1 (tcp_cfg.ip6_src_addrs, start[0]);

      /* Lookup the prefix, to identify the interface involved */
      prefix.fp_len = 128;
      prefix.fp_proto = FIB_PROTOCOL_IP6;
      memcpy (&prefix.fp_addr.ip6, start, sizeof (ip6_address_t));

      fei = fib_table_lookup (fib_index, &prefix);

      /* Couldn't find route to destination. Bail out. */
      if (fei == FIB_NODE_INDEX_INVALID)
	return VNET_API_ERROR_NEXT_HOP_NOT_IN_FIB;

      sw_if_index = fib_entry_get_resolving_interface (fei);

      if (sw_if_index == (u32) ~ 0)
	return VNET_API_ERROR_NO_MATCHING_INTERFACE;

      /* Add a proxy neighbor discovery entry for this address */
      ip6_neighbor_proxy_add (sw_if_index, start);

      /* Add a receive adjacency for this address */
      receive_dpo_add_or_lock (DPO_PROTO_IP6, ~0 /* sw_if_index */ ,
			       NULL, &dpo);

      fib_table_entry_special_dpo_update (fib_index,
					  &prefix,
					  FIB_SOURCE_API,
					  FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
      dpo_reset (&dpo);

      /* Done with the entire range? */
      if (!memcmp (start, end, sizeof (start[0])))
	break;

      /* Increment the address. DGMS. */
      tmp = start[0];
      for (i = 15; i >= 0; i--)
	{
	  tmp.as_u8[i] += 1;
	  if (tmp.as_u8[i] != 0)
	    break;
	}
      start[0] = tmp;
    }
  return 0;
}

static clib_error_t *
tcp_src_address_fn (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  ip4_address_t v4start, v4end;
  ip6_address_t v6start, v6end;
  u32 table_id = 0;
  int v4set = 0;
  int v6set = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U - %U", unformat_ip4_address, &v4start,
		    unformat_ip4_address, &v4end))
	v4set = 1;
      else if (unformat (input, "%U", unformat_ip4_address, &v4start))
	{
	  memcpy (&v4end, &v4start, sizeof (v4start));
	  v4set = 1;
	}
      else if (unformat (input, "%U - %U", unformat_ip6_address, &v6start,
			 unformat_ip6_address, &v6end))
	v6set = 1;
      else if (unformat (input, "%U", unformat_ip6_address, &v6start))
	{
	  memcpy (&v6end, &v6start, sizeof (v6start));
	  v6set = 1;
	}
      else if (unformat (input, "fib-table %d", &table_id))
	;
      else
	break;
    }

  if (!v4set && !v6set)
    return clib_error_return (0, "at least one v4 or v6 address required");

  if (v4set)
    {
      rv = tcp_configure_v4_source_address_range (vm, &v4start, &v4end,
						  table_id);
      switch (rv)
	{
	case 0:
	  break;

	case VNET_API_ERROR_NO_SUCH_FIB:
	  return clib_error_return (0, "Invalid table-id %d", table_id);

	case VNET_API_ERROR_INVALID_ARGUMENT:
	  return clib_error_return (0, "Invalid address range %U - %U",
				    format_ip4_address, &v4start,
				    format_ip4_address, &v4end);
	default:
	  return clib_error_return (0, "error %d", rv);
	  break;
	}
    }
  if (v6set)
    {
      rv = tcp_configure_v6_source_address_range (vm, &v6start, &v6end,
						  table_id);
      switch (rv)
	{
	case 0:
	  break;

	case VNET_API_ERROR_NO_SUCH_FIB:
	  return clib_error_return (0, "Invalid table-id %d", table_id);

	default:
	  return clib_error_return (0, "error %d", rv);
	  break;
	}
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tcp_src_address_command, static) =
{
  .path = "tcp src-address",
  .short_help = "tcp src-address <ip-addr> [- <ip-addr>] add src address range",
  .function = tcp_src_address_fn,
};
/* *INDENT-ON* */

static u8 *
tcp_scoreboard_dump_trace (u8 * s, sack_scoreboard_t * sb)
{
#if TCP_SCOREBOARD_TRACE

  scoreboard_trace_elt_t *block;
  int i = 0;

  if (!sb->trace)
    return s;

  s = format (s, "scoreboard trace:");
  vec_foreach (block, sb->trace)
  {
    s = format (s, "{%u, %u, %u, %u, %u}, ", block->start, block->end,
		block->ack, block->snd_una_max, block->group);
    if ((++i % 3) == 0)
      s = format (s, "\n");
  }
  return s;
#else
  return 0;
#endif
}

static clib_error_t *
tcp_show_scoreboard_trace_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd_arg)
{
  transport_connection_t *tconn = 0;
  tcp_connection_t *tc;
  u8 *s = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_transport_connection, &tconn,
		    TRANSPORT_PROTO_TCP))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!TCP_SCOREBOARD_TRACE)
    {
      vlib_cli_output (vm, "scoreboard tracing not enabled");
      return 0;
    }

  tc = tcp_get_connection_from_transport (tconn);
  s = tcp_scoreboard_dump_trace (s, &tc->sack_sb);
  vlib_cli_output (vm, "%v", s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tcp_show_scoreboard_trace_command, static) =
{
  .path = "show tcp scoreboard trace",
  .short_help = "show tcp scoreboard trace <connection>",
  .function = tcp_show_scoreboard_trace_fn,
};
/* *INDENT-ON* */

u8 *
tcp_scoreboard_replay (u8 * s, tcp_connection_t * tc, u8 verbose)
{
  int i, trace_len;
  scoreboard_trace_elt_t *trace;
  u32 next_ack, left, group, has_new_ack = 0;
  tcp_connection_t _placeholder_tc, *placeholder_tc = &_placeholder_tc;
  sack_block_t *block;

  if (!TCP_SCOREBOARD_TRACE)
    {
      s = format (s, "scoreboard tracing not enabled");
      return s;
    }

  if (!tc)
    return s;

  clib_memset (placeholder_tc, 0, sizeof (*placeholder_tc));
  tcp_connection_timers_init (placeholder_tc);
  scoreboard_init (&placeholder_tc->sack_sb);
  placeholder_tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;

#if TCP_SCOREBOARD_TRACE
  trace = tc->sack_sb.trace;
  trace_len = vec_len (tc->sack_sb.trace);
#endif

  for (i = 0; i < trace_len; i++)
    {
      if (trace[i].ack != 0)
	{
	  placeholder_tc->snd_una = trace[i].ack - 1448;
	  placeholder_tc->snd_una_max = trace[i].ack;
	}
    }

  left = 0;
  while (left < trace_len)
    {
      group = trace[left].group;
      vec_reset_length (placeholder_tc->rcv_opts.sacks);
      has_new_ack = 0;
      while (trace[left].group == group)
	{
	  if (trace[left].ack != 0)
	    {
	      if (verbose)
		s = format (s, "Adding ack %u, snd_una_max %u, segs: ",
			    trace[left].ack, trace[left].snd_una_max);
	      placeholder_tc->snd_una_max = trace[left].snd_una_max;
	      next_ack = trace[left].ack;
	      has_new_ack = 1;
	    }
	  else
	    {
	      if (verbose)
		s = format (s, "[%u, %u], ", trace[left].start,
			    trace[left].end);
	      vec_add2 (placeholder_tc->rcv_opts.sacks, block, 1);
	      block->start = trace[left].start;
	      block->end = trace[left].end;
	    }
	  left++;
	}

      /* Push segments */
      tcp_rcv_sacks (placeholder_tc, next_ack);
      if (has_new_ack)
	placeholder_tc->snd_una = next_ack;

      if (verbose)
	s = format (s, "result: %U", format_tcp_scoreboard,
		    &placeholder_tc->sack_sb);

    }
  s =
    format (s, "result: %U", format_tcp_scoreboard, &placeholder_tc->sack_sb);

  return s;
}

static clib_error_t *
tcp_scoreboard_trace_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd_arg)
{
  transport_connection_t *tconn = 0;
  tcp_connection_t *tc = 0;
  u8 *str = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_transport_connection, &tconn,
		    TRANSPORT_PROTO_TCP))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!TCP_SCOREBOARD_TRACE)
    {
      vlib_cli_output (vm, "scoreboard tracing not enabled");
      return 0;
    }

  tc = tcp_get_connection_from_transport (tconn);
  if (!tc)
    {
      vlib_cli_output (vm, "connection not found");
      return 0;
    }
  str = tcp_scoreboard_replay (str, tc, 1);
  vlib_cli_output (vm, "%v", str);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tcp_replay_scoreboard_command, static) =
{
  .path = "tcp replay scoreboard",
  .short_help = "tcp replay scoreboard <connection>",
  .function = tcp_scoreboard_trace_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_tcp_punt_fn (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd_arg)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			      input);
  vlib_cli_output (vm, "IPv4 TCP punt: %s",
		   tm->punt_unknown4 ? "enabled" : "disabled");
  vlib_cli_output (vm, "IPv6 TCP punt: %s",
		   tm->punt_unknown6 ? "enabled" : "disabled");
  return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_tcp_punt_command, static) =
{
  .path = "show tcp punt",
  .short_help = "show tcp punt",
  .function = show_tcp_punt_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_tcp_stats_fn (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_worker_ctx_t *wrk;
  u32 thread;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			      input);
  for (thread = 0; thread < vec_len (tm->wrk_ctx); thread++)
    {
      wrk = tcp_get_worker (thread);
      vlib_cli_output (vm, "Thread %u:\n", thread);

      if (clib_fifo_elts (wrk->pending_timers))
	vlib_cli_output (vm, " %lu pending timers",
			 clib_fifo_elts (wrk->pending_timers));

#define _(name,type,str)					\
  if (wrk->stats.name)						\
    vlib_cli_output (vm, " %lu %s", wrk->stats.name, str);
      foreach_tcp_wrk_stat
#undef _
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_tcp_stats_command, static) =
{
  .path = "show tcp stats",
  .short_help = "show tcp stats",
  .function = show_tcp_stats_fn,
};
/* *INDENT-ON* */

static clib_error_t *
clear_tcp_stats_fn (vlib_main_t * vm, unformat_input_t * input,
		    vlib_cli_command_t * cmd)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_worker_ctx_t *wrk;
  u32 thread;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			      input);

  for (thread = 0; thread < vec_len (tm->wrk_ctx); thread++)
    {
      wrk = tcp_get_worker (thread);
      clib_memset (&wrk->stats, 0, sizeof (wrk->stats));
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_tcp_stats_command, static) =
{
  .path = "clear tcp stats",
  .short_help = "clear tcp stats",
  .function = clear_tcp_stats_fn,
};
/* *INDENT-ON* */

static void
tcp_show_half_open (vlib_main_t * vm, u32 start, u32 end, u8 verbose)
{
  tcp_main_t *tm = &tcp_main;
  u8 output_suppressed = 0;
  u32 n_elts, count = 0;
  tcp_connection_t *tc;
  int max_index, i;

  n_elts = pool_elts (tm->half_open_connections);
  max_index = clib_max (pool_len (tm->half_open_connections), 1) - 1;
  if (verbose && end == ~0 && n_elts > 50)
    {
      vlib_cli_output (vm, "Too many connections, use range <start> <end>");
      return;
    }

  if (!verbose)
    {
      vlib_cli_output (vm, "%u tcp half-open connections", n_elts);
      return;
    }

  for (i = start; i <= clib_min (end, max_index); i++)
    {
      if (pool_is_free_index (tm->half_open_connections, i))
	continue;

      tc = pool_elt_at_index (tm->half_open_connections, i);

      count += 1;
      if (verbose)
	{
	  if (count > 50 || (verbose > 1 && count > 10))
	    {
	      output_suppressed = 1;
	      continue;
	    }
	}
      vlib_cli_output (vm, "%U", format_tcp_connection, tc, verbose);
    }
  if (!output_suppressed)
    vlib_cli_output (vm, "%u tcp half-open connections", n_elts);
  else
    vlib_cli_output (vm, "%u tcp half-open connections matched. Output "
		     "suppressed. Use finer grained filter.", count);

}

static clib_error_t *
show_tcp_half_open_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 start, end = ~0, verbose = 0;
  clib_error_t *error = 0;

  session_cli_return_if_not_enabled ();

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      tcp_show_half_open (vm, 0, ~0, 0);
      return 0;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "range %u %u", &start, &end))
	;
      else if (unformat (line_input, "verbose %d", &verbose))
	;
      else if (unformat (line_input, "verbose"))
	verbose = 1;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (start > end)
    {
      error = clib_error_return (0, "invalid range start: %u end: %u", start,
				 end);
      goto done;
    }

  tcp_show_half_open (vm, start, end, verbose);

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_tcp_half_open_command, static) =
{
  .path = "show tcp half-open",
  .short_help = "show tcp half-open [verbose <n>] [range <start> <end>]",
  .function = show_tcp_half_open_fn,
};
/* *INDENT-ON* */

uword
unformat_tcp_cc_algo (unformat_input_t * input, va_list * va)
{
  tcp_cc_algorithm_type_e *result = va_arg (*va, tcp_cc_algorithm_type_e *);
  tcp_main_t *tm = &tcp_main;
  char *cc_algo_name;
  u8 found = 0;
  uword *p;

  if (unformat (input, "%s", &cc_algo_name)
      && ((p = hash_get_mem (tm->cc_algo_by_name, cc_algo_name))))
    {
      *result = *p;
      found = 1;
    }

  vec_free (cc_algo_name);
  return found;
}

uword
unformat_tcp_cc_algo_cfg (unformat_input_t * input, va_list * va)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_cc_algorithm_t *cc_alg;
  unformat_input_t sub_input;
  int found = 0;

  vec_foreach (cc_alg, tm->cc_algos)
  {
    if (!unformat (input, cc_alg->name))
      continue;

    if (cc_alg->unformat_cfg
	&& unformat (input, "%U", unformat_vlib_cli_sub_input, &sub_input))
      {
	if (cc_alg->unformat_cfg (&sub_input))
	  found = 1;
      }
  }
  return found;
}

static clib_error_t *
tcp_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  u32 cwnd_multiplier, tmp_time, mtu, max_gso_size;
  uword memory_size;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "preallocated-connections %d",
		    &tcp_cfg.preallocated_connections))
	;
      else if (unformat (input, "preallocated-half-open-connections %d",
			 &tcp_cfg.preallocated_half_open_connections))
	;
      else if (unformat (input, "buffer-fail-fraction %f",
			 &tcp_cfg.buffer_fail_fraction))
	;
      else if (unformat (input, "max-rx-fifo %U", unformat_memory_size,
			 &memory_size))
	{
	  if (memory_size >= 0x100000000)
	    {
	      return clib_error_return
		(0, "max-rx-fifo %llu (0x%llx) too large", memory_size,
		 memory_size);
	    }
	  tcp_cfg.max_rx_fifo = memory_size;
	}
      else if (unformat (input, "min-rx-fifo %U", unformat_memory_size,
			 &memory_size))
	{
	  if (memory_size >= 0x100000000)
	    {
	      return clib_error_return
		(0, "min-rx-fifo %llu (0x%llx) too large", memory_size,
		 memory_size);
	    }
	  tcp_cfg.min_rx_fifo = memory_size;
	}
      else if (unformat (input, "mtu %u", &mtu))
	tcp_cfg.default_mtu = mtu;
      else if (unformat (input, "rwnd-min-update-ack %d",
			 &tcp_cfg.rwnd_min_update_ack))
	;
      else if (unformat (input, "initial-cwnd-multiplier %u",
			 &cwnd_multiplier))
	tcp_cfg.initial_cwnd_multiplier = cwnd_multiplier;
      else if (unformat (input, "no-tx-pacing"))
	tcp_cfg.enable_tx_pacing = 0;
      else if (unformat (input, "tso"))
	tcp_cfg.allow_tso = 1;
      else if (unformat (input, "no-csum-offload"))
	tcp_cfg.csum_offload = 0;
      else if (unformat (input, "max-gso-size %u", &max_gso_size))
	tcp_cfg.max_gso_size = clib_min (max_gso_size, TCP_MAX_GSO_SZ);
      else if (unformat (input, "cc-algo %U", unformat_tcp_cc_algo,
			 &tcp_cfg.cc_algo))
	;
      else if (unformat (input, "%U", unformat_tcp_cc_algo_cfg))
	;
      else if (unformat (input, "closewait-time %u", &tmp_time))
	tcp_cfg.closewait_time = tmp_time / TCP_TIMER_TICK;
      else if (unformat (input, "timewait-time %u", &tmp_time))
	tcp_cfg.timewait_time = tmp_time / TCP_TIMER_TICK;
      else if (unformat (input, "finwait1-time %u", &tmp_time))
	tcp_cfg.finwait1_time = tmp_time / TCP_TIMER_TICK;
      else if (unformat (input, "finwait2-time %u", &tmp_time))
	tcp_cfg.finwait2_time = tmp_time / TCP_TIMER_TICK;
      else if (unformat (input, "lastack-time %u", &tmp_time))
	tcp_cfg.lastack_time = tmp_time / TCP_TIMER_TICK;
      else if (unformat (input, "closing-time %u", &tmp_time))
	tcp_cfg.closing_time = tmp_time / TCP_TIMER_TICK;
      else if (unformat (input, "cleanup-time %u", &tmp_time))
	tcp_cfg.cleanup_time = tmp_time / 1000.0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (tcp_config_fn, "tcp");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
