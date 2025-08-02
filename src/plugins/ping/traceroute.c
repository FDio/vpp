/*
 * Copyright (c) 2025 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/ip/ip4_forward.h>
#include <vnet/ip/ip6_forward.h>
#include <vppinfra/format_table.h>
#include <vnet/tcp/tcp.h>
#include <vnet/session/session.h>

#include <ping/common.h>
#include <ping/ping.h>
#include <ping/traceroute.h>

/** ANSI escape code. */
#define ESC "\x1b"

/** ANSI Control Sequence Introducer. */
#define CSI ESC "["

traceroute_main_t traceroute_main;

typedef struct
{
  u32 extracted_id;
  u32 cli_process_id;
  u8 hop;
  u8 repeat;
} traceroute_trace_t;

u8 *
format_traceroute_trace (u8 *s, va_list *va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  traceroute_trace_t *t = va_arg (*va, traceroute_trace_t *);

  s = format (s, "Packet back, hop: %d, repeat: %d", t->hop, t->repeat);
  if (t->cli_process_id == CLI_UNKNOWN_NODE)
    s = format (s, " (unknown cli node, %d)", t->extracted_id);
  else
    s = format (s, " send to cli node %d", t->cli_process_id);
  return s;
}

static u8 *
format_traceroute_result (u8 *s, va_list *args)
{
  traceroute_result_t res = va_arg (*args, traceroute_result_t);

  switch (res)
    {
#define _(v, n)                                                               \
  case TRACEROUTE_##v:                                                        \
    s = format (s, "%s", n);                                                  \
    break;
      foreach_traceroute_result
#undef _
    }

  return (s);
}

static u8 *
format_time_subsecond (u8 *s, va_list *args)
{
  f64 time = va_arg (*args, f64);
  if (time < 1e-6)
    return format (s, "%5.3f ns", time * 1e9);
  else if (time < 1e-3)
    return format (s, "%5.3f us", time * 1e6);
  else if (time < 1.0)
    return format (s, "%5.3f ms", time * 1e3);
  return format (s, "%5.3f s ", time);
}

static u8 *
format_time_series (u8 *s, va_list *args)
{
  f64 *times = va_arg (*args, f64 *);
  int size = va_arg (*args, int);
  if (size <= 0)
    return s;
  else if (size == 1)
    return format (s, "%U", format_time_subsecond, times[0]);

  f64 min = times[0];
  f64 max = times[0];
  f64 mean = 0.0;
  for (int i = 0; i < size; i++)
    {
      if (times[i] < min)
	min = times[i];
      if (times[i] > max)
	max = times[i];
      mean += times[i];
    }
  mean /= size;
  return format (s, "%U", format_time_subsecond, mean);
}

static traceroute_result_t
send_ip46_traceroute (vlib_main_t *vm, traceroute_run_t *trr, u64 *time_sent)
{
  traceroute_args_t *args = trr->args;
  vlib_buffer_t *b0;
  u32 bi0 = 0;
  u32 n_buf0 = 0;
  u16 seq_host =
    get_seq_from_hop_and_repeat (trr->current_hop, trr->current_repeat);
  int err = TRACEROUTE_OK;
  u8 is_ip6 = (trr->args->dest.version == AF_IP6);

  n_buf0 = vlib_buffer_alloc (vm, &bi0, 1);
  if (n_buf0 < 1)
    ERROR_OUT (TRACEROUTE_ALLOC_FAIL);

  b0 = vlib_get_buffer (vm, bi0);

  vnet_buffer (b0)->sw_if_index[VLIB_RX] = args->sw_if_index;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = args->fib_index;

  /* we compensate for the ttl decrement done in ip46_rewrite */
  int l4_header_offset = ip46_fill_l3_header (
    &args->dest.ip, b0, args->l4_proto, trr->current_hop + 1, is_ip6);

  /* set the src address in the buffer */
  if (!ip46_set_src_address (args->sw_if_index, b0, is_ip6))
    ERROR_OUT (TRACEROUTE_NO_SRC_ADDRESS);

  if (args->verbose)
    ip46_print_buffer_src_address (vm, b0, is_ip6);

  u16 payload_len =
    ip46_fill_l4_payload (vm, b0, l4_header_offset, args->l4_proto, seq_host,
			  trr->id, args->data_len, args->port, is_ip6);

  ip46_fix_len_and_csum (vm, b0, l4_header_offset, args->l4_proto, payload_len,
			 is_ip6);

  u32 node_index = ip4_lookup_node.index;
  if (is_ip6)
    {
      node_index = ip6_lookup_node.index;
      if (args->dest.ip.ip6.as_u32[0] == clib_host_to_net_u32 (0xff020000))
	{
	  node_index = ip6_rewrite_mcast_node.index;
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = args->sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = args->sw_if_index;
	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
	    ip6_link_get_mcast_adj (args->sw_if_index);
	}
    }
  int n_sent = ip46_enqueue_packet (vm, b0, trr->args->burst, node_index);
  if (n_sent < trr->args->burst)
    err = TRACEROUTE_NO_BUFFERS;

  *time_sent = clib_cpu_time_now ();

done:
  if (err != TRACEROUTE_OK)
    {
      if (n_buf0 > 0)
	vlib_buffer_free (vm, &bi0, 1);
    }
  return err;
}

static traceroute_reply_result_t
parse_ip46_traceroute_reply (vlib_main_t *vm, u32 bi0, u8 sent_l4_proto,
			     u32 expected_hash, u64 time_sent,
			     ip_address_t *addr, f64 *rtt, int is_ip6)
{
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  cli_msg_t *cli_msg = vnet_buffer_cli_msg (b0);
  icmp46_header_t *icmp46;
  tcp_header_t *tcp0;
  u8 l4_proto;
  ;
  u8 stop = 0;

  if (cli_msg->hash != expected_hash)
    return TRACEROUTE_REPLY_BAD_HASH;

  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
      ip_address_set (addr, &ip6->src_address, AF_IP6);
      l4_proto = ip6->protocol;
      icmp46 = ip6_next_header (ip6);
    }
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
      ip_address_set (addr, &ip4->src_address, AF_IP4);
      l4_proto = ip4->protocol;
      icmp46 = ip4_next_header (ip4);
    }
  tcp0 = (tcp_header_t *) icmp46;

  f64 clocks_per_second = ((f64) vm->clib_time.clocks_per_second);
  *rtt = ((f64) (cli_msg->time_now - time_sent)) / clocks_per_second;

  switch (sent_l4_proto)
    {
    case IP_PROTOCOL_ICMP6:
      stop = icmp46->type == ICMP6_echo_reply;
      break;
    case IP_PROTOCOL_ICMP:
      stop = icmp46->type == ICMP4_echo_reply;
      break;
    case IP_PROTOCOL_TCP:
      stop = l4_proto == IP_PROTOCOL_TCP && tcp_rst (tcp0) && tcp_ack (tcp0);
      break;
    case IP_PROTOCOL_UDP:
      stop = (is_ip6 && icmp46->type ==
			  ICMP6_destination_unreachable_port_unreachable) ||
	     (!is_ip6 &&
	      icmp46->type == ICMP4_destination_unreachable_port_unreachable);
      break;
    }

  return stop ? TRACEROUTE_REPLY_GOOD_STOP : TRACEROUTE_REPLY_GOOD_CONTINUE;
}

void
vlib_cli_output_no_cr (vlib_main_t *vm, char *fmt, ...)
{
  vlib_process_t *cp = vlib_get_current_process (vm);
  va_list va;
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);

  /* some format functions might return 0
   * e.g. show int addr */
  if (NULL == s)
    return;

  if ((!cp) || (!cp->output_function))
    fformat (stdout, "%v", s);
  else
    cp->output_function (cp->output_function_arg, s, vec_len (s));

  vec_free (s);
}

static u8
run_ip46_traceroute_one_hop (vlib_main_t *vm, traceroute_run_t *trr)
{
  u8 repeat = trr->args->repeat;
  u8 *rep = &trr->current_repeat;

  ip_address_t dest;
  f64 rtt[trr->args->burst];
  u8 dest_set = 0;
  u8 stop_repeat = 0;
  u8 stop_hop = 0;

  vlib_cli_output_no_cr (vm, " %3d  ", trr->current_hop);

  for (*rep = 0; *rep < repeat; (*rep)++)
    {
      ip_address_t tmp_dest;
      f64 sleep_interval;
      f64 time_sent = vlib_time_now (vm);
      u64 clib_time_sent;
      u32 received = 0;
      u16 current_seq = get_seq_from_hop_and_repeat (trr->current_hop, *rep);
      uword current_hash = id_seq_hash (trr->id, current_seq);
      set_hash_by_run_id (vm, trr->id, current_hash);

      u8 got_reply = 0;
      traceroute_result_t res =
	send_ip46_traceroute (vm, trr, &clib_time_sent);

      if (res != TRACEROUTE_OK)
	vlib_cli_output (vm, "\nFailed: %U", format_traceroute_result, res);
      else
	trr->n_packets_sent += trr->args->burst;

      /* Collect and print the responses until it is time to send a next
       * packet.
       */
      while (!stop_repeat &&
	     (sleep_interval =
		time_sent + trr->args->interval - vlib_time_now (vm)) > 0.0)
	{
	  uword event_type, *event_data = 0;
	  vlib_process_wait_for_event_or_clock (vm, sleep_interval);
	  event_type = vlib_process_get_events (vm, &event_data);
	  int is_ip6 = 0;
	  switch (event_type)
	    {
	    case ~0: /* no events => timeout */
	      break;
	    case RESPONSE_IP6:
	      is_ip6 = 1;
	      /* fall-through */
	    case RESPONSE_IP4:
	      for (int ii = 0; ii < vec_len (event_data); ii++)
		{
		  u32 bi0 = event_data[ii];
		  traceroute_reply_result_t s = parse_ip46_traceroute_reply (
		    vm, event_data[ii], trr->args->l4_proto, current_hash,
		    clib_time_sent, &tmp_dest, &rtt[received++], is_ip6);
		  stop_hop |= (s == TRACEROUTE_REPLY_GOOD_STOP);
		  got_reply |= (s == TRACEROUTE_REPLY_GOOD_STOP ||
				s == TRACEROUTE_REPLY_GOOD_CONTINUE);

		  if (bi0)
		    vlib_buffer_free (vm, &bi0, 1);

		  if (!got_reply)
		    continue;

		  if (!dest_set)
		    {
		      ip_address_copy (&dest, &tmp_dest);
		      dest_set = 1;
		      vlib_cli_output_no_cr (vm, "%15U  ", format_ip_address,
					     &dest);
		    }
		  else if (!ip_address_cmp (&dest, &tmp_dest))
		    {
		      vlib_cli_output (vm,
				       "\nReceived reply from %U, expected %U",
				       format_ip_address, &tmp_dest,
				       format_ip_address, &dest);
		    }
		}
	      break;
	    case UNIX_CLI_PROCESS_EVENT_READ_READY:
	    case UNIX_CLI_PROCESS_EVENT_QUIT:
	      /* someone pressed a key, abort */
	      stop_repeat = 1;
	      stop_hop = 1;
	      break;
	    }
	  vec_free (event_data);
	}

      trr->n_packets_received += received;

      if (!got_reply)
	{
	  if (stop_repeat)
	    break;
	  if (dest_set)
	    vlib_cli_output_no_cr (vm, "%8s  ", "*");
	  continue;
	}

      if (dest_set)
	vlib_cli_output_no_cr (vm, "%U  ", format_time_series, rtt, received);

      if (stop_repeat)
	break;
    }

  if (!dest_set)
    {
      vlib_cli_output_no_cr (vm, "%15s  ", "*");
      for (int i = 0; i < *rep; i++)
	vlib_cli_output_no_cr (vm, "%8s  ", "*");
    }

  if (stop_repeat)
    vlib_cli_output (vm, "\nAborted due to a keypress.");
  else
    vlib_cli_output (vm, "\n");
  return stop_hop;
}

/*
 * Perform the traceroute run with the given parameters in the current CLI
 * process.
 */

static void
run_ip46_traceroute (vlib_main_t *vm, traceroute_args_t *args)
{
  uword curr_proc = vlib_current_process (vm);
  traceroute_run_t trr = {
    .args = args,
    .cli_process_id = curr_proc,
  };
  static u32 rand_seed = 0;
  u16 id;
  u8 *hop = &trr.current_hop;

  if (PREDICT_FALSE (!rand_seed))
    rand_seed = random_default_seed ();

  id = random_u32 (&rand_seed) & 0xffff;

  if (args->l4_proto == IP_PROTOCOL_TCP)
    {
      if (args->dest.version == AF_IP4)
	vnet_feature_enable_disable ("ip4-punt", "ip4-tcp-punted", 0, 1, 0, 0);
      else
	vnet_feature_enable_disable ("ip6-punt", "ip6-tcp-punted", 0, 1, 0, 0);
    }

  while (get_cli_process_id_by_run_id (vm, id) != CLI_UNKNOWN_NODE)
    {
      vlib_cli_output (vm, "ID collision at %d, new random", id);
      id = random_u32 (&rand_seed) & 0xffff;
    }

  set_cli_process_id_by_run_id (vm, id, curr_proc);

  trr.id = id;
  vec_add1 (traceroute_main.active_runs, &trr);

  vlib_cli_output (vm, "traceroute to %U, %d hops max", format_ip_address,
		   args->dest, args->max_hops);

  for (*hop = 1; *hop <= args->max_hops; (*hop)++)
    if (run_ip46_traceroute_one_hop (vm, &trr))
      break;

  clear_cli_process_id_by_run_id (vm, id);

  if (args->l4_proto == IP_PROTOCOL_TCP)
    {
      if (args->dest.version == AF_IP4)
	vnet_feature_enable_disable ("ip4-punt", "ip4-tcp-punted", 0, 0, 0, 0);
      else
	vnet_feature_enable_disable ("ip6-punt", "ip6-tcp-punted", 0, 0, 0, 0);
    }
}

static clib_error_t *
traceroute_ip_address (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  traceroute_args_t args = {
    .dest = { .version = AF_IP4 },
    .interval = TRACEROUTE_DEFAULT_INTERVAL,
    .fib_index = ~0,
    .sw_if_index = ~0,
    .max_hops = 30,
    .repeat = 3,
    .data_len = 60,
    .port = 80,
    .l4_proto = IP_PROTOCOL_ICMP,
    .burst = 1,
    .verbose = 0,
  };
  u32 table_id = 0;
  u8 has_addr = 0;
  u8 is_ip6 = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (!has_addr &&
	  unformat (line_input, "%U", unformat_ip6_address, &args.dest.ip.ip6))
	has_addr = is_ip6 = 1;
      else if (!has_addr && unformat (line_input, "%U", unformat_ip4_address,
				      &args.dest.ip.ip4))
	has_addr = 1;
      else if (unformat (line_input, "source %U", unformat_vnet_sw_interface,
			 vnm, &args.sw_if_index))
	;
      else if (unformat (line_input, "port %D", sizeof (args.port),
			 &args.port))
	;
      else if (unformat (line_input, "table-id %u", &table_id))
	;
      else if (unformat (line_input, "max-hops %D", sizeof (args.max_hops),
			 &args.max_hops))
	;
      else if (unformat (line_input, "repeat %D", sizeof (args.repeat),
			 &args.repeat))
	;
      else if (unformat (line_input, "size %u", &args.data_len))
	;
      else if (unformat (line_input, "interval %f", &args.interval))
	;
      else if (unformat (line_input, "burst %D", sizeof (args.burst),
			 &args.burst))
	;
      else if (unformat (line_input, "icmp"))
	args.l4_proto = IP_PROTOCOL_ICMP;
      else if (unformat (line_input, "tcp"))
	args.l4_proto = IP_PROTOCOL_TCP;
      else if (unformat (line_input, "udp"))
	args.l4_proto = IP_PROTOCOL_UDP;
      else if (unformat (input, "verbose"))
	args.verbose = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!has_addr)
    return clib_error_return (0, "expecting either IPv4 or IPv6 address");

  if (is_ip6)
    {
      args.dest.version = AF_IP6;
      if (args.l4_proto == IP_PROTOCOL_ICMP)
	args.l4_proto = IP_PROTOCOL_ICMP6;
    }

  if (args.burst < 1)
    return clib_error_return (0, "burst size must be at least 1");

  args.fib_index = ip46_fib_index_from_table_id (table_id, is_ip6);
  if (args.fib_index == ~0)
    return clib_error_return (0, "no FIB table for lookup");

  if (args.sw_if_index == ~0)
    args.sw_if_index =
      ip46_get_resolving_interface (args.fib_index, &args.dest.ip, is_ip6);
  if (args.sw_if_index == ~0)
    return clib_error_return (0, "no egress interface for the destination");

  u8 old_pager = vlib_unix_cli_enable_disable_pager (0);
  run_ip46_traceroute (vm, &args);
  vlib_unix_cli_enable_disable_pager (old_pager);

  return 0;
}

VLIB_CLI_COMMAND (traceroute_command, static) = {
  .path = "traceroute",
  .function = traceroute_ip_address,
  .short_help =
    "traceroute <ip-addr> [icmp|tcp|udp] [port <port:80>]"
    " [source <interface>] [max-hops <hops:30>] [repeat <repeat:3>]"
    " [size <pktsize:60>] [interval <sec:1>] [burst <burst:1>]"
    " [table-id <id:0>] [verbose]",
  .is_mp_safe = 1,
};

static clib_error_t *
traceroute_init (vlib_main_t *vm)
{
  clib_error_t *error = 0;
  session_enable_disable_args_t args = {
    .rt_engine_type = RT_BACKEND_ENGINE_DISABLE,
    .is_en = 1,
  };

  tcp_punt_unknown (vm, 0, 1);
  tcp_punt_unknown (vm, 1, 1);
  error = vnet_session_enable_disable (vm, &args);

  return error;
}

VLIB_INIT_FUNCTION (traceroute_init) = {
  .runs_after = VLIB_INITS ("ping_traceroute_common_init"),
};
