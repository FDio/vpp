/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/ip/ip.h>
#include <math.h>

/* 20 byte TCP + 12 bytes of options (timestamps) = 32 bytes */
typedef struct {
  u64 sequence_number;
  f64 time_stamp;
  u32 stream_index;
  u32 unused[3];
} __attribute__ ((packed)) rtt_test_header_t;

typedef struct {
  ip4_header_t ip4;
  rtt_test_header_t rtt;
  u8 payload[0];
} __attribute__ ((packed)) rtt_test_packet_t;

typedef struct {
  ip4_address_t src_address, dst_address;

  f64 n_packets_to_send;

  f64 send_rate_bits_per_second;
  f64 send_rate_packets_per_second;

  f64 packet_accumulator;

  u64 n_packets_sent;

  /* [0] from past, [1] in sequence, [2] from future. */
  u64 n_packets_received[3];

  f64 tx_time_stream_created;
  f64 tx_time_last_sent;

  f64 rx_ack_times[2];

  u64 rx_expected_sequence_number;

  u32 n_bytes_payload;

  /* Including IP & L2 header. */
  u32 n_bytes_per_packet_on_wire;

  f64 ave_rtt, rms_rtt, rtt_count;

  u32 max_n_rx_ack_dts;
  f64 * rx_ack_dts;

  u32 * rtt_histogram;

  vlib_packet_template_t packet_template;
} rtt_test_stream_t;

typedef struct {
  /* Size of encapsulation (e.g. 14 for ethernet). */
  u32 n_encap_bytes;

  u32 is_sender;

  u32 verbose;

  f64 rms_histogram_units;

  rtt_test_stream_t stream_history[32];
  u32 stream_history_index;

  rtt_test_stream_t * stream_pool;

  vlib_packet_template_t ack_packet_template;
  u16 ack_packet_template_ip4_checksum;
} rtt_test_main_t;

/* Use 2 IP protocols 253/254 which are assigned for experimental testing. */
typedef enum {
  RTT_TEST_IP_PROTOCOL_DATA = 253,
  RTT_TEST_IP_PROTOCOL_ACK = 254,
} rtt_test_ip_protcol_t;

always_inline void
rtt_test_stream_free (vlib_main_t * vm, rtt_test_main_t * tm, rtt_test_stream_t * s)
{
  vlib_packet_template_free (vm, &s->packet_template);
  memset (&s->packet_template, 0, sizeof (s->packet_template));

  tm->stream_history[tm->stream_history_index++] = s[0];
  if (tm->stream_history_index >= ARRAY_LEN (tm->stream_history))
    tm->stream_history_index = 0;

  s->rtt_histogram = 0;
  pool_put (tm->stream_pool, s);
}

rtt_test_main_t rtt_test_main;

#define foreach_rtt_test_error				\
  _ (packets_received, "packets received")		\
  _ (listener_acks_dropped, "listener acks dropped")	\
  _ (unknown_stream, "unknown stream")

typedef enum {
#define _(sym,str) RTT_TEST_ERROR_##sym,
  foreach_rtt_test_error
#undef _
  RTT_TEST_N_ERROR,
} rtt_test_error_t;

static char * rtt_test_error_strings[] = {
#define _(sym,string) string,
  foreach_rtt_test_error
#undef _
};

typedef enum {
  RTT_TEST_RX_NEXT_DROP,
  RTT_TEST_RX_NEXT_ECHO,
  RTT_TEST_RX_N_NEXT,
} rtt_test_rx_next_t;

static uword
rtt_test_rx_data (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  rtt_test_main_t * tm = &rtt_test_main;
  uword n_packets = frame->n_vectors;
  u32 * from, * to_drop, * to_echo;
  u32 n_left_from, n_left_to_drop, n_left_to_echo;

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, RTT_TEST_RX_NEXT_DROP, to_drop, n_left_to_drop);
      vlib_get_next_frame (vm, node, RTT_TEST_RX_NEXT_ECHO, to_echo, n_left_to_echo);

      while (n_left_from > 0 && n_left_to_drop > 0 && n_left_to_echo > 0)
	{
	  vlib_buffer_t * p0;
	  ip4_header_t * ip0;
	  rtt_test_header_t * r0;
	  rtt_test_packet_t * ack0;
	  ip_csum_t sum0;
	  u32 bi0;
      
	  bi0 = to_drop[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_drop += 1;
	  n_left_to_drop -= 1;
      
	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);

	  r0 = ip4_next_header (ip0);

	  p0->error = node->errors[RTT_TEST_ERROR_listener_acks_dropped];

	  ack0 = vlib_packet_template_get_packet (vm, &tm->ack_packet_template, to_echo);

	  to_echo += 1;
	  n_left_to_echo -= 1;

	  sum0 = tm->ack_packet_template_ip4_checksum;

	  ack0->ip4.src_address = ip0->dst_address;
	  sum0 = ip_csum_add_even (sum0, ack0->ip4.src_address.as_u32);

	  ack0->ip4.dst_address = ip0->src_address;
	  sum0 = ip_csum_add_even (sum0, ack0->ip4.dst_address.as_u32);

	  ack0->ip4.checksum = ip_csum_fold (sum0);

	  ASSERT (ack0->ip4.checksum == ip4_header_checksum (&ack0->ip4));

	  ack0->rtt = r0[0];
	}
  
      vlib_put_next_frame (vm, node, RTT_TEST_RX_NEXT_DROP, n_left_to_drop);
      vlib_put_next_frame (vm, node, RTT_TEST_RX_NEXT_ECHO, n_left_to_echo);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (rtt_test_rx_data_node) = {
  .function = rtt_test_rx_data,
  .name = "rtt-test-rx-data",

  .vector_size = sizeof (u32),

  .n_next_nodes = RTT_TEST_RX_N_NEXT,
  .next_nodes = {
    [RTT_TEST_RX_NEXT_DROP] = "error-drop",
    [RTT_TEST_RX_NEXT_ECHO] = "ip4-input-no-checksum",
  },

  .n_errors = RTT_TEST_N_ERROR,
  .error_strings = rtt_test_error_strings,
};

static uword
rtt_test_rx_ack (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * frame)
{
  rtt_test_main_t * tm = &rtt_test_main;
  uword n_packets = frame->n_vectors;
  u32 * from, * to_drop;
  u32 n_left_from, n_left_to_drop;
  f64 now = vlib_time_now (vm);
  vlib_node_runtime_t * error_node = vlib_node_get_runtime (vm, rtt_test_rx_data_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = n_packets;
  
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, RTT_TEST_RX_NEXT_DROP, to_drop, n_left_to_drop);

      while (n_left_from > 0 && n_left_to_drop > 0)
	{
	  vlib_buffer_t * p0;
	  ip4_header_t * ip0;
	  rtt_test_header_t * r0;
	  rtt_test_stream_t * s0;
	  u32 bi0, i0;
	  u64 rseq0, eseq0;
      
	  i0 = 0;
	  bi0 = to_drop[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_drop += 1;
	  n_left_to_drop -= 1;
      
	  p0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (p0);

	  r0 = ip4_next_header (ip0);

	  p0->error = error_node->errors[RTT_TEST_ERROR_listener_acks_dropped];

	  if (pool_is_free_index (tm->stream_pool, r0->stream_index))
	    goto bad_stream_x1;

	  s0 = pool_elt_at_index (tm->stream_pool, r0->stream_index);

	  rseq0 = r0->sequence_number;
	  eseq0 = s0->rx_expected_sequence_number;

	  if (rseq0 != eseq0)
	    goto out_of_sequence_x1;

	  s0->rx_expected_sequence_number = rseq0 + 1;
	  s0->n_packets_received[1] += 1;
	  
	  vec_add1 (s0->rx_ack_dts, now - r0->time_stamp);
	  _vec_len (s0->rx_ack_dts) -= _vec_len (s0->rx_ack_dts) >= s0->max_n_rx_ack_dts;

	  i0 = rseq0 != 0;
	  s0->rx_ack_times[i0] = now;
	  continue;

	bad_stream_x1:
	  {
	    ELOG_TYPE_DECLARE (e) = {
	      .format = "rtt-test: unknown stream %d",
	      .format_args = "i4",
	    };
	    struct { u32 stream; } * ed;
	    ed = ELOG_DATA (&vm->elog_main, e);
	    ed->stream = r0->stream_index;
	  }
	  continue;

	out_of_sequence_x1:
	  i0 = (r0->sequence_number < s0->rx_expected_sequence_number
		? 0
		: (i0 ? 1 : 2));
	  if (i0 != 1)
	    {
	      ELOG_TYPE_DECLARE (e) = {
		.format = "rtt-test: out-of-seq expected %Ld got %Ld",
		.format_args = "i8i8",
	      };
	      struct { u64 expected, got; } * ed;
	      ed = ELOG_DATA (&vm->elog_main, e);
	      ed->expected = s0->rx_expected_sequence_number;
	      ed->got = r0->sequence_number;
	    }

	  s0->rx_expected_sequence_number = i0 > 0 ? r0->sequence_number + 1 : s0->rx_expected_sequence_number;

	  s0->n_packets_received[i0] += 1;

	  i0 = r0->sequence_number > 0;
	  s0->rx_ack_times[i0] = now;
	}
  
      vlib_put_next_frame (vm, node, RTT_TEST_RX_NEXT_DROP, n_left_to_drop);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (rtt_test_rx_ack_node) = {
  .function = rtt_test_rx_ack,
  .name = "rtt-test-rx-ack",

  .vector_size = sizeof (u32),

  .n_next_nodes = RTT_TEST_RX_N_NEXT,
  .next_nodes = {
    [RTT_TEST_RX_NEXT_DROP] = "error-drop",
    [RTT_TEST_RX_NEXT_ECHO] = "ip4-input-no-checksum",
  },
};

always_inline void
rtt_test_tx_packets (vlib_main_t * vm,
		     vlib_node_runtime_t * node,
		     rtt_test_stream_t * s,
		     f64 time_now,
		     uword n_packets_to_send)
{
  u32 * to_next, n_this_frame, n_left, n_trace, next, i;
  rtt_test_packet_t * p;
  vlib_buffer_t * b;

  next = 0;
  while (n_packets_to_send > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left);

      n_this_frame = clib_min (n_packets_to_send, n_left);

      for (i = 0; i < n_this_frame; i++)
	{
	  p = vlib_packet_template_get_packet (vm, &s->packet_template, to_next + i);
	  p->rtt.time_stamp = time_now;
	  p->rtt.sequence_number = s->n_packets_sent + i;
	}

      n_trace = vlib_get_trace_count (vm, node);
      if (n_trace > 0)
	{
	  u32 n = clib_min (n_trace, n_this_frame);

	  vlib_set_trace_count (vm, node, n_trace - n);
	  for (i = 0; i < n_this_frame; i++)
	    {
	      b = vlib_get_buffer (vm, to_next[i]);
	      vlib_trace_buffer (vm, node, next, b, /* follow_chain */ 1);
	    }
	}

      s->n_packets_sent += n_this_frame;
      n_packets_to_send -= n_this_frame;
      n_left -= n_this_frame;

      vlib_put_next_frame (vm, node, next, n_left);
    }
}

always_inline uword
rtt_test_stream_is_done (rtt_test_stream_t * s, f64 time_now)
{
  /* Need to send more packets? */
  if (s->n_packets_to_send > 0 && s->n_packets_sent < s->n_packets_to_send)
    return 0;

  /* Received everything we've sent? */
  if (s->n_packets_received[0] + s->n_packets_received[1] + s->n_packets_received[2] >= s->n_packets_to_send)
    return 1;

  /* No ACK received after 5 seconds of sending. */
  if (s->rx_ack_times[0] == 0
      && s->n_packets_sent > 0
      && time_now - s->tx_time_stream_created > 5)
    return 1;

  /* No ACK received after 5 seconds of waiting? */
  if (time_now - s->rx_ack_times[1] > 5)
    return 1;

  return 0;
}

static_always_inline uword
rtt_test_tx_stream (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    rtt_test_stream_t * s)
{
  rtt_test_main_t * tm = &rtt_test_main;
  uword n_packets;
  f64 time_now, dt;

  time_now = vlib_time_now (vm);

  if (rtt_test_stream_is_done (s, time_now))
    {
      {
	ELOG_TYPE_DECLARE (e) = {
	  .format = "rtt-test: done stream %d",
	  .format_args = "i4",
	};
	struct { u32 stream_index; } * ed;
	ed = ELOG_DATA (&vm->elog_main, e);
	ed->stream_index = s - tm->stream_pool;
      }

      rtt_test_stream_free (vm, tm, s);
      if (pool_elts (tm->stream_pool) == 0)
	vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_DISABLED);
      return 0;
    }

  /* Apply rate limit. */
  dt = time_now - s->tx_time_last_sent;
  s->tx_time_last_sent = time_now;

  n_packets = VLIB_FRAME_SIZE;
  if (s->send_rate_packets_per_second > 0)
    {
      s->packet_accumulator += dt * s->send_rate_packets_per_second;
      n_packets = s->packet_accumulator;

      /* Never allow accumulator to grow if we get behind. */
      s->packet_accumulator -= n_packets;
    }

  /* Apply fixed limit. */
  if (s->n_packets_to_send > 0
      && s->n_packets_sent + n_packets > s->n_packets_to_send)
    n_packets = s->n_packets_to_send - s->n_packets_sent;

  /* Generate up to one frame's worth of packets. */
  if (n_packets > VLIB_FRAME_SIZE)
    n_packets = VLIB_FRAME_SIZE;

  if (n_packets > 0)
    rtt_test_tx_packets (vm, node, s, time_now, n_packets);

  return n_packets;
}

static uword
rtt_test_tx (vlib_main_t * vm,
	     vlib_node_runtime_t * node,
	     vlib_frame_t * frame)
{
  rtt_test_main_t * tm = &rtt_test_main;
  rtt_test_stream_t * s;
  uword n_packets = 0;

  pool_foreach (s, tm->stream_pool, ({
    n_packets += rtt_test_tx_stream (vm, node, s);
  }));

  return n_packets;
}

VLIB_REGISTER_NODE (rtt_test_tx_node) = {
  .function = rtt_test_tx,
  .name = "rtt-test-tx",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,

  .vector_size = sizeof (u32),

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "ip4-input-no-checksum",
  },
};

static void rtt_test_stream_compute (rtt_test_main_t * tm, rtt_test_stream_t * s)
{
  int i;

  /* Compute average and standard deviation of RTT time. */
  if (vec_len (s->rx_ack_dts) == 0)
    return;

  {
    f64 c = vec_len (s->rx_ack_dts);

    s->ave_rtt = s->rms_rtt = 0;
    vec_foreach_index (i, s->rx_ack_dts)
      {
	f64 dt = s->rx_ack_dts[i];
	s->ave_rtt += dt;
	s->rms_rtt += dt*dt;
      }
    s->ave_rtt /= c;
    s->rms_rtt = sqrt (s->rms_rtt / c - s->ave_rtt*s->ave_rtt);
    s->rtt_count = c;
  }

  if (! tm->rms_histogram_units)
    tm->rms_histogram_units = .1;

  /* Generate historgram. */
  vec_foreach_index (i, s->rx_ack_dts)
    {
      i32 bin = flt_round_nearest ((s->rx_ack_dts[i] - s->ave_rtt) / (tm->rms_histogram_units * s->rms_rtt));
      u32 ib = bin < 0 ? 2*(-bin) + 1 : 2 *bin;
      vec_validate (s->rtt_histogram, ib);
      s->rtt_histogram[ib] += 1;
    }  

  if (s->n_packets_sent >= s->n_packets_to_send)
    vec_free (s->rx_ack_dts);
}

static clib_error_t *
do_plot_stream (rtt_test_main_t * tm, rtt_test_stream_t * s, char * file_name, int n)
{
  FILE * out;
  char * f;
  clib_error_t * error = 0;
  u32 i;

  f = (char *) format (0, "%s.%d%c", file_name, n, 0);
  out = fopen (f, "w");

  if (! out)
    {
      error = clib_error_return_unix (0, "open `%s'", f);
      goto done;
    }

  rtt_test_stream_compute (tm, s);
  vec_foreach_index (i, s->rtt_histogram)
    {
      if (s->rtt_histogram[i] > 0)
	{
	  i32 bi = (i & 1) ? -(i/2) : (i/2);
	  f64 dt = s->ave_rtt + (bi * tm->rms_histogram_units * s->rms_rtt);
	  fformat (out, "%.6e %.6e\n",
		   dt, s->rtt_histogram[i] / s->rtt_count);
	}
    }
  clib_warning ("wrote `%s'", f);

 done:
  vec_free (f);
  fclose (out);
  return error;
}

static clib_error_t *
do_plot (rtt_test_main_t * tm, char * file_name)
{
  rtt_test_stream_t * s;
  clib_error_t * error = 0;
  int i, n;

  n = 0;
  for (i = 0; i < ARRAY_LEN (tm->stream_history); i++)
    {
      s = tm->stream_history + i;
      if (s->n_packets_sent > 0)
	{
	  error = do_plot_stream (tm, s, file_name, n++);
	  if (error)
	    return error;
	}
    }

  pool_foreach (s, tm->stream_pool, ({
    error = do_plot_stream (tm, s, file_name, n++);
    if (error)
      return error;
  }));

  return error;
}

static clib_error_t *
rtt_test_command (vlib_main_t * vm,
		  unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  rtt_test_main_t * tm = &rtt_test_main;
  rtt_test_stream_t * s;

  {
    char * file_name;

    if (unformat (input, "plot %s", &file_name))
      {
	clib_error_t * e = do_plot (tm, file_name);
	vec_free (file_name);
	return e;
      }
  }

  pool_get (tm->stream_pool, s);

  memset (s, 0, sizeof (s[0]));
  s->n_packets_to_send = 1;
  s->send_rate_bits_per_second = 1e6;
  s->n_bytes_payload = 1448;
  s->max_n_rx_ack_dts = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U -> %U",
		    unformat_ip4_address, &s->src_address,
		    unformat_ip4_address, &s->dst_address))
	;
      else if (unformat (input, "count %f", &s->n_packets_to_send))
	;
      else if (unformat (input, "hist %d", &s->max_n_rx_ack_dts))
	;
      else if (unformat (input, "rate %f", &s->send_rate_bits_per_second))
	;
      else if (unformat (input, "size %d", &s->n_bytes_payload))
	;
      else
	return clib_error_return (0, "parse error: %U", format_unformat_error, input);
    }

  if (pool_elts (tm->stream_pool) == 1)
    vlib_node_set_state (vm, rtt_test_tx_node.index, VLIB_NODE_STATE_POLLING);

  if (! s->max_n_rx_ack_dts)
    s->max_n_rx_ack_dts = s->n_packets_to_send;
  vec_validate (s->rx_ack_dts, s->max_n_rx_ack_dts - 1);
  _vec_len (s->rx_ack_dts) = 0;

  s->tx_time_stream_created = vlib_time_now (vm);
  s->tx_time_last_sent = s->tx_time_stream_created;
  s->n_bytes_per_packet_on_wire
    = (s->n_bytes_payload
       + sizeof (rtt_test_header_t)
       + sizeof (ip4_header_t)
       + tm->n_encap_bytes);

  s->send_rate_packets_per_second = s->send_rate_bits_per_second / (s->n_bytes_per_packet_on_wire * BITS (u8));

  {
    rtt_test_packet_t * t;
    int i;

    t = clib_mem_alloc_no_fail (sizeof (t[0]) + s->n_bytes_payload);
    memset (t, 0, sizeof (t[0]));

    t->ip4.ip_version_and_header_length = 0x45;
    t->ip4.length = clib_host_to_net_u16 (sizeof (t[0]) + s->n_bytes_payload);
    t->ip4.flags_and_fragment_offset = clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);
    t->ip4.protocol = RTT_TEST_IP_PROTOCOL_DATA;
    t->ip4.ttl = 64;

    t->ip4.src_address = s->src_address;
    t->ip4.dst_address = s->dst_address;
    
    t->ip4.checksum = ip4_header_checksum (&t->ip4);

    t->rtt.stream_index = s - tm->stream_pool;

    for (i = 0; i < s->n_bytes_payload; i++)
      t->payload[i] = i;

    vlib_packet_template_init (vm, &s->packet_template,
			       t, sizeof (t[0]) + s->n_bytes_payload,
			       /* alloc chunk size */ VLIB_FRAME_SIZE,
			       "rtt-test stream %d data", s - tm->stream_pool);

    clib_mem_free (t);
  }

  {
    ELOG_TYPE_DECLARE (e) = {
      .format = "rtt-test: start stream %d",
      .format_args = "i4",
    };
    struct { u32 stream_index; } * ed;
    ed = ELOG_DATA (&vm->elog_main, e);
    ed->stream_index = s - tm->stream_pool;
  }

  return 0;
}

VLIB_CLI_COMMAND (rtt_test_cli_command, static) = {
  .path = "test rtt",
  .short_help = "Measure RTT test protocol",
  .function = rtt_test_command,
};

static u8 * format_rtt_test_stream (u8 * s, va_list * args)
{
  rtt_test_stream_t * t = va_arg (*args, rtt_test_stream_t *);
  uword indent = format_get_indent (s);

  s = format (s, "%U -> %U",
	      format_ip4_address, &t->src_address,
	      format_ip4_address, &t->dst_address);

  s = format (s, "\n%U  sent %Ld, received: from-past %Ld in-sequence %Ld from-future %Ld",
	      format_white_space, indent,
	      t->n_packets_sent,
	      t->n_packets_received[0], t->n_packets_received[1], t->n_packets_received[2]);

  s = format (s, "\n%U  rx-rate %.4e bits/sec",
	      format_white_space, indent,
	      (((f64) (t->n_packets_received[0] + t->n_packets_received[1] + t->n_packets_received[2]) * (f64) t->n_bytes_per_packet_on_wire * BITS (u8))
	       / (t->rx_ack_times[1] - t->rx_ack_times[0])));
	       
  rtt_test_stream_compute (&rtt_test_main, t);

  s = format (s, "\n%U  rtt %.4e +- %.4e",
	      format_white_space, indent,
	      t->ave_rtt, t->rms_rtt);

  return s;
}

static clib_error_t *
rtt_show_command (vlib_main_t * vm,
		  unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  rtt_test_main_t * tm = &rtt_test_main;
  rtt_test_stream_t * s;
  int i;

  for (i = 0; i < ARRAY_LEN (tm->stream_history); i++)
    {
      s = tm->stream_history + i;
      if (s->n_packets_sent > 0)
	vlib_cli_output (vm, "%U", format_rtt_test_stream, s);
    }

  pool_foreach (s, tm->stream_pool, ({
    vlib_cli_output (vm, "%U", format_rtt_test_stream, s);
  }));

  return 0;
}

VLIB_CLI_COMMAND (rtt_show_cli_command, static) = {
  .path = "show rtt",
  .short_help = "Show RTT measurements",
  .function = rtt_show_command,
};

static clib_error_t *
rtt_test_init (vlib_main_t * vm)
{
  rtt_test_main_t * tm = &rtt_test_main;

  ip4_register_protocol (RTT_TEST_IP_PROTOCOL_DATA, rtt_test_rx_data_node.index);
  ip4_register_protocol (RTT_TEST_IP_PROTOCOL_ACK, rtt_test_rx_ack_node.index);

  {
    rtt_test_packet_t ack;

    memset (&ack, 0, sizeof (ack));

    ack.ip4.ip_version_and_header_length = 0x45;
    ack.ip4.length = clib_host_to_net_u16 (sizeof (ack));
    ack.ip4.flags_and_fragment_offset = clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);
    ack.ip4.protocol = RTT_TEST_IP_PROTOCOL_ACK;
    ack.ip4.ttl = 64;

    ack.ip4.checksum = ip4_header_checksum (&ack.ip4);
    tm->ack_packet_template_ip4_checksum = ack.ip4.checksum;

    vlib_packet_template_init (vm, &tm->ack_packet_template,
			       &ack,
			       sizeof (ack),
			       /* alloc chunk size */ VLIB_FRAME_SIZE,
			       "rtt-test ack");
  }

  return /* no error */ 0;
}

static VLIB_INIT_FUNCTION (rtt_test_init);

static clib_error_t *
rtt_test_config (vlib_main_t * vm, unformat_input_t * input)
{
  rtt_test_main_t * tm = &rtt_test_main;
  clib_error_t * error = 0;

  tm->rms_histogram_units = .1;
  tm->n_encap_bytes = 
    (14 /* ethernet header */
     + 8 /* preamble */
     + 12 /* inter packet gap */
     + 4 /* crc */);
  tm->verbose = 1;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "rms-histogram-units %f", &tm->rms_histogram_units))
	;
      else if (unformat (input, "silent"))
	tm->verbose = 0;
      else
	clib_error ("%U", format_unformat_error, input);
    }

  return error;
}

VLIB_CONFIG_FUNCTION (rtt_test_config, "rtt-test");
