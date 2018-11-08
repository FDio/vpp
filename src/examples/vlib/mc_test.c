/*
 * mc_test.c: test program for vlib mc
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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
#include <vlib/unix/mc_socket.h>
#include <vppinfra/random.h>

typedef struct
{
  u32 min_n_msg_bytes;
  u32 max_n_msg_bytes;
  u32 tx_serial;
  u32 rx_serial;
  u32 seed;
  u32 verbose;
  u32 validate;
  u32 window_size;
  f64 min_delay, max_delay;
  f64 n_packets_to_send;
} mc_test_main_t;

always_inline u32
choose_msg_size (mc_test_main_t * tm)
{
  u32 r = tm->min_n_msg_bytes;
  if (tm->max_n_msg_bytes > tm->min_n_msg_bytes)
    r +=
      random_u32 (&tm->seed) % (1 + tm->max_n_msg_bytes -
				tm->min_n_msg_bytes);
  return r;
}

static mc_test_main_t mc_test_main;

static void
serialize_test_msg (serialize_main_t * m, va_list * va)
{
  mc_test_main_t *tm = &mc_test_main;
  u32 n_bytes = choose_msg_size (tm);
  u8 *msg;
  int i;
  serialize_integer (m, n_bytes, sizeof (n_bytes));
  msg = serialize_get (m, n_bytes);
  for (i = 0; i < n_bytes; i++)
    msg[i] = i + tm->tx_serial;
  tm->tx_serial += n_bytes;
}

static void
unserialize_test_msg (serialize_main_t * m, va_list * va)
{
  mc_test_main_t *tm = &mc_test_main;
  u32 i, n_bytes, dump_msg = tm->verbose;
  u8 *p;
  unserialize_integer (m, &n_bytes, sizeof (n_bytes));
  p = unserialize_get (m, n_bytes);
  if (tm->validate)
    for (i = 0; i < n_bytes; i++)
      if (p[i] != ((tm->rx_serial + i) & 0xff))
	{
	  clib_warning ("corrupt msg at offset %d", i);
	  dump_msg = 1;
	  break;
	}
  if (dump_msg)
    clib_warning ("got %d bytes, %U", n_bytes, format_hex_bytes, p, n_bytes);
  tm->rx_serial += n_bytes;
}

MC_SERIALIZE_MSG (test_msg, static) =
{
.name = "test_msg",.serialize = serialize_test_msg,.unserialize =
    unserialize_test_msg,};

#define SERIALIZE 1

#define EVENT_JOIN_STREAM 	10
#define EVENT_SEND_DATA 	11

static void
test_rx_callback (mc_main_t * mcm,
		  mc_stream_t * stream,
		  mc_peer_id_t peer_id, u32 buffer_index)
{
  if (SERIALIZE)
    {
      return mc_unserialize (mcm, stream, buffer_index);
    }
  else
    {
#if DEBUG > 1
      vlib_main_t *vm = mcm->vlib_main;
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
      u8 *dp = vlib_buffer_get_current (b);

      fformat (stdout, "RX from %U %U\n",
	       stream->transport->format_peer_id, peer_id,
	       format_hex_bytes, dp, tm->n_msg_bytes);

#endif
    }
}

static u8 *
test_snapshot_callback (mc_main_t * mcm,
			u8 * data_vector, u32 last_global_sequence_processed)
{
  if (SERIALIZE)
    {
      serialize_main_t m;

      /* Append serialized data to data vector. */
      serialize_open_vector (&m, data_vector);
      m.stream.current_buffer_index = vec_len (data_vector);

      return serialize_close_vector (&m);
    }
  else
    return format (data_vector,
		   "snapshot, last global seq 0x%x",
		   last_global_sequence_processed);
}

static void
test_handle_snapshot_callback (mc_main_t * mcm, u8 * data, u32 n_data_bytes)
{
  if (SERIALIZE)
    {
      serialize_main_t s;
      unserialize_open_data (&s, data, n_data_bytes);
    }
  else
    clib_warning ("snapshot `%*s'", n_data_bytes, data);
}

static mc_socket_main_t mc_socket_main;

static uword
mc_test_process (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * f)
{
  mc_test_main_t *tm = &mc_test_main;
  mc_socket_main_t *msm = &mc_socket_main;
  mc_main_t *mcm = &msm->mc_main;
  uword event_type, *event_data = 0;
  u32 data_serial = 0, stream_index;
  f64 delay;
  mc_stream_config_t config;
  clib_error_t *error;
  int i;
  char *intfcs[] = { "eth1", "eth0", "ce" };

  clib_memset (&config, 0, sizeof (config));
  config.name = "test";
  config.window_size = tm->window_size;
  config.rx_buffer = test_rx_callback;
  config.catchup_snapshot = test_snapshot_callback;
  config.catchup = test_handle_snapshot_callback;
  stream_index = ~0;

  msm->multicast_tx_ip4_address_host_byte_order = 0xefff0100;
  msm->base_multicast_udp_port_host_byte_order = 0xffab;

  error = mc_socket_main_init (&mc_socket_main, intfcs, ARRAY_LEN (intfcs));
  if (error)
    {
      clib_error_report (error);
      exit (1);
    }

  mcm->we_can_be_relay_master = 1;

  while (1)
    {
      vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case EVENT_JOIN_STREAM:
	  stream_index = mc_stream_join (mcm, &config);
	  break;

	case EVENT_SEND_DATA:
	  {
	    f64 times[2];

	    if (stream_index == ~0)
	      stream_index = mc_stream_join (mcm, &config);

	    times[0] = vlib_time_now (vm);
	    for (i = 0; i < event_data[0]; i++)
	      {
		u32 bi;
		if (SERIALIZE)
		  {
		    mc_serialize_stream (mcm, stream_index, &test_msg,
					 data_serial);
		  }
		else
		  {
		    u8 *mp;
		    mp = mc_get_vlib_buffer (vm, sizeof (mp[0]), &bi);
		    mp[0] = data_serial;
		    mc_stream_send (mcm, stream_index, bi);
		  }
		if (tm->min_delay > 0)
		  {
		    delay =
		      tm->min_delay +
		      random_f64 (&tm->seed) * (tm->max_delay -
						tm->min_delay);
		    vlib_process_suspend (vm, delay);
		  }
		data_serial++;
	      }
	    times[1] = vlib_time_now (vm);
	    clib_warning ("done sending %d; %.4e per sec",
			  event_data[0],
			  (f64) event_data[0] / (times[1] - times[0]));
	    break;
	  }

	default:
	  clib_warning ("bug");
	  break;
	}

      if (event_data)
	_vec_len (event_data) = 0;
    }
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (mc_test_process_node, static) =
{
.function = mc_test_process,.type = VLIB_NODE_TYPE_PROCESS,.name =
    "mc-test-process",};
/* *INDENT-ON* */

static clib_error_t *
mc_test_command (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  f64 npkts = 10;

  if (unformat (input, "join"))
    {
      vlib_cli_output (vm, "Join stream...\n");
      vlib_process_signal_event (vm, mc_test_process_node.index,
				 EVENT_JOIN_STREAM, 0);
      return 0;
    }
  else if (unformat (input, "send %f", &npkts) || unformat (input, "send"))
    {
      vlib_process_signal_event (vm, mc_test_process_node.index,
				 EVENT_SEND_DATA, (uword) npkts);
      vlib_cli_output (vm, "Send %.0f pkts...\n", npkts);

      return 0;
    }
  else
    return unformat_parse_error (input);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_mc_command, static) =
{
.path = "test mc",.short_help = "Test mc command",.function =
    mc_test_command,};
/* *INDENT-ON* */

static clib_error_t *
mc_show_command (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  mc_main_t *mcm = &mc_socket_main.mc_main;
  vlib_cli_output (vm, "%U", format_mc_main, mcm);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_mc_command, static) =
{
.path = "show mc",.short_help = "Show mc command",.function =
    mc_show_command,};
/* *INDENT-ON* */

static clib_error_t *
mc_clear_command (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  mc_main_t *mcm = &mc_socket_main.mc_main;
  mc_clear_stream_stats (mcm);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_mc_command, static) =
{
.path = "clear mc",.short_help = "Clear mc command",.function =
    mc_clear_command,};
/* *INDENT-ON* */

static clib_error_t *
mc_config (vlib_main_t * vm, unformat_input_t * input)
{
  mc_test_main_t *tm = &mc_test_main;
  mc_socket_main_t *msm = &mc_socket_main;
  clib_error_t *error = 0;

  tm->min_n_msg_bytes = 4;
  tm->max_n_msg_bytes = 4;
  tm->window_size = 8;
  tm->seed = getpid ();
  tm->verbose = 0;
  tm->validate = 1;
  tm->min_delay = 10e-6;
  tm->max_delay = 10e-3;
  tm->n_packets_to_send = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "interface %s", &msm->multicast_interface_name))
	;

      else if (unformat (input, "n-bytes %d", &tm->max_n_msg_bytes))
	tm->min_n_msg_bytes = tm->max_n_msg_bytes;
      else if (unformat (input, "max-n-bytes %d", &tm->max_n_msg_bytes))
	;
      else if (unformat (input, "min-n-bytes %d", &tm->min_n_msg_bytes))
	;
      else if (unformat (input, "seed %d", &tm->seed))
	;
      else if (unformat (input, "window %d", &tm->window_size))
	;
      else if (unformat (input, "verbose"))
	tm->verbose = 1;
      else if (unformat (input, "no-validate"))
	tm->validate = 0;
      else if (unformat (input, "min-delay %f", &tm->min_delay))
	;
      else if (unformat (input, "max-delay %f", &tm->max_delay))
	;
      else if (unformat (input, "no-delay"))
	tm->min_delay = tm->max_delay = 0;
      else if (unformat (input, "n-packets %f", &tm->n_packets_to_send))
	;

      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (tm->n_packets_to_send > 0)
    vlib_process_signal_event (vm, mc_test_process_node.index,
			       EVENT_SEND_DATA,
			       (uword) tm->n_packets_to_send);

  return error;
}

VLIB_CONFIG_FUNCTION (mc_config, "mc");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
