/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
/**
 * @file syslog.c
 * RFC5424 syslog protocol implementation
 */

#include <unistd.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/format.h>
#include <vnet/syslog/syslog.h>
#include <vnet/syslog/syslog_udp.h>

#define SYSLOG_VERSION "1"
#define NILVALUE "-"
#define DEFAULT_UDP_PORT 514
#define DEFAULT_MAX_MSG_SIZE 480

#define encode_priority(f, p) ((f << 3) | p)

syslog_main_t syslog_main;

/* format timestamp RFC5424 6.2.3. */
static u8 *
format_syslog_timestamp (u8 * s, va_list * args)
{
  f64 timestamp = va_arg (*args, f64);
  struct tm *tm;
  word msec;

  time_t t = timestamp;
  tm = gmtime (&t);
  msec = 1e6 * (timestamp - t);
  return format (s, "%4d-%02d-%02dT%02d:%02d:%02d.%06dZ", 1900 + tm->tm_year,
		 1 + tm->tm_mon, tm->tm_mday, tm->tm_hour, tm->tm_min,
		 tm->tm_sec, msec);
}

/* format header RFC5424 6.2. */
static u8 *
format_syslog_header (u8 * s, va_list * args)
{
  syslog_main_t *sm = &syslog_main;
  syslog_header_t *h = va_arg (*args, syslog_header_t *);
  u32 pri = encode_priority (h->facility, h->severity);

  return format (s, "<%d>%s %U %U %s %d %s", pri, SYSLOG_VERSION,
		 format_syslog_timestamp, h->timestamp + sm->time_offset,
		 format_ip4_address, &sm->src_address,
		 h->app_name ? h->app_name : NILVALUE, sm->procid,
		 h->msgid ? h->msgid : NILVALUE);
}

/* format strucured data elements RFC5424 6.3. */
static u8 *
format_syslog_structured_data (u8 * s, va_list * args)
{
  u8 **sds = va_arg (*args, u8 **);
  int i;

  if (vec_len (sds))
    {
      for (i = 0; i < vec_len (sds); i++)
	s = format (s, "[%v]", sds[i]);
    }
  /* if zero structured data elemts field must contain NILVALUE */
  else
    s = format (s, "%s", NILVALUE);

  return s;
}

static u8 *
format_syslog_msg (u8 * s, va_list * args)
{
  syslog_msg_t *m = va_arg (*args, syslog_msg_t *);

  s =
    format (s, "%U %U", format_syslog_header, &m->header,
	    format_syslog_structured_data, m->structured_data);
  /* free-form message is optional */
  if (m->msg)
    s = format (s, " %s", m->msg);

  return s;
}

void
syslog_msg_sd_init (syslog_msg_t * syslog_msg, char *sd_id)
{
  u8 *sd;

  sd = format (0, "%s", sd_id);
  vec_add1 (syslog_msg->structured_data, sd);
  syslog_msg->curr_sd_index++;
}

void
syslog_msg_add_sd_param (syslog_msg_t * syslog_msg, char *name, char *fmt,
			 ...)
{
  va_list va;
  u8 *value;

  va_start (va, fmt);
  value = va_format (0, fmt, &va);
  va_end (va);
  vec_terminate_c_string (value);

  syslog_msg->structured_data[syslog_msg->curr_sd_index] =
    format (syslog_msg->structured_data[syslog_msg->curr_sd_index],
	    " %s=\"%s\"", name, value);
  vec_free (value);
}

void
syslog_msg_add_msg (syslog_msg_t * syslog_msg, char *fmt, ...)
{
  va_list va;
  u8 *msg;

  va_start (va, fmt);
  msg = va_format (0, fmt, &va);
  va_end (va);
  vec_terminate_c_string (msg);

  syslog_msg->msg = msg;
}

void
syslog_msg_init (syslog_msg_t * syslog_msg, syslog_facility_t facility,
		 syslog_severity_t severity, char *app_name, char *msgid)
{
  vlib_main_t *vm = vlib_get_main ();

  syslog_msg->header.facility = facility;
  syslog_msg->header.severity = severity;
  syslog_msg->header.timestamp = vlib_time_now (vm);
  syslog_msg->header.app_name = app_name;
  syslog_msg->header.msgid = msgid;
  syslog_msg->structured_data = 0;
  syslog_msg->curr_sd_index = ~0;
  syslog_msg->msg = 0;
}

int
syslog_msg_send (syslog_msg_t * syslog_msg)
{
  syslog_main_t *sm = &syslog_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 bi, msg_len, *to_next;
  u8 *tmp;
  vlib_buffer_t *b;
  vlib_frame_t *f;
  int i;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return -1;

  b = vlib_get_buffer (vm, bi);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);

  /* one message per UDP datagram RFC5426 3.1. */
  tmp = format (0, "%U", format_syslog_msg, syslog_msg);
  msg_len = vec_len (tmp) - (vec_c_string_is_terminated (tmp) ? 1 : 0);
  msg_len = msg_len < sm->max_msg_size ? msg_len : sm->max_msg_size;
  clib_memcpy_fast (b->data, tmp, msg_len);
  b->current_length = msg_len;
  vec_free (tmp);

  vec_free (syslog_msg->msg);
  for (i = 0; i < vec_len (syslog_msg->structured_data); i++)
    vec_free (syslog_msg->structured_data[i]);
  vec_free (syslog_msg->structured_data);

  syslog_add_udp_transport (vm, bi);

  f = vlib_get_frame_to_node (vm, sm->ip4_lookup_node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, sm->ip4_lookup_node_index, f);

  return 0;
}

static uword
unformat_syslog_facility (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = SYSLOG_FACILITY_##f;
  foreach_syslog_facility
#undef _
    else
    return 0;

  return 1;
}

static uword
unformat_syslog_severity (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = SYSLOG_SEVERITY_##f;
  foreach_syslog_severity
#undef _
    else
    return 0;

  return 1;
}

static u8 *
format_syslog_severity (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v,f,str) case SYSLOG_SEVERITY_##f: t = (u8 *) str; break;
      foreach_syslog_severity
#undef _
    default:
      return format (s, "unknown");
    }

  return format (s, "%s", t);
}

vnet_api_error_t
set_syslog_sender (ip4_address_t * collector, u16 collector_port,
		   ip4_address_t * src, u32 vrf_id, u32 max_msg_size)
{
  syslog_main_t *sm = &syslog_main;
  u32 fib_index;

  if (max_msg_size < DEFAULT_MAX_MSG_SIZE)
    return VNET_API_ERROR_INVALID_VALUE;

  if (collector->as_u32 == 0 || collector_port == 0 || src->as_u32 == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  if (vrf_id == ~0)
    {
      fib_index = ~0;
    }
  else
    {
      fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);
      if (fib_index == ~0)
	return VNET_API_ERROR_NO_SUCH_FIB;
    }

  sm->fib_index = fib_index;

  sm->collector.as_u32 = collector->as_u32;
  sm->collector_port = (u16) collector_port;
  sm->src_address.as_u32 = src->as_u32;
  sm->max_msg_size = max_msg_size;

  return 0;
}

static clib_error_t *
set_syslog_sender_command_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t collector, src;
  u32 collector_port = DEFAULT_UDP_PORT;
  u32 vrf_id = ~0;
  u32 max_msg_size = DEFAULT_MAX_MSG_SIZE;
  clib_error_t *ret = 0;

  collector.as_u32 = 0;
  src.as_u32 = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "collector %U", unformat_ip4_address, &collector))
	;
      else if (unformat (line_input, "port %u", &collector_port))
	;
      else if (unformat (line_input, "src %U", unformat_ip4_address, &src))
	;
      else if (unformat (line_input, "vrf-id %u", &vrf_id))
	;
      else if (unformat (line_input, "max-msg-size %u", &max_msg_size))
	;
      else
	{
	  ret = clib_error_return (0, "Unknown input `%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (collector.as_u32 == 0)
    {
      ret = clib_error_return (0, "collector address required");
      goto done;
    }

  if (src.as_u32 == 0)
    {
      ret = clib_error_return (0, "src address required");
      goto done;
    }

  if (max_msg_size < DEFAULT_MAX_MSG_SIZE)
    {
      ret =
	clib_error_return (0, "too small max-msg-size value, minimum is %u",
			   DEFAULT_MAX_MSG_SIZE);
      goto done;
    }

  vnet_api_error_t rv =
    set_syslog_sender (&collector, collector_port, &src, vrf_id,
		       max_msg_size);

  if (rv)
    ret =
      clib_error_return (0, "set syslog sender failed rv=%d:%U", (int) rv,
			 format_vnet_api_errno, rv);

done:
  unformat_free (line_input);
  return ret;
}

static clib_error_t *
show_syslog_sender_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  syslog_main_t *sm = &syslog_main;
  u32 vrf_id = ~0;

  if (sm->fib_index != ~0)
    vrf_id = fib_table_get_table_id (sm->fib_index, FIB_PROTOCOL_IP4);

  if (syslog_is_enabled ())
    vlib_cli_output (vm, "collector %U:%u, src address %U, VRF ID %d, "
		     "max-msg-size %u",
		     format_ip4_address, &sm->collector, sm->collector_port,
		     format_ip4_address, &sm->src_address,
		     vrf_id, sm->max_msg_size);
  else
    vlib_cli_output (vm, "syslog sender is disabled");

  return 0;
}

static clib_error_t *
test_syslog_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  syslog_msg_t syslog_msg;
  syslog_facility_t facility;
  syslog_severity_t severity;
  clib_error_t *ret = 0;
  u8 *app_name = 0, *msgid = 0, *sd_id = 0, *param_name = 0, *param_value = 0;

  if (!syslog_is_enabled ())
    return 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat (line_input, "%U", unformat_syslog_facility, &facility))
    {
      if (unformat (line_input, "%U", unformat_syslog_severity, &severity))
	{
	  if (syslog_severity_filter_block (severity))
	    goto done;

	  if (unformat (line_input, "%s", &app_name))
	    {
	      if (unformat (line_input, "%s", &msgid))
		{
		  syslog_msg_init (&syslog_msg, facility, severity,
				   (char *) app_name, (char *) msgid);
		  while (unformat (line_input, "sd-id %s", &sd_id))
		    {
		      syslog_msg_sd_init (&syslog_msg, (char *) sd_id);
		      while (unformat
			     (line_input, "sd-param %s %s", &param_name,
			      &param_value))
			{
			  syslog_msg_add_sd_param (&syslog_msg,
						   (char *) param_name,
						   (char *) param_value);
			  vec_free (param_name);
			  vec_free (param_value);
			}
		      vec_free (sd_id);
		    }
		  if (unformat_check_input (line_input) !=
		      UNFORMAT_END_OF_INPUT)
		    syslog_msg_add_msg (&syslog_msg, "%U",
					format_unformat_input, line_input);
		  syslog_msg_send (&syslog_msg);
		}
	      else
		{
		  ret =
		    clib_error_return (0, "Unknown input `%U'",
				       format_unformat_error, line_input);
		  goto done;
		}
	    }
	  else
	    {
	      ret =
		clib_error_return (0, "Unknown input `%U'",
				   format_unformat_error, line_input);
	      goto done;
	    }
	}
      else
	{
	  ret =
	    clib_error_return (0, "Unknown input `%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }
  else
    {
      ret =
	clib_error_return (0, "Unknown input `%U'", format_unformat_error,
			   line_input);
      goto done;
    }

done:
  vec_free (app_name);
  vec_free (msgid);
  unformat_free (line_input);
  return ret;
}

static clib_error_t *
set_syslog_filter_command_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  syslog_main_t *sm = &syslog_main;
  clib_error_t *ret = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "severity %U", unformat_syslog_severity,
	   &sm->severity_filter))
	;
      else
	{
	  ret = clib_error_return (0, "Unknown input `%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  unformat_free (line_input);
  return ret;
}

static clib_error_t *
show_syslog_filter_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  syslog_main_t *sm = &syslog_main;

  vlib_cli_output (vm, "severity-filter: %U", format_syslog_severity,
		   sm->severity_filter);

  return 0;
}

/* *INDENT-OFF* */
/*?
 * Set syslog sender configuration.
 *
 * @cliexpar
 * @parblock
 *
 * Example of how to configure syslog sender:
 * @cliexcmd{set syslog sender collector 10.10.10.10 port 514 src 172.16.2.2}
 * @endparblock
?*/
VLIB_CLI_COMMAND (set_syslog_sender_command, static) = {
    .path = "set syslog sender",
    .short_help = "set syslog sender "
                  "collector <ip4-address> [port <port>] "
                  "src <ip4-address> [vrf-id <vrf-id>] "
                  "[max-msg-size <max-msg-size>]",
    .function = set_syslog_sender_command_fn,
};

/*?
 * Show syslog sender configuration.
 *
 * @cliexpar
 * @parblock
 *
 * Example of how to display syslog sender configuration:
 * @cliexstart{show syslog sender}
 * collector 10.10.10.10:514, src address 172.16.2.2, VRF ID 0, max-msg-size 480
 * @cliexend
 * @endparblock
?*/
VLIB_CLI_COMMAND (show_syslog_sender_command, static) = {
    .path = "show syslog sender",
    .short_help = "show syslog sender",
    .function = show_syslog_sender_command_fn,
};

/*?
 * This command generate test syslog message.
 *
 * @cliexpar
 * @parblock
 *
 * Example of how to generate following syslog message
 * '<em><180>1 2018-11-07T11:36:41.231759Z 172.16.1.1 test 10484 testMsg
 * [exampleSDID@32473 eventID="1011" eventSource="App" iut="3"]
 * this is message</em>'
 * @cliexcmd{test syslog local6 warning test testMsg sd-id <!--
 * --> exampleSDID@32473 sd-param eventID 1011 sd-param eventSource App <!--
 * --> sd-param iut 3 this is message}
 * @endparblock
?*/
VLIB_CLI_COMMAND (test_syslog_command, static) = {
    .path = "test syslog",
    .short_help = "test syslog <facility> <severity> <app-name> <msgid> "
                  "[sd-id <sd-id> sd-param <name> <value>] [<message]",
    .function = test_syslog_command_fn,
};

/*?
 * Set syslog severity filter, specified severity and greater match.
 *
 * @cliexpar
 * @parblock
 *
 * Example of how to configure syslog severity filter:
 * @cliexcmd{set syslog filter severity warning}
 * @endparblock
?*/
VLIB_CLI_COMMAND (set_syslog_filter_command, static) = {
    .path = "set syslog filter",
    .short_help = "set syslog filter severity <severity>",
    .function = set_syslog_filter_command_fn,
};

/*?
 * Show syslog severity filter.
 *
 * @cliexpar
 * @parblock
 *
 * Example of how to display syslog severity filter:
 * @cliexstart{show syslog filter}
 * severity-filter: warning
 * @cliexend
 * @endparblock
?*/
VLIB_CLI_COMMAND (show_syslog_filter_command, static) = {
    .path = "show syslog filter",
    .short_help = "show syslog filter",
    .function = show_syslog_filter_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
syslog_init (vlib_main_t * vm)
{
  syslog_main_t *sm = &syslog_main;
  f64 vlib_time_0 = vlib_time_now (vm);
  struct timeval timeval_0;
  vlib_node_t *ip4_lookup_node;

  sm->vnet_main = vnet_get_main ();

  sm->procid = getpid ();
  gettimeofday (&timeval_0, 0);
  sm->time_offset =
    (f64) timeval_0.tv_sec + (((f64) timeval_0.tv_usec) * 1e-6) - vlib_time_0;

  sm->collector.as_u32 = 0;
  sm->src_address.as_u32 = 0;
  sm->collector_port = DEFAULT_UDP_PORT;
  sm->max_msg_size = DEFAULT_MAX_MSG_SIZE;
  sm->fib_index = ~0;
  sm->severity_filter = SYSLOG_SEVERITY_INFORMATIONAL;

  ip4_lookup_node = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
  sm->ip4_lookup_node_index = ip4_lookup_node->index;

  return 0;
}

VLIB_INIT_FUNCTION (syslog_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
