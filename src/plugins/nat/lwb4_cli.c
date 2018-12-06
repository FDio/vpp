/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <nat/lwb4.h>

static clib_error_t *
lwb4_set_config_fn (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lwb4_main_t *dm = &lwb4_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip6_address_t aftr_ip6_addr, b4_ip6_addr;
  ip4_address_t b4_ip4_addr;
  u32 psid = 0, psid_length = 0, psid_shift = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U %U %U %u %u %u",
		    unformat_ip6_address, &aftr_ip6_addr,
		    unformat_ip6_address, &b4_ip6_addr,
		    unformat_ip4_address, &b4_ip4_addr,
		    &psid_length, &psid_shift, &psid))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }


  lwb4_set_b4_params (dm, &b4_ip6_addr, &b4_ip4_addr,
		      psid_length, psid_shift, psid);
  lwb4_set_aftr_ip6_addr (dm, &aftr_ip6_addr);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
lwb4_show_config_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  lwb4_main_t *dm = &lwb4_main;

  vlib_cli_output (vm,
		   "AFTR IPv6: %U, B4 IPv6: %U, B4 IPv4: %U, PSID Length: %u, PSID shift: %u, PSID: %u",
		   format_ip6_address, &dm->aftr_ip6_addr, format_ip6_address,
		   &dm->b4_ip6_addr, format_ip4_address, &dm->b4_ip4_addr,
		   dm->psid_length, dm->psid_shift, dm->psid);
  return 0;
}

static u8 *
format_lwb4_session (u8 * s, va_list * args)
{
  lwb4_session_t *session = va_arg (*args, lwb4_session_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%Uin %U:%u out %U:%u protocol %U\n",
	      format_white_space, indent + 2,
	      format_ip4_address, &session->in2out.addr,
	      clib_net_to_host_u16 (session->in2out.port),
	      format_ip4_address, &session->out2in.addr,
	      clib_net_to_host_u16 (session->out2in.port),
	      format_snat_protocol, session->in2out.proto);
  s = format (s, "%Utotal pkts %d, total bytes %lld\n",
	      format_white_space, indent + 4,
	      session->total_pkts, session->total_bytes);
  return s;
}

static clib_error_t *
lwb4_show_sessions_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  lwb4_main_t *dm = &lwb4_main;
  lwb4_per_thread_data_t *td = dm->per_thread_data;
  dlist_elt_t *head, *elt;
  u32 elt_index, head_index;
  u32 session_index;
  lwb4_session_t *session;

  vlib_cli_output (vm, "B4 %U %d sessions\n", format_ip6_address, &td->addr,
		   td->nsessions);

  if (td->nsessions == 0)
    return 0;

  head_index = td->sessions_list_head_index;
  head = pool_elt_at_index (td->list_pool, head_index);
  elt_index = head->next;
  elt = pool_elt_at_index (td->list_pool, elt_index);
  session_index = elt->value;
  while (session_index != ~0)
    {
      session = pool_elt_at_index (td->sessions, session_index);
      vlib_cli_output (vm, "%U", format_lwb4_session, session);
      elt_index = elt->next;
      elt = pool_elt_at_index (td->list_pool, elt_index);
      session_index = elt->value;
    }

  return 0;
}

/* *INDENT-OFF* */

/*?
 * @cliexpar
 * @cliexstart{lwb4 set config}
 * Configures B4
 * vpp# lwb4 set config fc00::100 fde4:8dba:82e1::1 10.10.1.2 6 10 1
 * @cliexend
?*/
VLIB_CLI_COMMAND (lwb4_set_config, static) = {
  .path = "lwb4 set config",
  .short_help = "lwb4 set config <aftr_ip6> <b4_ip6> <b4_ip4> <psid_length> <shift> <psid>",
  .function = lwb4_set_config_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show lwb4 config}
 * Show current configuration
 * vpp# show lwb4 config
 * 2001:db8:62aa::375e:f4c1:1
 * @cliexend
?*/
VLIB_CLI_COMMAND (lwb4_show_config, static) = {
  .path = "show lwb4 config",
  .short_help = "show lwb4 config",
  .function = lwb4_show_config_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show lwb4 sessions}
 * Show LWB4 sessions.
 * vpp# show lwb4 sessions
 * B4 fd01:2::2 1 sessions
 *   in 192.168.1.1:20000 out 10.0.0.3:16253 protocol udp
 *     total pkts 2, total bytes 136
 * B4 fd01:2::3 2 sessions
 *   in 192.168.1.1:20001 out 10.0.0.3:18995 protocol tcp
 *     total pkts 2, total bytes 160
 *   in 192.168.1.1:4000 out 10.0.0.3:53893 protocol icmp
 *     total pkts 2, total bytes 136
 * @cliexend
?*/
VLIB_CLI_COMMAND (lwb4_show_sessions, static) = {
  .path = "show lwb4 sessions",
  .short_help = "show lwb4 sessions",
  .function = lwb4_show_sessions_command_fn,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
