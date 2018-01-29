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

#include <nat/dslite.h>

static clib_error_t *
dslite_add_del_pool_addr_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  dslite_main_t *dm = &dslite_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t start_addr, end_addr, this_addr;
  u32 start_host_order, end_host_order;
  int i, count, rv;
  u8 is_add = 1;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U - %U",
		    unformat_ip4_address, &start_addr,
		    unformat_ip4_address, &end_addr))
	;
      else if (unformat (line_input, "%U", unformat_ip4_address, &start_addr))
	end_addr = start_addr;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  start_host_order = clib_host_to_net_u32 (start_addr.as_u32);
  end_host_order = clib_host_to_net_u32 (end_addr.as_u32);

  if (end_host_order < start_host_order)
    {
      error = clib_error_return (0, "end address less than start address");
      goto done;
    }

  count = (end_host_order - start_host_order) + 1;
  this_addr = start_addr;

  for (i = 0; i < count; i++)
    {
      rv = dslite_add_del_pool_addr (dm, &this_addr, is_add);

      switch (rv)
	{
	case VNET_API_ERROR_NO_SUCH_ENTRY:
	  error =
	    clib_error_return (0, "DS-Lite pool address %U not exist.",
			       format_ip4_address, &this_addr);
	  goto done;
	case VNET_API_ERROR_VALUE_EXIST:
	  error =
	    clib_error_return (0, "DS-Lite pool address %U exist.",
			       format_ip4_address, &this_addr);
	  goto done;
	default:
	  break;

	}
      increment_v4_address (&this_addr);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
dslite_show_pool_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  dslite_main_t *dm = &dslite_main;
  snat_address_t *ap;

  vlib_cli_output (vm, "DS-Lite pool:");

  /* *INDENT-OFF* */
  vec_foreach (ap, dm->addr_pool)
    {
      vlib_cli_output (vm, "%U", format_ip4_address, &ap->addr);
    }
  /* *INDENT-ON* */
  return 0;
}

static clib_error_t *
dslite_set_aftr_tunnel_addr_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  dslite_main_t *dm = &dslite_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip6_address_t ip6_addr;
  int rv;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip6_address, &ip6_addr))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = dslite_set_aftr_ip6_addr (dm, &ip6_addr);

  if (rv)
    error =
      clib_error_return (0,
			 "Set DS-Lite AFTR tunnel endpoint address failed.");

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
dslite_show_aftr_ip6_addr_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  dslite_main_t *dm = &dslite_main;

  vlib_cli_output (vm, "%U", format_ip6_address, &dm->aftr_ip6_addr);
  return 0;
}

static clib_error_t *
dslite_set_b4_tunnel_addr_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  dslite_main_t *dm = &dslite_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip6_address_t ip6_addr;
  int rv;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip6_address, &ip6_addr))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = dslite_set_b4_ip6_addr (dm, &ip6_addr);

  if (rv)
    error =
      clib_error_return (0, "Set DS-Lite B4 tunnel endpoint address failed.");

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
dslite_show_b4_ip6_addr_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  dslite_main_t *dm = &dslite_main;

  vlib_cli_output (vm, "%U", format_ip6_address, &dm->b4_ip6_addr);
  return 0;
}

static u8 *
format_dslite_session (u8 * s, va_list * args)
{
  dslite_session_t *session = va_arg (*args, dslite_session_t *);
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

static u8 *
format_dslite_b4 (u8 * s, va_list * args)
{
  dslite_per_thread_data_t *td = va_arg (*args, dslite_per_thread_data_t *);
  dslite_b4_t *b4 = va_arg (*args, dslite_b4_t *);
  dlist_elt_t *head, *elt;
  u32 elt_index, head_index;
  u32 session_index;
  dslite_session_t *session;

  s =
    format (s, "B4 %U %d sessions\n", format_ip6_address, &b4->addr,
	    b4->nsessions);

  if (b4->nsessions == 0)
    return s;

  head_index = b4->sessions_per_b4_list_head_index;
  head = pool_elt_at_index (td->list_pool, head_index);
  elt_index = head->next;
  elt = pool_elt_at_index (td->list_pool, elt_index);
  session_index = elt->value;
  while (session_index != ~0)
    {
      session = pool_elt_at_index (td->sessions, session_index);
      s = format (s, "%U", format_dslite_session, session);
      elt_index = elt->next;
      elt = pool_elt_at_index (td->list_pool, elt_index);
      session_index = elt->value;
    }

  return s;
}

static clib_error_t *
dslite_show_sessions_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  dslite_main_t *dm = &dslite_main;
  dslite_per_thread_data_t *td;
  dslite_b4_t *b4;

  /* *INDENT-OFF* */
  vec_foreach (td, dm->per_thread_data)
    {
      pool_foreach (b4, td->b4s,
      ({
        vlib_cli_output (vm, "%U", format_dslite_b4, td, b4);
      }));
    }
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */

/*?
 * @cliexpar
 * @cliexstart{dslite add pool address}
 * Add/delete DS-Lite pool address for AFTR element.
 * To add DS-Lite pool address use:
 *  vpp# dslite add pool address 10.1.1.3
 * To add DS-Lite pool address range use:
 *  vpp# dslite add pool address 10.1.1.5 - 10.1.1.7
 * @cliexend
?*/
VLIB_CLI_COMMAND (dslite_add_pool_address_command, static) = {
  .path = "dslite add pool address",
  .short_help = "dslite add pool address <ip4-range-start> [- <ip4-range-end>] "
                " [del]",
  .function = dslite_add_del_pool_addr_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show dslite pool}
 * Show DS-lite pool addresses.
 * vpp# show dslite pool
 * DS-Lite pool:
 * 10.0.0.3
 * 10.0.0.5
 * 10.0.0.6
 * 10.0.0.7
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_dslite_pool_command, static) = {
  .path = "show dslite pool",
  .short_help = "show dslite pool",
  .function = dslite_show_pool_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{dslite set aftr-tunnel-endpoint-address}
 * Set IPv6 tunnel endpoint address of the AFTR element.
 * To set AFTR tunnel endpoint address use:
 * vpp# dslite set aftr-tunnel-endpoint-address 2001:db8:85a3::8a2e:370:1
 * @cliexend
?*/
VLIB_CLI_COMMAND (dslite_set_aftr_tunnel_addr, static) = {
  .path = "dslite set aftr-tunnel-endpoint-address",
  .short_help = "dslite set aftr-tunnel-endpoint-address <ip6>",
  .function = dslite_set_aftr_tunnel_addr_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show dslite aftr-tunnel-endpoint-address}
 * Show IPv6 tunnel endpoint address of the AFTR element.
 * vpp# show dslite aftr-tunnel-endpoint-address
 * 2001:db8:85a3::8a2e:370:1
 * @cliexend
?*/
VLIB_CLI_COMMAND (dslite_show_aftr_ip6_addr, static) = {
  .path = "show dslite aftr-tunnel-endpoint-address",
  .short_help = "show dslite aftr-tunnel-endpoint-address",
  .function = dslite_show_aftr_ip6_addr_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{dslite set b4-tunnel-endpoint-address}
 * Set IPv6 tunnel endpoint address of the B4 element.
 * To set B4 tunnel endpoint address use:
 * vpp# dslite set b4-tunnel-endpoint-address 2001:db8:62aa::375e:f4c1:1
 * @cliexend
?*/
VLIB_CLI_COMMAND (dslite_set_b4_tunnel_addr, static) = {
  .path = "dslite set b4-tunnel-endpoint-address",
  .short_help = "dslite set b4-tunnel-endpoint-address <ip6>",
  .function = dslite_set_b4_tunnel_addr_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show dslite b4-tunnel-endpoint-address}
 * Show IPv6 tunnel endpoint address of the B4 element.
 * vpp# show dslite b4-tunnel-endpoint-address
 * 2001:db8:62aa::375e:f4c1:1
 * @cliexend
?*/
VLIB_CLI_COMMAND (dslite_show_b4_ip6_addr, static) = {
  .path = "show dslite b4-tunnel-endpoint-address",
  .short_help = "show dslite b4-tunnel-endpoint-address",
  .function = dslite_show_b4_ip6_addr_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show dslite sessions}
 * Show DS-Lite sessions.
 * vpp# show dslite sessions
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
VLIB_CLI_COMMAND (dslite_show_sessions, static) = {
  .path = "show dslite sessions",
  .short_help = "show dslite sessions",
  .function = dslite_show_sessions_command_fn,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
