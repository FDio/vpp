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

#include <vnet/udp/udp.h>
#include <vnet/session/session_types.h>

u8 *
format_udp_connection_id (u8 * s, va_list * args)
{
  udp_connection_t *uc = va_arg (*args, udp_connection_t *);
  if (!uc)
    return s;
  if (uc->c_is_ip4)
    s = format (s, "[%u:%u][%s] %U:%d->%U:%d", uc->c_thread_index,
		uc->c_s_index, "U", format_ip4_address, &uc->c_lcl_ip4,
		clib_net_to_host_u16 (uc->c_lcl_port), format_ip4_address,
		&uc->c_rmt_ip4, clib_net_to_host_u16 (uc->c_rmt_port));
  else
    s = format (s, "[%u:%u][%s] %U:%d->%U:%d", uc->c_thread_index,
		uc->c_s_index, "U", format_ip6_address, &uc->c_lcl_ip6,
		clib_net_to_host_u16 (uc->c_lcl_port), format_ip6_address,
		&uc->c_rmt_ip6, clib_net_to_host_u16 (uc->c_rmt_port));
  return s;
}

static const char *udp_connection_flags_str[] = {
#define _(sym, str) str,
  foreach_udp_connection_flag
#undef _
};

static u8 *
format_udp_connection_flags (u8 * s, va_list * args)
{
  udp_connection_t *uc = va_arg (*args, udp_connection_t *);
  int i, last = -1;

  for (i = 0; i < UDP_CONN_N_FLAGS; i++)
    if (uc->flags & (1 << i))
      last = i;
  for (i = 0; i < last; i++)
    {
      if (uc->flags & (1 << i))
	s = format (s, "%s, ", udp_connection_flags_str[i]);
    }
  if (last >= 0)
    s = format (s, "%s", udp_connection_flags_str[last]);
  return s;
}

static u8 *
format_udp_vars (u8 * s, va_list * args)
{
  udp_connection_t *uc = va_arg (*args, udp_connection_t *);
  s = format (s, " index %u flags: %U", uc->c_c_index,
	      format_udp_connection_flags, uc);

  if (!(uc->flags & UDP_CONN_F_LISTEN))
    s = format (s, "\n");
  return s;
}

u8 *
format_udp_connection (u8 * s, va_list * args)
{
  udp_connection_t *uc = va_arg (*args, udp_connection_t *);
  u32 verbose = va_arg (*args, u32);
  if (!uc)
    return s;
  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_udp_connection_id, uc);
  if (verbose)
    {
      s = format (s, "%-" SESSION_CLI_STATE_LEN "s",
		  (uc->flags & UDP_CONN_F_LISTEN) ? "LISTEN" : "OPENED", uc);
      if (verbose > 1)
	s = format (s, "\n%U", format_udp_vars, uc);
    }
  return s;
}

static clib_error_t *
udp_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  udp_main_t *um = &udp_main;
  u32 tmp;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "mtu %u", &tmp))
	um->default_mtu = tmp;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (udp_config_fn, "udp");

static clib_error_t *
show_udp_punt_fn (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd_arg)
{
  udp_main_t *um = vnet_get_udp_main ();

  clib_error_t *error = NULL;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			      input);

  udp_dst_port_info_t *port_info;
  if (um->punt_unknown4)
    {
      vlib_cli_output (vm, "IPv4 UDP punt: enabled");
    }
  else
    {
      u8 *s = NULL;
      vec_foreach (port_info, um->dst_port_infos[UDP_IP4])
      {
	if (udp_is_valid_dst_port (port_info->dst_port, 1))
	  {
	    s = format (s, (!s) ? "%d" : ", %d", port_info->dst_port);
	  }
      }
      s = format (s, "%c", 0);
      vlib_cli_output (vm, "IPV4 UDP ports punt : %s", s);
    }

  if (um->punt_unknown6)
    {
      vlib_cli_output (vm, "IPv6 UDP punt: enabled");
    }
  else
    {
      u8 *s = NULL;
      vec_foreach (port_info, um->dst_port_infos[UDP_IP6])
      {
	if (udp_is_valid_dst_port (port_info->dst_port, 01))
	  {
	    s = format (s, (!s) ? "%d" : ", %d", port_info->dst_port);
	  }
      }
      s = format (s, "%c", 0);
      vlib_cli_output (vm, "IPV6 UDP ports punt : %s", s);
    }

  return (error);
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_tcp_punt_command, static) =
{
  .path = "show udp punt",
  .short_help = "show udp punt [ipv4|ipv6]",
  .function = show_udp_punt_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
