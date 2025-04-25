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

#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/format_table.h>
#include <vnet/udp/udp.h>
#include <vnet/session/session_types.h>
#include <vnet/session/session.h>

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

static const char *udp_cfg_flags_str[] = {
#define _(sym, str) str,
  foreach_udp_cfg_flag
#undef _
};

static u8 *
format_udp_cfg_flags (u8 *s, va_list *args)
{
  udp_connection_t *tc = va_arg (*args, udp_connection_t *);
  int i, last = -1;

  for (i = 0; i < UDP_CFG_N_FLAG_BITS; i++)
    if (tc->cfg_flags & (1 << i))
      last = i;
  if (last >= 0)
    s = format (s, " cfg: ");
  for (i = 0; i < last; i++)
    {
      if (tc->cfg_flags & (1 << i))
	s = format (s, "%s, ", udp_cfg_flags_str[i]);
    }
  if (last >= 0)
    s = format (s, "%s", udp_cfg_flags_str[last]);
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
format_udp_stats (u8 *s, va_list *args)
{
  udp_connection_t *uc = va_arg (*args, udp_connection_t *);
  u32 indent = format_get_indent (s);
  s = format (s, "in dgrams %lu bytes %lu err %lu\n", uc->dgrams_in,
	      uc->bytes_in, uc->errors_in);
  s = format (s, "%Uout dgrams %lu bytes %lu", format_white_space, indent,
	      uc->dgrams_out, uc->bytes_out);
  return s;
}

static u8 *
format_udp_vars (u8 * s, va_list * args)
{
  udp_connection_t *uc = va_arg (*args, udp_connection_t *);

  s = format (s, " index %u cfg: %U flags: %U\n", uc->c_c_index,
	      format_udp_cfg_flags, uc, format_udp_connection_flags, uc);
  s = format (s, " fib_index %u next_node %u opaque %u", uc->c_fib_index,
	      uc->next_node_index, uc->next_node_opaque);

  if (uc->flags & UDP_CONN_F_LISTEN)
    {
      s = format (s, "\n");
      return s;
    }

  s = format (s, " sw_if_index %d mss %u duration %.3f\n", uc->sw_if_index,
	      uc->mss, transport_time_now (uc->c_thread_index) - uc->start_ts);
  s = format (s, " stats: %U\n", format_udp_stats, uc);

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
      else if (unformat (input, "icmp-unreachable-disabled"))
	um->icmp_send_unreachable_disabled = 1;
      else if (unformat (input, "no-csum-offload"))
	um->csum_offload = 0;
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
	if (udp_is_valid_dst_port (port_info->dst_port, 0))
	  {
	    s = format (s, (!s) ? "%d" : ", %d", port_info->dst_port);
	  }
      }
      s = format (s, "%c", 0);
      vlib_cli_output (vm, "IPV6 UDP ports punt : %s", s);
    }

  return (error);
}
VLIB_CLI_COMMAND (show_tcp_punt_command, static) =
{
  .path = "show udp punt",
  .short_help = "show udp punt [ipv4|ipv6]",
  .function = show_udp_punt_fn,
};

static void
table_format_udp_port_ (vlib_main_t *vm, udp_main_t *um, table_t *t, int *c,
			int port, int bind, int is_ip4)
{
  const udp_dst_port_info_t *pi;

  if (bind && !udp_is_valid_dst_port (port, is_ip4))
    return;

  pi = udp_get_dst_port_info (um, port, is_ip4);
  if (!pi)
    return;

  table_format_cell (t, *c, 0, "%d", pi->dst_port);
  table_format_cell (t, *c, 1, is_ip4 ? "ip4" : "ip6");
  table_format_cell (t, *c, 2, ~0 == pi->node_index ? "none" : "%U",
		     format_vlib_node_name, vm, pi->node_index);
  table_format_cell (t, *c, 3, "%s", pi->name);

  (*c)++;
}

static void
table_format_udp_port (vlib_main_t *vm, udp_main_t *um, table_t *t, int *c,
		       int port, int bind, int ip4, int ip6)
{
  if (ip4)
    table_format_udp_port_ (vm, um, t, c, port, bind, 1 /* is_ip4 */);
  if (ip6)
    table_format_udp_port_ (vm, um, t, c, port, bind, 0 /* is_ip4 */);
}

static clib_error_t *
show_udp_ports (vlib_main_t *vm, unformat_input_t *input,
		vlib_cli_command_t *cmd)
{
  table_t table = {}, *t = &table;
  udp_main_t *um = &udp_main;
  clib_error_t *err = 0;
  int ip4 = 1, ip6 = 1;
  int port = -1;
  int bind = 1;
  int c = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ip4"))
	ip6 = 0;
      else if (unformat (input, "ip6"))
	ip4 = 0;
      else if (unformat (input, "bind"))
	bind = 1;
      else if (unformat (input, "all"))
	bind = 0;
      else if (unformat (input, "%d", &port))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
	  goto out;
	}
    }

  table_add_header_col (t, 4, "port", "proto", "node", "desc");

  if (port > 65535)
    {
      err = clib_error_return (0, "wrong port %d", port);
      goto out;
    }
  else if (port < 0)
    {
      for (port = 0; port < 65536; port++)
	table_format_udp_port (vm, um, t, &c, port, bind, ip4, ip6);
    }
  else
    {
      table_format_udp_port (vm, um, t, &c, port, bind, ip4, ip6);
    }

  vlib_cli_output (vm, "%U", format_table, t);

out:
  table_free (t);
  return err;
}

VLIB_CLI_COMMAND (show_udp_ports_cmd, static) = {
  .path = "show udp ports",
  .function = show_udp_ports,
  .short_help = "show udp ports [ip4|ip6] [bind|all|<port>]",
  .is_mp_safe = 1,
};

static void
table_format_udp_transport_port_ (vlib_main_t *vm, table_t *t, int *c,
				  int port, int is_ip4)
{
  udp_main_t *um = &udp_main;
  u32 refcnt;
  u16 port_ne;

  port_ne = clib_host_to_net_u16 (port);
  refcnt = um->transport_ports_refcnt[is_ip4][port_ne];
  if (!refcnt)
    return;

  if (!udp_is_valid_dst_port (port, is_ip4))
    {
      clib_warning ("Port %u is not registered refcnt %u!", port, refcnt);
      return;
    }

  table_format_cell (t, *c, 0, "%d", port);
  table_format_cell (t, *c, 1, is_ip4 ? "ip4" : "ip6");
  table_format_cell (t, *c, 2, "%d", refcnt);

  (*c)++;
}

static void
table_format_udp_transport_port (vlib_main_t *vm, table_t *t, int *c, int port,
				 int ipv)
{
  if (ipv == -1 || ipv == 0)
    table_format_udp_transport_port_ (vm, t, c, port, 1 /* is_ip4 */);
  if (ipv == -1 || ipv == 1)
    table_format_udp_transport_port_ (vm, t, c, port, 0 /* is_ip4 */);
}

static clib_error_t *
show_udp_transport_ports (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  table_t table = {}, *t = &table;
  int ipv = -1, port = -1, c = 0;
  clib_error_t *err = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ip4"))
	ipv = 0;
      else if (unformat (input, "ip6"))
	ipv = 1;
      else if (unformat (input, "%d", &port))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
	  goto out;
	}
    }

  table_add_header_col (t, 3, "port", "proto", "ref-cnt");

  if (port > 65535)
    {
      err = clib_error_return (0, "wrong port %d", port);
      goto out;
    }

  if (port < 0)
    {
      for (port = 0; port < 65536; port++)
	table_format_udp_transport_port (vm, t, &c, port, ipv);
    }
  else
    {
      table_format_udp_transport_port (vm, t, &c, port, ipv);
    }

  vlib_cli_output (vm, "%U\n", format_table, t);

out:
  table_free (t);
  return err;
}

VLIB_CLI_COMMAND (show_udp_transport_ports_cmd, static) = {
  .path = "show udp transport ports",
  .function = show_udp_transport_ports,
  .short_help = "show udp transport ports [ip4|ip6] [<port>]",
  .is_mp_safe = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
