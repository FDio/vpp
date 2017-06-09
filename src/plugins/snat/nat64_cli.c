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
/**
 * @file
 * @brief NAT64 CLI
 */

#include <snat/nat64.h>
#include <snat/snat.h>
#include <vnet/fib/fib_table.h>

static clib_error_t *
nat64_add_del_pool_addr_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t start_addr, end_addr, this_addr;
  u32 start_host_order, end_host_order;
  int i, count, rv;
  u32 vrf_id = ~0;
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
      else if (unformat (line_input, "tenant-vrf %u", &vrf_id))
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
      rv = nat64_add_del_pool_addr (&this_addr, vrf_id, is_add);

      switch (rv)
	{
	case VNET_API_ERROR_NO_SUCH_ENTRY:
	  error =
	    clib_error_return (0, "NAT64 pool address %U not exist.",
			       format_ip4_address, &this_addr);
	  goto done;
	case VNET_API_ERROR_VALUE_EXIST:
	  error =
	    clib_error_return (0, "NAT64 pool address %U exist.",
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

static int
nat64_cli_pool_walk (snat_address_t * ap, void *ctx)
{
  vlib_main_t *vm = ctx;

  if (ap->fib_index != ~0)
    {
      fib_table_t *fib;
      fib = fib_table_get (ap->fib_index, FIB_PROTOCOL_IP4);
      if (!fib)
	return -1;
      vlib_cli_output (vm, " %U tenant VRF: %u", format_ip4_address,
		       &ap->addr, fib->ft_table_id);
    }
  else
    vlib_cli_output (vm, " %U", format_ip4_address, &ap->addr);

  return 0;
}

static clib_error_t *
nat64_show_pool_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "NAT64 pool:");
  nat64_pool_addr_walk (nat64_cli_pool_walk, vm);

  return 0;
}

static clib_error_t *
nat64_interface_feature_command_fn (vlib_main_t * vm,
				    unformat_input_t *
				    input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;
  u32 *inside_sw_if_indices = 0;
  u32 *outside_sw_if_indices = 0;
  u8 is_add = 1;
  int i, rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "in %U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	vec_add1 (inside_sw_if_indices, sw_if_index);
      else if (unformat (line_input, "out %U", unformat_vnet_sw_interface,
			 vnm, &sw_if_index))
	vec_add1 (outside_sw_if_indices, sw_if_index);
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (vec_len (inside_sw_if_indices))
    {
      for (i = 0; i < vec_len (inside_sw_if_indices); i++)
	{
	  sw_if_index = inside_sw_if_indices[i];
	  rv = nat64_add_del_interface (sw_if_index, 1, is_add);
	  switch (rv)
	    {
	    case VNET_API_ERROR_NO_SUCH_ENTRY:
	      error =
		clib_error_return (0, "%U NAT64 feature not enabled.",
				   format_vnet_sw_interface_name, vnm,
				   vnet_get_sw_interface (vnm, sw_if_index));
	      goto done;
	    case VNET_API_ERROR_VALUE_EXIST:
	      error =
		clib_error_return (0, "%U NAT64 feature already enabled.",
				   format_vnet_sw_interface_name, vnm,
				   vnet_get_sw_interface (vnm, sw_if_index));
	      goto done;
	    case VNET_API_ERROR_INVALID_VALUE:
	    case VNET_API_ERROR_INVALID_VALUE_2:
	      error =
		clib_error_return (0,
				   "%U NAT64 feature enable/disable failed.",
				   format_vnet_sw_interface_name, vnm,
				   vnet_get_sw_interface (vnm, sw_if_index));
	      goto done;
	    default:
	      break;

	    }
	}
    }

  if (vec_len (outside_sw_if_indices))
    {
      for (i = 0; i < vec_len (outside_sw_if_indices); i++)
	{
	  sw_if_index = outside_sw_if_indices[i];
	  rv = nat64_add_del_interface (sw_if_index, 0, is_add);
	  switch (rv)
	    {
	    case VNET_API_ERROR_NO_SUCH_ENTRY:
	      error =
		clib_error_return (0, "%U NAT64 feature not enabled.",
				   format_vnet_sw_interface_name, vnm,
				   vnet_get_sw_interface (vnm, sw_if_index));
	      goto done;
	    case VNET_API_ERROR_VALUE_EXIST:
	      error =
		clib_error_return (0, "%U NAT64 feature already enabled.",
				   format_vnet_sw_interface_name, vnm,
				   vnet_get_sw_interface (vnm, sw_if_index));
	      goto done;
	    case VNET_API_ERROR_INVALID_VALUE:
	    case VNET_API_ERROR_INVALID_VALUE_2:
	      error =
		clib_error_return (0,
				   "%U NAT64 feature enable/disable failed.",
				   format_vnet_sw_interface_name, vnm,
				   vnet_get_sw_interface (vnm, sw_if_index));
	      goto done;
	    default:
	      break;

	    }
	}
    }

done:
  unformat_free (line_input);
  vec_free (inside_sw_if_indices);
  vec_free (outside_sw_if_indices);

  return error;
}

static int
nat64_cli_interface_walk (snat_interface_t * i, void *ctx)
{
  vlib_main_t *vm = ctx;
  vnet_main_t *vnm = vnet_get_main ();

  vlib_cli_output (vm, " %U %s", format_vnet_sw_interface_name, vnm,
		   vnet_get_sw_interface (vnm, i->sw_if_index),
		   i->is_inside ? "in" : "out");
  return 0;
}

static clib_error_t *
nat64_show_interfaces_command_fn (vlib_main_t * vm,
				  unformat_input_t *
				  input, vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "NAT64 interfaces:");
  nat64_interfaces_walk (nat64_cli_interface_walk, vm);

  return 0;
}

static clib_error_t *
nat64_add_del_static_bib_command_fn (vlib_main_t *
				     vm,
				     unformat_input_t
				     * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u8 is_add = 1;
  ip6_address_t in_addr;
  ip4_address_t out_addr;
  u16 in_port = 0;
  u16 out_port = 0;
  u32 vrf_id = 0;
  snat_protocol_t proto = 0;
  u8 p = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U %u", unformat_ip6_address,
		    &in_addr, &in_port))
	;
      else if (unformat (line_input, "%U %u", unformat_ip4_address,
			 &out_addr, &out_port))
	;
      else if (unformat (line_input, "vrf %u", &vrf_id))
	;
      else if (unformat (line_input, "%U", unformat_snat_protocol, &proto))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!in_port)
    {
      error = clib_error_return (0, "inside port and address  must be set");
      goto done;
    }

  if (!out_port)
    {
      error = clib_error_return (0, "outside port and address  must be set");
      goto done;
    }

  p = snat_proto_to_ip_proto (proto);

  rv =
    nat64_add_del_static_bib_entry (&in_addr, &out_addr, in_port, out_port, p,
				    vrf_id, is_add);

  switch (rv)
    {
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "NAT64 BIB entry not exist.");
      goto done;
    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "NAT64 BIB entry exist.");
      goto done;
    case VNET_API_ERROR_UNSPECIFIED:
      error = clib_error_return (0, "Crerate NAT64 BIB entry failed.");
      goto done;
    case VNET_API_ERROR_INVALID_VALUE:
      error =
	clib_error_return (0, "Outside addres %U and port %u already in use.",
			   format_ip4_address, &out_addr, out_port);
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

static int
nat64_cli_bib_walk (nat64_db_bib_entry_t * bibe, void *ctx)
{
  vlib_main_t *vm = ctx;
  fib_table_t *fib;

  fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
  if (!fib)
    return -1;

  vlib_cli_output (vm, " %U %u %U %u %U vrf %u %s %u sessions",
		   format_ip6_address, &bibe->in_addr,
		   clib_net_to_host_u16 (bibe->in_port), format_ip4_address,
		   &bibe->out_addr, clib_net_to_host_u16 (bibe->out_port),
		   format_snat_protocol, bibe->proto, fib->ft_table_id,
		   bibe->is_static ? "static" : "dynamic", bibe->ses_num);
  return 0;
}

static clib_error_t *
nat64_show_bib_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  nat64_main_t *nm = &nat64_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  snat_protocol_t proto = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat (line_input, "%U", unformat_snat_protocol, &proto))
    ;
  else
    {
      error = clib_error_return (0, "unknown input: '%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  vlib_cli_output (vm, "NAT64 %U BIB:", format_snat_protocol, proto);
  nat64_db_bib_walk (&nm->db, proto, nat64_cli_bib_walk, vm);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat64_set_timeouts_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 timeout, tcp_trans, tcp_est, tcp_incoming_syn;

  tcp_trans = nat64_get_tcp_trans_timeout ();
  tcp_est = nat64_get_tcp_est_timeout ();
  tcp_incoming_syn = nat64_get_tcp_incoming_syn_timeout ();

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "udp %u", &timeout))
	{
	  if (nat64_set_udp_timeout (timeout))
	    {
	      error = clib_error_return (0, "Invalid UDP timeout value");
	      goto done;
	    }
	}
      else if (unformat (line_input, "icmp %u", &timeout))
	{
	  if (nat64_set_icmp_timeout (timeout))
	    {
	      error = clib_error_return (0, "Invalid ICMP timeout value");
	      goto done;
	    }
	}
      else if (unformat (line_input, "tcp-trans %u", &tcp_trans))
	{
	  if (nat64_set_tcp_timeouts (tcp_trans, tcp_est, tcp_incoming_syn))
	    {
	      error =
		clib_error_return (0, "Invalid TCP transitory tiemout value");
	      goto done;
	    }
	}
      else if (unformat (line_input, "tcp-est %u", &tcp_est))
	{
	  if (nat64_set_tcp_timeouts (tcp_trans, tcp_est, tcp_incoming_syn))
	    {
	      error =
		clib_error_return (0,
				   "Invalid TCP established tiemout value");
	      goto done;
	    }
	}
      else
	if (unformat (line_input, "tcp-incoming-syn %u", &tcp_incoming_syn))
	{
	  if (nat64_set_tcp_timeouts (tcp_trans, tcp_est, tcp_incoming_syn))
	    {
	      error =
		clib_error_return (0,
				   "Invalid TCP incoming SYN tiemout value");
	      goto done;
	    }
	}
      else if (unformat (line_input, "reset"))
	{
	  nat64_set_udp_timeout (0);
	  nat64_set_icmp_timeout (0);
	  nat64_set_tcp_timeouts (0, 0, 0);
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat64_show_timeouts_command_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "NAT64 session timeouts:");
  vlib_cli_output (vm, " UDP %usec", nat64_get_udp_timeout ());
  vlib_cli_output (vm, " ICMP %usec", nat64_get_icmp_timeout ());
  vlib_cli_output (vm, " TCP transitory %usec",
		   nat64_get_tcp_trans_timeout ());
  vlib_cli_output (vm, " TCP established %usec",
		   nat64_get_tcp_est_timeout ());
  vlib_cli_output (vm, " TCP incoming SYN %usec",
		   nat64_get_tcp_incoming_syn_timeout ());

  return 0;
}

static int
nat64_cli_st_walk (nat64_db_st_entry_t * ste, void *ctx)
{
  vlib_main_t *vm = ctx;
  nat64_main_t *nm = &nat64_main;
  nat64_db_bib_entry_t *bibe;
  fib_table_t *fib;

  bibe = nat64_db_bib_entry_by_index (&nm->db, ste->proto, ste->bibe_index);
  if (!bibe)
    return -1;

  fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
  if (!fib)
    return -1;

  u32 vrf_id = fib->ft_table_id;

  if (ste->proto == SNAT_PROTOCOL_ICMP)
    vlib_cli_output (vm, " %U %U %u %U %U %u %U vrf %u",
		     format_ip6_address, &bibe->in_addr,
		     format_ip6_address, &ste->in_r_addr,
		     clib_net_to_host_u16 (bibe->in_port),
		     format_ip4_address, &bibe->out_addr,
		     format_ip4_address, &ste->out_r_addr,
		     clib_net_to_host_u16 (bibe->out_port),
		     format_snat_protocol, bibe->proto, vrf_id);
  else
    vlib_cli_output (vm, " %U %u %U %u %U %u %U %u %U vrf %u",
		     format_ip6_address, &bibe->in_addr,
		     clib_net_to_host_u16 (bibe->in_port),
		     format_ip6_address, &ste->in_r_addr,
		     clib_net_to_host_u16 (ste->r_port),
		     format_ip4_address, &bibe->out_addr,
		     clib_net_to_host_u16 (bibe->out_port),
		     format_ip4_address, &ste->out_r_addr,
		     clib_net_to_host_u16 (ste->r_port),
		     format_snat_protocol, bibe->proto, vrf_id);
  return 0;
}

static clib_error_t *
nat64_show_st_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  nat64_main_t *nm = &nat64_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  snat_protocol_t proto = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (unformat (line_input, "%U", unformat_snat_protocol, &proto))
    ;
  else
    {
      error = clib_error_return (0, "unknown input: '%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  vlib_cli_output (vm, "NAT64 %U session table:", format_snat_protocol,
		   proto);
  nat64_db_st_walk (&nm->db, proto, nat64_cli_st_walk, vm);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */

VLIB_CLI_COMMAND (nat64_add_pool_address_command, static) = {
  .path = "nat64 add pool address",
  .short_help = "nat64 add pool address <ip4-range-start> [- <ip4-range-end>] "
                "[tenant-vrf <vrf-id>] [del]",
  .function = nat64_add_del_pool_addr_command_fn,
};

VLIB_CLI_COMMAND (show_nat64_pool_command, static) = {
  .path = "show nat64 pool",
  .short_help = "show nat64 pool",
  .function = nat64_show_pool_command_fn,
};

VLIB_CLI_COMMAND (set_interface_nat64_command, static) = {
  .path = "set interface nat64",
  .short_help = "set interface nat64 in|out <intfc> [del]",
  .function = nat64_interface_feature_command_fn,
};

VLIB_CLI_COMMAND (show_nat64_interfaces_command, static) = {
  .path = "show nat64 interfaces",
  .short_help = "show nat64 interfaces",
  .function = nat64_show_interfaces_command_fn,
};

VLIB_CLI_COMMAND (nat64_add_del_static_bib_command, static) = {
  .path = "nat64 add static bib",
  .short_help = "nat64 add static bib <ip6-addr> <port> <ip4-addr> <port> "
                "tcp|udp|icmp [vfr <table-id>] [del]",
  .function = nat64_add_del_static_bib_command_fn,
};

VLIB_CLI_COMMAND (show_nat64_bib_command, static) = {
  .path = "show nat64 bib",
  .short_help = "show nat64 bib tcp|udp|icmp",
  .function = nat64_show_bib_command_fn,
};

VLIB_CLI_COMMAND (set_nat64_timeouts_command, static) = {
  .path = "set nat64 timeouts",
  .short_help = "set nat64 timeouts udp <sec> icmp <sec> tcp-trans <sec> "
                "tcp-est <sec> tcp-incoming-syn <sec> | reset",
  .function = nat64_set_timeouts_command_fn,
};

VLIB_CLI_COMMAND (show_nat64_timeouts_command, static) = {
  .path = "show nat64 tiemouts",
  .short_help = "show nat64 tiemouts",
  .function = nat64_show_timeouts_command_fn,
};

VLIB_CLI_COMMAND (show_nat64_st_command, static) = {
  .path = "show nat64 session table",
  .short_help = "show nat64 session table tcp|udp|icmp",
  .function = nat64_show_st_command_fn,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
