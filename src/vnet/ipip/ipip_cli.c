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

#include "ipip.h"
#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/fib/fib_table.h>

static clib_error_t *
create_ipip_tunnel_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t src = ip46_address_initializer, dst =
    ip46_address_initializer;
  u32 instance = ~0;
  u32 fib_index = 0;
  u32 table_id = 0;
  int rv;
  u32 num_m_args = 0;
  u32 sw_if_index;
  clib_error_t *error = NULL;
  bool ip4_set = false, ip6_set = false;
  tunnel_mode_t mode = TUNNEL_MODE_P2P;
  tunnel_encap_decap_flags_t flags = TUNNEL_ENCAP_DECAP_FLAG_NONE;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "instance %d", &instance))
	;
      else
	if (unformat (line_input, "src %U", unformat_ip4_address, &src.ip4))
	{
	  num_m_args++;
	  ip4_set = true;
	}
      else
	if (unformat (line_input, "dst %U", unformat_ip4_address, &dst.ip4))
	{
	  num_m_args++;
	  ip4_set = true;
	}
      else
	if (unformat (line_input, "src %U", unformat_ip6_address, &src.ip6))
	{
	  num_m_args++;
	  ip6_set = true;
	}
      else
	if (unformat (line_input, "dst %U", unformat_ip6_address, &dst.ip6))
	{
	  num_m_args++;
	  ip6_set = true;
	}
      else if (unformat (line_input, "%U", unformat_tunnel_mode, &mode))
	{
	  num_m_args++;
	}
      else if (unformat (line_input, "outer-table-id %d", &table_id))
	;
      else
	if (unformat
	    (line_input, "flags %U", unformat_tunnel_encap_decap_flags,
	     &flags))
	;
      else
	{
	  error =
	    clib_error_return (0, "unknown input `%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  if (num_m_args < 2)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      goto done;
    }
  if (ip4_set && ip6_set)
    {
      error =
	clib_error_return (0,
			   "source and destination must be of same address family");
      goto done;
    }

  fib_index = fib_table_find (fib_ip_proto (ip6_set), table_id);

  if (~0 == fib_index)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
    }
  else
    {
      rv = ipip_add_tunnel (ip6_set ? IPIP_TRANSPORT_IP6 : IPIP_TRANSPORT_IP4,
			    instance,
			    &src,
			    &dst,
			    fib_index,
			    flags, IP_DSCP_CS0, mode, &sw_if_index);
    }

  switch (rv)
    {
    case 0:
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);
      break;
    case VNET_API_ERROR_IF_ALREADY_EXISTS:
      error = clib_error_return (0, "IPIP tunnel already exists...");
      goto done;
    case VNET_API_ERROR_NO_SUCH_FIB:
      error =
	clib_error_return (0, "outer fib ID %d doesn't exist\n", fib_index);
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "IPIP tunnel doesn't exist");
      goto done;
    case VNET_API_ERROR_INSTANCE_IN_USE:
      error = clib_error_return (0, "Instance is in use");
      goto done;
    case VNET_API_ERROR_INVALID_DST_ADDRESS:
      error =
	clib_error_return (0,
			   "destination IP address when mode is multi-point");
      goto done;
    default:
      error =
	clib_error_return (0, "vnet_ipip_add_del_tunnel returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
delete_ipip_tunnel_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  int rv;
  u32 num_m_args = 0;
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	num_m_args++;
      else
	{
	  error =
	    clib_error_return (0, "unknown input `%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  if (num_m_args < 1)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      goto done;
    }

  rv = ipip_del_tunnel (sw_if_index);
  printf ("RV %d\n", rv);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(create_ipip_tunnel_command, static) = {
    .path = "create ipip tunnel",
    .short_help = "create ipip tunnel src <addr> dst <addr> [instance <n>] "
                  "[outer-table-id <ID>] [p2mp]",
    .function = create_ipip_tunnel_command_fn,
};
VLIB_CLI_COMMAND(delete_ipip_tunnel_command, static) = {
    .path = "delete ipip tunnel",
    .short_help = "delete ipip tunnel sw_if_index <sw_if_index>",
    .function = delete_ipip_tunnel_command_fn,
};
/* *INDENT-ON* */

static u8 *
format_ipip_tunnel (u8 * s, va_list * args)
{
  ipip_tunnel_t *t = va_arg (*args, ipip_tunnel_t *);

  ip46_type_t type =
    (t->transport == IPIP_TRANSPORT_IP4) ? IP46_TYPE_IP4 : IP46_TYPE_IP6;
  u32 table_id;

  table_id = fib_table_get_table_id (t->fib_index,
				     fib_proto_from_ip46 (type));
  switch (t->mode)
    {
    case IPIP_MODE_6RD:
      s = format (s, "[%d] 6rd src %U ip6-pfx %U/%d ",
		  t->dev_instance,
		  format_ip46_address, &t->tunnel_src, type,
		  format_ip6_address, &t->sixrd.ip6_prefix,
		  t->sixrd.ip6_prefix_len);
      break;
    case IPIP_MODE_P2P:
      s = format (s, "[%d] instance %d src %U dst %U ",
		  t->dev_instance, t->user_instance,
		  format_ip46_address, &t->tunnel_src, type,
		  format_ip46_address, &t->tunnel_dst, type);
      break;
    case IPIP_MODE_P2MP:
      s = format (s, "[%d] instance %d p2mp src %U ",
		  t->dev_instance, t->user_instance,
		  format_ip46_address, &t->tunnel_src, type);
      break;
    }

  s = format (s, "table-ID %d sw-if-idx %d flags [%U] dscp %U",
	      table_id, t->sw_if_index,
	      format_tunnel_encap_decap_flags, t->flags,
	      format_ip_dscp, t->dscp);

  return s;
}

static clib_error_t *
show_ipip_tunnel_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  ipip_main_t *gm = &ipip_main;
  ipip_tunnel_t *t;
  u32 ti = ~0;

  if (pool_elts (gm->tunnels) == 0)
    vlib_cli_output (vm, "No IPIP tunnels configured...");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &ti))
	;
      else
	break;
    }

  if (ti == ~0)
    {
    /* *INDENT-OFF* */
    pool_foreach(t, gm->tunnels,
                 ({vlib_cli_output(vm, "%U", format_ipip_tunnel, t); }));
    /* *INDENT-ON* */
    }
  else
    {
      if (pool_is_free_index (gm->tunnels, ti))
	return clib_error_return (0, "unknown index:%d", ti);
      t = pool_elt_at_index (gm->tunnels, ti);
      if (t)
	vlib_cli_output (vm, "%U", format_ipip_tunnel, t);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(show_ipip_tunnel_command, static) = {
    .path = "show ipip tunnel",
    .function = show_ipip_tunnel_command_fn,
};
/* *INDENT-ON* */

static u8 *
format_ipip_tunnel_key (u8 * s, va_list * args)
{
  ipip_tunnel_key_t *t = va_arg (*args, ipip_tunnel_key_t *);

  s = format (s, "src:%U dst:%U fib:%d transport:%d mode:%d",
	      format_ip46_address, &t->src, IP46_TYPE_ANY,
	      format_ip46_address, &t->dst, IP46_TYPE_ANY,
	      t->fib_index, t->transport, t->mode);

  return (s);
}

static clib_error_t *
ipip_tunnel_hash_show (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ipip_main_t *im = &ipip_main;
  ipip_tunnel_key_t *key;
  u32 index;

  /* *INDENT-OFF* */
  hash_foreach(key, index, im->tunnel_by_key,
  ({
      vlib_cli_output (vm, " %U -> %d", format_ipip_tunnel_key, key, index);
  }));
  /* *INDENT-ON* */

  return NULL;
}

/**
 * show IPSEC tunnel protection hash tables
 */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ipip_tunnel_hash_show_node, static) =
{
  .path = "show ipip tunnel-hash",
  .function = ipip_tunnel_hash_show,
  .short_help =  "show ipip tunnel-hash",
};
/* *INDENT-ON* */

static clib_error_t *
create_sixrd_tunnel_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t ip4_prefix;
  ip6_address_t ip6_prefix;
  ip4_address_t ip4_src;
  u32 ip6_prefix_len = 0, ip4_prefix_len = 0, sixrd_tunnel_index;
  u32 num_m_args = 0;
  /* Optional arguments */
  u32 ip4_table_id = 0, ip4_fib_index;
  u32 ip6_table_id = 0, ip6_fib_index;
  clib_error_t *error = 0;
  bool security_check = false;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "security-check"))
	security_check = true;
      else if (unformat (line_input, "ip6-pfx %U/%d", unformat_ip6_address,
			 &ip6_prefix, &ip6_prefix_len))
	num_m_args++;
      else if (unformat (line_input, "ip4-pfx %U/%d", unformat_ip4_address,
			 &ip4_prefix, &ip4_prefix_len))
	num_m_args++;
      else
	if (unformat
	    (line_input, "ip4-src %U", unformat_ip4_address, &ip4_src))
	num_m_args++;
      else if (unformat (line_input, "ip4-table-id %d", &ip4_table_id))
	;
      else if (unformat (line_input, "ip6-table-id %d", &ip6_table_id))
	;
      else
	{
	  error =
	    clib_error_return (0, "unknown input `%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  if (num_m_args < 3)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      goto done;
    }
  ip4_fib_index = fib_table_find (FIB_PROTOCOL_IP4, ip4_table_id);
  ip6_fib_index = fib_table_find (FIB_PROTOCOL_IP6, ip6_table_id);

  if (~0 == ip4_fib_index)
    {
      error = clib_error_return (0, "No such IP4 table %d", ip4_table_id);
      rv = VNET_API_ERROR_NO_SUCH_FIB;
    }
  else if (~0 == ip6_fib_index)
    {
      error = clib_error_return (0, "No such IP6 table %d", ip6_table_id);
      rv = VNET_API_ERROR_NO_SUCH_FIB;
    }
  else
    {
      rv = sixrd_add_tunnel (&ip6_prefix, ip6_prefix_len, &ip4_prefix,
			     ip4_prefix_len, &ip4_src, security_check,
			     ip4_fib_index, ip6_fib_index,
			     &sixrd_tunnel_index);

      if (rv)
	error = clib_error_return (0, "adding tunnel failed %d", rv);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
delete_sixrd_tunnel_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 num_m_args = 0;
  /* Optional arguments */
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	num_m_args++;
      else
	{
	  error =
	    clib_error_return (0, "unknown input `%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  if (num_m_args < 1)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      goto done;
    }
  int rv = sixrd_del_tunnel (sw_if_index);
  printf ("RV %d\n", rv);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(create_sixrd_tunnel_command, static) = {
    .path = "create 6rd tunnel",
    .short_help = "create 6rd tunnel ip6-pfx <ip6-pfx> ip4-pfx <ip4-pfx> "
                  "ip4-src <ip4-addr> ip4-table-id <ID> ip6-table-id <ID> "
                  "[security-check]",
    .function = create_sixrd_tunnel_command_fn,
};
VLIB_CLI_COMMAND(delete_sixrd_tunnel_command, static) = {
    .path = "delete 6rd tunnel",
    .short_help = "delete 6rd tunnel sw_if_index <sw_if_index>",
    .function = delete_sixrd_tunnel_command_fn,
};
/* *INDENT-ON* */
