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

#include <vnet/fib/fib_table.h>
#include <nat/nat64/nat64.h>

#define NAT64_EXPECTED_ARGUMENT "expected required argument(s)"

static clib_error_t *
nat64_plugin_enable_disable_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 enable = 0, is_set = 0;
  clib_error_t *error = 0;
  nat64_config_t c = { 0 };

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT64_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (!is_set && unformat (line_input, "enable"))
	{
	  unformat (line_input, "bib-buckets %u", &c.bib_buckets);
	  unformat (line_input, "bib-memory %u", &c.bib_memory_size);
	  unformat (line_input, "st-buckets %u", &c.st_buckets);
	  unformat (line_input, "st-memory %u", &c.st_memory_size);
	  enable = 1;
	}
      else if (!is_set && unformat (line_input, "disable"));
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
      is_set = 1;
    }

  if (enable)
    {
      if (nat64_plugin_enable (c))
	error = clib_error_return (0, "plugin enable failed");
    }
  else
    {
      if (nat64_plugin_disable ())
	error = clib_error_return (0, "plugin disable failed");
    }
done:
  unformat_free (line_input);
  return error;
}

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
    return clib_error_return (0, NAT64_EXPECTED_ARGUMENT);

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
      rv = nat64_add_del_pool_addr (0, &this_addr, vrf_id, is_add);

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
nat64_cli_pool_walk (nat64_address_t * ap, void *ctx)
{
  vlib_main_t *vm = ctx;

  if (ap->fib_index != ~0)
    {
      fib_table_t *fib;
      fib = fib_table_get (ap->fib_index, FIB_PROTOCOL_IP6);
      if (!fib)
	return -1;
      vlib_cli_output (vm, " %U tenant VRF: %u", format_ip4_address,
		       &ap->addr, fib->ft_table_id);
    }
  else
    vlib_cli_output (vm, " %U", format_ip4_address, &ap->addr);

#define _(N, i, n, s) \
  vlib_cli_output (vm, "  %d busy %s ports", ap->busy_##n##_ports, s);
  foreach_nat_protocol
#undef _
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
    return clib_error_return (0, NAT64_EXPECTED_ARGUMENT);

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
	  rv = nat64_interface_add_del (sw_if_index, 1, is_add);
	  switch (rv)
	    {
	    case VNET_API_ERROR_NO_SUCH_ENTRY:
	      error =
		clib_error_return (0, "%U NAT64 feature not enabled.",
				   format_vnet_sw_if_index_name, vnm,
				   sw_if_index);
	      goto done;
	    case VNET_API_ERROR_VALUE_EXIST:
	      error =
		clib_error_return (0, "%U NAT64 feature already enabled.",
				   format_vnet_sw_if_index_name, vnm,
				   vnm, sw_if_index);
	      goto done;
	    case VNET_API_ERROR_INVALID_VALUE:
	    case VNET_API_ERROR_INVALID_VALUE_2:
	      error =
		clib_error_return (0,
				   "%U NAT64 feature enable/disable failed.",
				   format_vnet_sw_if_index_name, vnm,
				   sw_if_index);
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
	  rv = nat64_interface_add_del (sw_if_index, 0, is_add);
	  switch (rv)
	    {
	    case VNET_API_ERROR_NO_SUCH_ENTRY:
	      error =
		clib_error_return (0, "%U NAT64 feature not enabled.",
				   format_vnet_sw_if_index_name, vnm,
				   sw_if_index);
	      goto done;
	    case VNET_API_ERROR_VALUE_EXIST:
	      error =
		clib_error_return (0, "%U NAT64 feature already enabled.",
				   format_vnet_sw_if_index_name, vnm,
				   sw_if_index);
	      goto done;
	    case VNET_API_ERROR_INVALID_VALUE:
	    case VNET_API_ERROR_INVALID_VALUE_2:
	      error =
		clib_error_return (0,
				   "%U NAT64 feature enable/disable failed.",
				   format_vnet_sw_if_index_name, vnm,
				   sw_if_index);
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
nat64_cli_interface_walk (nat64_interface_t * i, void *ctx)
{
  vlib_main_t *vm = ctx;
  vnet_main_t *vnm = vnet_get_main ();

  vlib_cli_output (vm, " %U %s", format_vnet_sw_if_index_name, vnm,
		   i->sw_if_index,
		   (nat64_interface_is_inside (i)
		    && nat64_interface_is_outside (i)) ? "in out" :
		   nat64_interface_is_inside (i) ? "in" : "out");
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
  u32 in_port = 0;
  u32 out_port = 0;
  u32 vrf_id = 0, protocol;
  nat_protocol_t proto = 0;
  u8 p = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT64_EXPECTED_ARGUMENT);

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
      else if (unformat (line_input, "%U", unformat_nat_protocol, &proto))
	;
      else
	if (unformat
	    (line_input, "%U %U %u", unformat_ip6_address, &in_addr,
	     unformat_ip4_address, &out_addr, &protocol))
	p = (u8) protocol;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!p)
    {
      if (!in_port)
	{
	  error =
	    clib_error_return (0, "inside port and address  must be set");
	  goto done;
	}

      if (!out_port)
	{
	  error =
	    clib_error_return (0, "outside port and address  must be set");
	  goto done;
	}

      p = nat_proto_to_ip_proto (proto);
    }

  rv =
    nat64_add_del_static_bib_entry (&in_addr, &out_addr, (u16) in_port,
				    (u16) out_port, p, vrf_id, is_add);

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
	clib_error_return (0,
			   "Outside address %U and port %u already in use.",
			   format_ip4_address, &out_addr, out_port);
      goto done;
    case VNET_API_ERROR_INVALID_VALUE_2:
      error = clib_error_return (0, "Invalid outside port.");
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

  switch (bibe->proto)
    {
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_TCP:
    case IP_PROTOCOL_UDP:
      vlib_cli_output (vm, " %U %u %U %u protocol %U vrf %u %s %u sessions",
		       format_ip6_address, &bibe->in_addr,
		       clib_net_to_host_u16 (bibe->in_port),
		       format_ip4_address, &bibe->out_addr,
		       clib_net_to_host_u16 (bibe->out_port),
		       format_nat_protocol,
		       ip_proto_to_nat_proto (bibe->proto), fib->ft_table_id,
		       bibe->is_static ? "static" : "dynamic", bibe->ses_num);
      break;
    default:
      vlib_cli_output (vm, " %U %U protocol %u vrf %u %s %u sessions",
		       format_ip6_address, &bibe->in_addr,
		       format_ip4_address, &bibe->out_addr,
		       bibe->proto, fib->ft_table_id,
		       bibe->is_static ? "static" : "dynamic", bibe->ses_num);
    }
  return 0;
}

static clib_error_t *
nat64_show_bib_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  nat64_main_t *nm = &nat64_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 proto = NAT_PROTOCOL_OTHER;
  u8 p = 255;
  nat64_db_t *db;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT64_EXPECTED_ARGUMENT);

  if (unformat (line_input, "%U", unformat_nat_protocol, &proto))
    p = nat_proto_to_ip_proto (proto);
  else if (unformat (line_input, "unknown"))
    p = 0;
  else if (unformat (line_input, "all"))
    ;
  else
    {
      error = clib_error_return (0, "unknown input: '%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  if (p == 255)
    vlib_cli_output (vm, "NAT64 BIB entries:");
  else
    vlib_cli_output (vm, "NAT64 %U BIB entries:", format_nat_protocol, proto);

  vec_foreach (db, nm->db)
    nat64_db_bib_walk (db, p, nat64_cli_bib_walk, vm);

done:
  unformat_free (line_input);

  return error;
}

typedef struct nat64_cli_st_walk_ctx_t_
{
  vlib_main_t *vm;
  nat64_db_t *db;
} nat64_cli_st_walk_ctx_t;

static int
nat64_cli_st_walk (nat64_db_st_entry_t * ste, void *arg)
{
  nat64_cli_st_walk_ctx_t *ctx = arg;
  vlib_main_t *vm = ctx->vm;
  nat64_db_bib_entry_t *bibe;
  fib_table_t *fib;

  bibe = nat64_db_bib_entry_by_index (ctx->db, ste->proto, ste->bibe_index);
  if (!bibe)
    return -1;

  fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
  if (!fib)
    return -1;

  u32 vrf_id = fib->ft_table_id;

  if (ste->proto == IP_PROTOCOL_ICMP)
    vlib_cli_output (vm, " %U %U %u %U %U %u protocol %U vrf %u",
		     format_ip6_address, &bibe->in_addr,
		     format_ip6_address, &ste->in_r_addr,
		     clib_net_to_host_u16 (bibe->in_port),
		     format_ip4_address, &bibe->out_addr,
		     format_ip4_address, &ste->out_r_addr,
		     clib_net_to_host_u16 (bibe->out_port),
		     format_nat_protocol,
		     ip_proto_to_nat_proto (bibe->proto), vrf_id);
  else if (ste->proto == IP_PROTOCOL_TCP || ste->proto == IP_PROTOCOL_UDP)
    vlib_cli_output (vm, " %U %u %U %u %U %u %U %u protcol %U vrf %u",
		     format_ip6_address, &bibe->in_addr,
		     clib_net_to_host_u16 (bibe->in_port),
		     format_ip6_address, &ste->in_r_addr,
		     clib_net_to_host_u16 (ste->r_port),
		     format_ip4_address, &bibe->out_addr,
		     clib_net_to_host_u16 (bibe->out_port),
		     format_ip4_address, &ste->out_r_addr,
		     clib_net_to_host_u16 (ste->r_port),
		     format_nat_protocol,
		     ip_proto_to_nat_proto (bibe->proto), vrf_id);
  else
    vlib_cli_output (vm, " %U %U %U %U protocol %u vrf %u",
		     format_ip6_address, &bibe->in_addr,
		     format_ip6_address, &ste->in_r_addr,
		     format_ip4_address, &bibe->out_addr,
		     format_ip4_address, &ste->out_r_addr,
		     bibe->proto, vrf_id);

  return 0;
}

static clib_error_t *
nat64_show_st_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  nat64_main_t *nm = &nat64_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 proto = NAT_PROTOCOL_OTHER;
  u8 p = 255;
  nat64_db_t *db;
  nat64_cli_st_walk_ctx_t ctx = {
    .vm = vm,
  };

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT64_EXPECTED_ARGUMENT);

  if (unformat (line_input, "%U", unformat_nat_protocol, &proto))
    p = nat_proto_to_ip_proto (proto);
  else if (unformat (line_input, "unknown"))
    p = 0;
  else if (unformat (line_input, "all"))
    ;
  else
    {
      error = clib_error_return (0, "unknown input: '%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  if (p == 255)
    vlib_cli_output (vm, "NAT64 sessions:");
  else
    vlib_cli_output (vm, "NAT64 %U sessions:", format_nat_protocol, proto);
  vec_foreach (db, nm->db)
    {
      ctx.db = db;
      nat64_db_st_walk (db, p, nat64_cli_st_walk, &ctx);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat64_add_del_prefix_command_fn (vlib_main_t * vm, unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  nat64_main_t *nm = &nat64_main;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 vrf_id = 0, sw_if_index = ~0;
  ip6_address_t prefix;
  u32 plen = 0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT64_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U/%u", unformat_ip6_address, &prefix, &plen))
	;
      else if (unformat (line_input, "tenant-vrf %u", &vrf_id))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	if (unformat
	    (line_input, "interface %U", unformat_vnet_sw_interface, vnm,
	     &sw_if_index))
	;
      else
	{
	  error = clib_error_return (0, "unknown input: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!plen)
    {
      error = clib_error_return (0, "NAT64 prefix must be set.");
      goto done;
    }

  rv = nat64_add_del_prefix (&prefix, (u8) plen, vrf_id, is_add);

  switch (rv)
    {
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "NAT64 prefix not exist.");
      goto done;
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "Invalid prefix length.");
      goto done;
    default:
      break;
    }

  /*
   * Add RX interface route, whenNAT isn't running on the real input
   * interface
   */
  if (sw_if_index != ~0)
    {
      u32 fib_index;
      fib_prefix_t fibpfx = {
	.fp_len = plen,
	.fp_proto = FIB_PROTOCOL_IP6,
	.fp_addr = {
		    .ip6 = prefix}
      };

      if (is_add)
	{
	  fib_index =
	    fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6,
					       vrf_id, nm->fib_src_hi);
	  fib_table_entry_update_one_path (fib_index, &fibpfx,
					   nm->fib_src_hi,
					   FIB_ENTRY_FLAG_NONE,
					   DPO_PROTO_IP6, NULL,
					   sw_if_index, ~0, 0,
					   NULL, FIB_ROUTE_PATH_INTF_RX);
	}
      else
	{
	  fib_index = fib_table_find (FIB_PROTOCOL_IP6, vrf_id);
	  fib_table_entry_path_remove (fib_index, &fibpfx,
				       nm->fib_src_hi,
				       DPO_PROTO_IP6, NULL,
				       sw_if_index, ~0, 1,
				       FIB_ROUTE_PATH_INTF_RX);
	  fib_table_unlock (fib_index, FIB_PROTOCOL_IP6, nm->fib_src_hi);
	}
    }

done:
  unformat_free (line_input);

  return error;
}

static int
nat64_cli_prefix_walk (nat64_prefix_t * p, void *ctx)
{
  vlib_main_t *vm = ctx;

  vlib_cli_output (vm, " %U/%u tenant-vrf %u",
		   format_ip6_address, &p->prefix, p->plen, p->vrf_id);

  return 0;
}

static clib_error_t *
nat64_show_prefix_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "NAT64 prefix:");
  nat64_prefix_walk (nat64_cli_prefix_walk, vm);

  return 0;
}

static clib_error_t *
nat64_add_interface_address_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index;
  int rv;
  int is_add = 1;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, NAT64_EXPECTED_ARGUMENT);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index));
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = nat64_add_interface_address (sw_if_index, is_add);

  switch (rv)
    {
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "entry not exist");
      break;
    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "entry exist");
      break;
    default:
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * @cliexpar
 * @cliexstart{nat64 plugin}
 * Enable/disable NAT64 plugin.
 * To enable NAT64 plugin use:
 *  vpp# nat64 plugin enable
 * To enable NAT64 plugin and configure buckets/memory:
 *  vpp# nat64 plugin enable bib-buckets <n> bib-memory <s> \
 *    st-buckets <n> st-memory <s>
 * To disable NAT64 plugin:
 *  vpp# nat64 plugin disable
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat64_plugin_enable_disable_command, static) =
{
  .path = "nat64 plugin",
  .short_help = "nat64 plugin <enable "
                "[bib-buckets <count>] [bib-memory <size>] "
                "[st-buckets <count>] [st-memory <size>] | disable>",
  .function = nat64_plugin_enable_disable_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat64 add pool address}
 * Add/delete NAT64 pool address.
 * To add single NAT64 pool address use:
 *  vpp# nat64 add pool address 10.1.1.10
 * To add NAT64 pool address range use:
 *  vpp# nat64 add pool address 10.1.1.2 - 10.1.1.5
 * To add NAT64 pool address for specific tenant use:
 *  vpp# nat64 add pool address 10.1.1.100 tenant-vrf 100
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat64_add_pool_address_command, static) = {
  .path = "nat64 add pool address",
  .short_help = "nat64 add pool address <ip4-range-start> [- <ip4-range-end>] "
                "[tenant-vrf <vrf-id>] [del]",
  .function = nat64_add_del_pool_addr_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat64 pool}
 * Show NAT64 pool.
 *  vpp# show nat64 pool
 *  NAT64 pool:
 *   10.1.1.3 tenant VRF: 0
 *   10.1.1.10 tenant VRF: 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_nat64_pool_command, static) = {
  .path = "show nat64 pool",
  .short_help = "show nat64 pool",
  .function = nat64_show_pool_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set interface nat64}
 * Enable/disable NAT64 feature on the interface.
 * To enable NAT64 feature with local (IPv6) network interface
 * GigabitEthernet0/8/0 and external (IPv4) network interface
 * GigabitEthernet0/a/0 use:
 *  vpp# set interface nat64 in GigabitEthernet0/8/0 out GigabitEthernet0/a/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_interface_nat64_command, static) = {
  .path = "set interface nat64",
  .short_help = "set interface nat64 in|out <intfc> [del]",
  .function = nat64_interface_feature_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat64 interfaces}
 * Show interfaces with NAT64 feature.
 * To show interfaces with NAT64 feature use:
 *  vpp# show nat64 interfaces
 *  NAT64 interfaces:
 *   GigabitEthernet0/8/0 in
 *   GigabitEthernet0/a/0 out
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_nat64_interfaces_command, static) = {
  .path = "show nat64 interfaces",
  .short_help = "show nat64 interfaces",
  .function = nat64_show_interfaces_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat64 add static bib}
 * Add/delete NAT64 static BIB entry.
 * To create NAT64 satatic BIB entry use:
 *  vpp# nat64 add static bib 2001:db8:c000:221:: 1234 10.1.1.3 5678 tcp
 *  vpp# nat64 add static bib 2001:db8:c000:221:: 1234 10.1.1.3 5678 udp vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat64_add_del_static_bib_command, static) = {
  .path = "nat64 add static bib",
  .short_help = "nat64 add static bib <ip6-addr> <port> <ip4-addr> <port> "
                "tcp|udp|icmp [vfr <table-id>] [del]",
  .function = nat64_add_del_static_bib_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat64 bib}
 * Show NAT64 BIB entries.
 * To show NAT64 TCP BIB entries use:
 *  vpp# show nat64 bib tcp
 *  NAT64 tcp BIB:
 *   fd01:1::2 6303 10.0.0.3 62303 tcp vrf 0 dynamic 1 sessions
 *   2001:db8:c000:221:: 1234 10.1.1.3 5678 tcp vrf 0 static 2 sessions
 * To show NAT64 UDP BIB entries use:
 *  vpp# show nat64 bib udp
 *  NAT64 udp BIB:
 *   fd01:1::2 6304 10.0.0.3 10546 udp vrf 0 dynamic 10 sessions
 *   2001:db8:c000:221:: 1234 10.1.1.3 5678 udp vrf 10 static 0 sessions
 * To show NAT64 ICMP BIB entries use:
 *  vpp# show nat64 bib icmp
 *  NAT64 icmp BIB:
 *   fd01:1::2 6305 10.0.0.3 63209 icmp vrf 10 dynamic 1 sessions
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_nat64_bib_command, static) = {
  .path = "show nat64 bib",
  .short_help = "show nat64 bib all|tcp|udp|icmp|unknown",
  .function = nat64_show_bib_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat64 session table}
 * Show NAT64 session table.
 * To show NAT64 TCP session table use:
 *  vpp# show nat64 session table tcp
 *  NAT64 tcp session table:
 *   fd01:1::2 6303 64:ff9b::ac10:202 20 10.0.0.3 62303 172.16.2.2 20 tcp vrf 0
 *   fd01:3::2 6303 64:ff9b::ac10:202 20 10.0.10.3 21300 172.16.2.2 20 tcp vrf 10
 * To show NAT64 UDP session table use:
 * #vpp show nat64 session table udp
 * NAT64 udp session table:
 *  fd01:1::2 6304 64:ff9b::ac10:202 20 10.0.0.3 10546 172.16.2.2 20 udp vrf 0
 *  fd01:3::2 6304 64:ff9b::ac10:202 20 10.0.10.3 58627 172.16.2.2 20 udp vrf 10
 *  fd01:1::2 1235 64:ff9b::a00:3 4023 10.0.0.3 24488 10.0.0.3 4023 udp vrf 0
 *  fd01:1::3 23 64:ff9b::a00:3 24488 10.0.0.3 4023 10.0.0.3 24488 udp vrf 0
 * To show NAT64 ICMP session table use:
 * #vpp show nat64 session table icmp
 * NAT64 icmp session table:
 *  fd01:1::2 64:ff9b::ac10:202 6305 10.0.0.3 172.16.2.2 63209 icmp vrf 0
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_nat64_st_command, static) = {
  .path = "show nat64 session table",
  .short_help = "show nat64 session table all|tcp|udp|icmp|unknown",
  .function = nat64_show_st_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat64 add prefix}
 * Set NAT64 prefix for generating IPv6 representations of IPv4 addresses.
 * To set NAT64 global prefix use:
 *  vpp# nat64 add prefix 2001:db8::/32
 * To set NAT64 prefix for specific tenant use:
 *  vpp# nat64 add prefix 2001:db8:122:300::/56 tenant-vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat64_add_del_prefix_command, static) = {
  .path = "nat64 add prefix",
  .short_help = "nat64 add prefix <ip6-prefix>/<plen> [tenant-vrf <vrf-id>] "
                "[del] [interface <interface]",
  .function = nat64_add_del_prefix_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat64 prefix}
 * Show NAT64 prefix.
 * To show NAT64 prefix use:
 *  vpp# show nat64 prefix
 *  NAT64 prefix:
 *   2001:db8::/32 tenant-vrf 0
 *   2001:db8:122:300::/56 tenant-vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_nat64_prefix_command, static) = {
  .path = "show nat64 prefix",
  .short_help = "show nat64 prefix",
  .function = nat64_show_prefix_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat64 add interface address}
 * Add/delete NAT64 pool address from specific (DHCP addressed) interface.
 * To add NAT64 pool address from specific interface use:
 *  vpp# nat64 add interface address GigabitEthernet0/8/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat64_add_interface_address_command, static) = {
    .path = "nat64 add interface address",
    .short_help = "nat64 add interface address <interface> [del]",
    .function = nat64_add_interface_address_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
