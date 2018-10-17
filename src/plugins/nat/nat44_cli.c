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
 * @file
 * @brief NAT44 CLI
 */

#include <nat/nat.h>
#include <nat/nat_ipfix_logging.h>
#include <nat/nat_det.h>
#include <nat/nat64.h>
#include <nat/nat_inlines.h>
#include <nat/nat_affinity.h>
#include <vnet/fib/fib_table.h>

#define UNSUPPORTED_IN_DET_MODE_STR \
  "This command is unsupported in deterministic mode"
#define SUPPORTED_ONLY_IN_DET_MODE_STR \
  "This command is supported only in deterministic mode"

static clib_error_t *
set_workers_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snat_main_t *sm = &snat_main;
  uword *bitmap = 0;
  int rv = 0;
  clib_error_t *error = 0;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_bitmap_list, &bitmap))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (bitmap == 0)
    {
      error = clib_error_return (0, "List of workers must be specified.");
      goto done;
    }

  rv = snat_set_workers (bitmap);

  clib_bitmap_free (bitmap);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_WORKER:
      error = clib_error_return (0, "Invalid worker(s).");
      goto done;
    case VNET_API_ERROR_FEATURE_DISABLED:
      error = clib_error_return (0,
				 "Supported only if 2 or more workes available.");
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat_show_workers_commnad_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  u32 *worker;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  if (sm->num_workers > 1)
    {
      vlib_cli_output (vm, "%d workers", vec_len (sm->workers));
      /* *INDENT-OFF* */
      vec_foreach (worker, sm->workers)
        {
          vlib_worker_thread_t *w =
            vlib_worker_threads + *worker + sm->first_worker_index;
          vlib_cli_output (vm, "  %s", w->name);
        }
      /* *INDENT-ON* */
    }

  return 0;
}

static clib_error_t *
snat_ipfix_logging_enable_disable_command_fn (vlib_main_t * vm,
					      unformat_input_t * input,
					      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 domain_id = 0;
  u32 src_port = 0;
  u8 enable = 1;
  int rv = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "domain %d", &domain_id))
	;
      else if (unformat (line_input, "src-port %d", &src_port))
	;
      else if (unformat (line_input, "disable"))
	enable = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = snat_ipfix_logging_enable_disable (enable, domain_id, (u16) src_port);

  if (rv)
    {
      error = clib_error_return (0, "ipfix logging enable failed");
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_show_hash_commnad_fn (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  nat_affinity_main_t *nam = &nat_affinity_main;
  int i;
  int verbose = 0;

  if (unformat (input, "detail"))
    verbose = 1;
  else if (unformat (input, "verbose"))
    verbose = 2;

  vlib_cli_output (vm, "%U", format_bihash_8_8, &sm->static_mapping_by_local,
		   verbose);
  vlib_cli_output (vm, "%U",
		   format_bihash_8_8, &sm->static_mapping_by_external,
		   verbose);
  vec_foreach_index (i, sm->per_thread_data)
  {
    tsm = vec_elt_at_index (sm->per_thread_data, i);
    vlib_cli_output (vm, "-------- thread %d %s --------\n",
		     i, vlib_worker_threads[i].name);
    if (sm->endpoint_dependent)
      {
	vlib_cli_output (vm, "%U", format_bihash_16_8, &tsm->in2out_ed,
			 verbose);
	vlib_cli_output (vm, "%U", format_bihash_16_8, &tsm->out2in_ed,
			 verbose);
      }
    else
      {
	vlib_cli_output (vm, "%U", format_bihash_8_8, &tsm->in2out, verbose);
	vlib_cli_output (vm, "%U", format_bihash_8_8, &tsm->out2in, verbose);
      }
    vlib_cli_output (vm, "%U", format_bihash_8_8, &tsm->user_hash, verbose);
  }

  if (sm->endpoint_dependent)
    vlib_cli_output (vm, "%U", format_bihash_16_8, &nam->affinity_hash,
		     verbose);
  return 0;
}

static clib_error_t *
nat44_set_alloc_addr_and_port_alg_command_fn (vlib_main_t * vm,
					      unformat_input_t * input,
					      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snat_main_t *sm = &snat_main;
  clib_error_t *error = 0;
  u32 psid, psid_offset, psid_length, port_start, port_end;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "default"))
	nat_set_alloc_addr_and_port_default ();
      else
	if (unformat
	    (line_input, "map-e psid %d psid-offset %d psid-len %d", &psid,
	     &psid_offset, &psid_length))
	nat_set_alloc_addr_and_port_mape ((u16) psid, (u16) psid_offset,
					  (u16) psid_length);
      else
	if (unformat
	    (line_input, "port-range %d - %d", &port_start, &port_end))
	{
	  if (port_end <= port_start)
	    {
	      error =
		clib_error_return (0,
				   "The end-port must be greater than start-port");
	      goto done;
	    }
	  nat_set_alloc_addr_and_port_range ((u16) port_start,
					     (u16) port_end);
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
};

static clib_error_t *
nat44_show_alloc_addr_and_port_alg_command_fn (vlib_main_t * vm,
					       unformat_input_t * input,
					       vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  vlib_cli_output (vm, "NAT address and port: %U",
		   format_nat_addr_and_port_alloc_alg,
		   sm->addr_and_port_alloc_alg);
  switch (sm->addr_and_port_alloc_alg)
    {
    case NAT_ADDR_AND_PORT_ALLOC_ALG_MAPE:
      vlib_cli_output (vm, "  psid %d psid-offset %d psid-len %d", sm->psid,
		       sm->psid_offset, sm->psid_length);
      break;
    case NAT_ADDR_AND_PORT_ALLOC_ALG_RANGE:
      vlib_cli_output (vm, "  start-port %d end-port %d", sm->start_port,
		       sm->end_port);
      break;
    default:
      break;
    }

  return 0;
}

static clib_error_t *
nat_set_mss_clamping_command_fn (vlib_main_t * vm, unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snat_main_t *sm = &snat_main;
  clib_error_t *error = 0;
  u32 mss;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "disable"))
	sm->mss_clamping = 0;
      else if (unformat (line_input, "%d", &mss))
	{
	  sm->mss_clamping = (u16) mss;
	  sm->mss_value_net = clib_host_to_net_u16 (sm->mss_clamping);
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
nat_show_mss_clamping_command_fn (vlib_main_t * vm, unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;

  if (sm->mss_clamping)
    vlib_cli_output (vm, "mss-clamping %d", sm->mss_clamping);
  else
    vlib_cli_output (vm, "mss-clamping disabled");

  return 0;
}

static clib_error_t *
add_address_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snat_main_t *sm = &snat_main;
  ip4_address_t start_addr, end_addr, this_addr;
  u32 start_host_order, end_host_order;
  u32 vrf_id = ~0;
  int i, count;
  int is_add = 1;
  int rv = 0;
  clib_error_t *error = 0;
  u8 twice_nat = 0;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

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
      else if (unformat (line_input, "twice-nat"))
	twice_nat = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sm->static_mapping_only)
    {
      error = clib_error_return (0, "static mapping only mode");
      goto done;
    }

  start_host_order = clib_host_to_net_u32 (start_addr.as_u32);
  end_host_order = clib_host_to_net_u32 (end_addr.as_u32);

  if (end_host_order < start_host_order)
    {
      error = clib_error_return (0, "end address less than start address");
      goto done;
    }

  count = (end_host_order - start_host_order) + 1;

  if (count > 1024)
    nat_log_info ("%U - %U, %d addresses...",
		  format_ip4_address, &start_addr,
		  format_ip4_address, &end_addr, count);

  this_addr = start_addr;

  for (i = 0; i < count; i++)
    {
      if (is_add)
	rv = snat_add_address (sm, &this_addr, vrf_id, twice_nat);
      else
	rv = snat_del_address (sm, this_addr, 0, twice_nat);

      switch (rv)
	{
	case VNET_API_ERROR_VALUE_EXIST:
	  error = clib_error_return (0, "NAT address already in use.");
	  goto done;
	case VNET_API_ERROR_NO_SUCH_ENTRY:
	  error = clib_error_return (0, "NAT address not exist.");
	  goto done;
	case VNET_API_ERROR_UNSPECIFIED:
	  error =
	    clib_error_return (0, "NAT address used in static mapping.");
	  goto done;
	case VNET_API_ERROR_FEATURE_DISABLED:
	  error =
	    clib_error_return (0,
			       "twice NAT available only for endpoint-dependent mode.");
	  goto done;
	default:
	  break;
	}

      if (sm->out2in_dpo)
	nat44_add_del_address_dpo (this_addr, is_add);

      increment_v4_address (&this_addr);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_show_addresses_command_fn (vlib_main_t * vm, unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  snat_address_t *ap;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  vlib_cli_output (vm, "NAT44 pool addresses:");
  /* *INDENT-OFF* */
  vec_foreach (ap, sm->addresses)
    {
      vlib_cli_output (vm, "%U", format_ip4_address, &ap->addr);
      if (ap->fib_index != ~0)
          vlib_cli_output (vm, "  tenant VRF: %u",
            fib_table_get(ap->fib_index, FIB_PROTOCOL_IP4)->ft_table_id);
      else
        vlib_cli_output (vm, "  tenant VRF independent");
    #define _(N, i, n, s) \
      vlib_cli_output (vm, "  %d busy %s ports", ap->busy_##n##_ports, s);
      foreach_snat_protocol
    #undef _
    }
  vlib_cli_output (vm, "NAT44 twice-nat pool addresses:");
  vec_foreach (ap, sm->twice_nat_addresses)
    {
      vlib_cli_output (vm, "%U", format_ip4_address, &ap->addr);
      if (ap->fib_index != ~0)
          vlib_cli_output (vm, "  tenant VRF: %u",
            fib_table_get(ap->fib_index, FIB_PROTOCOL_IP4)->ft_table_id);
      else
        vlib_cli_output (vm, "  tenant VRF independent");
    #define _(N, i, n, s) \
      vlib_cli_output (vm, "  %d busy %s ports", ap->busy_##n##_ports, s);
      foreach_snat_protocol
    #undef _
    }
  /* *INDENT-ON* */
  return 0;
}

static clib_error_t *
snat_feature_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;
  u32 *inside_sw_if_indices = 0;
  u32 *outside_sw_if_indices = 0;
  u8 is_output_feature = 0;
  int is_del = 0;
  int i;

  sw_if_index = ~0;

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
      else if (unformat (line_input, "output-feature"))
	is_output_feature = 1;
      else if (unformat (line_input, "del"))
	is_del = 1;
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
	  if (is_output_feature)
	    {
	      if (snat_interface_add_del_output_feature
		  (sw_if_index, 1, is_del))
		{
		  error = clib_error_return (0, "%s %U failed",
					     is_del ? "del" : "add",
					     format_vnet_sw_if_index_name,
					     vnm, sw_if_index);
		  goto done;
		}
	    }
	  else
	    {
	      if (snat_interface_add_del (sw_if_index, 1, is_del))
		{
		  error = clib_error_return (0, "%s %U failed",
					     is_del ? "del" : "add",
					     format_vnet_sw_if_index_name,
					     vnm, sw_if_index);
		  goto done;
		}
	    }
	}
    }

  if (vec_len (outside_sw_if_indices))
    {
      for (i = 0; i < vec_len (outside_sw_if_indices); i++)
	{
	  sw_if_index = outside_sw_if_indices[i];
	  if (is_output_feature)
	    {
	      if (snat_interface_add_del_output_feature
		  (sw_if_index, 0, is_del))
		{
		  error = clib_error_return (0, "%s %U failed",
					     is_del ? "del" : "add",
					     format_vnet_sw_if_index_name,
					     vnm, sw_if_index);
		  goto done;
		}
	    }
	  else
	    {
	      if (snat_interface_add_del (sw_if_index, 0, is_del))
		{
		  error = clib_error_return (0, "%s %U failed",
					     is_del ? "del" : "add",
					     format_vnet_sw_if_index_name,
					     vnm, sw_if_index);
		  goto done;
		}
	    }
	}
    }

done:
  unformat_free (line_input);
  vec_free (inside_sw_if_indices);
  vec_free (outside_sw_if_indices);

  return error;
}

static clib_error_t *
nat44_show_interfaces_command_fn (vlib_main_t * vm, unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;
  vnet_main_t *vnm = vnet_get_main ();

  vlib_cli_output (vm, "NAT44 interfaces:");
  /* *INDENT-OFF* */
  pool_foreach (i, sm->interfaces,
  ({
    vlib_cli_output (vm, " %U %s", format_vnet_sw_if_index_name, vnm,
                     i->sw_if_index,
                     (nat_interface_is_inside(i) &&
                      nat_interface_is_outside(i)) ? "in out" :
                     (nat_interface_is_inside(i) ? "in" : "out"));
  }));

  pool_foreach (i, sm->output_feature_interfaces,
  ({
    vlib_cli_output (vm, " %U output-feature %s",
                     format_vnet_sw_if_index_name, vnm,
                     i->sw_if_index,
                     (nat_interface_is_inside(i) &&
                      nat_interface_is_outside(i)) ? "in out" :
                     (nat_interface_is_inside(i) ? "in" : "out"));
  }));
  /* *INDENT-ON* */

  return 0;
}

static clib_error_t *
add_static_mapping_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snat_main_t *sm = &snat_main;
  clib_error_t *error = 0;
  ip4_address_t l_addr, e_addr;
  u32 l_port = 0, e_port = 0, vrf_id = ~0;
  int is_add = 1;
  int addr_only = 1;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();
  int rv;
  snat_protocol_t proto = ~0;
  u8 proto_set = 0;
  twice_nat_type_t twice_nat = TWICE_NAT_DISABLED;
  u8 out2in_only = 0;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U %u", unformat_ip4_address, &l_addr,
		    &l_port))
	addr_only = 0;
      else
	if (unformat (line_input, "local %U", unformat_ip4_address, &l_addr))
	;
      else if (unformat (line_input, "external %U %u", unformat_ip4_address,
			 &e_addr, &e_port))
	addr_only = 0;
      else if (unformat (line_input, "external %U", unformat_ip4_address,
			 &e_addr))
	;
      else if (unformat (line_input, "external %U %u",
			 unformat_vnet_sw_interface, vnm, &sw_if_index,
			 &e_port))
	addr_only = 0;

      else if (unformat (line_input, "external %U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "vrf %u", &vrf_id))
	;
      else if (unformat (line_input, "%U", unformat_snat_protocol, &proto))
	proto_set = 1;
      else if (unformat (line_input, "twice-nat"))
	twice_nat = TWICE_NAT;
      else if (unformat (line_input, "self-twice-nat"))
	twice_nat = TWICE_NAT_SELF;
      else if (unformat (line_input, "out2in-only"))
	out2in_only = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (twice_nat && addr_only)
    {
      error = clib_error_return (0, "twice NAT only for 1:1 NAPT");
      goto done;
    }

  if (!addr_only && !proto_set)
    {
      error = clib_error_return (0, "missing protocol");
      goto done;
    }

  rv = snat_add_static_mapping (l_addr, e_addr, (u16) l_port, (u16) e_port,
				vrf_id, addr_only, sw_if_index, proto, is_add,
				twice_nat, out2in_only, 0, 0);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "External port already in use.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      if (is_add)
	error = clib_error_return (0, "External address must be allocated.");
      else
	error = clib_error_return (0, "Mapping not exist.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_FIB:
      error = clib_error_return (0, "No such VRF id.");
      goto done;
    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "Mapping already exist.");
      goto done;
    case VNET_API_ERROR_FEATURE_DISABLED:
      error =
	clib_error_return (0,
			   "twice-nat/out2in-only available only for endpoint-dependent mode.");
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
add_identity_mapping_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snat_main_t *sm = &snat_main;
  clib_error_t *error = 0;
  ip4_address_t addr;
  u32 port = 0, vrf_id = ~0;
  int is_add = 1;
  int addr_only = 1;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();
  int rv;
  snat_protocol_t proto;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  addr.as_u32 = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip4_address, &addr))
	;
      else if (unformat (line_input, "external %U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "vrf %u", &vrf_id))
	;
      else if (unformat (line_input, "%U %u", unformat_snat_protocol, &proto,
			 &port))
	addr_only = 0;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = snat_add_static_mapping (addr, addr, (u16) port, (u16) port,
				vrf_id, addr_only, sw_if_index, proto, is_add,
				0, 0, 0, 1);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "External port already in use.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      if (is_add)
	error = clib_error_return (0, "External address must be allocated.");
      else
	error = clib_error_return (0, "Mapping not exist.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_FIB:
      error = clib_error_return (0, "No such VRF id.");
      goto done;
    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "Mapping already exist.");
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
add_lb_static_mapping_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  snat_main_t *sm = &snat_main;
  clib_error_t *error = 0;
  ip4_address_t l_addr, e_addr;
  u32 l_port = 0, e_port = 0, vrf_id = 0, probability = 0, affinity = 0;
  int is_add = 1;
  int rv;
  snat_protocol_t proto;
  u8 proto_set = 0;
  nat44_lb_addr_port_t *locals = 0, local;
  twice_nat_type_t twice_nat = TWICE_NAT_DISABLED;
  u8 out2in_only = 0;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U:%u probability %u",
		    unformat_ip4_address, &l_addr, &l_port, &probability))
	{
	  clib_memset (&local, 0, sizeof (local));
	  local.addr = l_addr;
	  local.port = (u16) l_port;
	  local.probability = (u8) probability;
	  vec_add1 (locals, local);
	}
      else if (unformat (line_input, "local %U:%u vrf %u probability %u",
			 unformat_ip4_address, &l_addr, &l_port, &vrf_id,
			 &probability))
	{
	  clib_memset (&local, 0, sizeof (local));
	  local.addr = l_addr;
	  local.port = (u16) l_port;
	  local.probability = (u8) probability;
	  local.vrf_id = vrf_id;
	  vec_add1 (locals, local);
	}
      else if (unformat (line_input, "external %U:%u", unformat_ip4_address,
			 &e_addr, &e_port))
	;
      else if (unformat (line_input, "protocol %U", unformat_snat_protocol,
			 &proto))
	proto_set = 1;
      else if (unformat (line_input, "twice-nat"))
	twice_nat = TWICE_NAT;
      else if (unformat (line_input, "self-twice-nat"))
	twice_nat = TWICE_NAT_SELF;
      else if (unformat (line_input, "out2in-only"))
	out2in_only = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "affinity %u", &affinity))
	;
      else
	{
	  error = clib_error_return (0, "unknown input: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (vec_len (locals) < 2)
    {
      error = clib_error_return (0, "at least two local must be set");
      goto done;
    }

  if (!proto_set)
    {
      error = clib_error_return (0, "missing protocol");
      goto done;
    }

  rv = nat44_add_del_lb_static_mapping (e_addr, (u16) e_port, proto, locals,
					is_add, twice_nat, out2in_only, 0,
					affinity);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (0, "External port already in use.");
      goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      if (is_add)
	error = clib_error_return (0, "External address must be allocated.");
      else
	error = clib_error_return (0, "Mapping not exist.");
      goto done;
    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "Mapping already exist.");
      goto done;
    case VNET_API_ERROR_FEATURE_DISABLED:
      error =
	clib_error_return (0, "Available only for endpoint-dependent mode.");
      goto done;
    default:
      break;
    }

done:
  unformat_free (line_input);
  vec_free (locals);

  return error;
}

static clib_error_t *
nat44_show_static_mappings_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  snat_static_map_resolve_t *rp;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  vlib_cli_output (vm, "NAT44 static mappings:");
  /* *INDENT-OFF* */
  pool_foreach (m, sm->static_mappings,
  ({
    vlib_cli_output (vm, " %U", format_snat_static_mapping, m);
  }));
  vec_foreach (rp, sm->to_resolve)
    vlib_cli_output (vm, " %U", format_snat_static_map_to_resolve, rp);
  /* *INDENT-ON* */

  return 0;
}

static clib_error_t *
snat_add_interface_address_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index;
  int rv;
  int is_del = 0;
  clib_error_t *error = 0;
  u8 twice_nat = 0;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface,
		    sm->vnet_main, &sw_if_index))
	;
      else if (unformat (line_input, "twice-nat"))
	twice_nat = 1;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = snat_add_interface_address (sm, sw_if_index, is_del, twice_nat);

  switch (rv)
    {
    case 0:
      break;

    default:
      error = clib_error_return (0, "snat_add_interface_address returned %d",
				 rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_show_interface_address_command_fn (vlib_main_t * vm,
					 unformat_input_t * input,
					 vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 *sw_if_index;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  /* *INDENT-OFF* */
  vlib_cli_output (vm, "NAT44 pool address interfaces:");
  vec_foreach (sw_if_index, sm->auto_add_sw_if_indices)
    {
      vlib_cli_output (vm, " %U", format_vnet_sw_if_index_name, vnm,
                       *sw_if_index);
    }
  vlib_cli_output (vm, "NAT44 twice-nat pool address interfaces:");
  vec_foreach (sw_if_index, sm->auto_add_sw_if_indices_twice_nat)
    {
      vlib_cli_output (vm, " %U", format_vnet_sw_if_index_name, vnm,
                       *sw_if_index);
    }
  /* *INDENT-ON* */

  return 0;
}

static clib_error_t *
nat44_show_sessions_command_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  int verbose = 0;
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  snat_user_t *u;
  int i = 0;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  if (unformat (input, "detail"))
    verbose = 1;

  vlib_cli_output (vm, "NAT44 sessions:");

  /* *INDENT-OFF* */
  vec_foreach_index (i, sm->per_thread_data)
    {
      tsm = vec_elt_at_index (sm->per_thread_data, i);

      vlib_cli_output (vm, "-------- thread %d %s: %d sessions --------\n",
                       i, vlib_worker_threads[i].name,
                       pool_elts (tsm->sessions));
      pool_foreach (u, tsm->users,
      ({
        vlib_cli_output (vm, "  %U", format_snat_user, tsm, u, verbose);
      }));
    }
  /* *INDENT-ON* */

  return 0;
}

static clib_error_t *
nat44_del_session_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  int is_in = 0, is_ed = 0;
  clib_error_t *error = 0;
  ip4_address_t addr, eh_addr;
  u32 port = 0, eh_port = 0, vrf_id = sm->outside_vrf_id;
  snat_protocol_t proto;
  int rv;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U:%u %U", unformat_ip4_address, &addr, &port,
	   unformat_snat_protocol, &proto))
	;
      else if (unformat (line_input, "in"))
	{
	  is_in = 1;
	  vrf_id = sm->inside_vrf_id;
	}
      else if (unformat (line_input, "out"))
	{
	  is_in = 0;
	  vrf_id = sm->outside_vrf_id;
	}
      else if (unformat (line_input, "vrf %u", &vrf_id))
	;
      else
	if (unformat
	    (line_input, "external-host %U:%u", unformat_ip4_address,
	     &eh_addr, &eh_port))
	is_ed = 1;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (is_ed)
    rv =
      nat44_del_ed_session (sm, &addr, port, &eh_addr, eh_port,
			    snat_proto_to_ip_proto (proto), vrf_id, is_in);
  else
    rv = nat44_del_session (sm, &addr, port, proto, vrf_id, is_in);

  switch (rv)
    {
    case 0:
      break;

    default:
      error = clib_error_return (0, "nat44_del_session returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
snat_forwarding_set_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 forwarding_enable;
  u8 forwarding_enable_set = 0;
  clib_error_t *error = 0;

  if (sm->deterministic)
    return clib_error_return (0, UNSUPPORTED_IN_DET_MODE_STR);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "'enable' or 'disable' expected");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (!forwarding_enable_set && unformat (line_input, "enable"))
	{
	  forwarding_enable = 1;
	  forwarding_enable_set = 1;
	}
      else if (!forwarding_enable_set && unformat (line_input, "disable"))
	{
	  forwarding_enable = 0;
	  forwarding_enable_set = 1;
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!forwarding_enable_set)
    {
      error = clib_error_return (0, "'enable' or 'disable' expected");
      goto done;
    }

  sm->forwarding_enabled = forwarding_enable;

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
snat_det_map_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, out_addr;
  u32 in_plen, out_plen;
  int is_add = 1, rv;
  clib_error_t *error = 0;

  if (!sm->deterministic)
    return clib_error_return (0, SUPPORTED_ONLY_IN_DET_MODE_STR);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "in %U/%u", unformat_ip4_address, &in_addr, &in_plen))
	;
      else
	if (unformat
	    (line_input, "out %U/%u", unformat_ip4_address, &out_addr,
	     &out_plen))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = snat_det_add_map (sm, &in_addr, (u8) in_plen, &out_addr, (u8) out_plen,
			 is_add);

  if (rv)
    {
      error = clib_error_return (0, "snat_det_add_map return %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
nat44_det_show_mappings_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  snat_det_map_t *dm;

  if (!sm->deterministic)
    return clib_error_return (0, SUPPORTED_ONLY_IN_DET_MODE_STR);

  vlib_cli_output (vm, "NAT44 deterministic mappings:");
  /* *INDENT-OFF* */
  pool_foreach (dm, sm->det_maps,
  ({
    vlib_cli_output (vm, " in %U/%d out %U/%d\n",
                     format_ip4_address, &dm->in_addr, dm->in_plen,
                     format_ip4_address, &dm->out_addr, dm->out_plen);
    vlib_cli_output (vm, "  outside address sharing ratio: %d\n",
                     dm->sharing_ratio);
    vlib_cli_output (vm, "  number of ports per inside host: %d\n",
                     dm->ports_per_host);
    vlib_cli_output (vm, "  sessions number: %d\n", dm->ses_num);
  }));
  /* *INDENT-ON* */

  return 0;
}

static clib_error_t *
snat_det_forward_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, out_addr;
  u16 lo_port;
  snat_det_map_t *dm;
  clib_error_t *error = 0;

  if (!sm->deterministic)
    return clib_error_return (0, SUPPORTED_ONLY_IN_DET_MODE_STR);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip4_address, &in_addr))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  dm = snat_det_map_by_user (sm, &in_addr);
  if (!dm)
    vlib_cli_output (vm, "no match");
  else
    {
      snat_det_forward (dm, &in_addr, &out_addr, &lo_port);
      vlib_cli_output (vm, "%U:<%d-%d>", format_ip4_address, &out_addr,
		       lo_port, lo_port + dm->ports_per_host - 1);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
snat_det_reverse_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, out_addr;
  u32 out_port;
  snat_det_map_t *dm;
  clib_error_t *error = 0;

  if (!sm->deterministic)
    return clib_error_return (0, SUPPORTED_ONLY_IN_DET_MODE_STR);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U:%d", unformat_ip4_address, &out_addr, &out_port))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (out_port < 1024 || out_port > 65535)
    {
      error = clib_error_return (0, "wrong port, must be <1024-65535>");
      goto done;
    }

  dm = snat_det_map_by_out (sm, &out_addr);
  if (!dm)
    vlib_cli_output (vm, "no match");
  else
    {
      snat_det_reverse (dm, &out_addr, (u16) out_port, &in_addr);
      vlib_cli_output (vm, "%U", format_ip4_address, &in_addr);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
set_timeout_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "udp %u", &sm->udp_timeout))
	{
	  if (nat64_set_udp_timeout (sm->udp_timeout))
	    {
	      error = clib_error_return (0, "Invalid UDP timeout value");
	      goto done;
	    }
	}
      else if (unformat (line_input, "tcp-established %u",
			 &sm->tcp_established_timeout))
	{
	  if (nat64_set_tcp_timeouts
	      (sm->tcp_transitory_timeout, sm->tcp_established_timeout))
	    {
	      error =
		clib_error_return (0,
				   "Invalid TCP established timeouts value");
	      goto done;
	    }
	}
      else if (unformat (line_input, "tcp-transitory %u",
			 &sm->tcp_transitory_timeout))
	{
	  if (nat64_set_tcp_timeouts
	      (sm->tcp_transitory_timeout, sm->tcp_established_timeout))
	    {
	      error =
		clib_error_return (0,
				   "Invalid TCP transitory timeouts value");
	      goto done;
	    }
	}
      else if (unformat (line_input, "icmp %u", &sm->icmp_timeout))
	{
	  if (nat64_set_icmp_timeout (sm->icmp_timeout))
	    {
	      error = clib_error_return (0, "Invalid ICMP timeout value");
	      goto done;
	    }
	}
      else if (unformat (line_input, "reset"))
	{
	  sm->udp_timeout = SNAT_UDP_TIMEOUT;
	  sm->tcp_established_timeout = SNAT_TCP_ESTABLISHED_TIMEOUT;
	  sm->tcp_transitory_timeout = SNAT_TCP_TRANSITORY_TIMEOUT;
	  sm->icmp_timeout = SNAT_ICMP_TIMEOUT;
	  nat64_set_udp_timeout (0);
	  nat64_set_icmp_timeout (0);
	  nat64_set_tcp_timeouts (0, 0);
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
nat_show_timeouts_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;

  vlib_cli_output (vm, "udp timeout: %dsec", sm->udp_timeout);
  vlib_cli_output (vm, "tcp-established timeout: %dsec",
		   sm->tcp_established_timeout);
  vlib_cli_output (vm, "tcp-transitory timeout: %dsec",
		   sm->tcp_transitory_timeout);
  vlib_cli_output (vm, "icmp timeout: %dsec", sm->icmp_timeout);

  return 0;
}

static clib_error_t *
nat44_det_show_sessions_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  snat_det_map_t *dm;
  snat_det_session_t *ses;
  int i;

  if (!sm->deterministic)
    return clib_error_return (0, SUPPORTED_ONLY_IN_DET_MODE_STR);

  vlib_cli_output (vm, "NAT44 deterministic sessions:");
  /* *INDENT-OFF* */
  pool_foreach (dm, sm->det_maps,
  ({
    vec_foreach_index (i, dm->sessions)
      {
        ses = vec_elt_at_index (dm->sessions, i);
        if (ses->in_port)
          vlib_cli_output (vm, "  %U", format_det_map_ses, dm, ses, &i);
      }
  }));
  /* *INDENT-ON* */
  return 0;
}

static clib_error_t *
snat_det_close_session_out_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t out_addr, ext_addr, in_addr;
  u32 out_port, ext_port;
  snat_det_map_t *dm;
  snat_det_session_t *ses;
  snat_det_out_key_t key;
  clib_error_t *error = 0;

  if (!sm->deterministic)
    return clib_error_return (0, SUPPORTED_ONLY_IN_DET_MODE_STR);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%d %U:%d",
		    unformat_ip4_address, &out_addr, &out_port,
		    unformat_ip4_address, &ext_addr, &ext_port))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  unformat_free (line_input);

  dm = snat_det_map_by_out (sm, &out_addr);
  if (!dm)
    vlib_cli_output (vm, "no match");
  else
    {
      snat_det_reverse (dm, &ext_addr, (u16) out_port, &in_addr);
      key.ext_host_addr = out_addr;
      key.ext_host_port = ntohs ((u16) ext_port);
      key.out_port = ntohs ((u16) out_port);
      ses = snat_det_get_ses_by_out (dm, &out_addr, key.as_u64);
      if (!ses)
	vlib_cli_output (vm, "no match");
      else
	snat_det_ses_close (dm, ses);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
snat_det_close_session_in_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  snat_main_t *sm = &snat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_addr, ext_addr;
  u32 in_port, ext_port;
  snat_det_map_t *dm;
  snat_det_session_t *ses;
  snat_det_out_key_t key;
  clib_error_t *error = 0;

  if (!sm->deterministic)
    return clib_error_return (0, SUPPORTED_ONLY_IN_DET_MODE_STR);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U:%d %U:%d",
		    unformat_ip4_address, &in_addr, &in_port,
		    unformat_ip4_address, &ext_addr, &ext_port))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  unformat_free (line_input);

  dm = snat_det_map_by_user (sm, &in_addr);
  if (!dm)
    vlib_cli_output (vm, "no match");
  else
    {
      key.ext_host_addr = ext_addr;
      key.ext_host_port = ntohs ((u16) ext_port);
      ses =
	snat_det_find_ses_by_in (dm, &in_addr, ntohs ((u16) in_port), key);
      if (!ses)
	vlib_cli_output (vm, "no match");
      else
	snat_det_ses_close (dm, ses);
    }

done:
  unformat_free (line_input);

  return error;
}
/* *INDENT-OFF* */

/*?
 * @cliexpar
 * @cliexstart{set snat workers}
 * Set NAT workers if 2 or more workers available, use:
 *  vpp# set snat workers 0-2,5
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_workers_command, static) = {
  .path = "set nat workers",
  .function = set_workers_command_fn,
  .short_help = "set nat workers <workers-list>",
};

/*?
 * @cliexpar
 * @cliexstart{show nat workers}
 * Show NAT workers.
 *  vpp# show nat workers:
 *  2 workers
 *    vpp_wk_0
 *    vpp_wk_1
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_show_workers_command, static) = {
  .path = "show nat workers",
  .short_help = "show nat workers",
  .function = nat_show_workers_commnad_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set nat timeout}
 * Set values of timeouts for NAT sessions (in seconds), use:
 *  vpp# set nat timeout udp 120 tcp-established 7500 tcp-transitory 250 icmp 90
 * To reset default values use:
 *  vpp# set nat44 deterministic timeout reset
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_timeout_command, static) = {
  .path = "set nat timeout",
  .function = set_timeout_command_fn,
  .short_help =
    "set nat timeout [udp <sec> | tcp-established <sec> "
    "tcp-transitory <sec> | icmp <sec> | reset]",
};

/*?
 * @cliexpar
 * @cliexstart{show nat timeouts}
 * Show values of timeouts for NAT sessions.
 * vpp# show nat timeouts
 * udp timeout: 300sec
 * tcp-established timeout: 7440sec
 * tcp-transitory timeout: 240sec
 * icmp timeout: 60sec
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat_show_timeouts_command, static) = {
  .path = "show nat timeouts",
  .short_help = "show nat timeouts",
  .function = nat_show_timeouts_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{snat ipfix logging}
 * To enable NAT IPFIX logging use:
 *  vpp# nat ipfix logging
 * To set IPFIX exporter use:
 *  vpp# set ipfix exporter collector 10.10.10.3 src 10.10.10.1
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_ipfix_logging_enable_disable_command, static) = {
  .path = "nat ipfix logging",
  .function = snat_ipfix_logging_enable_disable_command_fn,
  .short_help = "nat ipfix logging [domain <domain-id>] [src-port <port>] [disable]",
};

/*?
 * @cliexpar
 * @cliexstart{nat addr-port-assignment-alg}
 * Set address and port assignment algorithm
 * For the MAP-E CE limit port choice based on PSID use:
 *  vpp# nat addr-port-assignment-alg map-e psid 10 psid-offset 6 psid-len 6
 * For port range use:
 *  vpp# nat addr-port-assignment-alg port-range <start-port> - <end-port>
 * To set standard (default) address and port assignment algorithm use:
 *  vpp# nat addr-port-assignment-alg default
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_set_alloc_addr_and_port_alg_command, static) = {
    .path = "nat addr-port-assignment-alg",
    .short_help = "nat addr-port-assignment-alg <alg-name> [<alg-params>]",
    .function = nat44_set_alloc_addr_and_port_alg_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat addr-port-assignment-alg}
 * Show address and port assignment algorithm
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_alloc_addr_and_port_alg_command, static) = {
    .path = "show nat addr-port-assignment-alg",
    .short_help = "show nat addr-port-assignment-alg",
    .function = nat44_show_alloc_addr_and_port_alg_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat mss-clamping}
 * Set TCP MSS rewriting configuration
 * To enable TCP MSS rewriting use:
 *  vpp# nat mss-clamping 1452
 * To disbale TCP MSS rewriting use:
 *  vpp# nat mss-clamping disable
?*/
VLIB_CLI_COMMAND (nat_set_mss_clamping_command, static) = {
    .path = "nat mss-clamping",
    .short_help = "nat mss-clamping <mss-value>|disable",
    .function = nat_set_mss_clamping_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat mss-clamping}
 * Show TCP MSS rewriting configuration
?*/
VLIB_CLI_COMMAND (nat_show_mss_clamping_command, static) = {
    .path = "show nat mss-clamping",
    .short_help = "show nat mss-clamping",
    .function = nat_show_mss_clamping_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 hash tables}
 * Show NAT44 hash tables
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_hash, static) = {
  .path = "show nat44 hash tables",
  .short_help = "show nat44 hash tables [detail|verbose]",
  .function = nat44_show_hash_commnad_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 add address}
 * Add/delete NAT44 pool address.
 * To add NAT44 pool address use:
 *  vpp# nat44 add address 172.16.1.3
 *  vpp# nat44 add address 172.16.2.2 - 172.16.2.24
 * To add NAT44 pool address for specific tenant (identified by VRF id) use:
 *  vpp# nat44 add address 172.16.1.3 tenant-vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_address_command, static) = {
  .path = "nat44 add address",
  .short_help = "nat44 add address <ip4-range-start> [- <ip4-range-end>] "
                "[tenant-vrf <vrf-id>] [twice-nat] [del]",
  .function = add_address_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 addresses}
 * Show NAT44 pool addresses.
 * vpp# show nat44 addresses
 * NAT44 pool addresses:
 * 172.16.2.2
 *   tenant VRF independent
 *   10 busy udp ports
 *   0 busy tcp ports
 *   0 busy icmp ports
 * 172.16.1.3
 *   tenant VRF: 10
 *   0 busy udp ports
 *   2 busy tcp ports
 *   0 busy icmp ports
 * NAT44 twice-nat pool addresses:
 * 10.20.30.72
 *   tenant VRF independent
 *   0 busy udp ports
 *   0 busy tcp ports
 *   0 busy icmp ports
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_addresses_command, static) = {
  .path = "show nat44 addresses",
  .short_help = "show nat44 addresses",
  .function = nat44_show_addresses_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set interface nat44}
 * Enable/disable NAT44 feature on the interface.
 * To enable NAT44 feature with local network interface use:
 *  vpp# set interface nat44 in GigabitEthernet0/8/0
 * To enable NAT44 feature with external network interface use:
 *  vpp# set interface nat44 out GigabitEthernet0/a/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_interface_snat_command, static) = {
  .path = "set interface nat44",
  .function = snat_feature_command_fn,
  .short_help = "set interface nat44 in <intfc> out <intfc> [output-feature] "
                "[del]",
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 interfaces}
 * Show interfaces with NAT44 feature.
 * vpp# show nat44 interfaces
 * NAT44 interfaces:
 *  GigabitEthernet0/8/0 in
 *  GigabitEthernet0/a/0 out
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_interfaces_command, static) = {
  .path = "show nat44 interfaces",
  .short_help = "show nat44 interfaces",
  .function = nat44_show_interfaces_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 add static mapping}
 * Static mapping allows hosts on the external network to initiate connection
 * to to the local network host.
 * To create static mapping between local host address 10.0.0.3 port 6303 and
 * external address 4.4.4.4 port 3606 for TCP protocol use:
 *  vpp# nat44 add static mapping tcp local 10.0.0.3 6303 external 4.4.4.4 3606
 * If not runnig "static mapping only" NAT plugin mode use before:
 *  vpp# nat44 add address 4.4.4.4
 * To create static mapping between local and external address use:
 *  vpp# nat44 add static mapping local 10.0.0.3 external 4.4.4.4
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_static_mapping_command, static) = {
  .path = "nat44 add static mapping",
  .function = add_static_mapping_command_fn,
  .short_help =
    "nat44 add static mapping tcp|udp|icmp local <addr> [<port>] "
    "external <addr> [<port>] [vrf <table-id>] [twice-nat|self-twice-nat] "
    "[out2in-only] [del]",
};

/*?
 * @cliexpar
 * @cliexstart{nat44 add identity mapping}
 * Identity mapping translate an IP address to itself.
 * To create identity mapping for address 10.0.0.3 port 6303 for TCP protocol
 * use:
 *  vpp# nat44 add identity mapping 10.0.0.3 tcp 6303
 * To create identity mapping for address 10.0.0.3 use:
 *  vpp# nat44 add identity mapping 10.0.0.3
 * To create identity mapping for DHCP addressed interface use:
 *  vpp# nat44 add identity mapping GigabitEthernet0/a/0 tcp 3606
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_identity_mapping_command, static) = {
  .path = "nat44 add identity mapping",
  .function = add_identity_mapping_command_fn,
  .short_help = "nat44 add identity mapping <interface>|<ip4-addr> "
    "[<protocol> <port>] [vrf <table-id>] [del]",
};

/*?
 * @cliexpar
 * @cliexstart{nat44 add load-balancing static mapping}
 * Service load balancing using NAT44
 * To add static mapping with load balancing for service with external IP
 * address 1.2.3.4 and TCP port 80 and mapped to 2 local servers
 * 10.100.10.10:8080 and 10.100.10.20:8080 with probability 80% resp. 20% use:
 *  vpp# nat44 add load-balancing static mapping protocol tcp external 1.2.3.4:80 local 10.100.10.10:8080 probability 80 local 10.100.10.20:8080 probability 20
 * @cliexend
?*/
VLIB_CLI_COMMAND (add_lb_static_mapping_command, static) = {
  .path = "nat44 add load-balancing static mapping",
  .function = add_lb_static_mapping_command_fn,
  .short_help =
    "nat44 add load-balancing static mapping protocol tcp|udp "
    "external <addr>:<port> local <addr>:<port> [vrf <table-id>] "
    "probability <n> [twice-nat|self-twice-nat] [out2in-only] "
    "[affinity <timeout-seconds>] [del]",
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 static mappings}
 * Show NAT44 static mappings.
 * vpp# show nat44 static mappings
 * NAT44 static mappings:
 *  local 10.0.0.3 external 4.4.4.4 vrf 0
 *  tcp local 192.168.0.4:6303 external 4.4.4.3:3606 vrf 0
 *  tcp vrf 0 external 1.2.3.4:80  out2in-only
 *   local 10.100.10.10:8080 probability 80
 *   local 10.100.10.20:8080 probability 20
 *  tcp local 10.100.3.8:8080 external 169.10.10.1:80 vrf 0 twice-nat
 *  tcp local 10.0.0.10:3603 external GigabitEthernet0/a/0:6306 vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_static_mappings_command, static) = {
  .path = "show nat44 static mappings",
  .short_help = "show nat44 static mappings",
  .function = nat44_show_static_mappings_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 add interface address}
 * Use NAT44 pool address from specific interfce
 * To add NAT44 pool address from specific interface use:
 *  vpp# nat44 add interface address GigabitEthernet0/8/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_add_interface_address_command, static) = {
    .path = "nat44 add interface address",
    .short_help = "nat44 add interface address <interface> [twice-nat] [del]",
    .function = snat_add_interface_address_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 interface address}
 * Show NAT44 pool address interfaces
 * vpp# show nat44 interface address
 * NAT44 pool address interfaces:
 *  GigabitEthernet0/a/0
 * NAT44 twice-nat pool address interfaces:
 *  GigabitEthernet0/8/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_interface_address_command, static) = {
  .path = "show nat44 interface address",
  .short_help = "show nat44 interface address",
  .function = nat44_show_interface_address_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 sessions}
 * Show NAT44 sessions.
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_show_sessions_command, static) = {
  .path = "show nat44 sessions",
  .short_help = "show nat44 sessions [detail]",
  .function = nat44_show_sessions_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 del session}
 * To administratively delete NAT44 session by inside address and port use:
 *  vpp# nat44 del session in 10.0.0.3:6303 tcp
 * To administratively delete NAT44 session by outside address and port use:
 *  vpp# nat44 del session out 1.0.0.3:6033 udp
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_del_session_command, static) = {
    .path = "nat44 del session",
    .short_help = "nat44 del session in|out <addr>:<port> tcp|udp|icmp [vrf <id>] [external-host <addr>:<port>]",
    .function = nat44_del_session_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 forwarding}
 * Enable or disable forwarding
 * Forward packets which don't match existing translation
 * or static mapping instead of dropping them.
 * To enable forwarding, use:
 *  vpp# nat44 forwarding enable
 * To disable forwarding, use:
 *  vpp# nat44 forwarding disable
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_forwarding_set_command, static) = {
  .path = "nat44 forwarding",
  .short_help = "nat44 forwarding enable|disable",
  .function = snat_forwarding_set_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 deterministic add}
 * Create bijective mapping of inside address to outside address and port range
 * pairs, with the purpose of enabling deterministic NAT to reduce logging in
 * CGN deployments.
 * To create deterministic mapping between inside network 10.0.0.0/18 and
 * outside network 1.1.1.0/30 use:
 * # vpp# nat44 deterministic add in 10.0.0.0/18 out 1.1.1.0/30
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_det_map_command, static) = {
    .path = "nat44 deterministic add",
    .short_help = "nat44 deterministic add in <addr>/<plen> out <addr>/<plen> [del]",
    .function = snat_det_map_command_fn,
};

/*?
 * @cliexpar
 * @cliexpstart{show nat44 deterministic mappings}
 * Show NAT44 deterministic mappings
 * vpp# show nat44 deterministic mappings
 * NAT44 deterministic mappings:
 *  in 10.0.0.0/24 out 1.1.1.1/32
 *   outside address sharing ratio: 256
 *   number of ports per inside host: 252
 *   sessions number: 0
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_det_show_mappings_command, static) = {
    .path = "show nat44 deterministic mappings",
    .short_help = "show nat44 deterministic mappings",
    .function = nat44_det_show_mappings_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 deterministic forward}
 * Return outside address and port range from inside address for deterministic
 * NAT.
 * To obtain outside address and port of inside host use:
 *  vpp# nat44 deterministic forward 10.0.0.2
 *  1.1.1.0:<1054-1068>
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_det_forward_command, static) = {
    .path = "nat44 deterministic forward",
    .short_help = "nat44 deterministic forward <addr>",
    .function = snat_det_forward_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 deterministic reverse}
 * Return inside address from outside address and port for deterministic NAT.
 * To obtain inside host address from outside address and port use:
 *  #vpp nat44 deterministic reverse 1.1.1.1:1276
 *  10.0.16.16
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_det_reverse_command, static) = {
    .path = "nat44 deterministic reverse",
    .short_help = "nat44 deterministic reverse <addr>:<port>",
    .function = snat_det_reverse_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat44 deterministic sessions}
 * Show NAT44 deterministic sessions.
 * vpp# show nat44 deterministic sessions
 * NAT44 deterministic sessions:
 *   in 10.0.0.3:3005 out 1.1.1.2:1146 external host 172.16.1.2:3006 state: udp-active expire: 306
 *   in 10.0.0.3:3000 out 1.1.1.2:1141 external host 172.16.1.2:3001 state: udp-active expire: 306
 *   in 10.0.0.4:3005 out 1.1.1.2:1177 external host 172.16.1.2:3006 state: udp-active expire: 306
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat44_det_show_sessions_command, static) = {
  .path = "show nat44 deterministic sessions",
  .short_help = "show nat44 deterministic sessions",
  .function = nat44_det_show_sessions_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 deterministic close session out}
 * Close session using outside ip address and port
 * and external ip address and port, use:
 *  vpp# nat44 deterministic close session out 1.1.1.1:1276 2.2.2.2:2387
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_det_close_sesion_out_command, static) = {
  .path = "nat44 deterministic close session out",
  .short_help = "nat44 deterministic close session out "
                "<out_addr>:<out_port> <ext_addr>:<ext_port>",
  .function = snat_det_close_session_out_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat44 deterministic close session in}
 * Close session using inside ip address and port
 * and external ip address and port, use:
 *  vpp# nat44 deterministic close session in 3.3.3.3:3487 2.2.2.2:2387
 * @cliexend
?*/
VLIB_CLI_COMMAND (snat_det_close_session_in_command, static) = {
  .path = "nat44 deterministic close session in",
  .short_help = "nat44 deterministic close session in "
                "<in_addr>:<in_port> <ext_addr>:<ext_port>",
  .function = snat_det_close_session_in_fn,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
