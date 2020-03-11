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

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/clib_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip.h>
#include "pool.h"
#include "unat.h"

extern vlib_node_registration_t unat_sp_i2o_node;
extern vlib_node_registration_t unat_sp_o2i_node;

static clib_error_t *
unat_interface_command_fn (vlib_main_t * vm,
				   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  unat_main_t *um = &unat_main;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 inside_sw_if_index = ~0;
  u32 outside_sw_if_index = ~0;
  u32 sw_if_index;
  bool is_enable = true;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "in %U", unformat_vnet_sw_interface,
                    vnm, &sw_if_index))
	inside_sw_if_index = sw_if_index;
      else if (unformat (line_input, "out %U", unformat_vnet_sw_interface,
                         vnm, &sw_if_index))
	outside_sw_if_index = sw_if_index;
      else if (unformat (line_input, "del"))
        is_enable = false;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  unat_enable(vm);

  if (inside_sw_if_index != ~0) {
    unat_register_interface(inside_sw_if_index, unat_sp_i2o_node.index, true, &um->in2out_hash);
    if (vnet_feature_enable_disable ("ip4-unicast", "unat-handoff",
				     inside_sw_if_index, is_enable, 0, 0) != 0)
      return clib_error_return(0, "VNET feature enable failed on %u", inside_sw_if_index);
  } else if (outside_sw_if_index != ~0) {
    unat_register_interface(outside_sw_if_index, unat_sp_o2i_node.index, false, &um->out2in_hash);
    if (vnet_feature_enable_disable ("ip4-unicast", "unat-handoff",
				     outside_sw_if_index, is_enable, 0, 0) != 0)
      return clib_error_return(0, "VNET feature enable failed on %u", outside_sw_if_index);
  }

 done:
  return error;
}
static clib_error_t *
unat_max_sessions_command_fn (vlib_main_t * vm,
				      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  unat_main_t *um = &unat_main;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u", &um->max_sessions))
	;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

 done:
  return error;
}

static clib_error_t *
unat_timeout_command_fn (vlib_main_t * vm,
				 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  unat_main_t *um = &unat_main;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "default %u", &um->default_timeout))
	;
      else if (unformat (line_input, "icmp %u", &um->icmp_timeout))
	;
      else if (unformat (line_input, "udp %u", &um->udp_timeout))
	;
      else if (unformat (line_input, "tcp-transitory %u", &um->tcp_transitory_timeout))
	;
      else if (unformat (line_input, "tcp-establshed %u", &um->tcp_established_timeout))
	;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

 done:
  return error;
}

static clib_error_t *
show_unat_sessions_command_fn (vlib_main_t * vm, unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  unat_main_t *um = &unat_main;
  unat_session_t *s;
  clib_error_t *error = 0;
  int i;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      for (i = 0; i <= vlib_num_workers(); i++) {
	vlib_cli_output(vm, "Thread %u:", i);
	/* *INDENT-OFF* */
	pool_foreach(s, um->sessions_per_worker[i],
		     ({vlib_cli_output(vm, "%U", format_unat_session,
				       s - um->sessions_per_worker[i], s);
		     }));
	/* *INDENT-ON* */
      }
      return 0;
    }
  unformat_free (line_input);

  return error;
}

static clib_error_t *
show_unat_pool_command_fn (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  unat_pool_t *p;
  clib_error_t *error = 0;
  int i;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input)) {
    for (i = 0; i < unat_pool_len(); i++) {
      p = unat_pool_get(i);
      vlib_cli_output(vm, "%U", format_unat_pool, p);
    }
    return 0;
  }
  unformat_free (line_input);

  return error;
}

static clib_error_t *
show_unat_summary_command_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  unat_main_t *um = &unat_main;
  unat_interface_t *interface;
  clib_error_t *error = 0;
  int i;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      /* *INDENT-OFF* */
      pool_foreach(interface, um->interfaces,
		   ({
		     vlib_cli_output(vm, "NAT: %U (%s)", format_vnet_sw_if_index_name, vnet_get_main(), interface->sw_if_index,
				     interface->in2out ? "in2out" : "out2in");
		   }));
      /* *INDENT-ON* */
      vlib_cli_output (vm, "Timouts:");
      vlib_cli_output (vm, "  default: %u ICMP: %u UDP: %u", um->default_timeout, um->icmp_timeout,
		       um->udp_timeout);
      vlib_cli_output (vm, "  TCP transitory: %u TCP established: %u", um->tcp_transitory_timeout, um->tcp_established_timeout);

      vlib_cli_output (vm, "in2out: %U", format_bihash_16_8, &um->in2out_hash, 0);
      vlib_cli_output (vm, "out2in: %U", format_bihash_16_8, &um->out2in_hash, 0);
      for (i = 0; i <= vlib_num_workers(); i++) {
	vlib_cli_output(vm, "Sessions: [%u]: %u", i, pool_elts(um->sessions_per_worker[i]));
	vlib_cli_output(vm, "LRU: [%u]: %u", i, pool_elts(um->lru_pool[i]));
      }

      return 0;
    }
  unformat_free (line_input);

  return error;
}

static clib_error_t *
unat_pool_command_fn (vlib_main_t * vm,
		      unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  unat_main_t *um = &unat_main;
  ip4_address_t prefix;
  u32 prefix_len, vrf_id = 0;
  clib_error_t *error = 0;
  u32 psid_length = 0, psid = 0;
  u32 thread_index = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
          (line_input, "%U/%d", unformat_ip4_address, &prefix, &prefix_len))
        ;
      else if (unformat (line_input, "psid-len %d", &psid_length))
        ;
      else if (unformat (line_input, "psid %d", &psid))
	;
      else if (unformat (line_input, "vrf %u", &vrf_id))
        ;
      else if (unformat (line_input, "worker %u", &thread_index))
        ;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  if (thread_index > vlib_num_workers()) {
    error = clib_error_return (0, "Invalid worker index %u (%u)", thread_index, vlib_num_workers());
  }

  unat_enable(vm);

  u32 poolindex = pool_add_addr_pool (&prefix, (u8) prefix_len, psid_length, psid, vrf_id,
				      thread_index);
  if (poolindex != ~0) {
    unat_enable_worker(thread_index);
    um->pool_per_thread[thread_index] = poolindex;
  } else {
    error = clib_error_return (0, "Error configuraing pool.");
  }

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (pool_add_ext_addr_pool_command, static) = {
  .path = "unat prefix-pool add",
  .short_help =
      "unat prefix-pool add <ip4-pfx> [psid-len <n> psid <n>] [vrf-id <id>] worker <n>",
  .function = unat_pool_command_fn,
};

VLIB_CLI_COMMAND(show_unat_pool_command, static) = {
  .path = "show unat pool",
  .short_help = "show unat pool",
  .function = show_unat_pool_command_fn,
};

VLIB_CLI_COMMAND(show_unat_summary_command, static) = {
  .path = "show unat summary",
  .short_help = "show unat summary",
  .function = show_unat_summary_command_fn,
  .is_mp_safe = 1,
};

VLIB_CLI_COMMAND (set_interface_unat_command, static) = {
  .path = "set interface unat",
  .function = unat_interface_command_fn,
  .short_help = "set interface unat <intfc> <in | out> [del]",
};

VLIB_CLI_COMMAND (set_unat_max_sessions_command, static) = {
  .path = "set unat max-sessions",
  .function = unat_max_sessions_command_fn,
  .short_help = "set unat max-sessions <n>",
};

VLIB_CLI_COMMAND (set_unat_timeout_command, static) = {
  .path = "set unat timeout",
  .function = unat_timeout_command_fn,
  .short_help = "set unat timeout [udp <sec> | icmp <sec> "
                "tcp-transitory <sec> | tcp-established <sec> | "
                "default <sec>]",
};
VLIB_CLI_COMMAND(show_unat_sessions_command, static) = {
  .path = "show unat sessions",
  .short_help = "show unat sessions",
  .function = show_unat_sessions_command_fn,
};
