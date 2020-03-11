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
#include <vnet/ip/ip4.h>
#include "cdb.h"

static clib_error_t *
unat_interface_command_fn (vlib_main_t * vm,
				   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  unat_main_t *um = &unat_main;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;
  bool in2out = false;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "in %U", unformat_vnet_sw_interface,
                    vnm, &sw_if_index)) {
	in2out = true;
      }
      else if (unformat (line_input, "out %U", unformat_vnet_sw_interface,
                         vnm, &sw_if_index))
	;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                     format_unformat_error, line_input);
          goto done;
        }
    }

  unat_cfg_interface_t cfg = { .sw_if_index = sw_if_index,
			       .in2out = in2out,
  };

  cdb_add(um->cdb, "/unat/interfaces", &cfg, sizeof(cfg), 0);

 done:
  unformat_free(line_input);
  return error;
}
static clib_error_t *
unat_params_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  unat_main_t *um = &unat_main;
  clib_error_t *error = 0;
  u32 max_sessions;
  u32 default_timeout;
  u32 icmp_timeout;
  u32 udp_timeout;
  u32 tcp_transitory_timeout;
  u32 tcp_established_timeout;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "max-sessions %u", &max_sessions))
	;
    else if (unformat (line_input, "timeout default %u", &default_timeout))
      ;
    else if (unformat (line_input, "timeout icmp %u", &icmp_timeout))
      ;
    else if (unformat (line_input, "timeout udp %u", &udp_timeout))
      ;
    else if (unformat (line_input, "timeout tcp-transitory %u", &tcp_transitory_timeout))
      ;
    else if (unformat (line_input, "timeout tcp-establshed %u", &tcp_established_timeout))
      ;
    else
      error = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, line_input);
  }

  unat_cfg_params_t cfg = { .max_sessions = max_sessions,
			    .default_timeout = default_timeout,
			    .icmp_timeout = icmp_timeout,
			    .udp_timeout = udp_timeout,
			    .tcp_transitory_timeout = tcp_transitory_timeout,
			    .tcp_established_timeout = tcp_established_timeout,
  };

  cdb_add(um->cdb, "/unat/parameters", &cfg, sizeof(cfg), 0);

  unformat_free(line_input);
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
      vlib_cli_output(vm, "NAT state: %s", um->enabled ? "enabled" : "disabled");
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

      vlib_cli_output (vm, "flow hash: %U", format_bihash_16_8, &um->flowhash, 0);
      for (i = 0; i < vec_len(um->sessions_per_worker); i++) {
	vlib_cli_output(vm, "Sessions: [%u]: %u", i, pool_elts(um->sessions_per_worker[i]));
	vlib_cli_output(vm, "LRU: [%u]: %u", i, pool_elts(um->lru_pool[i]));
      }

      return 0;
    }
  unformat_free (line_input);

  return error;
}

static clib_error_t *
clear_unat_sessions_command_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      unat_reset_tables();
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
  unat_main_t *um = &unat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t prefix;
  u32 prefixlen, vrf_id = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat
	(line_input, "%U/%d", unformat_ip4_address, &prefix, &prefixlen))
      ;
    else if (unformat (line_input, "vrf %u", &vrf_id))
      ;
    else {
      error = clib_error_return (0, "Unknown input '%U'",
				 format_unformat_error, line_input);
      goto done;
    }
  }

  unat_cfg_pool_t cfg = { .prefix = prefix,
			  .prefixlen = prefixlen,
			  .vrf_id = vrf_id
  };

  cdb_add(um->cdb, "/unat/pool/prefix", &cfg, sizeof(cfg), 0);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
unat_pool_interface_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unat_main_t *um = &unat_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat
	(line_input, "%U", unformat_vnet_sw_interface, vnet_get_main(), &sw_if_index))
      ;
    else {
      error = clib_error_return (0, "Unknown input '%U'",
				 format_unformat_error, line_input);
      goto done;
    }
  }

  unat_cfg_pool_interface_t cfg = { .sw_if_index = sw_if_index };
  cdb_add(um->cdb, "/unat/pool/interface", &cfg, sizeof(cfg), 0);

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (pool_ext_addr_pool_command, static) = {
  .path = "set unat prefix-pool",
  .short_help =
      "set unat prefix-pool <ip4-pfx> [vrf-id <id>]",
  .function = unat_pool_command_fn,
};

VLIB_CLI_COMMAND (pool_ext_interface_pool_command, static) = {
  .path = "set unat prefix-pool interface",
  .short_help =
      "set unat prefix-pool interface <interface>",
  .function = unat_pool_interface_command_fn,
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
  .short_help = "set interface unat <in | out> <intfc>",
};

VLIB_CLI_COMMAND (set_unat_params_command, static) = {
  .path = "set unat",
  .function = unat_params_command_fn,
  .short_help = "set unat max-sessions <n> | "
                "timeout [udp <sec> | icmp <sec> "
                "tcp-transitory <sec> | tcp-established <sec> | "
                "default <sec>]",
};

VLIB_CLI_COMMAND(show_unat_sessions_command, static) = {
  .path = "show unat sessions",
  .short_help = "show unat sessions",
  .function = show_unat_sessions_command_fn,
};

VLIB_CLI_COMMAND(cliear_unat_sessions_command, static) = {
  .path = "clear unat sessions",
  .short_help = "clear unat sessions",
  .function = clear_unat_sessions_command_fn,
};
