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

#include <urpf/urpf.h>

#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>

/* *INDENT-OFF* */
static const char *urpf_feats[N_AF][N_IP_FEATURE_LOCATIONS][URPF_N_MODES] =
{
  [AF_IP4] = {
    [IP_FEATURE_INPUT] = {
      [URPF_MODE_STRICT] = "ip4-rx-urpf-strict",
      [URPF_MODE_LOOSE] = "ip4-rx-urpf-loose",
    },
    [IP_FEATURE_OUTPUT] = {
      [URPF_MODE_STRICT] = "ip4-tx-urpf-strict",
      [URPF_MODE_LOOSE] = "ip4-tx-urpf-loose",
    },
    [IP_FEATURE_LOCAL] = {
      [URPF_MODE_STRICT] = "ip4-rx-urpf-strict",
      [URPF_MODE_LOOSE] = "ip4-rx-urpf-loose",
    },
  },
  [AF_IP6] = {
    [IP_FEATURE_INPUT] = {
      [URPF_MODE_STRICT] = "ip6-rx-urpf-strict",
      [URPF_MODE_LOOSE] = "ip6-rx-urpf-loose",
    },
    [IP_FEATURE_OUTPUT] = {
      [URPF_MODE_STRICT] = "ip6-tx-urpf-strict",
      [URPF_MODE_LOOSE] = "ip6-tx-urpf-loose",
    },
    [IP_FEATURE_LOCAL] = {
      [URPF_MODE_STRICT] = "ip6-rx-urpf-strict",
      [URPF_MODE_LOOSE] = "ip6-rx-urpf-loose",
    },
  },
};
/* *INDENT-ON* */

/**
 * Per-af, per-direction, per-interface uRPF configs
 */
static urpf_mode_t *urpf_cfgs[N_AF][N_IP_FEATURE_LOCATIONS];

u8 *
format_urpf_mode (u8 * s, va_list * a)
{
  urpf_mode_t mode = va_arg (*a, int);

  switch (mode)
    {
#define _(a,b)                                  \
    case URPF_MODE_##a:                         \
      return (format (s, "%s", b));
      foreach_urpf_mode
#undef _
    }

  return (format (s, "unknown"));
}

static uword
unformat_urpf_mode (unformat_input_t * input, va_list * args)
{
  urpf_mode_t *mode = va_arg (*args, urpf_mode_t *);

  if (0)
    ;
#define _(a,b)                                                  \
  else if (unformat (input, b))                                 \
    {                                                           \
    *mode = URPF_MODE_##a;                                      \
    return (1);                                                 \
    }
  foreach_urpf_mode
#undef _
    return 0;
}

void
urpf_update (urpf_mode_t mode,
	     u32 sw_if_index,
	     ip_address_family_t af, ip_feature_location_t loc)
{
  urpf_mode_t old;

  vec_validate_init_empty (urpf_cfgs[af][loc], sw_if_index, URPF_MODE_OFF);
  old = urpf_cfgs[af][loc][sw_if_index];

  if (mode != old)
    {
      if (URPF_MODE_OFF != old)
	/* disable what we have */
	ip_feature_enable_disable (af, N_SAFI, loc,
				   urpf_feats[af][loc][old],
				   sw_if_index, 0, 0, 0);

      if (URPF_MODE_OFF != mode)
	/* enable what's new */
	ip_feature_enable_disable (af, N_SAFI, loc,
				   urpf_feats[af][loc][mode],
				   sw_if_index, 1, 0, 0);
    }
  /* else - no change to existing config */

  urpf_cfgs[af][loc][sw_if_index] = mode;
}

static clib_error_t *
urpf_cli_update (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  ip_address_family_t af;
  urpf_mode_t mode;
  u32 sw_if_index;
  vlib_dir_t dir;

  sw_if_index = ~0;
  af = AF_IP4;
  dir = VLIB_RX;
  mode = URPF_MODE_STRICT;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "%U", unformat_urpf_mode, &mode))
	;
      else if (unformat (line_input, "%U", unformat_ip_address_family, &af))
	;
      else if (unformat (line_input, "%U", unformat_vlib_rx_tx, &dir))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (~0 == sw_if_index)
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  urpf_update (mode, sw_if_index, af, dir);
done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command configures uRPF on an interface.
 * Two flavours are supported (the default is strict):
 * - loose: accept ingress packet if there is a route to reach the source
 * - strict: accept ingress packet if it arrived on an interface which
 *          the route to the source uses. i.e. an interface that the source
 *          is reachable via.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before range checking is enabled:
 * @cliexstart{show vlib graph ip4-rx-urpf-strict}
 *            Name                      Next                    Previous
 * ip4-rx-urpf-strict         ip4-drop [0]
 * @cliexend
 *
 * Example of how to enable unicast source checking on an interface:
 * @cliexcmd{set urpf ip4 rx GigabitEthernet2/0/0 loose}
 *
 * Example of graph node after range checking is enabled:
 * @cliexstart{show vlib graph ip4-rx-urpf-loose}
 *            Name                      Next                    Previous
 * ip4-rx-urpf-loose                ip4-drop [0]           ip4-input-no-checksum
 *                           ip4-source-and-port-range-         ip4-input
 * @cliexend
 *
 * Example of how to display the feature enabed on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 *
 * ipv4 unicast:
 *   ip4-rx-urpf-loose
 *   ip4-lookup
 *
 * ipv4 multicast:
 *   ip4-lookup-multicast
 *
 * ipv4 multicast:
 *   interface-output
 *
 * ipv6 unicast:
 *   ip6-lookup
 *
 * ipv6 multicast:
 *   ip6-lookup
 *
 * ipv6 multicast:
 *   interface-output
 * @cliexend
 *
 * Example of how to disable unicast source checking on an interface:
 * @cliexcmd{set urpf ip4 off GigabitEthernet2/0/0}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip_source_check_command, static) = {
  .path = "set urpf",
  .function = urpf_cli_update,
  .short_help = "set urpf [ip4|ip6] [rx|tx] [off|strict|loose] <INTERFACE>",
};
/* *INDENT-ON* */

static clib_error_t *
urpf_cli_accept (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  fib_prefix_t fpfx;
  ip_prefix_t pfx;
  u32 table_id, is_add, fib_index;

  is_add = 1;
  table_id = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "%U", unformat_ip_prefix, &pfx))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  ip_prefix_to_fib_prefix (&pfx, &fpfx);

  fib_index = fib_table_find (fpfx.fp_proto, table_id);

  if (~0 == fib_index)
    {
      error = clib_error_return (0, "Nonexistent table id %d", table_id);
      goto done;
    }

  if (is_add)
    fib_table_entry_special_add (fib_index,
				 &fpfx,
				 FIB_SOURCE_URPF_EXEMPT, FIB_ENTRY_FLAG_DROP);
  else
    fib_table_entry_special_remove (fib_index, &fpfx, FIB_SOURCE_URPF_EXEMPT);

done:
  unformat_free (line_input);

  return (error);
}

/*?
 * Add an exemption for a prefix to pass the Unicast Reverse Path
 * Forwarding (uRPF) loose check. This is for testing purposes only.
 * If the '<em>table</em>' is not enter it is defaulted to 0. Default
 * is to '<em>add</em>'. VPP always performs a loose uRPF check for
 * for-us traffic.
 *
 * @cliexpar
 * Example of how to add a uRPF exception to a FIB table to pass the
 * loose RPF tests:
 * @cliexcmd{set urpf-accept table 7 10.0.0.0/8 add}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (urpf_accept_command, static) = {
  .path = "set urpf-accept",
  .function = urpf_cli_accept,
  .short_help = "urpf-accept [table <table-id>] [add|del] <PREFIX>",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
