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

#include <vnet/fib/fib_table.h>

/* *INDENT-OFF* */
static const char *urpf_feat_arcs[N_AF][VLIB_N_DIR] =
{
  [AF_IP4] = {
    [VLIB_RX] = "ip4-unicast",
    [VLIB_TX] = "ip4-output",
  },
  [AF_IP6] = {
    [VLIB_RX] = "ip6-unicast",
    [VLIB_TX] = "ip6-output",
  },
};

static const char *urpf_feats[N_AF][VLIB_N_DIR][URPF_N_MODES] =
{
  [AF_IP4] = {
    [VLIB_RX] = {
      [URPF_MODE_STRICT] = "ip4-rx-urpf-strict",
      [URPF_MODE_LOOSE] = "ip4-rx-urpf-loose",
    },
    [VLIB_TX] = {
      [URPF_MODE_STRICT] = "ip4-tx-urpf-strict",
      [URPF_MODE_LOOSE] = "ip4-tx-urpf-loose",
    },
  },
  [AF_IP6] = {
    [VLIB_RX] = {
      [URPF_MODE_STRICT] = "ip6-rx-urpf-strict",
      [URPF_MODE_LOOSE] = "ip6-rx-urpf-loose",
    },
    [VLIB_TX] = {
      [URPF_MODE_STRICT] = "ip6-tx-urpf-strict",
      [URPF_MODE_LOOSE] = "ip6-tx-urpf-loose",
    },
  },
};
/* *INDENT-ON* */

/**
 * Per-af, per-direction, per-interface uRPF configs
 */

urpf_data_t *urpf_cfgs[N_AF][VLIB_N_DIR];

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

int
urpf_update (urpf_mode_t mode, u32 sw_if_index, ip_address_family_t af,
	     vlib_dir_t dir, u32 table_id)
{
  fib_protocol_t proto;
  u32 fib_index;
  if (table_id != ~0)
    {
      proto = ip_address_family_to_fib_proto (af);
      fib_index = fib_table_find (proto, table_id);
      if (fib_index == (~0))
	return VNET_API_ERROR_INVALID_VALUE;
    }
  else
    {
      bool is_ip4 = (AF_IP4 == af);
      u32 *fib_index_by_sw_if_index = is_ip4 ?
					      ip4_main.fib_index_by_sw_if_index :
					      ip6_main.fib_index_by_sw_if_index;

      fib_index = fib_index_by_sw_if_index[sw_if_index];
    }
  urpf_data_t old;
  urpf_mode_t off = URPF_MODE_OFF;
  urpf_data_t empty = { .fib_index = 0, .mode = off };
  vec_validate_init_empty (urpf_cfgs[af][dir], sw_if_index, empty);
  old = urpf_cfgs[af][dir][sw_if_index];

  urpf_data_t data = { .fib_index = fib_index,
		       .mode = mode,
		       .fib_index_is_custom = (table_id != ~0) };
  urpf_cfgs[af][dir][sw_if_index] = data;
  if (data.mode != old.mode || data.fib_index != old.fib_index)
    {
      if (URPF_MODE_OFF != old.mode)
	/* disable what we have */
	vnet_feature_enable_disable (urpf_feat_arcs[af][dir],
				     urpf_feats[af][dir][old.mode],
				     sw_if_index, 0, 0, 0);

      if (URPF_MODE_OFF != data.mode)
	/* enable what's new */
	vnet_feature_enable_disable (urpf_feat_arcs[af][dir],
				     urpf_feats[af][dir][data.mode],
				     sw_if_index, 1, 0, 0);
    }
  /* else - no change to existing config */
  return 0;
}

static void
urpf_table_bind_v4 (ip4_main_t *im, uword opaque, u32 sw_if_index,
		    u32 new_fib_index, u32 old_fib_index)
{
  vlib_dir_t dir;
  urpf_data_t empty = { .fib_index = 0, .mode = URPF_MODE_OFF };
  FOREACH_VLIB_DIR (dir)
  {
    vec_validate_init_empty (urpf_cfgs[AF_IP4][dir], sw_if_index, empty);
    if (!urpf_cfgs[AF_IP4][dir][sw_if_index].fib_index_is_custom)
      {
	urpf_cfgs[AF_IP4][dir][sw_if_index].fib_index = new_fib_index;
      }
  }
}

static void
urpf_table_bind_v6 (ip6_main_t *im, uword opaque, u32 sw_if_index,
		    u32 new_fib_index, u32 old_fib_index)
{
  vlib_dir_t dir;
  urpf_data_t empty = { .fib_index = 0, .mode = URPF_MODE_OFF };
  FOREACH_VLIB_DIR (dir)
  {
    vec_validate_init_empty (urpf_cfgs[AF_IP6][dir], sw_if_index, empty);
    if (!urpf_cfgs[AF_IP6][dir][sw_if_index].fib_index_is_custom)
      {
	urpf_cfgs[AF_IP6][dir][sw_if_index].fib_index = new_fib_index;
      }
  }
}

static clib_error_t *
urpf_init (vlib_main_t *vm)
{
  ip4_table_bind_callback_t cb4 = {
    .function = urpf_table_bind_v4,
  };
  vec_add1 (ip4_main.table_bind_callbacks, cb4);

  ip6_table_bind_callback_t cb6 = {
    .function = urpf_table_bind_v6,
  };
  vec_add1 (ip6_main.table_bind_callbacks, cb6);
  return (NULL);
}

VLIB_INIT_FUNCTION (urpf_init);

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
  u32 table_id;

  sw_if_index = ~0;
  af = AF_IP4;
  dir = VLIB_RX;
  mode = URPF_MODE_STRICT;
  table_id = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "%U", unformat_urpf_mode, &mode))
	;
      else if (unformat (line_input, "table %u", &table_id))
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

  int rv = 0;
  rv = urpf_update (mode, sw_if_index, af, dir, table_id);
  if (rv)
    {
      error = clib_error_return (0, "unknown table id");
      goto done;
    }
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
 *       Name                    Next                  Previous
 * ip4-rx-urpf-loose          ip4-drop [0]        ip4-input-no-checksum
 *                    ip4-source-and-port-range-       ip4-input
 * @cliexend
 *
 * Example of how to display the feature enabled on an interface:
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
  .short_help = "set urpf [ip4|ip6] [rx|tx] [off|strict|loose] "
		"<INTERFACE> [table <table>]",
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
      if (unformat (line_input, "table %u", &table_id))
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
