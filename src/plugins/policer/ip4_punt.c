/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/ip/ip.h>
#include <vnet/ip/ip_punt_drop.h>

#include <policer/internal.h>
#include <policer/policer_node.h>
#include <policer/ip_punt.h>

extern ip_punt_policer_t ip4_punt_policer_cfg;

#ifndef CLIB_MARCH_VARIANT
u8 *
format_ip_punt_policer_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_punt_policer_trace_t *t = va_arg (*args, ip_punt_policer_trace_t *);

  s = format (s, "policer_index %d next %d", t->policer_index, t->next);
  return s;
}

ip_punt_policer_t ip4_punt_policer_cfg = {
  .policer_index = ~0,
};
#endif /* CLIB_MARCH_VARIANT */

static char *ip4_punt_policer_handoff_error_strings[] = { "congestion drop" };

VLIB_NODE_FN (ip4_punt_policer_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return policer_handoff (vm, node, frame, ip4_punt_policer_cfg.fq_index,
			  ip4_punt_policer_cfg.policer_index);
}

VLIB_REGISTER_NODE (ip4_punt_policer_handoff_node) = {
  .name = "ip4-punt-policer-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_policer_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ip4_punt_policer_handoff_error_strings),
  .error_strings = ip4_punt_policer_handoff_error_strings,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

static char *ip4_punt_policer_error_strings[] = {
#define _(sym, string) string,
  foreach_ip_punt_policer_error
#undef _
};

VLIB_NODE_FN (ip4_punt_policer_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u8 ip4_punt_feat_arc_index = vnet_get_feature_arc_index ("ip4-punt");
  return (
    ip_punt_policer (vm, node, frame, ip4_punt_feat_arc_index, ip4_punt_policer_cfg.policer_index));
}

VLIB_REGISTER_NODE (ip4_punt_policer_node) = {
  .name = "ip4-punt-policer",
  .vector_size = sizeof (u32),
  .n_next_nodes = IP_PUNT_POLICER_N_NEXT,
  .format_trace = format_ip_punt_policer_trace,
  .n_errors = ARRAY_LEN(ip4_punt_policer_error_strings),
  .error_strings = ip4_punt_policer_error_strings,

  .next_nodes = {
    [IP_PUNT_POLICER_NEXT_DROP] = "ip4-drop",
    [IP_PUNT_POLICER_NEXT_HANDOFF] = "ip4-punt-policer-handoff",
  },
};

VNET_FEATURE_INIT (ip4_punt_policer_node) = {
  .arc_name = "ip4-punt",
  .node_name = "ip4-punt-policer",
  .runs_before = VNET_FEATURES ("ip4-punt-redirect"),
  .runs_after = VNET_FEATURES ("ip4-punt-acl"),
};

#ifndef CLIB_MARCH_VARIANT
void
ip4_punt_policer_add_del (u8 is_add, u32 policer_index)
{
  ip4_punt_policer_cfg.policer_index = policer_index;

  vnet_feature_enable_disable ("ip4-punt", "ip4-punt-policer", 0, is_add, 0, 0);
}
#endif /* CLIB_MARCH_VARIANT */

static clib_error_t *
ip4_punt_police_cmd (vlib_main_t *vm, unformat_input_t *main_input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 policer_index;
  u8 is_add = 1;

  policer_index = ~0;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%d", &policer_index))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "add"))
	is_add = 1;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (is_add && ~0 == policer_index)
    {
      error =
	clib_error_return (0, "expected policer index `%U'", format_unformat_error, line_input);
      goto done;
    }
  if (!is_add)
    policer_index = ~0;

  ip4_punt_policer_add_del (is_add, policer_index);

done:
  unformat_free (line_input);
  return (error);
}

/*?
 *
 * @cliexpar
 * @cliexcmd{set ip punt policer <INDEX>}
 ?*/
VLIB_CLI_COMMAND (ip4_punt_policer_command, static) = {
  .path = "ip punt policer",
  .function = ip4_punt_police_cmd,
  .short_help = "ip punt policer [add|del] <index>",
};
