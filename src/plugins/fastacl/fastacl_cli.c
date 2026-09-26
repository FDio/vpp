/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <fastacl/fastacl.h>
#include <fastacl/fastacl_format.h>

static uword
unformat_fastacl_range (unformat_input_t *input, va_list *args)
{
  u32 *lo = va_arg (*args, u32 *);
  u32 *hi = va_arg (*args, u32 *);

  if (unformat (input, "%u-%u", lo, hi))
    return 1;
  if (unformat (input, "%u", lo))
    {
      *hi = *lo;
      return 1;
    }
  return 0;
}

static clib_error_t *
fastacl_cli_parse_action (unformat_input_t *input, fastacl_action_t *action, int *have_action,
			  int *handled)
{
  *handled = 1;

  if (unformat (input, "action drop"))
    {
      action->type = FASTACL_ACTION_TYPE_DROP;
      *have_action = 1;
    }

  else if (unformat (input, "action permit") || unformat (input, "action pass") ||
	   unformat (input, "action accept"))
    {
      action->type = FASTACL_ACTION_TYPE_PERMIT;
      *have_action = 1;
    }
  else if (unformat (input, "sample %u", &action->sample_ratio))
    {
      unformat (input, "group %u", &action->sample_group);
      if (action->sample_ratio == 0)
	return clib_error_return (0, "sample ratio must be 1 or more");
    }
  else
    *handled = 0;

  return 0;
}

static void
fastacl_cli_warn_if_racy (vlib_main_t *vm, const char *what)
{
  if (vlib_num_workers () == 0)
    return;

  vlib_cli_output (vm,
		   "warning: %s from the CLI is not synchronised against the "
		   "%u worker(s) and can corrupt the data plane while traffic "
		   "is running. It is a debug convenience; use the binary API "
		   "for anything automated or live.",
		   what, vlib_num_workers ());
}

static clib_error_t *
fastacl_cli_plen (u32 plen, int is_ip6, u8 *out)
{
  u32 max = fastacl_max_prefix_len (is_ip6);

  if (plen > max)
    return clib_error_return (0, "prefix length must be 0..%u", max);
  *out = (u8) plen;
  return 0;
}

static clib_error_t *
fastacl_cli_match_prefix (fastacl_match_t *m, u32 flag, int is_ip6, const void *addr, u32 plen)
{
  int is_dst = flag == FASTACL_MATCH_DST_PREFIX;
  ip46_address_t *dst = is_dst ? &m->dst_addr : &m->src_addr;
  clib_error_t *e =
    fastacl_cli_plen (plen, is_ip6, is_dst ? &m->dst_prefix_len : &m->src_prefix_len);

  if (e)
    return e;
  m->flags |= flag | (is_ip6 ? FASTACL_MATCH_IS_IP6 : 0);
  if (is_ip6)
    dst->ip6 = *(const ip6_address_t *) addr;
  else
    dst->ip4 = *(const ip4_address_t *) addr;
  return 0;
}

static clib_error_t *
fastacl_rule_add_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  fastacl_cli_warn_if_racy (vm, "adding a rule");

  fastacl_match_t match;
  fastacl_action_t action;
  u32 order = 0;
  u32 rule_index = ~0;
  ip4_address_t addr4;
  ip6_address_t addr6;
  u32 plen;
  u32 lo, hi;
  u32 val, mask;
  clib_error_t *e = 0;
  int handled;
  int rv;

  clib_memset (&match, 0, sizeof (match));
  clib_memset (&action, 0, sizeof (action));

  int have_action = 0;

  if (!unformat (input, "order %u", &order))
    return clib_error_return (0, "expected 'order <N>'");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "dst %U/%u", unformat_ip4_address, &addr4, &plen))
	e = fastacl_cli_match_prefix (&match, FASTACL_MATCH_DST_PREFIX, 0, &addr4, plen);
      else if (unformat (input, "dst6 %U/%u", unformat_ip6_address, &addr6, &plen))
	e = fastacl_cli_match_prefix (&match, FASTACL_MATCH_DST_PREFIX, 1, &addr6, plen);
      else if (unformat (input, "src %U/%u", unformat_ip4_address, &addr4, &plen))
	e = fastacl_cli_match_prefix (&match, FASTACL_MATCH_SRC_PREFIX, 0, &addr4, plen);
      else if (unformat (input, "src6 %U/%u", unformat_ip6_address, &addr6, &plen))
	e = fastacl_cli_match_prefix (&match, FASTACL_MATCH_SRC_PREFIX, 1, &addr6, plen);
      else if (unformat (input, "proto %u", &val))
	{
	  match.flags |= FASTACL_MATCH_PROTO;
	  match.proto = val;
	}
      else if (unformat (input, "dst-port %U", unformat_fastacl_range, &lo, &hi))
	{
	  match.flags |= FASTACL_MATCH_DST_PORT;
	  match.dst_port_min = lo;
	  match.dst_port_max = hi;
	}
      else if (unformat (input, "src-port %U", unformat_fastacl_range, &lo, &hi))
	{
	  match.flags |= FASTACL_MATCH_SRC_PORT;
	  match.src_port_min = lo;
	  match.src_port_max = hi;
	}
      else if (unformat (input, "either-port %U", unformat_fastacl_range, &lo, &hi))
	{
	  match.flags |= FASTACL_MATCH_EITHER_PORT;
	  match.either_port_min = lo;
	  match.either_port_max = hi;
	}
      else if (unformat (input, "icmp-type %u", &val))
	{
	  match.flags |= FASTACL_MATCH_ICMP_TYPE;
	  match.icmp_type = val;
	}
      else if (unformat (input, "icmp-code %u", &val))
	{
	  match.flags |= FASTACL_MATCH_ICMP_CODE;
	  match.icmp_code = val;
	}
      else if (unformat (input, "tcp-flags value %U mask %U", unformat_vlib_number, &val,
			 unformat_vlib_number, &mask))
	{
	  match.flags |= FASTACL_MATCH_TCP_FLAGS;
	  match.tcp_flags_value = val;
	  match.tcp_flags_mask = mask;
	}
      else if (unformat (input, "pkt-len %U", unformat_fastacl_range, &lo, &hi))
	{
	  match.flags |= FASTACL_MATCH_PKT_LEN;
	  match.pkt_len_min = lo;
	  match.pkt_len_max = hi;
	}
      else if (unformat (input, "dscp %u", &val))
	{
	  match.flags |= FASTACL_MATCH_DSCP;
	  match.dscp = val;
	}
      else if (unformat (input, "fragment flags %U mask %U", unformat_vlib_number, &val,
			 unformat_vlib_number, &mask))
	{
	  match.flags |= FASTACL_MATCH_FRAGMENT;
	  match.fragment_flags = val;
	  match.fragment_mask = mask;
	}
      else if (unformat (input, "fragment %U", unformat_vlib_number, &val))
	{
	  match.flags |= FASTACL_MATCH_FRAGMENT;
	  match.fragment_flags = val;
	  match.fragment_mask = val;
	}
      else
	{
	  e = fastacl_cli_parse_action (input, &action, &have_action, &handled);
	  if (!e && !handled)
	    e = clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
	}

      if (e)
	return e;
    }

  if (!have_action)
    return clib_error_return (0,
			      "an action is required: drop or permit (pass/accept).  Refusing to "
			      "default to drop — a rule added to sample traffic would otherwise "
			      "discard exactly what it was meant to watch.");

  rv = fastacl_rule_add (order, &match, &action, &rule_index);
  if (rv)
    {
      if (rv == VNET_API_ERROR_ENTRY_ALREADY_EXISTS)
	return clib_error_return (0, "duplicate rule (same order + match)");
      return clib_error_return (0, "fastacl_rule_add returned %d", rv);
    }

  vlib_cli_output (vm, "rule index %u added", rule_index);
  return 0;
}

VLIB_CLI_COMMAND (fastacl_rule_add_command, static) = {
  .path = "fastacl rule add",
  .short_help = "fastacl rule add order <N> [dst <ip4>/<len>] [dst6 <ip6>/<len>] "
		"[src <ip4>/<len>] [src6 <ip6>/<len>] [proto <N>] "
		"[dst-port <N>[-<N>]] [src-port <N>[-<N>]] "
		"[either-port <N>[-<N>]] [icmp-type <N>] [icmp-code <N>] "
		"[tcp-flags value <hex> mask <hex>] [pkt-len <N>[-<N>]] "
		"[dscp <N>] [fragment <N>] "
		"action {drop | permit} "
		"[sample <N> [group <N>]]",
  .function = fastacl_rule_add_command_fn,
};

static clib_error_t *
fastacl_rule_del_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  fastacl_cli_warn_if_racy (vm, "deleting a rule");

  u32 rule_index = ~0;
  int rv;

  if (unformat (input, "all"))
    {
      rv = fastacl_rule_del_all ();
      if (rv)
	return clib_error_return (0, "fastacl_rule_del_all returned %d", rv);
      vlib_cli_output (vm, "all rules deleted");
      return 0;
    }

  if (!unformat (input, "%u", &rule_index))
    return clib_error_return (0, "expected rule index or 'all'");

  rv = fastacl_rule_del (rule_index);
  if (rv)
    return clib_error_return (0, "fastacl_rule_del returned %d", rv);

  vlib_cli_output (vm, "rule index %u deleted", rule_index);
  return 0;
}

VLIB_CLI_COMMAND (fastacl_rule_del_command, static) = {
  .path = "fastacl rule del",
  .short_help = "fastacl rule del {<index> | all}",
  .function = fastacl_rule_del_command_fn,
};

static clib_error_t *
fastacl_rule_stats_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  fastacl_cli_warn_if_racy (vm, "changing per-rule statistics");

  fastacl_main_t *fsm = &fastacl_main;
  u8 enable = fsm->rule_stats_enabled;

  if (unformat (input, "enable"))
    enable = 1;
  else if (unformat (input, "disable"))
    enable = 0;
  else if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected enable | disable");

  fsm->rule_stats_enabled = enable;

  vlib_cli_output (vm, "per-rule stats: %s", fsm->rule_stats_enabled ? "enabled" : "disabled");
  return 0;
}

VLIB_CLI_COMMAND (fastacl_rule_stats_command, static) = {
  .path = "fastacl per-rule-stats",
  .short_help = "fastacl per-rule-stats [enable|disable]",
  .function = fastacl_rule_stats_command_fn,
};

static clib_error_t *
fastacl_show_tuples_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  fastacl_main_t *fsm = &fastacl_main;
  fastacl_tuple_t *t;

  vlib_cli_output (vm, "tuples: %u", pool_elts (fsm->tuples));
  if (pool_elts (fsm->tuples) == 0)
    return 0;

  vlib_cli_output (vm, "%-6s %-10s %-6s %-6s %-6s %-6s %-8s %-8s %-8s %-8s", "id", "flags", "dplen",
		   "splen", "v6", "key", "rules", "chains", "chained", "deepest");
  pool_foreach (t, fsm->tuples)
    {
      u32 n_chains, deepest, chained;
      const char *keyw = fastacl_tss_width_name (t->width);

      fastacl_tuple_chain_stats (fsm, t, &n_chains, &deepest, &chained);
      vlib_cli_output (vm, "%-6u 0x%-8x %-6u %-6u %-6u %-6s %-8u %-8u %-8u %-8u",
		       (u32) (t - fsm->tuples), t->mask.flags, t->mask.dst_plen, t->mask.src_plen,
		       t->mask.is_ip6, keyw, t->n_rules, n_chains, chained, deepest);
    }
  return 0;
}

VLIB_CLI_COMMAND (fastacl_show_tuples_command, static) = {
  .path = "show fastacl tuples",
  .short_help = "show fastacl tuples — TSS classifier state",
  .function = fastacl_show_tuples_command_fn,
};

static u32 *
fastacl_collect_sorted_indices (fastacl_main_t *fsm)
{
  u32 *v = 0;
  u32 ri;
  pool_foreach_index (ri, fsm->rules)
    vec_add1 (v, ri);
  vec_sort_with_function (v, fastacl_rule_order_cmp);
  return v;
}

static void
fastacl_show_rules_flat (vlib_main_t *vm, fastacl_main_t *fsm, u32 *sorted)
{
  u32 i;

  vlib_cli_output (vm, "%-8s %-8s %-20s %-20s %-8s %-32s %-12s %-12s %-12s %-12s %-14s %-14s",
		   "Index", "Order", "Dst Prefix", "Src Prefix", "Proto", "Match Extra", "Action",
		   "Packets", "Bytes", "pps", "L3 bps", "L1 bps");
  for (i = 0; i < vec_len (sorted); i++)
    fastacl_show_one_rule (vm, pool_elt_at_index (fsm->rules, sorted[i]));
}

static clib_error_t *
fastacl_show_rules_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  fastacl_main_t *fsm = &fastacl_main;

  if (pool_elts (fsm->rules) == 0)
    {
      vlib_cli_output (vm, "no rules configured");
      return 0;
    }

  fastacl_update_rates (vm);
  u32 *sorted = fastacl_collect_sorted_indices (fsm);

  fastacl_show_rules_flat (vm, fsm, sorted);

  vec_free (sorted);
  return 0;
}

VLIB_CLI_COMMAND (fastacl_show_rules_command, static) = {
  .path = "show fastacl rules",
  .short_help = "show fastacl rules",
  .function = fastacl_show_rules_command_fn,
};

static clib_error_t *
fastacl_clear_counters_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  fastacl_cli_warn_if_racy (vm, "clearing counters");

  fastacl_clear_counters ();
  vlib_cli_output (vm, "counters cleared");
  return 0;
}

VLIB_CLI_COMMAND (fastacl_clear_counters_command, static) = {
  .path = "clear fastacl counters",
  .short_help = "clear fastacl counters",
  .function = fastacl_clear_counters_command_fn,
};

static clib_error_t *
fastacl_set_interface_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int enable = 1;

  if (!unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
    return clib_error_return (0, "specify an interface");

  if (unformat (input, "disable"))
    enable = 0;
  else
    unformat (input, "enable");

  int rv = fastacl_interface_enable_disable (sw_if_index, enable);
  if (rv)
    return clib_error_return (0, "fastacl_interface_enable_disable returned %d", rv);

  vlib_cli_output (vm, "fastacl %s on %U", enable ? "enabled" : "disabled",
		   format_vnet_sw_if_index_name, vnm, sw_if_index);
  return 0;
}

VLIB_CLI_COMMAND (fastacl_set_interface_command, static) = {
  .path = "set interface fastacl",
  .short_help = "set interface fastacl <interface> [enable|disable]",
  .function = fastacl_set_interface_command_fn,
};

static clib_error_t *
fastacl_show_interface_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  fastacl_main_t *fsm = &fastacl_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 i;

  if (clib_bitmap_is_zero (fsm->enabled_interfaces))
    {
      vlib_cli_output (vm, "no interfaces have fastacl enabled");
      return 0;
    }

  clib_bitmap_foreach (i, fsm->enabled_interfaces)
    {
      vlib_cli_output (vm, "  %-24U", format_vnet_sw_if_index_name, vnm, i);
    }
  return 0;
}

VLIB_CLI_COMMAND (fastacl_show_interface_command, static) = {
  .path = "show fastacl interface",
  .short_help = "show fastacl interface",
  .function = fastacl_show_interface_command_fn,
};

static clib_error_t *
fastacl_show_aggregate_counters_command_fn (vlib_main_t *vm, unformat_input_t *input,
					    vlib_cli_command_t *cmd)
{
  fastacl_main_t *fsm = &fastacl_main;

  fastacl_update_aggregate_rates (vm);

  vlib_cli_output (vm, "Aggregate counters:");
  vlib_cli_output (vm, "  %-12s %-22s %-22s %-14s %-14s %-14s", "", "Packets", "Bytes", "pps",
		   "L3 bps", "L1 bps");
  vlib_cli_output (
    vm, "  %-12s %llu (%U)  %llu (%U)  %U  %U  %U", "Processed:", fsm->counters.total_processed,
    format_fastacl_count_si, fsm->counters.total_processed, fsm->counters.total_bytes_processed,
    format_fastacl_bytes_si, fsm->counters.total_bytes_processed, format_fastacl_pps,
    fsm->counters.processed_rate.pps, format_fastacl_bps, fsm->counters.processed_rate.l3_bps,
    format_fastacl_bps, fsm->counters.processed_rate.l1_bps);
  vlib_cli_output (
    vm, "  %-12s %llu (%U)  %llu (%U)  %U  %U  %U", "Dropped:", fsm->counters.total_dropped,
    format_fastacl_count_si, fsm->counters.total_dropped, fsm->counters.total_bytes_dropped,
    format_fastacl_bytes_si, fsm->counters.total_bytes_dropped, format_fastacl_pps,
    fsm->counters.dropped_rate.pps, format_fastacl_bps, fsm->counters.dropped_rate.l3_bps,
    format_fastacl_bps, fsm->counters.dropped_rate.l1_bps);
  return 0;
}

VLIB_CLI_COMMAND (fastacl_show_aggregate_counters_command, static) = {
  .path = "show fastacl aggregate-counters",
  .short_help = "show fastacl aggregate-counters",
  .function = fastacl_show_aggregate_counters_command_fn,
};

static clib_error_t *
fastacl_psample_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  fastacl_cli_warn_if_racy (vm, "changing sampling");

  int enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "enable"))
	enable = 1;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  int rv = fastacl_psample_enable_disable (enable);
  if (rv == VNET_API_ERROR_FEATURE_DISABLED)
    return clib_error_return (0,
			      "psample netlink family not found - is the psample module loaded?");
  if (rv)
    return clib_error_return (0, "failed to open psample sockets");
  return 0;
}

VLIB_CLI_COMMAND (fastacl_psample_command, static) = {
  .path = "fastacl psample",
  .short_help = "fastacl psample {enable | disable}",
  .function = fastacl_psample_command_fn,
};

static clib_error_t *
fastacl_show_sampling_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  fastacl_main_t *fsm = &fastacl_main;
  fastacl_rule_t *rule;

  vlib_cli_output (vm, "psample: %s", fsm->psample_enabled ? "enabled" : "disabled");
  if (fsm->psample.family_id)
    vlib_cli_output (vm, "psample multicast group id: %u", fsm->psample.group_id);

  if (fsm->n_sample_rules == 0)
    {
      vlib_cli_output (vm, "No rule carries a sample ratio.");
      return 0;
    }

  vlib_cli_output (vm, "%-8s %-8s %-8s %-14s %-14s", "rule", "ratio", "group", "sampled",
		   "send-failed");

  pool_foreach (rule, fsm->rules)
    {
      if (rule->action.sample_ratio == 0)
	continue;

      u64 taken = 0, missed = 0;
      fastacl_per_worker_t *pw;
      vec_foreach (pw, fsm->per_worker)
	{
	  if (rule->index < vec_len (pw->rule_sample_count))
	    taken += pw->rule_sample_count[rule->index];
	  if (rule->index < vec_len (pw->rule_sample_missed))
	    missed += pw->rule_sample_missed[rule->index];
	}
      vlib_cli_output (vm, "%-8u 1:%-6u %-8u %-14llu %-14llu", rule->index,
		       rule->action.sample_ratio, rule->action.sample_group, taken, missed);
    }
  return 0;
}

VLIB_CLI_COMMAND (fastacl_show_sampling_command, static) = {
  .path = "show fastacl sampling",
  .short_help = "show fastacl sampling",
  .function = fastacl_show_sampling_command_fn,
};
