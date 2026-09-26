/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#include <fastacl/fastacl.h>
#include <vlib/stats/stats.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>

extern int vnet_l2_feature_enable_disable (const char *arc_name, const char *node_name,
					   u32 sw_if_index, int enable_disable,
					   void *feature_config, u32 n_feature_config_bytes);

fastacl_main_t fastacl_main;

static clib_error_t *
fastacl_config (vlib_main_t *vm, unformat_input_t *input)
{
  fastacl_main_t *fsm = &fastacl_main;
  u32 buckets_val;
  u32 memory_mb_val;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tss-bihash-buckets %u", &buckets_val))
	fsm->tss_buckets = clib_max (buckets_val, FASTACL_TSS_BUCKETS_MIN);
      else if (unformat (input, "tss-bihash-memory-mb %u", &memory_mb_val))
	vlib_log_warn (fsm->log_class, "tss-bihash-memory-mb is accepted for configuration "
				       "compatibility and has no effect: the classifier tables "
				       "allocate from the VPP main heap");
      else if (unformat_skip_white_space (input) &&
	       unformat_check_input (input) == UNFORMAT_END_OF_INPUT)
	break;
      else
	return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (fastacl_config, "fastacl");

static clib_error_t *
fastacl_init (vlib_main_t *vm)
{
  fastacl_main_t *fsm = &fastacl_main;
  fsm->vlib_main = vm;
  fsm->vnet_main = vnet_get_main ();

  fsm->tuple_by_mask = hash_create_mem (0, sizeof (fastacl_tuple_mask_t), sizeof (uword));

  fsm->tss_buckets = FASTACL_TSS_BUCKETS_DEFAULT;
  fsm->rule_stats_enabled = 1;

  vec_validate (fsm->per_worker, vlib_num_workers ());

  fsm->log_class = vlib_log_register_class ("fastacl", 0);

  fsm->rule_counters.stat_segment_name = "/fastacl/rule";

  fsm->rule_gen_stat_index = ~0u;

  return 0;
}

static clib_error_t *
fastacl_counters_main_loop_enter (vlib_main_t *vm)
{
  fastacl_main_t *fsm = &fastacl_main;

  vlib_validate_combined_counter (&fsm->rule_counters, 0);
  if (fsm->rule_counter_len == 0)
    fsm->rule_counter_len = 1;

  fsm->rule_gen_stat_index = vlib_stats_add_counter_vector ("/fastacl/rule/gen");
  if (fsm->rule_gen_stat_index != ~0u)
    {
      vlib_stats_validate (fsm->rule_gen_stat_index, 0, 0);
      fsm->rule_gen_len = 1;
    }

  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (fastacl_counters_main_loop_enter);

static void
fastacl_psample_close_all (fastacl_main_t *fsm)
{
  fsm->psample_enabled = 0;
  foreach_fastacl_per_worker (pw, fsm) { fastacl_psample_worker_close (&pw->psample); }
}

static int
fastacl_psample_open_all (fastacl_main_t *fsm)
{
  foreach_fastacl_per_worker (pw, fsm)
  {
    if (fastacl_psample_worker_open (&pw->psample) < 0)
      return VNET_API_ERROR_SYSCALL_ERROR_1;
  }

  fsm->psample_enabled = 1;
  return 0;
}

int
fastacl_psample_enable_disable (int enable)
{
  fastacl_main_t *fsm = &fastacl_main;

  if (!enable)
    {
      fastacl_psample_close_all (fsm);
      return 0;
    }

  if (fastacl_psample_init () < 0)
    return VNET_API_ERROR_FEATURE_DISABLED;

  return fastacl_psample_open_all (fsm);
}

VLIB_INIT_FUNCTION (fastacl_init);

VNET_FEATURE_INIT (fastacl_filter_ip4, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "fastacl-filter",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
VNET_FEATURE_INIT (fastacl_filter_ip6, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "fastacl-filter",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
VNET_FEATURE_INIT (fastacl_filter_l2_ip4, static) = {
  .arc_name = "l2-input-ip4",
  .node_name = "fastacl-filter-l2",
};
VNET_FEATURE_INIT (fastacl_filter_l2_ip6, static) = {
  .arc_name = "l2-input-ip6",
  .node_name = "fastacl-filter-l2",
};

static const struct
{
  const char *arc_name;
  const char *node_name;
  u8 is_l2;
} fastacl_filter_arcs[] = {
  { "ip4-unicast", "fastacl-filter", 0 },
  { "ip6-unicast", "fastacl-filter", 0 },
  { "l2-input-ip4", "fastacl-filter-l2", 1 },
  { "l2-input-ip6", "fastacl-filter-l2", 1 },
};

static int
fastacl_arc_enable_disable (u32 i, u32 sw_if_index, int enable_disable)
{
  if (fastacl_filter_arcs[i].is_l2)
    return vnet_l2_feature_enable_disable (fastacl_filter_arcs[i].arc_name,
					   fastacl_filter_arcs[i].node_name, sw_if_index,
					   enable_disable, 0, 0);
  return vnet_feature_enable_disable (fastacl_filter_arcs[i].arc_name,
				      fastacl_filter_arcs[i].node_name, sw_if_index, enable_disable,
				      0, 0);
}

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "FastACL DDoS Filter",
};

static int
fastacl_interface_apply_arcs (fastacl_main_t *fsm, u32 sw_if_index, int enable_disable)
{
  u32 i;
  int rv = 0;

  for (i = 0; i < ARRAY_LEN (fastacl_filter_arcs); i++)
    if ((rv = fastacl_arc_enable_disable (i, sw_if_index, enable_disable)))
      break;

  if (rv)
    {
      while (i--)
	fastacl_arc_enable_disable (i, sw_if_index, !enable_disable);
      return rv;
    }

  fsm->enabled_interfaces = clib_bitmap_set (fsm->enabled_interfaces, sw_if_index, enable_disable);

  return 0;
}

int
fastacl_interface_enable_disable (u32 sw_if_index, int enable_disable)
{
  fastacl_main_t *fsm = &fastacl_main;

  if (!!clib_bitmap_get (fsm->enabled_interfaces, sw_if_index) == !!enable_disable)
    return 0;

  return fastacl_interface_apply_arcs (fsm, sw_if_index, enable_disable);
}
