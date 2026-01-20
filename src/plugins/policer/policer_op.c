/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/feature/feature.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/ethernet/ethernet.h>

#include <policer/internal.h>
#include <policer/policer_op.h>

int
policer_add (vlib_main_t *vm, const u8 *name, const qos_pol_cfg_params_st *cfg, u32 *policer_index)
{
  policer_main_t *pm = &policer_main;
  policer_t test_policer;
  policer_t *policer;
  policer_t *pp;
  qos_pol_cfg_params_st *cp;
  uword *p;
  u32 pi;
  int rv;
  int i;

  p = hash_get_mem (pm->policer_config_by_name, name);

  if (p != NULL)
    return VNET_API_ERROR_VALUE_EXIST;

  /* Vet the configuration before adding it to the table */
  rv = pol_logical_2_physical (cfg, &test_policer);

  if (rv != 0)
    return VNET_API_ERROR_INVALID_VALUE;

  pool_get (pm->configs, cp);
  pool_get_aligned (pm->policers, policer, CLIB_CACHE_LINE_BYTES);

  clib_memcpy (cp, cfg, sizeof (*cp));
  clib_memcpy (policer, &test_policer, sizeof (*pp));

  policer->name = format (0, "%s%c", name, 0);
  pi = policer - pm->policers;

  hash_set_mem (pm->policer_config_by_name, policer->name, cp - pm->configs);
  hash_set_mem (pm->policer_index_by_name, policer->name, pi);
  *policer_index = pi;
  policer->thread_index = ~0;

  for (i = 0; i < NUM_POLICE_RESULTS; i++)
    {
      vlib_validate_combined_counter (&policer_counters[i], pi);
      vlib_zero_combined_counter (&policer_counters[i], pi);
    }

  return 0;
}

int
policer_del (vlib_main_t *vm, u32 policer_index)
{
  policer_main_t *pm = &policer_main;
  policer_t *policer;
  uword *p;

  if (pool_is_free_index (pm->policers, policer_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  policer = &pm->policers[policer_index];

  p = hash_get_mem (pm->policer_config_by_name, policer->name);

  /* free policer config */
  if (p != NULL)
    {
      pool_put_index (pm->configs, p[0]);
      hash_unset_mem (pm->policer_config_by_name, policer->name);
    }

  /* free policer */
  hash_unset_mem (pm->policer_index_by_name, policer->name);
  vec_free (policer->name);
  pool_put_index (pm->policers, policer_index);

  return 0;
}

int
policer_update (vlib_main_t *vm, u32 policer_index, const qos_pol_cfg_params_st *cfg)
{
  policer_main_t *pm = &policer_main;
  policer_t test_policer;
  policer_t *policer;
  qos_pol_cfg_params_st *cp;
  uword *p;
  u8 *name;
  int rv;
  int i;

  if (pool_is_free_index (pm->policers, policer_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  policer = &pm->policers[policer_index];

  /* Vet the configuration before adding it to the table */
  rv = pol_logical_2_physical (cfg, &test_policer);
  if (rv != 0)
    return VNET_API_ERROR_INVALID_VALUE;

  p = hash_get_mem (pm->policer_config_by_name, policer->name);

  if (PREDICT_TRUE (p != NULL))
    {
      cp = &pm->configs[p[0]];
    }
  else
    {
      /* recover from a missing configuration */
      pool_get (pm->configs, cp);
      hash_set_mem (pm->policer_config_by_name, policer->name, cp - pm->configs);
    }

  name = policer->name;

  clib_memcpy (cp, cfg, sizeof (*cp));
  clib_memcpy (policer, &test_policer, sizeof (*policer));

  policer->name = name;
  policer->thread_index = ~0;

  for (i = 0; i < NUM_POLICE_RESULTS; i++)
    vlib_zero_combined_counter (&policer_counters[i], policer_index);

  return 0;
}

int
policer_reset (vlib_main_t *vm, u32 policer_index)
{
  policer_main_t *pm = &policer_main;
  policer_t *policer;

  if (pool_is_free_index (pm->policers, policer_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  policer = &pm->policers[policer_index];

  policer->current_bucket = policer->current_limit;
  policer->extended_bucket = policer->extended_limit;

  return 0;
}

int
policer_bind_worker (u32 policer_index, u32 worker, bool bind)
{
  policer_main_t *pm = &policer_main;
  policer_t *policer;

  if (pool_is_free_index (pm->policers, policer_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  policer = &pm->policers[policer_index];

  if (bind)
    {
      if (worker >= vlib_num_workers ())
	{
	  return VNET_API_ERROR_INVALID_WORKER;
	}

      policer->thread_index = vlib_get_worker_thread_index (worker);
    }
  else
    {
      policer->thread_index = ~0;
    }
  return 0;
}

static u8
policer_compute_l2_overhead (vnet_main_t *vnm, u32 sw_if_index, vlib_dir_t dir)
{
  /* L2 input/output policers don't need adjustment (packet has ethernet header).
   * L3 output runs after ip-rewrite, which has prepended the ethernet header (no adjustment).
   * L3 input runs after ip-unicast, which has stripped the ethernet header (adjustment needed).
   */
  if (dir == VLIB_TX)
    return 0;

  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (PREDICT_FALSE (hi->hw_class_index != ethernet_hw_interface_class.index))
    return 0; /* Not Ethernet */

  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
  if (si->type == VNET_SW_INTERFACE_TYPE_SUB)
    {
      if (si->sub.eth.flags.one_tag)
	return 18; /* Ethernet + single VLAN */
      if (si->sub.eth.flags.two_tags)
	return 22; /* Ethernet + QinQ */
    }

  return 14; /* Untagged Ethernet */
}

int
policer_input (u32 policer_index, u32 sw_if_index, vlib_dir_t dir, bool apply)
{
  policer_main_t *pm = &policer_main;

  if (pool_is_free_index (pm->policers, policer_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (apply)
    {
      vec_validate (pm->policer_index_by_sw_if_index[dir], sw_if_index);
      pm->policer_index_by_sw_if_index[dir][sw_if_index] = policer_index;

      /* Pre-compute L2 overhead for this interface (used by L3 input path) */
      vec_validate (pm->l2_overhead_by_sw_if_index[dir], sw_if_index);
      pm->l2_overhead_by_sw_if_index[dir][sw_if_index] =
	policer_compute_l2_overhead (pm->vnet_main, sw_if_index, dir);
    }
  else
    {
      pm->policer_index_by_sw_if_index[dir][sw_if_index] = ~0;
    }

  /* Enable policer on both L2 feature bitmap and L3 feature arcs */
  if (dir == VLIB_RX)
    {
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_POLICER, apply);
      vnet_feature_enable_disable ("ip4-unicast", "policer-input", sw_if_index, apply, 0, 0);
      vnet_feature_enable_disable ("ip6-unicast", "policer-input", sw_if_index, apply, 0, 0);
    }
  else
    {
      l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_POLICER, apply);
      vnet_feature_enable_disable ("ip4-output", "policer-output", sw_if_index, apply, 0, 0);
      vnet_feature_enable_disable ("ip6-output", "policer-output", sw_if_index, apply, 0, 0);
    }
  return 0;
}
