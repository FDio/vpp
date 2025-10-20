/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vnet/interface.h>
#include <vnet/plugin/plugin.h>
#include <vnet/api_errno.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>
#include <soft-rss/soft_rss.h>
#include <vpp/app/version.h>

soft_rss_main_t soft_rss_main;

__clib_export clib_error_t *
soft_rss_config (vlib_main_t __clib_unused *vm,
		 const soft_rss_config_t *config, u32 hw_if_index)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = sm->vnet_main;

  if (config == 0)
    return clib_error_return (0, "config is required");

  switch (config->hash_type)
    {
    case SOFT_RSS_HASH_UNKNOWN:
    case SOFT_RSS_HASH_CRC32:
    case SOFT_RSS_HASH_TOEPLITZ:
      break;
    default:
      return clib_error_return (0, "invalid hash type %u", config->hash_type);
    }

  if (pool_is_free_index (vnm->interface_main.hw_interfaces, hw_if_index))
    return clib_error_return (0, "invalid hardware interface index %u",
			      hw_if_index);

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  if (hi->sw_if_index == ~0)
    return clib_error_return (0, "hardware interface %u has no software index",
			      hw_if_index);

  vec_validate (sm->rt_by_sw_if_index, hi->sw_if_index);
  soft_rss_rt_data_t *rt = sm->rt_by_sw_if_index[hi->sw_if_index];

  if (rt == 0)
    {
      rt = clib_mem_alloc (sizeof (*rt));
      if (rt == 0)
	return clib_error_return (0, "allocation failed");
      clib_memset (rt, 0, sizeof (*rt));
      sm->rt_by_sw_if_index[hi->sw_if_index] = rt;
    }

  rt->hash_type = config->hash_type;

  return 0;
}

__clib_export clib_error_t *
soft_rss_clear (vlib_main_t __clib_unused *vm, u32 hw_if_index)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = sm->vnet_main;

  if (pool_is_free_index (vnm->interface_main.hw_interfaces, hw_if_index))
    return clib_error_return (0, "invalid hardware interface index %u",
			      hw_if_index);

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  if (hi->sw_if_index == ~0)
    return clib_error_return (0, "hardware interface %u has no software index",
			      hw_if_index);

  if (hi->sw_if_index < vec_len (sm->rt_by_sw_if_index))
    {
      soft_rss_rt_data_t *rt = sm->rt_by_sw_if_index[hi->sw_if_index];
      if (rt)
	{
	  clib_mem_free (rt);
	  sm->rt_by_sw_if_index[hi->sw_if_index] = 0;
	}
    }

  return 0;
}

__clib_export clib_error_t *
soft_rss_enable (vlib_main_t __clib_unused *vm, u32 hw_if_index)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = sm->vnet_main;

  if (pool_is_free_index (vnm->interface_main.hw_interfaces, hw_if_index))
    return clib_error_return (0, "invalid hardware interface index %u",
			      hw_if_index);

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  if (hi->sw_if_index == ~0)
    return clib_error_return (0, "hardware interface %u has no software index",
			      hw_if_index);

  int rv = soft_rss_enable_disable (hi->sw_if_index, 1);
  if (rv)
    return clib_error_return (0, "soft-rss enable failed (%d)", rv);

  return 0;
}

__clib_export clib_error_t *
soft_rss_disable (vlib_main_t __clib_unused *vm, u32 hw_if_index)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = sm->vnet_main;

  if (pool_is_free_index (vnm->interface_main.hw_interfaces, hw_if_index))
    return clib_error_return (0, "invalid hardware interface index %u",
			      hw_if_index);

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  if (hi->sw_if_index == ~0)
    return clib_error_return (0, "hardware interface %u has no software index",
			      hw_if_index);

  int rv = soft_rss_enable_disable (hi->sw_if_index, 0);
  if (rv)
    return clib_error_return (0, "soft-rss disable failed (%d)", rv);

  return 0;
}

__clib_export int
soft_rss_enable_disable (u32 sw_if_index, int enable_disable)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = sm->vnet_main;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  return vnet_feature_enable_disable ("ethernet-input", "soft-rss",
				      sw_if_index, enable_disable, 0, 0);
}

static clib_error_t *
soft_rss_init (vlib_main_t *vm)
{
  soft_rss_main_t *sm = &soft_rss_main;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (soft_rss_init);

VNET_FEATURE_INIT (soft_rss_feature, static) = {
  .arc_name = "ethernet-input",
  .node_name = "soft-rss",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Software RSS feature arc template",
  .default_disabled = 1,
};
