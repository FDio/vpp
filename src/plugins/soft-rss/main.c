/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vppinfra/clib.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/error.h>
#include <soft-rss/soft_rss.h>
#include <vpp/app/version.h>

soft_rss_main_t soft_rss_main;

typedef union
{
  struct
  {
    u16 ethertype;
    union
    {
      ip4_header_t ip4;
      ip6_header_t ip6;
    };
  } __clib_packed;
  u8x16 as_u8x16;
} __clib_packed soft_rss_match_template_t;

static void
soft_rss_add_match (soft_rss_rt_data_t *rt, int protocol, u8 key_start,
		    u8 key_len)
{
  soft_rss_rt_match_t *m = rt->match + rt->n_match++;

  soft_rss_match_template_t match = {
      .ethertype = clib_host_to_net_u16(0x0800),
      .ip4 = {
          .ip_version_and_header_length = 0x45,
          .protocol = protocol >= 0 ? protocol : 0,
      },
  };

  soft_rss_match_template_t mask = {
      .ethertype = 0xffff,
      .ip4 = {
          .ip_version_and_header_length = 0xff,
          .protocol = protocol >= 0 ? 0xff : 0,
          .flags_and_fragment_offset = clib_host_to_net_u16(0x3fff),
      },
  };

  m->match = match.as_u8x16;
  m->mask = mask.as_u8x16;
  m->key_start = key_start;
  m->key_len = key_len;
}

clib_error_t *
soft_rss_config (vlib_main_t __clib_unused *vm,
		 const soft_rss_config_t *config, u32 hw_if_index)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = sm->vnet_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface_or_null (vnm, hw_if_index);
  soft_rss_rt_data_t *rt;
  u32 n_threads = 0;
  clib_thread_index_t ti;

  if (!hi)
    return clib_error_return (0, "invalid hardware interface index %u",
			      hw_if_index);

  vec_validate (sm->rt_by_sw_if_index, hi->sw_if_index);
  rt = sm->rt_by_sw_if_index[hi->sw_if_index];

  if (rt == 0)
    {
      rt = clib_mem_alloc (sizeof (*rt));
      sm->rt_by_sw_if_index[hi->sw_if_index] = rt;
    }

  *rt = (soft_rss_rt_data_t){
    .match_offset = 12 + config->l2_hdr_offset,
  };

  if (config->threads)
    {
      clib_bitmap_foreach (ti, config->threads)
	rt->reta[n_threads++] = ti;
    }
  else
    {
      for (ti = 0; ti < vlib_get_n_threads (); ti++)
	rt->reta[n_threads++] = ti;
    }

  if (count_set_bits (n_threads) != 1)
    {
      for (u32 i = n_threads; i < ARRAY_LEN (rt->reta); i++)
	rt->reta[i] = rt->reta[i - n_threads];
      rt->reta_mask = ARRAY_LEN (rt->reta) - 1;
    }
  else
    rt->reta_mask = n_threads - 1;

  soft_rss_add_match (rt, IP_PROTOCOL_TCP, 14, 12);
  soft_rss_add_match (rt, IP_PROTOCOL_UDP, 14, 12);
  soft_rss_add_match (rt, -1, 14, 8);

  rt->key = clib_toeplitz_hash_key_init (config->key, vec_len (config->key));

  return 0;
}

clib_error_t *
soft_rss_clear (vlib_main_t __clib_unused *vm, u32 hw_if_index)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = sm->vnet_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface_or_null (vnm, hw_if_index);
  soft_rss_rt_data_t *rt;

  if (!hi)
    return clib_error_return (0, "invalid hardware interface index %u",
			      hw_if_index);

  if (hi->sw_if_index >= vec_len (sm->rt_by_sw_if_index) ||
      (rt = sm->rt_by_sw_if_index[hi->sw_if_index]) == 0)
    return clib_error_return (0, "soft-rss not configured on interface %U",
			      format_vnet_sw_if_index_name, vnm,
			      hi->sw_if_index);

  if (rt->key)
    clib_toeplitz_hash_key_free (rt->key);

  clib_mem_free (rt);
  sm->rt_by_sw_if_index[hi->sw_if_index] = 0;

  return 0;
}

clib_error_t *
soft_rss_enable (vlib_main_t __clib_unused *vm, u32 hw_if_index)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = sm->vnet_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface_or_null (vnm, hw_if_index);
  soft_rss_rt_data_t *rt;
  int rv;

  if (!hi)
    return clib_error_return (0, "invalid hardware interface index %u",
			      hw_if_index);

  if (hi->sw_if_index >= vec_len (sm->rt_by_sw_if_index) ||
      (rt = sm->rt_by_sw_if_index[hi->sw_if_index]) == 0)
    return clib_error_return (0, "soft-rss not configured on interface %U",
			      format_vnet_sw_if_index_name, vnm,
			      hi->sw_if_index);

  if (rt->enabled)
    return clib_error_return (0, "soft-rss already enabled on interface %U",
			      format_vnet_sw_if_index_name, vnm,
			      hi->sw_if_index);

  rv = vnet_feature_enable_disable ("device-input", "soft-rss",
				    hi->sw_if_index, 1, 0, 0);
  if (rv)
    return clib_error_return (0, "soft-rss enable failed on interface %U: %d",
			      format_vnet_sw_if_index_name, vnm,
			      hi->sw_if_index, rv);

  rt->enabled = 1;

  return 0;
}

clib_error_t *
soft_rss_disable (vlib_main_t __clib_unused *vm, u32 hw_if_index)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = sm->vnet_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface_or_null (vnm, hw_if_index);
  soft_rss_rt_data_t *rt;
  int rv;

  if (!hi)
    return clib_error_return (0, "invalid hardware interface index %u",
			      hw_if_index);

  if (hi->sw_if_index >= vec_len (sm->rt_by_sw_if_index) ||
      (rt = sm->rt_by_sw_if_index[hi->sw_if_index]) == 0)
    return clib_error_return (0, "soft-rss not configured on interface %U",
			      format_vnet_sw_if_index_name, vnm,
			      hi->sw_if_index);

  if (!rt->enabled)
    return clib_error_return (0, "soft-rss already disabled on interface %U",
			      format_vnet_sw_if_index_name, vnm,
			      hi->sw_if_index);

  rv = vnet_feature_enable_disable ("device-input", "soft-rss",
				    hi->sw_if_index, 0, 0, 0);
  if (rv)
    return clib_error_return (0, "soft-rss disable failed on interface %U: %d",
			      format_vnet_sw_if_index_name, vnm,
			      hi->sw_if_index, rv);

  rt->enabled = 0;

  return 0;
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
  .arc_name = "device-input",
  .node_name = "soft-rss",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Software RSS feature arc template",
};
