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
#include <vppinfra/vec.h>
#include <soft-rss/soft_rss.h>
#include <vpp/app/version.h>

soft_rss_main_t soft_rss_main = {
  .frame_queue_index = CLIB_U32_MAX,
};

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
soft_rss_add_ip4_match (soft_rss_rt_data_t *rt, int protocol, u8 key_start,
			u8 key_len)
{
  soft_rss_rt_match_t *m = rt->match4 + rt->n_match4++;
  ASSERT (rt->n_match4 <= ARRAY_LEN (rt->match4));

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

static void
soft_rss_add_ip6_match (soft_rss_rt_data_t *rt, int protocol, u8 key_start,
			u8 key_len)
{
  soft_rss_rt_match_t *m = rt->match6 + rt->n_match6++;
  ASSERT (rt->n_match6 <= ARRAY_LEN (rt->match6));

  soft_rss_match_template_t match = {
    .ethertype = clib_host_to_net_u16(0x86dd),
    .ip6 = {
      .ip_version_traffic_class_and_flow_label =
        clib_host_to_net_u32(0x60000000),
      .protocol = protocol >= 0 ? protocol : 0,
    },
  };

  soft_rss_match_template_t mask = {
    .ethertype = 0xffff,
    .ip6 = {
      .ip_version_traffic_class_and_flow_label =
        clib_host_to_net_u32(0xF0000000),
      .protocol = protocol >= 0 ? 0xff : 0,
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
  vnet_main_t *vnm = vnet_get_main ();
  u8 ip4_src_off, ip4_dst_off, ip6_src_off, ip6_dst_off;
  vnet_hw_interface_t *hi = vnet_get_hw_interface_or_null (vnm, hw_if_index);
  soft_rss_rt_data_t *rt;
  u32 n_threads = 0;
  clib_thread_index_t ti, n_vlib_threads = vlib_get_n_threads ();
  soft_rss_type_t type4 = config->ipv4_type != SOFT_RSS_TYPE_NOT_SET ?
			    config->ipv4_type :
			    config->type;
  soft_rss_type_t type6 = config->ipv6_type != SOFT_RSS_TYPE_NOT_SET ?
			    config->ipv6_type :
			    config->type;

  if (type4 == SOFT_RSS_TYPE_NOT_SET || type6 == SOFT_RSS_TYPE_NOT_SET)
    return clib_error_return (0, "RSS type not set");

  if (type4 == SOFT_RSS_TYPE_DISABLED && type6 == SOFT_RSS_TYPE_DISABLED)
    return clib_error_return (0, "both IPv4 and IPv6 cannot be disabled");

  if (config->type >= SOFT_RSS_N_TYPES)
    return clib_error_return (0, "invalid rss type %u", config->type);

  if (!hi)
    return clib_error_return (0, "invalid hardware interface index %u",
			      hw_if_index);

  if (n_vlib_threads <= 1)
    return clib_error_return (0, "soft-rss requires more than one thread");
  if (n_vlib_threads > 256)
    return clib_error_return (0, "not supported: more than 256 vlib threads");

  if (sm->frame_queue_index == CLIB_U32_MAX)
    sm->frame_queue_index =
      vlib_frame_queue_main_init (soft_rss_handoff_node.index, 0);

  vec_validate (sm->rt_by_sw_if_index, hi->sw_if_index);
  rt = sm->rt_by_sw_if_index[hi->sw_if_index];

  if (rt && rt->key)
    {
      clib_toeplitz_hash_key_free (rt->key);
      rt->key = 0;
    }

  if (rt == 0)
    {
      rt = clib_mem_alloc (sizeof (*rt));
      sm->rt_by_sw_if_index[hi->sw_if_index] = rt;
    }

  *rt = (soft_rss_rt_data_t){
    .ipv4_type = type4,
    .ipv6_type = type6,
    .match_offset = 12 + config->l2_hdr_offset,
  };

  if (config->threads)
    {
      uword last_set = clib_bitmap_last_set (config->threads);
      if (last_set == ~0)
	return clib_error_return (0, "no threads selected for soft-rss");
      if (clib_bitmap_count_set_bits (config->threads) > ARRAY_LEN (rt->reta))
	return clib_error_return (0, "not supported: more than %u RSS threads selected",
				  ARRAY_LEN (rt->reta));
      if (last_set >= n_vlib_threads)
	return clib_error_return (0, "invalid thread index specified");
      clib_bitmap_foreach (ti, config->threads)
	{
	  if (ti > 255)
	    return clib_error_return (0, "thread index too large: %u", ti);
	  rt->reta[n_threads++] = ti;
	}
    }
  else
    {
      for (ti = config->with_main_thread ? 0 : 1; ti < n_vlib_threads; ti++)
	{
	  if (ti > 255)
	    return clib_error_return (0, "thread index too large: %u", ti);
	  if (n_threads >= ARRAY_LEN (rt->reta))
	    return clib_error_return (0, "not supported: more than %u RSS threads available",
				      ARRAY_LEN (rt->reta));
	  rt->reta[n_threads++] = ti;
	}
    }

  if (count_set_bits (n_threads) != 1)
    {
      /* n_threads is not power-of-2 */
      for (u32 i = n_threads; i < ARRAY_LEN (rt->reta); i++)
	rt->reta[i] = rt->reta[i - n_threads];
      rt->reta_mask = ARRAY_LEN (rt->reta) - 1;
    }
  else
    rt->reta_mask = n_threads - 1;

  ip4_src_off = STRUCT_OFFSET_OF (soft_rss_match_template_t, ip4.src_address);
  ip4_dst_off = STRUCT_OFFSET_OF (soft_rss_match_template_t, ip4.dst_address);
  ip6_src_off = STRUCT_OFFSET_OF (soft_rss_match_template_t, ip6.src_address);
  ip6_dst_off = STRUCT_OFFSET_OF (soft_rss_match_template_t, ip6.dst_address);

  if (type4 == SOFT_RSS_TYPE_SRC_IP)
    soft_rss_add_ip4_match (rt, -1, ip4_src_off, 4);
  if (type6 == SOFT_RSS_TYPE_SRC_IP)
    soft_rss_add_ip6_match (rt, -1, ip6_src_off, 16);

  if (type4 == SOFT_RSS_TYPE_DST_IP)
    soft_rss_add_ip4_match (rt, -1, ip4_dst_off, 4);
  if (type6 == SOFT_RSS_TYPE_DST_IP)
    soft_rss_add_ip6_match (rt, -1, ip6_dst_off, 16);

  if (type4 == SOFT_RSS_TYPE_4_TUPLE)
    soft_rss_add_ip4_match (rt, IP_PROTOCOL_TCP, ip4_src_off, 12);
  if (type6 == SOFT_RSS_TYPE_4_TUPLE)
    soft_rss_add_ip6_match (rt, IP_PROTOCOL_TCP, ip6_src_off, 36);
  if (type4 == SOFT_RSS_TYPE_4_TUPLE)
    soft_rss_add_ip4_match (rt, IP_PROTOCOL_UDP, ip4_src_off, 12);
  if (type6 == SOFT_RSS_TYPE_4_TUPLE)
    soft_rss_add_ip6_match (rt, IP_PROTOCOL_UDP, ip6_src_off, 36);

  if (type4 == SOFT_RSS_TYPE_4_TUPLE || type4 == SOFT_RSS_TYPE_2_TUPLE)
    soft_rss_add_ip4_match (rt, -1, ip4_src_off, 8);
  if (type6 == SOFT_RSS_TYPE_4_TUPLE || type6 == SOFT_RSS_TYPE_2_TUPLE)
    soft_rss_add_ip6_match (rt, -1, ip6_src_off, 32);

  rt->key = clib_toeplitz_hash_key_init (config->key, vec_len (config->key));

  return 0;
}

clib_error_t *
soft_rss_clear (vlib_main_t __clib_unused *vm, u32 hw_if_index)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = vnet_get_main ();
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

static clib_error_t *
soft_rss_enable_disable (u32 hw_if_index, u8 is_enable)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface_or_null (vnm, hw_if_index);
  soft_rss_rt_data_t *rt;
  char *action = is_enable ? "enable" : "disable";
  int rv;

  if (!hi)
    return clib_error_return (0, "invalid hardware interface index %u",
			      hw_if_index);

  if (hi->sw_if_index >= vec_len (sm->rt_by_sw_if_index) ||
      (rt = sm->rt_by_sw_if_index[hi->sw_if_index]) == 0)
    return clib_error_return (0, "soft-rss not configured on interface %U",
			      format_vnet_sw_if_index_name, vnm,
			      hi->sw_if_index);

  if (!!rt->enabled == !!is_enable)
    return clib_error_return (0, "soft-rss already %sd on interface %U",
			      action, format_vnet_sw_if_index_name, vnm,
			      hi->sw_if_index);

  rv = vnet_feature_enable_disable ("device-input", "soft-rss",
				    hi->sw_if_index, is_enable, 0, 0);
  if (rv)
    return clib_error_return (0, "soft-rss %s failed on interface %U: %d",
			      action, format_vnet_sw_if_index_name, vnm,
			      hi->sw_if_index, rv);

  rv = vnet_feature_enable_disable ("port-rx-eth", "soft-rss", hi->sw_if_index,
				    is_enable, 0, 0);
  if (rv)
    {
      vnet_feature_enable_disable ("device-input", "soft-rss", hi->sw_if_index,
				   !is_enable, 0, 0);
      return clib_error_return (0, "soft-rss %s failed on interface %U: %d",
				action, format_vnet_sw_if_index_name, vnm,
				hi->sw_if_index, rv);
    }

  rt->enabled = is_enable;

  return 0;
}

clib_error_t *
soft_rss_enable (vlib_main_t __clib_unused *vm, u32 hw_if_index)
{
  return soft_rss_enable_disable (hw_if_index, 1);
}

clib_error_t *
soft_rss_disable (vlib_main_t __clib_unused *vm, u32 hw_if_index)
{
  return soft_rss_enable_disable (hw_if_index, 0);
}

VNET_FEATURE_INIT (soft_rss_feature, static) = {
  .arc_name = "device-input",
  .node_name = "soft-rss",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (soft_rss_feature2, static) = {
  .arc_name = "port-rx-eth",
  .node_name = "soft-rss",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Software RSS feature arc template",
};
