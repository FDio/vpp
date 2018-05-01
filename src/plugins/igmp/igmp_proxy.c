/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/mfib/mfib_entry.h>
#include <vnet/mfib/mfib_table.h>

#include <igmp/igmp_proxy.h>
#include <igmp/igmp.h>
#include <igmp/igmp_pkt.h>

void
igmp_proxy_device_mfib_path_add_del (igmp_group_t * group, u8 add)
{
  igmp_config_t *config;
  u32 mfib_index;

  config = igmp_config_get (group->config);
  mfib_index =
    mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
					  config->sw_if_index);

  /* *INDENT-OFF* */
  mfib_prefix_t mpfx_group_addr = {
      .fp_proto = FIB_PROTOCOL_IP4,
      .fp_len = 32,
      .fp_grp_addr = {
	.ip4 = (*group->key).ip4,
      },
    };
  fib_route_path_t via_itf_path =
    {
      .frp_proto = fib_proto_to_dpo (FIB_PROTOCOL_IP4),
      .frp_addr = zero_addr,
      .frp_sw_if_index = config->sw_if_index,
      .frp_fib_index = 0,
      .frp_weight = 1,
      .frp_mitf_flags = MFIB_ITF_FLAG_FORWARD,
    };
  /* *INDENT-ON* */

  if (add)
    mfib_table_entry_path_update (mfib_index, &mpfx_group_addr,
				  MFIB_SOURCE_IGMP, &via_itf_path);
  else
    mfib_table_entry_path_remove (mfib_index, &mpfx_group_addr,
				  MFIB_SOURCE_IGMP, &via_itf_path);
}

igmp_proxy_device_t *
igmp_proxy_device_lookup (u32 vrf_id)
{
  igmp_main_t *im = &igmp_main;

  if (vec_len (im->igmp_proxy_device_by_vrf_id) > vrf_id)
    {
      u32 index;
      index = im->igmp_proxy_device_by_vrf_id[vrf_id];
      if (index != ~0)
	return (vec_elt_at_index (im->proxy_devices, index));
    }
  return NULL;
}

int
igmp_proxy_device_add_del (u32 vrf_id, u32 sw_if_index, u8 add)
{
  igmp_main_t *im = &igmp_main;
  igmp_proxy_device_t *proxy_device;
  igmp_config_t *config;
  u32 mfib_index;

  /* check VRF id */
  mfib_index =
    mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);
  if (mfib_index == ~0)
    return VNET_API_ERROR_INVALID_INTERFACE;
  if (vrf_id != mfib_table_get (mfib_index, FIB_PROTOCOL_IP4)->mft_table_id)
    return VNET_API_ERROR_INVALID_INTERFACE;

  /* check IGMP configuration */
  config = igmp_config_lookup (sw_if_index);
  if (!config)
    return VNET_API_ERROR_INVALID_INTERFACE;
  if (config->mode != IGMP_MODE_HOST)
    return VNET_API_ERROR_INVALID_INTERFACE;

  proxy_device = igmp_proxy_device_lookup (vrf_id);
  if (!proxy_device && add)
    {
      vec_validate_init_empty (im->igmp_proxy_device_by_vrf_id, vrf_id, ~0);
      pool_get (im->proxy_devices, proxy_device);
      im->igmp_proxy_device_by_vrf_id[vrf_id] =
	proxy_device - im->proxy_devices;
      clib_memset (proxy_device, 0, sizeof (igmp_proxy_device_t));
      proxy_device->vrf_id = vrf_id;
      proxy_device->upstream_if = sw_if_index;
      config->proxy_device_id = vrf_id;
      /* lock mfib table */
      mfib_table_lock (mfib_index, FIB_PROTOCOL_IP4, MFIB_SOURCE_IGMP);
    }
  else if (proxy_device && !add)
    {
      while (vec_len (proxy_device->downstream_ifs) > 0)
	{
	  igmp_proxy_device_add_del_interface (vrf_id,
					       proxy_device->downstream_ifs
					       [0], 0);
	}
      vec_free (proxy_device->downstream_ifs);
      proxy_device->downstream_ifs = NULL;
      im->igmp_proxy_device_by_vrf_id[vrf_id] = ~0;
      pool_put (im->proxy_devices, proxy_device);
      config->proxy_device_id = ~0;
      /* clear proxy database */
      igmp_clear_config (config);
      /* unlock mfib table */
      mfib_table_unlock (mfib_index, FIB_PROTOCOL_IP4, MFIB_SOURCE_IGMP);
    }
  else
    return -1;

  return 0;
}

int
igmp_proxy_device_add_del_interface (u32 vrf_id, u32 sw_if_index, u8 add)
{
  igmp_proxy_device_t *proxy_device;
  u32 index;
  u32 mfib_index;

  proxy_device = igmp_proxy_device_lookup (vrf_id);
  if (!proxy_device)
    return -1;

  /* check VRF id */
  mfib_index =
    mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);
  if (mfib_index == ~0)
    return VNET_API_ERROR_INVALID_INTERFACE;
  if (vrf_id != mfib_table_get (mfib_index, FIB_PROTOCOL_IP4)->mft_table_id)
    return VNET_API_ERROR_INVALID_INTERFACE;

  /* check IGMP configuration */
  igmp_config_t *config;
  config = igmp_config_lookup (sw_if_index);
  if (!config)
    return VNET_API_ERROR_INVALID_INTERFACE;
  if (config->mode != IGMP_MODE_ROUTER)
    return VNET_API_ERROR_INVALID_INTERFACE;

  if (add)
    {
      if (proxy_device->downstream_ifs)
	{
	  index = vec_search (proxy_device->downstream_ifs, sw_if_index);
	  if (index != ~0)
	    return -1;
	}
      vec_add1 (proxy_device->downstream_ifs, sw_if_index);
      config->proxy_device_id = vrf_id;
    }
  else
    {
      if (!proxy_device->downstream_ifs)
	return -2;
      index = vec_search (proxy_device->downstream_ifs, sw_if_index);
      if (index == ~0)
	return -3;
      /* remove (S,G)s belonging to this interface from proxy database */
      igmp_proxy_device_merge_config (config, /* block */ 1);
      vec_del1 (proxy_device->downstream_ifs, index);
      config->proxy_device_id = ~0;
    }

  return 0;
}

void
igmp_proxy_device_block_src (igmp_config_t * config, igmp_group_t * group,
			     igmp_src_t * src)
{
  igmp_proxy_device_t *proxy_device;
  igmp_config_t *proxy_config;
  igmp_group_t *proxy_group;
  igmp_src_t *proxy_src;
  u8 *ref;

  proxy_device = igmp_proxy_device_lookup (config->proxy_device_id);
  if (!proxy_device)
    return;

  proxy_config = igmp_config_lookup (proxy_device->upstream_if);
  ASSERT (proxy_config);

  proxy_group = igmp_group_lookup (proxy_config, group->key);
  if (proxy_group == NULL)
    return;

  proxy_src = igmp_src_lookup (proxy_group, src->key);
  if (proxy_src == NULL)
    return;

  if (vec_len (proxy_src->referance_by_config_index) <= group->config)
    {
      IGMP_DBG ("proxy block src: invalid config %u", group->config);
      return;
    }
  proxy_src->referance_by_config_index[group->config] = 0;
  vec_foreach (ref, proxy_src->referance_by_config_index)
  {
    if ((*ref) > 0)
      return;
  }

  /* build "Block Old Sources" report */
  igmp_pkt_build_report_t br;
  ip46_address_t *srcaddrs = NULL;

  igmp_pkt_build_report_init (&br, proxy_config->sw_if_index);
  vec_add1 (srcaddrs, *proxy_src->key);
  igmp_pkt_report_v3_add_report (&br, proxy_group->key, srcaddrs,
				 IGMP_MEMBERSHIP_GROUP_block_old_sources);
  igmp_pkt_report_v3_send (&br);


  igmp_group_src_remove (proxy_group, proxy_src);
  igmp_src_free (proxy_src);

  if (igmp_group_n_srcs (proxy_group, IGMP_FILTER_MODE_INCLUDE) == 0)
    {
      igmp_proxy_device_mfib_path_add_del (proxy_group, 0);
      igmp_proxy_device_mfib_path_add_del (group, 0);
      igmp_group_clear (proxy_group);
    }
}

always_inline void
igmp_proxy_device_merge_src (igmp_group_t * proxy_group, igmp_src_t * src,
			     ip46_address_t ** srcaddrs, u8 block)
{
  igmp_src_t *proxy_src;
  u32 d_config;

  proxy_src = igmp_src_lookup (proxy_group, src->key);

  if (proxy_src == NULL)
    {
      if (block)
	return;
      /* store downstream config index */
      d_config = igmp_group_get (src->group)->config;

      proxy_src =
	igmp_src_alloc (igmp_group_index (proxy_group), src->key,
			IGMP_MODE_HOST);

      hash_set_mem (proxy_group->igmp_src_by_key
		    [proxy_group->router_filter_mode], proxy_src->key,
		    igmp_src_index (proxy_src));

      vec_validate_init_empty (proxy_src->referance_by_config_index, d_config,
			       0);
      proxy_src->referance_by_config_index[d_config] = 1;
      vec_add1 (*srcaddrs, *proxy_src->key);
    }
  else
    {
      if (block)
	{
	  d_config = igmp_group_get (src->group)->config;
	  if (vec_len (proxy_src->referance_by_config_index) <= d_config)
	    {
	      IGMP_DBG ("proxy block src: invalid config %u", d_config);
	      return;
	    }
	  proxy_src->referance_by_config_index[d_config] = 0;
	  u8 *ref;
	  vec_foreach (ref, proxy_src->referance_by_config_index)
	  {
	    if ((*ref) > 0)
	      return;
	  }

	  vec_add1 (*srcaddrs, *proxy_src->key);

	  igmp_group_src_remove (proxy_group, proxy_src);
	  igmp_src_free (proxy_src);

	  if (igmp_group_n_srcs (proxy_group, IGMP_FILTER_MODE_INCLUDE) == 0)
	    {
	      igmp_proxy_device_mfib_path_add_del (proxy_group, 0);
	      igmp_group_clear (proxy_group);
	    }
	  return;
	}
      d_config = igmp_group_get (src->group)->config;
      vec_validate (proxy_src->referance_by_config_index, d_config);
      proxy_src->referance_by_config_index[d_config] = 1;
      return;
    }
}

always_inline igmp_group_t *
igmp_proxy_device_merge_group (igmp_proxy_device_t * proxy_device,
			       igmp_group_t * group,
			       ip46_address_t ** srcaddrs, u8 block)
{
  igmp_config_t *proxy_config;
  igmp_group_t *proxy_group;
  igmp_src_t *src;

  proxy_config = igmp_config_lookup (proxy_device->upstream_if);
  ASSERT (proxy_config);

  proxy_group = igmp_group_lookup (proxy_config, group->key);
  if (!proxy_group)
    {
      if (block)
	return NULL;
      u32 tmp = igmp_group_index (group);
      proxy_group =
	igmp_group_alloc (proxy_config, group->key,
			  group->router_filter_mode);
      igmp_proxy_device_mfib_path_add_del (proxy_group, 1);
      group = igmp_group_get (tmp);
    }
  if (block)
    {
      igmp_proxy_device_mfib_path_add_del (group, 0);
    }

  /* *INDENT-OFF* */
  FOR_EACH_SRC (src, group, group->router_filter_mode,
    ({
      igmp_proxy_device_merge_src (proxy_group, src, srcaddrs, block);
    }));
  /* *INDENT-ON* */
  return proxy_group;
}

void
igmp_proxy_device_merge_config (igmp_config_t * config, u8 block)
{
  igmp_proxy_device_t *proxy_device;
  igmp_group_t *group;
  igmp_group_t *proxy_group;
  ip46_address_t *srcaddrs = NULL;
  igmp_pkt_build_report_t br;

  proxy_device = igmp_proxy_device_lookup (config->proxy_device_id);
  if (!proxy_device)
    return;

  igmp_pkt_build_report_init (&br, proxy_device->upstream_if);

  /* *INDENT-OFF* */
  FOR_EACH_GROUP(group, config,
    ({
      proxy_group = igmp_proxy_device_merge_group (proxy_device, group, &srcaddrs, block);

      if ((vec_len(srcaddrs) > 0) && proxy_group)
	{
	  igmp_pkt_report_v3_add_report (&br, proxy_group->key, srcaddrs,
					 block ? IGMP_MEMBERSHIP_GROUP_block_old_sources :
					 IGMP_MEMBERSHIP_GROUP_allow_new_sources);
	}
      vec_free (srcaddrs);
    }));
  /* *INDENT-ON* */

  igmp_pkt_report_v3_send (&br);

}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
