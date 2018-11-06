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

#include <igmp/igmp_report.h>
#include <igmp/igmp_pkt.h>

static ip46_address_t *
igmp_group_mk_source_list (const igmp_membership_group_v3_t * r)
{
  ip46_address_t *srcs = NULL;
  const ip4_address_t *s;
  u16 ii, n;

  /*
   * we validated this packet when we accepted it in the DP, so
   * this number is safe to use
   */
  n = clib_net_to_host_u16 (r->n_src_addresses);

  if (0 == n)
    {
      /* a (*,G) join has no source address specified */
      vec_validate (srcs, 0);
      srcs[0].ip4.as_u32 = 0;
    }
  else
    {
      vec_validate (srcs, n - 1);
      s = r->src_addresses;

      for (ii = 0; ii < n; ii++)
	{
	  srcs[ii].ip4 = *s;
	  s++;
	}
    }

  return (srcs);
}

static void
igmp_handle_group_exclude (igmp_config_t * config,
			   const igmp_membership_group_v3_t * igmp_group)
{
  ip46_address_t key = {
    .ip4 = igmp_group->group_address,
  };
  u16 n;

  /*
   * treat an exclude all sources as a *,G join
   */
  n = clib_net_to_host_u16 (igmp_group->n_src_addresses);

  if (0 == n)
    {
      ip46_address_t *src, *srcs;
      igmp_group_t *group;

      group = igmp_group_lookup (config, &key);
      srcs = igmp_group_mk_source_list (igmp_group);

      IGMP_DBG (" ..group-update: %U (*, %U)",
		format_vnet_sw_if_index_name,
		vnet_get_main (), config->sw_if_index, format_igmp_key, &key);

      if (NULL == group)
	{
	  group = igmp_group_alloc (config, &key, IGMP_FILTER_MODE_INCLUDE);
	}
      vec_foreach (src, srcs)
      {
	igmp_group_src_update (group, src, IGMP_MODE_ROUTER);
      }

      vec_free (srcs);
    }
  else
    {
      IGMP_DBG (" ..group-update: %U (*, %U) source exclude ignored",
		format_vnet_sw_if_index_name,
		vnet_get_main (), config->sw_if_index, format_igmp_key, &key);
    }
}

static void
igmp_handle_group_block (igmp_config_t * config,
			 const igmp_membership_group_v3_t * igmp_group)
{
  ip46_address_t *s, *srcs;
  igmp_pkt_build_query_t bq;
  igmp_group_t *group;
  ip46_address_t key = {
    .ip4 = igmp_group->group_address,
  };

  srcs = igmp_group_mk_source_list (igmp_group);
  group = igmp_group_lookup (config, &key);

  IGMP_DBG (" ..group-block: %U (%U, %U)",
	    format_vnet_sw_if_index_name,
	    vnet_get_main (), config->sw_if_index,
	    format_igmp_key, &key, format_igmp_src_addr_list, srcs);

  if (group)
    {
      igmp_src_t *src;
      /*
       * send a group+source specific query
       */
      igmp_pkt_build_query_init (&bq, config->sw_if_index);
      igmp_pkt_query_v3_add_group (&bq, group, srcs);
      igmp_pkt_query_v3_send (&bq);

      /*
       * for each source left/blocked drop the source expire timer to the leave
       * latency timer
       */
      vec_foreach (s, srcs)
      {
	src = igmp_src_lookup (group, s);
	if (NULL != src)
	  igmp_src_blocked (src);
      }
    }
  /*
   * a block/leave from a group for which we have no state
   */

  vec_free (srcs);
}

static void
igmp_handle_group_update (igmp_config_t * config,
			  const igmp_membership_group_v3_t * igmp_group)
{
  ip46_address_t *src, *srcs;
  igmp_group_t *group;
  ip46_address_t key = {
    .ip4 = igmp_group->group_address,
  };

  /*
   * treat a TO_INC({}) as a (*,G) leave
   */
  if (0 == clib_net_to_host_u16 (igmp_group->n_src_addresses))
    {
      return (igmp_handle_group_block (config, igmp_group));
    }

  srcs = igmp_group_mk_source_list (igmp_group);
  group = igmp_group_lookup (config, &key);

  IGMP_DBG (" ..group-update: %U (%U, %U)",
	    format_vnet_sw_if_index_name,
	    vnet_get_main (), config->sw_if_index,
	    format_igmp_key, &key, format_igmp_src_addr_list, srcs);

  if (NULL == group)
    {
      group = igmp_group_alloc (config, &key, IGMP_FILTER_MODE_INCLUDE);
    }

  /* create or update all sources */
  vec_foreach (src, srcs)
  {
    igmp_group_src_update (group, src, IGMP_MODE_ROUTER);
  }

  vec_free (srcs);
}

static void
igmp_handle_group (igmp_config_t * config,
		   const igmp_membership_group_v3_t * igmp_group)
{
  IGMP_DBG ("rx-group-report: %U",
	    format_vnet_sw_if_index_name,
	    vnet_get_main (), config->sw_if_index);

  switch (igmp_group->type)
    {
    case IGMP_MEMBERSHIP_GROUP_mode_is_include:
    case IGMP_MEMBERSHIP_GROUP_change_to_include:
    case IGMP_MEMBERSHIP_GROUP_allow_new_sources:
      igmp_handle_group_update (config, igmp_group);
      break;
    case IGMP_MEMBERSHIP_GROUP_block_old_sources:
      igmp_handle_group_block (config, igmp_group);
      break;
    case IGMP_MEMBERSHIP_GROUP_mode_is_exclude:
    case IGMP_MEMBERSHIP_GROUP_change_to_exclude:
      igmp_handle_group_exclude (config, igmp_group);
      break;
      /*
       * all other types ignored
       */
    }
}

void
igmp_handle_report (const igmp_report_args_t * args)
{
  const igmp_membership_group_v3_t *igmp_group;
  igmp_config_t *config;
  u16 n_groups, ii;

  config = igmp_config_lookup (args->sw_if_index);

  if (!config)
    /*
     * no IGMP config on the interface. quit
     */
    return;

  if (IGMP_MODE_HOST == config->mode)
    {
      /*
       * Hosts need not listen to the reports of other hosts.
       * we're done here
       */
      return;
    }

  /*
   * we validated this packet when we accepted it in the DP, so
   * this number is safe to use
   */
  n_groups = clib_net_to_host_u16 (args->report[0].n_groups);
  igmp_group = args->report[0].groups;

  for (ii = 0; ii < n_groups; ii++)
    {
      igmp_handle_group (config, igmp_group);

      igmp_group = group_cptr (igmp_group,
			       igmp_membership_group_v3_length (igmp_group));
    }

  igmp_proxy_device_merge_config (config, 0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
