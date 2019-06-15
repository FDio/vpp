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

#include <igmp/igmp_query.h>
#include <igmp/igmp_pkt.h>

static f64
igmp_get_random_resp_delay (const igmp_header_t * header)
{
  u32 seed;

  seed = vlib_time_now (vlib_get_main ());

  return ((random_f64 (&seed) * igmp_header_get_max_resp_time (header)));

}

static ip46_address_t *
igmp_query_mk_source_list (const igmp_membership_query_v3_t * q)
{
  ip46_address_t *srcs = NULL;
  const ip4_address_t *s;
  u16 ii, n;

  /*
   * we validated this packet when we accepted it in the DP, so
   * this number is safe to use
   */
  n = clib_net_to_host_u16 (q->n_src_addresses);

  if (0 == n)
    return (NULL);

  vec_validate (srcs, n - 1);
  s = q->src_addresses;

  for (ii = 0; ii < n; ii++)
    {
      srcs[ii].ip4 = *s;
      s++;
    }

  return (srcs);
}

static void
igmp_send_group_report_v3 (u32 obj, void *data)
{
  igmp_pkt_build_report_t br;
  igmp_config_t *config;
  ip46_address_t *srcs;
  igmp_group_t *group;
  igmp_main_t *im;

  im = &igmp_main;
  srcs = data;
  group = pool_elt_at_index (im->groups, obj);
  config = pool_elt_at_index (im->configs, group->config);

  igmp_pkt_build_report_init (&br, config->sw_if_index);
  ASSERT (group->timers[IGMP_GROUP_TIMER_QUERY_REPLY] !=
	  IGMP_TIMER_ID_INVALID);

  IGMP_DBG ("send-group-report: %U",
	    format_vnet_sw_if_index_name,
	    vnet_get_main (), config->sw_if_index);

  if (NULL == srcs)
    {
      /*
       * there were no sources specified, so this is a group-specific query.
       * We should respond with all our sources
       */
      igmp_pkt_report_v3_add_group (&br, group,
				    IGMP_MEMBERSHIP_GROUP_mode_is_include);
    }
  else
    {
      /*
       * the sources stored in the timer object are the combined set of sources
       * to be required. We need to respond only to those queried, not our full set.
       */
      ip46_address_t *intersect;

      intersect = igmp_group_new_intersect_present (group,
						    IGMP_FILTER_MODE_INCLUDE,
						    srcs);

      if (vec_len (intersect))
	{
	  igmp_pkt_report_v3_add_report (&br,
					 group->key,
					 intersect,
					 IGMP_MEMBERSHIP_GROUP_mode_is_include);
	  vec_free (intersect);
	}
    }

  igmp_pkt_report_v3_send (&br);

  igmp_timer_retire (&group->timers[IGMP_GROUP_TIMER_QUERY_REPLY]);
  vec_free (srcs);
}

static igmp_membership_group_v3_type_t
igmp_filter_mode_to_report_type (igmp_filter_mode_t mode)
{
  switch (mode)
    {
    case IGMP_FILTER_MODE_INCLUDE:
      return (IGMP_MEMBERSHIP_GROUP_mode_is_include);
    case IGMP_FILTER_MODE_EXCLUDE:
      return (IGMP_MEMBERSHIP_GROUP_mode_is_exclude);
    }

  return (IGMP_MEMBERSHIP_GROUP_mode_is_include);
}

/**
 * Send igmp membership general report.
 */
static void
igmp_send_general_report_v3 (u32 obj, void *data)
{
  igmp_pkt_build_report_t br;
  igmp_config_t *config;
  igmp_group_t *group;
  igmp_main_t *im;

  im = &igmp_main;
  config = pool_elt_at_index (im->configs, obj);

  ASSERT (config->timers[IGMP_CONFIG_TIMER_GENERAL_REPORT] !=
	  IGMP_TIMER_ID_INVALID);

  igmp_timer_retire (&config->timers[IGMP_CONFIG_TIMER_GENERAL_REPORT]);

  IGMP_DBG ("send-general-report: %U",
	    format_vnet_sw_if_index_name,
	    vnet_get_main (), config->sw_if_index);

  igmp_pkt_build_report_init (&br, config->sw_if_index);

  /* *INDENT-OFF* */
  FOR_EACH_GROUP (group, config,
    ({
      igmp_pkt_report_v3_add_group
        (&br, group,
         igmp_filter_mode_to_report_type(group->router_filter_mode));
    }));
  /* *INDENT-ON* */

  igmp_pkt_report_v3_send (&br);
}

/**
 * Called from the main thread on reception of a Query message
 */
void
igmp_handle_query (const igmp_query_args_t * args)
{
  igmp_config_t *config;

  config = igmp_config_lookup (args->sw_if_index);

  if (!config)
    /*
     * no IGMP config on the interface. quit
     */
    return;

  if (IGMP_MODE_ROUTER == config->mode)
    {
      ASSERT (0);
      // code here for querier election */
    }

  IGMP_DBG ("query-rx: %U", format_vnet_sw_if_index_name,
	    vnet_get_main (), args->sw_if_index);


  /*
     Section 5.2
     "When a system receives a Query, it does not respond immediately.
     Instead, it delays its response by a random amount of time, bounded
     by the Max Resp Time value derived from the Max Resp Code in the
     received Query message.  A system may receive a variety of Queries on
     different interfaces and of different kinds (e.g., General Queries,
     Group-Specific Queries, and Group-and-Source-Specific Queries), each
     of which may require its own delayed response.
   */
  if (igmp_membership_query_v3_is_general (args->query))
    {
      IGMP_DBG ("...general-query-rx: %U", format_vnet_sw_if_index_name,
		vnet_get_main (), args->sw_if_index);

      /*
       * A general query has no info that needs saving from the response
       */
      if (IGMP_TIMER_ID_INVALID ==
	  config->timers[IGMP_CONFIG_TIMER_GENERAL_REPORT])
	{
	  f64 delay = igmp_get_random_resp_delay (&args->query[0].header);

	  IGMP_DBG ("...general-query-rx: %U schedule for %f",
		    format_vnet_sw_if_index_name, vnet_get_main (),
		    args->sw_if_index, delay);

	  /*
	   * no currently running timer, schedule a new one
	   */
	  config->timers[IGMP_CONFIG_TIMER_GENERAL_REPORT] =
	    igmp_timer_schedule (delay,
				 igmp_config_index (config),
				 igmp_send_general_report_v3, NULL);
	}
      /*
       * else
       *  don't reschedule timers, we'll reply soon enough..
       */
    }
  else
    {
      /*
       * G or SG query. we'll need to save the sources quered
       */
      igmp_key_t key = {
	.ip4 = args->query[0].group_address,
      };
      ip46_address_t *srcs;
      igmp_timer_id_t tid;
      igmp_group_t *group;

      group = igmp_group_lookup (config, &key);

      /*
       * If there is no group config, no worries, we can ignore this
       * query. If the group state does come soon, we'll send a
       * state-change report at that time.
       */
      if (!group)
	return;

      srcs = igmp_query_mk_source_list (args->query);
      tid = group->timers[IGMP_GROUP_TIMER_QUERY_REPLY];

      IGMP_DBG ("...group-query-rx: %U for (%U, %U)",
		format_vnet_sw_if_index_name,
		vnet_get_main (), args->sw_if_index,
		format_igmp_src_addr_list, srcs, format_igmp_key, &key);


      if (IGMP_TIMER_ID_INVALID != tid)
	{
	  /*
	   * There is a timer already running, merge the sources list
	   */
	  ip46_address_t *current, *s;

	  current = igmp_timer_get_data (tid);

	  vec_foreach (s, srcs)
	  {
	    if (~0 == vec_search_with_function (current, s,
						ip46_address_is_equal))
	      {
		vec_add1 (current, *s);
	      }
	  }

	  igmp_timer_set_data (tid, current);
	}
      else
	{
	  /*
	   * schedule a new G-specific query
	   */
	  f64 delay = igmp_get_random_resp_delay (&args->query[0].header);

	  IGMP_DBG ("...group-query-rx: schedule:%f", delay);

	  group->timers[IGMP_GROUP_TIMER_QUERY_REPLY] =
	    igmp_timer_schedule (delay,
				 igmp_group_index (group),
				 igmp_send_group_report_v3, srcs);
	}
    }
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
