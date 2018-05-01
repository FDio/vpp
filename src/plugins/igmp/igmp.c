/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip.h>
#include <vnet/mfib/mfib_entry.h>
#include <vlib/unix/unix.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>

#include <igmp/igmp.h>
#include <igmp/igmp_format.h>
#include <igmp/igmp_pkt.h>

#include <limits.h>
#include <float.h>

igmp_main_t igmp_main;

/* *INDENT-OFF* */
/* General Query address */
const static mfib_prefix_t mpfx_general_query = {
  .fp_proto = FIB_PROTOCOL_IP4,
  .fp_len = 32,
  .fp_grp_addr = {
    .ip4 = {
      .as_u32 = IGMP_GENERAL_QUERY_ADDRESS,
    },
  },
};

/* Report address */
const static mfib_prefix_t mpfx_report = {
  .fp_proto = FIB_PROTOCOL_IP4,
  .fp_len = 32,
  .fp_grp_addr = {
    .ip4 = {
      .as_u32 = IGMP_MEMBERSHIP_REPORT_ADDRESS,
    },
  },
};
/* *INDENT-ON* */

/**
 * @brief igmp send query (igmp_timer_function_t)
 *
 *   Send an igmp query.
 *   If the timer holds group key, send Group-Specific query,
 *   else send General query.
 */
static void
igmp_send_general_query (u32 obj, void *dat)
{
  igmp_pkt_build_query_t bq;
  igmp_config_t *config;

  config = igmp_config_get (obj);

  IGMP_DBG ("send-general-query: %U",
	    format_vnet_sw_if_index_name, vnet_get_main (),
	    config->sw_if_index);

  igmp_timer_retire (&config->timers[IGMP_CONFIG_TIMER_GENERAL_QUERY]);

  igmp_pkt_build_query_init (&bq, config->sw_if_index);
  igmp_pkt_query_v3_add_group (&bq, NULL, NULL);
  igmp_pkt_query_v3_send (&bq);

  /*
   * re-schedule
   */
  config->timers[IGMP_CONFIG_TIMER_GENERAL_QUERY] =
    igmp_timer_schedule (igmp_timer_type_get (IGMP_TIMER_QUERY),
			 igmp_config_index (config),
			 igmp_send_general_query, NULL);
}

static void
igmp_send_state_change_group_report_v3 (u32 sw_if_index,
					const igmp_group_t * group)
{
  igmp_pkt_build_report_t br;

  IGMP_DBG ("state-change-group: %U", format_igmp_key, group->key);

  igmp_pkt_build_report_init (&br, sw_if_index);
  igmp_pkt_report_v3_add_group (&br,
				group,
				IGMP_MEMBERSHIP_GROUP_allow_new_sources);
  igmp_pkt_report_v3_send (&br);
}

static void
igmp_resend_state_change_group_report_v3 (u32 gi, void *data)
{
  igmp_config_t *config;
  igmp_group_t *group;

  group = igmp_group_get (gi);
  config = igmp_config_get (group->config);

  igmp_timer_retire (&group->timers[IGMP_GROUP_TIMER_RESEND_REPORT]);
  igmp_send_state_change_group_report_v3 (config->sw_if_index, group);

  if (++group->n_reports_sent < config->robustness_var)
    {
      group->timers[IGMP_GROUP_TIMER_RESEND_REPORT] =
	igmp_timer_schedule (igmp_timer_type_get (IGMP_TIMER_REPORT_INTERVAL),
			     igmp_group_index (group),
			     igmp_resend_state_change_group_report_v3, NULL);
    }
}

int
igmp_listen (vlib_main_t * vm,
	     igmp_filter_mode_t mode,
	     u32 sw_if_index,
	     const ip46_address_t * saddrs, const ip46_address_t * gaddr)
{
  const ip46_address_t *saddr;
  igmp_config_t *config;
  igmp_group_t *group;

  /*
   * RFC 3376 Section 2
   " For a given combination of socket, interface, and multicast address,
   only a single filter mode and source list can be in effect at any one
   time.  However, either the filter mode or the source list, or both,
   may be changed by subsequent IPMulticastListen requests that specify
   the same socket, interface, and multicast address.  Each subsequent
   request completely replaces any earlier request for the given socket,
   interface and multicast address."
   */
  int rv = 0;
  IGMP_DBG ("listen: (%U, %U) %U %U",
	    format_igmp_src_addr_list, saddrs,
	    format_igmp_key, gaddr,
	    format_vnet_sw_if_index_name, vnet_get_main (),
	    sw_if_index, format_igmp_filter_mode, mode);
  /*
   * find configuration, if it doesn't exist, then this interface is
   * not IGMP enabled
   */
  config = igmp_config_lookup (sw_if_index);

  if (!config)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      goto error;
    }
  if (config->mode != IGMP_MODE_HOST)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      goto error;
    }

  /* find igmp group, if it doesn't exist, create new */
  group = igmp_group_lookup (config, gaddr);

  if (!group)
    {
      group = igmp_group_alloc (config, gaddr, mode);

      /* new group implies create all sources */
      vec_foreach (saddr, saddrs)
      {
	igmp_group_src_update (group, saddr, IGMP_MODE_HOST);
      }

      /*
       * Send state changed event report for the group.
       *
       * RFC3376 Section 5.1
       *  "To cover the possibility of the State-Change Report being missed by
       *   one or more multicast routers, it is retransmitted [Robustness
       *   Variable] - 1 more times, at intervals chosen at random from the
       *   range (0, [Unsolicited Report Interval])."
       */
      igmp_send_state_change_group_report_v3 (config->sw_if_index, group);

      igmp_timer_retire (&group->timers[IGMP_GROUP_TIMER_RESEND_REPORT]);

      group->n_reports_sent = 1;
      group->timers[IGMP_GROUP_TIMER_RESEND_REPORT] =
	igmp_timer_schedule (igmp_timer_type_get (IGMP_TIMER_REPORT_INTERVAL),
			     igmp_group_index (group),
			     igmp_resend_state_change_group_report_v3, NULL);
    }
  else
    {
      IGMP_DBG ("... update (%U, %U) %U %U",
		format_igmp_src_addr_list, saddrs,
		format_igmp_key, gaddr,
		format_vnet_sw_if_index_name, vnet_get_main (),
		sw_if_index, format_igmp_filter_mode, mode);

      /*
       * RFC 3367 Section 5.1
       *
       *   Old State         New State         State-Change Record Sent
       *   ---------         ---------         ------------------------
       *
       * 1) INCLUDE (A)       INCLUDE (B)       ALLOW (B-A), BLOCK (A-B)
       * 2) EXCLUDE (A)       EXCLUDE (B)       ALLOW (A-B), BLOCK (B-A)
       * 3) INCLUDE (A)       EXCLUDE (B)       TO_EX (B)
       * 4) EXCLUDE (A)       INCLUDE (B)       TO_IN (B)
       *
       * N.B. We do not split state-change records for pending transfer
       * hence there is no merge logic required.
       */

      if (IGMP_FILTER_MODE_INCLUDE == mode)
	{
	  ip46_address_t *added, *removed;
	  igmp_pkt_build_report_t br;

	  /*
	   * find the list of sources that have been added and removed from
	   * the include set
	   */
	  removed =
	    igmp_group_present_minus_new (group, IGMP_FILTER_MODE_INCLUDE,
					  saddrs);
	  added =
	    igmp_group_new_minus_present (group, IGMP_FILTER_MODE_INCLUDE,
					  saddrs);

	  if (!(vec_len (added) || vec_len (removed)))
	    /* no change => done */
	    goto error;

	  igmp_pkt_build_report_init (&br, config->sw_if_index);

	  if (vec_len (added))
	    {
	      igmp_pkt_report_v3_add_report (&br,
					     group->key,
					     added,
					     IGMP_MEMBERSHIP_GROUP_allow_new_sources);
	    }

	  if (vec_len (removed))
	    {
	      igmp_pkt_report_v3_add_report (&br,
					     group->key,
					     removed,
					     IGMP_MEMBERSHIP_GROUP_block_old_sources);
	    }

	  IGMP_DBG ("... added %U", format_igmp_src_addr_list, added);
	  IGMP_DBG ("... removed %U", format_igmp_src_addr_list, removed);

	  igmp_pkt_report_v3_send (&br);

	  /*
	   * clear the group of the old sources and populate it with the new
	   * set requested
	   */
	  igmp_group_free_all_srcs (group);

	  vec_foreach (saddr, saddrs)
	  {
	    igmp_group_src_update (group, saddr, IGMP_MODE_HOST);
	  }

	  if (0 == igmp_group_n_srcs (group, mode))
	    igmp_group_clear (group);

	  vec_free (added);
	  vec_free (removed);
	}
      else
	{
	  /*
	   * The control plane is excluding some sources.
	   *  - First; check for those that are present in the include list
	   *  - Second; check add them to the exclude list
	   *
	   * TODO
	   */
	}
    }

error:
  return (rv);
}

/** \brief igmp hardware interface link up down
    @param vnm - vnet main
    @param hw_if_index - interface hw_if_index
    @param flags - hw interface flags

    If an interface goes down, remove its (S,G)s.
*/
static walk_rc_t
igmp_sw_if_down (vnet_main_t * vnm, u32 sw_if_index, void *ctx)
{
  igmp_config_t *config;
  config = igmp_config_lookup (sw_if_index);
  IGMP_DBG ("down: %U",
	    format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);
  if (NULL != config)
    {
      igmp_clear_config (config);
    }

  return (WALK_CONTINUE);
}

static clib_error_t *
igmp_hw_interface_link_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  clib_error_t *error = NULL;
  /* remove igmp state from down interfaces */
  if (!(flags & VNET_HW_INTERFACE_FLAG_LINK_UP))
    vnet_hw_interface_walk_sw (vnm, hw_if_index, igmp_sw_if_down, NULL);
  return error;
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (igmp_hw_interface_link_up_down);
int
igmp_enable_disable (u32 sw_if_index, u8 enable, igmp_mode_t mode)
{
  igmp_config_t *config;
  igmp_main_t *im = &igmp_main;
  u32 mfib_index;
  IGMP_DBG ("%s:  %U", (enable ? "Enabled" : "Disabled"),
	    format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index);

  /* *INDENT-OFF* */
  fib_route_path_t via_itf_path =
    {
      .frp_proto = fib_proto_to_dpo (FIB_PROTOCOL_IP4),
      .frp_addr = zero_addr,
      .frp_sw_if_index = sw_if_index,
      .frp_fib_index = 0,
      .frp_weight = 1,
    .frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT,
    };
  fib_route_path_t for_us_path = {
    .frp_proto = fib_proto_to_dpo (FIB_PROTOCOL_IP4),
    .frp_addr = zero_addr,
    .frp_sw_if_index = 0xffffffff,
    .frp_fib_index = 1,
    .frp_weight = 0,
    .frp_flags = FIB_ROUTE_PATH_LOCAL,
    .frp_mitf_flags = MFIB_ITF_FLAG_FORWARD,
  };

  /* *INDENT-ON* */
  /* find configuration, if it doesn't exist, create new */
  config = igmp_config_lookup (sw_if_index);
  mfib_index = mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						     sw_if_index);
  if (!config && enable)
    {
      u32 ii;

      vec_validate_init_empty (im->igmp_config_by_sw_if_index,
			       sw_if_index, ~0);
      pool_get (im->configs, config);
      clib_memset (config, 0, sizeof (igmp_config_t));
      config->sw_if_index = sw_if_index;
      config->igmp_group_by_key =
	hash_create_mem (0, sizeof (igmp_key_t), sizeof (uword));
      config->robustness_var = IGMP_DEFAULT_ROBUSTNESS_VARIABLE;
      config->mode = mode;
      config->proxy_device_id = ~0;

      for (ii = 0; ii < IGMP_CONFIG_N_TIMERS; ii++)
	config->timers[ii] = IGMP_TIMER_ID_INVALID;

      if (IGMP_MODE_ROUTER == mode)
	{
	  config->timers[IGMP_CONFIG_TIMER_GENERAL_QUERY] =
	    igmp_timer_schedule (igmp_timer_type_get (IGMP_TIMER_QUERY),
				 igmp_config_index (config),
				 igmp_send_general_query, NULL);
	}

      config->adj_index =
	adj_mcast_add_or_lock (FIB_PROTOCOL_IP4, VNET_LINK_IP4,
			       config->sw_if_index);
      im->igmp_config_by_sw_if_index[config->sw_if_index] =
	(config - im->configs);
      {
	vec_validate (im->n_configs_per_mfib_index, mfib_index);
	im->n_configs_per_mfib_index[mfib_index]++;
	if (1 == im->n_configs_per_mfib_index[mfib_index])
	  {
	    /* first config in this FIB */
	    mfib_table_lock (mfib_index, FIB_PROTOCOL_IP4, MFIB_SOURCE_IGMP);
	    mfib_table_entry_path_update (mfib_index,
					  &mpfx_general_query,
					  MFIB_SOURCE_IGMP, &for_us_path);
	    mfib_table_entry_path_update (mfib_index,
					  &mpfx_report,
					  MFIB_SOURCE_IGMP, &for_us_path);
	  }
	mfib_table_entry_path_update (mfib_index,
				      &mpfx_general_query,
				      MFIB_SOURCE_IGMP, &via_itf_path);
	mfib_table_entry_path_update (mfib_index, &mpfx_report,
				      MFIB_SOURCE_IGMP, &via_itf_path);
      }
    }
  else if (config && !enable)
    {
      vec_validate (im->n_configs_per_mfib_index, mfib_index);
      im->n_configs_per_mfib_index[mfib_index]--;
      if (0 == im->n_configs_per_mfib_index[mfib_index])
	{
	  /* last config in this FIB */
	  mfib_table_entry_path_remove (mfib_index,
					&mpfx_general_query,
					MFIB_SOURCE_IGMP, &for_us_path);
	  mfib_table_entry_path_remove (mfib_index,
					&mpfx_report,
					MFIB_SOURCE_IGMP, &for_us_path);
	  mfib_table_unlock (mfib_index, FIB_PROTOCOL_IP4, MFIB_SOURCE_IGMP);
	}

      mfib_table_entry_path_remove (mfib_index,
				    &mpfx_general_query,
				    MFIB_SOURCE_IGMP, &via_itf_path);
      mfib_table_entry_path_remove (mfib_index,
				    &mpfx_report,
				    MFIB_SOURCE_IGMP, &via_itf_path);

      /*
       * remove interface from proxy device
       * if this device is upstream, delete proxy device
       */
      if (config->mode == IGMP_MODE_ROUTER)
	igmp_proxy_device_add_del_interface (config->proxy_device_id,
					     config->sw_if_index, 0);
      else if (config->mode == IGMP_MODE_HOST)
	igmp_proxy_device_add_del (config->proxy_device_id,
				   config->sw_if_index, 0);

      igmp_clear_config (config);
      im->igmp_config_by_sw_if_index[config->sw_if_index] = ~0;
      hash_free (config->igmp_group_by_key);
      pool_put (im->configs, config);
    }
  else
    {
      return -1;
    }

  return (0);
}

/** \brief igmp initialization
    @param vm - vlib main

    initialize igmp plugin. Initialize igmp_main, set mfib to allow igmp traffic.
*/
static clib_error_t *
igmp_init (vlib_main_t * vm)
{
  clib_error_t *error;
  igmp_main_t *im = &igmp_main;

  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;

  im->igmp_api_client_by_client_index = hash_create (0, sizeof (u32));
  im->logger = vlib_log_register_class ("igmp", 0);

  IGMP_DBG ("initialized");

  return (error);
}

VLIB_INIT_FUNCTION (igmp_init);
/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "IGMP messaging",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
