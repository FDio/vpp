/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <stddef.h>
#include <vnet/vnet.h>
#include <vpp/app/version.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/tm/tm.api_enum.h>
#include <vnet/tm/tm.api_types.h>
#include <vppinfra/hash.h>

static u32 vnet_tm_base_msg_id;
#define REPLY_MSG_ID_BASE vnet_tm_base_msg_id

#include <vlibapi/api_helper_macros.h>

void
vl_api_tm_sys_node_add_t_handler (vl_api_tm_sys_node_add_t *mp)
{
  vl_api_tm_sys_node_add_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_tm_node_params_t n_p;
  int rv = -1;
  u32 node_id = 0;
  i32 parent_node_id = 0;
  u32 priority = 0;
  u32 weight = 0;
  u32 lvl = 0;
  char *flow_name = (char *) mp->flow_name;
  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));

  node_id = clib_net_to_host_u32 (mp->node_id);
  parent_node_id = clib_net_to_host_i32 (mp->parent_node_id);
  n_p.shaper_profile_id = clib_net_to_host_i32 (mp->shaper_id);
  weight = clib_net_to_host_u32 (mp->weight);
  priority = clib_net_to_host_u32 (mp->priority);
  lvl = clib_net_to_host_u32 (mp->lvl);

  rv = vnet_tm_sys_node_add (sw->hw_if_index, node_id, parent_node_id, priority, weight, lvl, &n_p,
			     flow_name);

  REPLY_MACRO (VL_API_TM_SYS_NODE_ADD_REPLY);
}

void
vl_api_tm_sys_node_suspend_t_handler (vl_api_tm_sys_node_suspend_t *mp)
{
  vl_api_tm_sys_node_suspend_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = -1;
  u32 node_id = 0;
  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));

  node_id = clib_net_to_host_u32 (mp->tm_node_id);

  rv = vnet_tm_sys_node_suspend (sw->hw_if_index, node_id);

  REPLY_MACRO (VL_API_TM_SYS_NODE_SUSPEND_REPLY);
}

void
vl_api_tm_sys_node_resume_t_handler (vl_api_tm_sys_node_resume_t *mp)
{
  vl_api_tm_sys_node_resume_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = -1;
  u32 node_id = 0;
  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));

  node_id = clib_net_to_host_u32 (mp->tm_node_id);
  rv = vnet_tm_sys_node_resume (sw->hw_if_index, node_id);

  REPLY_MACRO (VL_API_TM_SYS_NODE_RESUME_REPLY);
}

void
vl_api_tm_sys_node_delete_t_handler (vl_api_tm_sys_node_delete_t *mp)
{
  vl_api_tm_sys_node_delete_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 node_id = 0;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));

  node_id = clib_net_to_host_u32 (mp->tm_node_id);

  rv = vnet_tm_sys_node_delete (sw->hw_if_index, node_id);

  REPLY_MACRO (VL_API_TM_SYS_NODE_DELETE_REPLY);
}

void
vl_api_tm_sys_shaper_profile_create_t_handler (vl_api_tm_sys_shaper_profile_create_t *mp)
{
  vl_api_tm_sys_shaper_profile_create_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_tm_shaper_params_t s_p;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));

  s_p.shaper_id = clib_net_to_host_u32 (mp->tm_shaper_id);
  s_p.commit.rate = clib_net_to_host_u64 (mp->shaper_commit_rate);
  s_p.commit.burst_size = clib_net_to_host_u64 (mp->shaper_commit_burst);
  s_p.peak.rate = clib_net_to_host_u64 (mp->shaper_peak_rate);
  s_p.peak.burst_size = clib_net_to_host_u64 (mp->shaper_peak_burst);
  s_p.pkt_len_adj = clib_net_to_host_i64 (mp->shaper_len_adjust);
  s_p.pkt_mode = mp->is_pkt_mode;

  rv = vnet_tm_sys_shaper_profile_create (sw->hw_if_index, &s_p);

  REPLY_MACRO (VL_API_TM_SYS_SHAPER_PROFILE_CREATE_REPLY);
}

void
vl_api_tm_sys_node_shaper_update_t_handler (vl_api_tm_sys_node_shaper_update_t *mp)
{
  vl_api_tm_sys_node_shaper_update_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  i32 shaper_profile_id = 0;
  u32 node_id = 0;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));

  node_id = clib_net_to_host_u32 (mp->node_id);
  shaper_profile_id = clib_net_to_host_u32 (mp->shaper_id);

  rv = vnet_tm_sys_node_shaper_update (sw->hw_if_index, node_id, shaper_profile_id);

  REPLY_MACRO (VL_API_TM_SYS_NODE_SHAPER_UPDATE_REPLY);
}

void
vl_api_tm_sys_shaper_profile_delete_t_handler (vl_api_tm_sys_shaper_profile_delete_t *mp)
{
  vl_api_tm_sys_shaper_profile_delete_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  i32 shaper_id = 0;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));
  shaper_id = clib_net_to_host_u32 (mp->shaper_id);

  rv = vnet_tm_sys_shaper_profile_delete (sw->hw_if_index, shaper_id);

  REPLY_MACRO (VL_API_TM_SYS_SHAPER_PROFILE_DELETE_REPLY);
}

void
vl_api_tm_sys_node_sched_weight_update_t_handler (vl_api_tm_sys_node_sched_weight_update_t *mp)
{
  vl_api_tm_sys_node_sched_weight_update_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 node_id = 0, weight = 0;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));

  node_id = clib_net_to_host_u32 (mp->node_id);
  weight = clib_net_to_host_u32 (mp->weight);

  rv = vnet_tm_sys_node_sched_weight_update (sw->hw_if_index, node_id, weight);

  REPLY_MACRO (VL_API_TM_SYS_NODE_SCHED_WEIGHT_UPDATE_REPLY);
}

void
vl_api_tm_sys_node_read_stats_t_handler (vl_api_tm_sys_node_read_stats_t *mp)
{
  vl_api_tm_sys_node_read_stats_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_tm_stats_params_t s_p = { 0 };
  u32 node_id = 0;
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));

  node_id = clib_net_to_host_u32 (mp->node_id);

  rv = vnet_tm_sys_node_read_stats (sw->hw_if_index, node_id, &s_p);

  REPLY_MACRO (VL_API_TM_SYS_NODE_READ_STATS_REPLY);
}

void
vl_api_tm_sys_get_capabilities_t_handler (vl_api_tm_sys_get_capabilities_t *mp)
{
  vl_api_tm_sys_get_capabilities_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_tm_capa_params_t s_p = { 0 };
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));

  rv = vnet_tm_sys_get_capabilities (sw->hw_if_index, &s_p);

  REPLY_MACRO (VL_API_TM_SYS_GET_CAPABILITIES_REPLY);
}

void
vl_api_tm_sys_level_get_capabilities_t_handler (vl_api_tm_sys_level_get_capabilities_t *mp)
{
  vl_api_tm_sys_level_get_capabilities_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_tm_level_capa_params_t s_p = { 0 };
  int rv = -1;
  u32 lvl = 0;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));

  lvl = clib_net_to_host_u32 (mp->level);

  rv = vnet_tm_sys_level_get_capabilities (sw->hw_if_index, &s_p, lvl);

  REPLY_MACRO (VL_API_TM_SYS_LEVEL_GET_CAPABILITIES_REPLY);
}

void
vl_api_tm_sys_start_tm_t_handler (vl_api_tm_sys_start_tm_t *mp)
{
  vl_api_tm_sys_start_tm_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));

  rv = vnet_tm_sys_start_tm (sw->hw_if_index);

  REPLY_MACRO (VL_API_TM_SYS_START_TM_REPLY);
}

void
vl_api_tm_sys_stop_tm_t_handler (vl_api_tm_sys_stop_tm_t *mp)
{
  vl_api_tm_sys_stop_tm_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = -1;

  vnet_sw_interface_t *sw = vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));

  rv = vnet_tm_sys_stop_tm (sw->hw_if_index);

  REPLY_MACRO (VL_API_TM_SYS_STOP_TM_REPLY);
}

#include <vnet/tm/tm.api.c>

static clib_error_t *
vnet_tm_api_init (vlib_main_t *vm)
{
  vnet_tm_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (vnet_tm_api_init);
