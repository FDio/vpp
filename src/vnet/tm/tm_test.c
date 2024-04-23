/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip_format_fns.h>
#include <vpp/api/types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} tm_test_main_t;

tm_test_main_t tm_test_main;

#define __plugin_msg_base tm_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>
uword unformat_sw_if_index (unformat_input_t *input, va_list *args);

/* Declare message IDs */
#include <vnet/tm/tm.api_enum.h>
#include <vnet/tm/tm.api_types.h>
#include <vlibmemory/vlib.api_types.h>

static int
api_tm_sys_node_add (vat_main_t *vam)
{
  u32 level, priority, node_id, weight;
  i32 parent_node_id = 0;
  i32 shaper_id = 0;
  u8 priority_set = 0, level_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_node_add_t *mp;
  u32 msg_size = sizeof (*mp);
  u8 sw_if_idx_set = 0;
  u32 sw_if_idx = 0;
  u8 *flow_name = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "node_id %u", &node_id))
	;
      else if (unformat (i, "parent_node_id %d", &parent_node_id))
	;
      else if (unformat (i, "shaper_prof %d", &shaper_id))
	;
      else if (unformat (i, "weight %u", &weight))
	;
      else if (unformat (i, "priority %u", &priority))
	priority_set = 1;
      else if (unformat (i, "level %u", &level))
	level_set = 1;
      else if (unformat (i, "flow_name %s", &flow_name))
	;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set || !priority_set || !level_set)
    return -EINVAL;

  M (TM_SYS_NODE_ADD, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->node_id = clib_host_to_net_u32 (node_id);
  mp->parent_node_id = clib_host_to_net_i32 (parent_node_id);
  mp->shaper_id = clib_host_to_net_i32 (shaper_id);
  mp->weight = clib_host_to_net_u32 (weight);
  mp->priority = clib_host_to_net_u32 (priority);
  mp->lvl = clib_host_to_net_u32 (level);
  if (flow_name != NULL)
    {
      strncpy ((char *) mp->flow_name, (char *) flow_name,
	       sizeof (mp->flow_name) - 1);
    }

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_node_suspend (vat_main_t *vam)
{
  u8 sw_if_idx_set = 0, tm_node_idx_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_node_suspend_t *mp;
  u32 msg_size = sizeof (*mp);
  u32 tm_node_id = 0;
  u32 sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "tm_node_id %u", &tm_node_id))
	tm_node_idx_set = 1;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set || !tm_node_idx_set)
    return -EINVAL;

  M (TM_SYS_NODE_SUSPEND, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->tm_node_id = clib_host_to_net_u32 (tm_node_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_node_resume (vat_main_t *vam)
{
  u8 sw_if_idx_set = 0, tm_node_idx_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_node_resume_t *mp;
  u32 msg_size = sizeof (*mp);
  u32 tm_node_id = 0;
  u32 sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "tm_node_id %u", &tm_node_id))
	tm_node_idx_set = 1;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set || !tm_node_idx_set)
    return -EINVAL;

  M (TM_SYS_NODE_RESUME, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->tm_node_id = clib_host_to_net_u32 (tm_node_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_node_delete (vat_main_t *vam)
{
  u8 sw_if_idx_set = 0, tm_node_idx_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_node_delete_t *mp;
  u32 msg_size = sizeof (*mp);
  u32 tm_node_id = 0;
  u32 sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "tm_node_id %u", &tm_node_id))
	tm_node_idx_set = 1;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set || !tm_node_idx_set)
    return -EINVAL;

  M (TM_SYS_NODE_DELETE, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->tm_node_id = clib_host_to_net_u32 (tm_node_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_shaper_profile_create (vat_main_t *vam)
{
  vl_api_tm_sys_shaper_profile_create_t *mp;
  unformat_input_t *i = vam->input;
  u32 msg_size = sizeof (*mp);
  i32 shaper_len_adjust = 0;
  u64 shaper_commit_rate = 0;
  u64 shaper_commit_burst = 0;
  u64 shaper_peak_rate = 0;
  u64 shaper_peak_burst = 0;
  u32 tm_shaper_id = 0;
  u8 sw_if_idx_set = 0, tm_shaper_id_set = 0;
  u32 is_packet_mode = 0;
  u32 sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;

  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "shaper_id %u", &tm_shaper_id))
	tm_shaper_id_set = 1;
      else if (unformat (i, "packet_mode %u", &is_packet_mode))
	;
      else if (unformat (i, "shaper_peak_burst %llu", &shaper_peak_burst))
	;
      else if (unformat (i, "shaper_commit_rate %llu", &shaper_commit_rate))
	;
      else if (unformat (i, "shaper_commit_burst %llu", &shaper_commit_burst))
	;
      else if (unformat (i, "shaper_peak_rate %llu", &shaper_peak_rate))
	;
      else if (unformat (i, "shaper_len_adjust %d", &shaper_len_adjust))
	;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set || !tm_shaper_id_set)
    return -EINVAL;

  M (TM_SYS_SHAPER_PROFILE_CREATE, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->tm_shaper_id = clib_host_to_net_u32 (tm_shaper_id);
  mp->is_pkt_mode = (u8) is_packet_mode;
  mp->shaper_commit_rate = clib_host_to_net_u64 (shaper_commit_rate);
  mp->shaper_commit_burst = clib_host_to_net_u64 (shaper_commit_burst);
  mp->shaper_peak_rate = clib_host_to_net_u64 (shaper_peak_rate);
  mp->shaper_peak_burst = clib_host_to_net_u64 (shaper_peak_burst);
  mp->shaper_len_adjust = clib_host_to_net_i64 (shaper_len_adjust);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_node_shaper_update (vat_main_t *vam)
{
  u8 sw_if_idx_set = 0, shaper_profile_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_node_shaper_update_t *mp;
  u32 msg_size = sizeof (*mp);
  u32 shaper_profile = 0, node_id = 0;
  u32 sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "shaper_profile %d", &shaper_profile))
	shaper_profile_set = 1;
      else if (unformat (i, "node_id %u", &node_id))
	;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set || !shaper_profile_set)
    return -EINVAL;

  M (TM_SYS_NODE_SHAPER_UPDATE, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->shaper_id = clib_host_to_net_u32 (shaper_profile);
  mp->node_id = clib_host_to_net_u32 (node_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_shaper_profile_delete (vat_main_t *vam)
{
  vl_api_tm_sys_shaper_profile_delete_t *mp;
  unformat_input_t *i = vam->input;
  u32 msg_size = sizeof (*mp);
  u8 sw_if_idx_set = 0, shaper_id_set = 0;
  u32 sw_if_idx = 0;
  u32 shaper_id = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "shaper_id %u", &shaper_id))
	shaper_id_set = 1;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set || !shaper_id_set)
    return -EINVAL;

  M (TM_SYS_SHAPER_PROFILE_DELETE, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->shaper_id = clib_host_to_net_u32 (shaper_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_node_sched_weight_update (vat_main_t *vam)
{
  u8 sw_if_idx_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_node_sched_weight_update_t *mp;
  u32 msg_size = sizeof (*mp);
  u32 node_id = 0, weight = 0;
  u32 sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "node_id %u", &node_id))
	;
      else if (unformat (i, "weight %u", &weight))
	;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set)
    return -EINVAL;

  M (TM_SYS_NODE_SCHED_WEIGHT_UPDATE, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->node_id = clib_host_to_net_u32 (node_id);
  mp->weight = clib_host_to_net_u32 (weight);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_node_read_stats (vat_main_t *vam)
{
  u8 sw_if_idx_set = 0, tm_node_idx_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_node_read_stats_t *mp;
  u32 msg_size = sizeof (*mp);
  u32 tm_node_id = 0;
  u32 sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "tm_node_id %u", &tm_node_id))
	tm_node_idx_set = 1;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set || !tm_node_idx_set)
    return -EINVAL;

  M (TM_SYS_NODE_READ_STATS, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->node_id = clib_host_to_net_u32 (tm_node_id);
  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_get_capabilities (vat_main_t *vam)
{
  u8 sw_if_idx_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_get_capabilities_t *mp;
  u32 msg_size = sizeof (*mp);
  u32 sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set)
    return -EINVAL;

  M (TM_SYS_GET_CAPABILITIES, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_level_get_capabilities (vat_main_t *vam)
{
  u8 sw_if_idx_set = 0, tm_lvl_idx_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_level_get_capabilities_t *mp;
  u32 msg_size = sizeof (*mp);
  u32 tm_lvl, sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "tm_level %u", &tm_lvl))
	tm_lvl_idx_set = 1;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set || !tm_lvl_idx_set)
    return -EINVAL;

  M (TM_SYS_LEVEL_GET_CAPABILITIES, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->level = clib_host_to_net_u32 (tm_lvl);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_start_tm (vat_main_t *vam)
{
  u8 sw_if_idx_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_start_tm_t *mp;
  u32 msg_size = sizeof (*mp);
  u32 sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set)
    return -EINVAL;

  M (TM_SYS_START_TM, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_stop_tm (vat_main_t *vam)
{
  u8 sw_if_idx_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_stop_tm_t *mp;
  u32 msg_size = sizeof (*mp);
  u32 sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set)
    return -EINVAL;

  M (TM_SYS_STOP_TM, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_tm_sys_node_add_reply_t_handler (vl_api_tm_sys_node_add_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("TM node_add_id : %u\n", clib_net_to_host_u32 (mp->node_id));
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_node_suspend_reply_t_handler (
  vl_api_tm_sys_node_suspend_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("TM node_suspend_id : %u\n",
		clib_net_to_host_u32 (mp->node_id));
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_node_resume_reply_t_handler (
  vl_api_tm_sys_node_resume_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("TM node_resume_ id : %u\n",
		clib_net_to_host_u32 (mp->node_id));
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_node_delete_reply_t_handler (
  vl_api_tm_sys_node_delete_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("TM node_delete_id : %u\n",
		clib_net_to_host_u32 (mp->node_id));
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_shaper_profile_create_reply_t_handler (
  vl_api_tm_sys_shaper_profile_create_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("Shaper profile id : %u\n",
		clib_net_to_host_u32 (mp->shaper_id));
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_node_shaper_update_reply_t_handler (
  vl_api_tm_sys_node_shaper_update_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("TM node updated shaper id : %d\n",
		clib_net_to_host_u32 (mp->shaper_id));

  vam->result_ready = 1;
}

static void
vl_api_tm_sys_shaper_profile_delete_reply_t_handler (
  vl_api_tm_sys_shaper_profile_delete_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("TM shaper profile delete id : %u\n",
		clib_net_to_host_u32 (mp->shaper_id));
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_node_sched_weight_update_reply_t_handler (
  vl_api_tm_sys_node_sched_weight_update_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("TM node sched weight updated\n");
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_node_read_stats_reply_t_handler (
  vl_api_tm_sys_node_read_stats_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("TM stats for node id : %u\n",
		clib_net_to_host_u32 (mp->node_id));

  vam->result_ready = 1;
}

static void
vl_api_tm_sys_get_capabilities_reply_t_handler (
  vl_api_tm_sys_get_capabilities_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("TM Capability Passed  : %u\n");
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_level_get_capabilities_reply_t_handler (
  vl_api_tm_sys_level_get_capabilities_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("TM Level Capability Passed  : %u\n");
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_start_tm_reply_t_handler (vl_api_tm_sys_start_tm_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_stop_tm_reply_t_handler (vl_api_tm_sys_stop_tm_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  vam->result_ready = 1;
}

#include <vnet/tm/tm.api_test.c>
