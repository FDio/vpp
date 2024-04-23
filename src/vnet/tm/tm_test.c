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
api_tm_sys_node_create (vat_main_t *vam)
{
  u32 level, priority, node_id, weight, parent_node_id;
  u8 priority_set = 0, level_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_node_create_t *mp;
  u32 msg_size = sizeof (*mp);
  u8 sw_if_idx_set = 0;
  u32 sw_if_idx = 0;
  u64 shaper_id = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "node_id %u", &node_id))
	;
      else if (unformat (i, "parent_node_id %u", &parent_node_id))
	;
      else if (unformat (i, "shaper_prof %llu", &shaper_id))
	;
      else if (unformat (i, "weight %llu", &weight))
	;
      else if (unformat (i, "priority %u", &priority))
	priority_set = 1;
      else if (unformat (i, "level %u", &level))
	level_set = 1;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set || !priority_set || !level_set)
    return -EINVAL;

  M (TM_SYS_NODE_CREATE, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->node_id = clib_host_to_net_u32 (node_id);
  mp->parent_node_id = clib_host_to_net_u32 (parent_node_id);
  mp->weight = clib_host_to_net_u32 (weight);
  mp->priority = (u8) priority;
  mp->level = (u8) level;
  mp->shaper_id = clib_host_to_net_u64 (shaper_id);

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
api_tm_sys_node_connect (vat_main_t *vam)
{
  u8 sw_if_idx_set = 0, tm_node_idx_set = 0;
  unformat_input_t *i = vam->input;
  vl_api_tm_sys_node_connect_t *mp;
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

  M (TM_SYS_NODE_CONNECT, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->tm_node_id = clib_host_to_net_u32 (tm_node_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_node_disconnect (vat_main_t *vam)
{
  u8 sw_if_idx_set = 0, tm_node_idx_set = 0;
  vl_api_tm_sys_node_disconnect_t *mp;
  unformat_input_t *i = vam->input;
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

  M (TM_SYS_NODE_DISCONNECT, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->tm_node_id = clib_host_to_net_u32 (tm_node_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_sched_create (vat_main_t *vam)
{
  u32 sched_weight = 1, sched_mode = 0;
  vl_api_tm_sys_sched_create_t *mp;
  unformat_input_t *i = vam->input;
  u32 msg_size = sizeof (*mp);
  u8 sw_if_idx_set = 0;
  u32 sw_if_idx = 0;
  int ret;

  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      if (unformat (i, "sched_weight %u", &sched_weight))
	;
      else if (unformat (i, "sched_mode %u", &sched_mode))
	;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set)
    return -EINVAL;

  M (TM_SYS_SCHED_CREATE, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->sched_weight = clib_host_to_net_u32 (sched_weight);
  mp->sched_mode = (u8) sched_mode;

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_sched_delete (vat_main_t *vam)
{
  vl_api_tm_sys_sched_delete_t *mp;
  unformat_input_t *i = vam->input;
  u32 msg_size = sizeof (*mp);
  u8 sw_if_idx_set = 0;
  u32 sw_if_idx = 0;
  u64 sched_id = 0;

  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;

      if (unformat (i, "sched_id %llu", &sched_id))
	;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set && !sched_id)
    return -EINVAL;

  M (TM_SYS_SCHED_DELETE, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->sched_id = clib_host_to_net_u64 (sched_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_shaper_create (vat_main_t *vam)
{
  vl_api_tm_sys_shaper_create_t *mp;
  unformat_input_t *i = vam->input;
  u32 msg_size = sizeof (*mp);
  int shaper_len_adjust = 0;
  u64 shaper_rate = 2000000;
  u32 shaper_burst = 10000;
  u8 tm_shaper_mode = 0;
  u8 sw_if_idx_set = 0;
  u32 packet_mode = 0;
  u32 sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;

  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      if (unformat (i, "shaper_rate %llu", &shaper_rate))
	;
      else if (unformat (i, "shaper_burst %u", &shaper_burst))
	;
      else if (unformat (i, "packet_mode %u", &packet_mode))
	;
      else if (unformat (i, "shaper_len_adjust %d", &shaper_len_adjust))
	;
      else if (unformat (i, "shaper_mode %u", &tm_shaper_mode))
	;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set)
    return -EINVAL;

  M (TM_SYS_SHAPER_CREATE, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->shaper_rate = clib_host_to_net_u64 (shaper_rate);
  mp->shaper_burst = clib_host_to_net_u32 (shaper_burst);
  mp->is_pkt_mode = packet_mode;
  mp->shaper_len_adjust = (u8) shaper_len_adjust;
  mp->tm_shaper_mode = tm_shaper_mode;

  S (mp);
  W (ret);
  return ret;
}

static int
api_tm_sys_shaper_delete (vat_main_t *vam)
{
  vl_api_tm_sys_shaper_delete_t *mp;
  unformat_input_t *i = vam->input;
  u32 msg_size = sizeof (*mp);
  u8 sw_if_idx_set = 0;
  u32 sw_if_idx = 0;
  u64 sched_id = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;

      if (unformat (i, "sched_id %llu", &sched_id))
	;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sched_id && !sw_if_idx_set)
    return -EINVAL;

  M (TM_SYS_SHAPER_DELETE, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->shaper_id = clib_host_to_net_u64 (sched_id);

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_tm_sys_node_create_reply_t_handler (
  vl_api_tm_sys_node_create_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("TM node idx : %u retval : %d",
		clib_net_to_host_u16 (mp->node_id),
		clib_net_to_host_u32 (mp->retval));
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_node_delete_reply_t_handler (
  vl_api_tm_sys_node_delete_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  vam->retval = clib_net_to_host_u32 (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_node_connect_reply_t_handler (
  vl_api_tm_sys_node_connect_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  vam->retval = clib_net_to_host_u32 (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_node_disconnect_reply_t_handler (
  vl_api_tm_sys_node_disconnect_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  vam->retval = clib_net_to_host_u32 (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_sched_create_reply_t_handler (
  vl_api_tm_sys_sched_create_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("scheduler profile : 0x%llu retval : %d",
		clib_net_to_host_u32 (mp->sched_id),
		clib_net_to_host_u32 (mp->retval));
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_sched_delete_reply_t_handler (
  vl_api_tm_sys_sched_delete_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  vam->retval = clib_net_to_host_u32 (mp->retval);
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_shaper_create_reply_t_handler (
  vl_api_tm_sys_shaper_create_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  clib_warning ("shaper profile : 0x%llu retval : %d",
		clib_net_to_host_u64 (mp->shaper_id),
		clib_net_to_host_u32 (mp->retval));
  vam->result_ready = 1;
}

static void
vl_api_tm_sys_shaper_delete_reply_t_handler (
  vl_api_tm_sys_shaper_delete_reply_t *mp)
{
  vat_main_t *vam = tm_test_main.vat_main;
  vam->retval = clib_net_to_host_u32 (mp->retval);
  vam->result_ready = 1;
}

#include <vnet/tm/tm.api_test.c>
