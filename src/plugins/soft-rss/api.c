/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/interface.h>
#include <vnet/plugin/plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/vec.h>
#include <soft-rss/soft_rss.h>

#include <soft-rss/soft_rss.api_enum.h>
#include <soft-rss/soft_rss.api_types.h>

#define REPLY_MSG_ID_BASE (soft_rss_main.msg_id_base)
#include <vlibapi/api_helper_macros.h>

STATIC_ASSERT ((int) SOFT_RSS_TYPE_API_NOT_SET == (int) SOFT_RSS_TYPE_NOT_SET, "NOT_SET");
STATIC_ASSERT ((int) SOFT_RSS_TYPE_API_DISABLED == (int) SOFT_RSS_TYPE_DISABLED, "DISABLED");
STATIC_ASSERT ((int) SOFT_RSS_TYPE_API_4_TUPLE == (int) SOFT_RSS_TYPE_4_TUPLE, "4-tuple");
STATIC_ASSERT ((int) SOFT_RSS_TYPE_API_2_TUPLE == (int) SOFT_RSS_TYPE_2_TUPLE, "2-tuple");
STATIC_ASSERT ((int) SOFT_RSS_TYPE_API_SRC_IP == (int) SOFT_RSS_TYPE_SRC_IP, "src-ip");
STATIC_ASSERT ((int) SOFT_RSS_TYPE_API_DST_IP == (int) SOFT_RSS_TYPE_DST_IP, "dst-ip");

static u32
sw_to_hw (u32 sw_if_index)
{
  vnet_hw_interface_t *hi =
    vnet_get_sup_hw_interface_api_visible_or_null (vnet_get_main (), sw_if_index);
  return hi ? hi->hw_if_index : ~0;
}

static int
api_err_from_clib (clib_error_t *err)
{
  if (!err)
    return 0;
  clib_error_free (err);
  return VNET_API_ERROR_INVALID_VALUE;
}

static void
vl_api_soft_rss_config_set_t_handler (vl_api_soft_rss_config_set_t *mp)
{
  vl_api_soft_rss_config_set_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 hw_if_index;
  soft_rss_config_t cfg = {};
  clib_error_t *err;
  int rv = 0;
  u8 flags;

  VALIDATE_SW_IF_INDEX (mp);

  hw_if_index = sw_to_hw (sw_if_index);
  if (hw_if_index == ~0)
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto reply;
    }

  cfg.type = (soft_rss_type_t) mp->default_type;
  cfg.ipv4_type = (soft_rss_type_t) mp->ipv4_type;
  cfg.ipv6_type = (soft_rss_type_t) mp->ipv6_type;
  cfg.offset = ntohs (mp->offset);

  flags = (u8) mp->flags;
  cfg.with_main_thread = (flags & SOFT_RSS_CFG_F_WITH_MAIN_THREAD) ? 1 : 0;
  cfg.l3_offset = (flags & SOFT_RSS_CFG_F_L3_OFFSET) ? 1 : 0;

  for (u32 i = 0; i < mp->n_threads; i++)
    cfg.threads = clib_bitmap_set (cfg.threads, mp->threads[i], 1);

  if (mp->key_len)
    {
      u8 klen = mp->key_len;
      if (klen > sizeof (mp->key))
	klen = sizeof (mp->key);
      vec_validate (cfg.key, klen - 1);
      clib_memcpy (cfg.key, mp->key, klen);
    }

  err = soft_rss_config (vlib_get_main (), &cfg, hw_if_index);
  rv = api_err_from_clib (err);

  clib_bitmap_free (cfg.threads);
  vec_free (cfg.key);

  BAD_SW_IF_INDEX_LABEL;
reply:
  REPLY_MACRO (VL_API_SOFT_RSS_CONFIG_SET_REPLY);
}

static void
vl_api_soft_rss_config_clear_t_handler (vl_api_soft_rss_config_clear_t *mp)
{
  vl_api_soft_rss_config_clear_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 hw_if_index;
  clib_error_t *err;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  hw_if_index = sw_to_hw (sw_if_index);
  if (hw_if_index == ~0)
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto reply;
    }

  err = soft_rss_disable (vlib_get_main (), hw_if_index);
  if (err)
    clib_error_free (err);

  err = soft_rss_clear (vlib_get_main (), hw_if_index);
  rv = api_err_from_clib (err);

  BAD_SW_IF_INDEX_LABEL;
reply:
  REPLY_MACRO (VL_API_SOFT_RSS_CONFIG_CLEAR_REPLY);
}

static void
vl_api_soft_rss_enable_disable_t_handler (vl_api_soft_rss_enable_disable_t *mp)
{
  vl_api_soft_rss_enable_disable_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 hw_if_index;
  clib_error_t *err;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  hw_if_index = sw_to_hw (sw_if_index);
  if (hw_if_index == ~0)
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto reply;
    }

  err = mp->enable ? soft_rss_enable (vlib_get_main (), hw_if_index) :
		     soft_rss_disable (vlib_get_main (), hw_if_index);
  rv = api_err_from_clib (err);

  BAD_SW_IF_INDEX_LABEL;
reply:
  REPLY_MACRO (VL_API_SOFT_RSS_ENABLE_DISABLE_REPLY);
}

static u8
compute_flags (const soft_rss_rt_data_t *rt)
{
  u8 f = 0;
  if (rt->with_main_thread)
    f |= SOFT_RSS_CFG_F_WITH_MAIN_THREAD;
  if (rt->l3_offset)
    f |= SOFT_RSS_CFG_F_L3_OFFSET;
  return f;
}

static void
vl_api_soft_rss_config_get_t_handler (vl_api_soft_rss_config_get_t *mp)
{
  vl_api_soft_rss_config_get_reply_t *rmp;
  soft_rss_main_t *sm = &soft_rss_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  soft_rss_rt_data_t *rt = 0;
  int rv = 0;
  u8 n_threads = 0;

  VALIDATE_SW_IF_INDEX (mp);

  if (sw_if_index < vec_len (sm->rt_by_sw_if_index))
    rt = sm->rt_by_sw_if_index[sw_if_index];

  if (!rt)
    rv = VNET_API_ERROR_FEATURE_DISABLED;
  else
    n_threads = rt->n_threads;

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO3 (VL_API_SOFT_RSS_CONFIG_GET_REPLY, n_threads, ({
		  rmp->sw_if_index = htonl (sw_if_index);
		  if (rt)
		    {
		      rmp->enabled = rt->enabled ? true : false;
		      rmp->ipv4_type = (vl_api_soft_rss_type_t) rt->ipv4_type;
		      rmp->ipv6_type = (vl_api_soft_rss_type_t) rt->ipv6_type;
		      rmp->flags = (vl_api_soft_rss_config_flags_t) compute_flags (rt);
		      rmp->match_offset = htons (rt->match_offset);
		      rmp->n_threads = n_threads;
		      for (u8 i = 0; i < n_threads; i++)
			rmp->threads[i] = rt->reta[i];
		    }
		}));
}

static void
send_soft_rss_interface_details (u32 sw_if_index, const soft_rss_rt_data_t *rt,
				 vl_api_registration_t *rp, u32 context)
{
  vl_api_soft_rss_interface_details_t *rmp;
  soft_rss_main_t *sm = &soft_rss_main;
  u8 n_threads = rt->n_threads;
  u32 msg_size = sizeof (*rmp) + n_threads * sizeof (u8);

  rmp = vl_msg_api_alloc_zero (msg_size);
  rmp->_vl_msg_id = htons (VL_API_SOFT_RSS_INTERFACE_DETAILS + sm->msg_id_base);
  rmp->context = context;
  rmp->sw_if_index = htonl (sw_if_index);
  rmp->enabled = rt->enabled ? true : false;
  rmp->ipv4_type = (vl_api_soft_rss_type_t) rt->ipv4_type;
  rmp->ipv6_type = (vl_api_soft_rss_type_t) rt->ipv6_type;
  rmp->flags = (vl_api_soft_rss_config_flags_t) compute_flags (rt);
  rmp->match_offset = htons (rt->match_offset);
  rmp->n_threads = n_threads;
  for (u8 i = 0; i < n_threads; i++)
    rmp->threads[i] = rt->reta[i];

  vl_api_send_msg (rp, (u8 *) rmp);
}

static void
vl_api_soft_rss_interface_dump_t_handler (vl_api_soft_rss_interface_dump_t *mp)
{
  soft_rss_main_t *sm = &soft_rss_main;
  vl_api_registration_t *reg = vl_api_client_index_to_registration (mp->client_index);

  if (!reg)
    return;

  for (u32 i = 0; i < vec_len (sm->rt_by_sw_if_index); i++)
    {
      soft_rss_rt_data_t *rt = sm->rt_by_sw_if_index[i];
      if (!rt)
	continue;
      send_soft_rss_interface_details (i, rt, reg, mp->context);
    }
}

#include <vnet/format_fns.h>
#include <soft-rss/soft_rss.api.c>

static clib_error_t *
soft_rss_api_hookup (vlib_main_t *vm)
{
  soft_rss_main.msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (soft_rss_api_hookup);
