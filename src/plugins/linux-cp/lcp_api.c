/*
 * Copyright 2020 Rubicon Communications, LLC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vnet/format_fns.h>

#include <linux-cp/lcp_interface.h>
#include <linux-cp/lcp.api_enum.h>
#include <linux-cp/lcp.api_types.h>


typedef struct lcp_main_s
{
  /* API message ID base */
  u16 msg_id_base;
} lcp_main_t;

#define REPLY_MSG_ID_BASE lcpm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static lcp_main_t lcp_main;

#include <vlibapi/api_helper_macros.h>


static void
vl_api_lcp_itf_pair_add_del_t_handler (vl_api_lcp_itf_pair_add_del_t *mp)
{
  lcp_main_t *lcpm = &lcp_main;
  u32 phy_sw_if_index;
  vl_api_lcp_itf_pair_add_del_reply_t *rmp;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  phy_sw_if_index = ntohl (mp->sw_if_index);
  if (mp->is_add)
    {
      rv = lcp_itf_pair_create (phy_sw_if_index, mp->host_if_name);
    }
  else
    {
      rv = lcp_itf_pair_delete (phy_sw_if_index);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_LCP_ITF_PAIR_ADD_DEL_REPLY);
}


static void
send_lcp_itf_pair_details (vl_api_registration_t *reg,
			   u32 context,
			   lcp_itf_pair_t *lcp_pair)
{
  vl_api_lcp_itf_pair_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return;
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_LCP_ITF_PAIR_DETAILS);
  mp->context = context;

  mp->phy_sw_if_index = htonl (lcp_pair->lip_phy_sw_if_index);
  mp->host_sw_if_index = htonl (lcp_pair->lip_host_sw_if_index);
  mp->vif_index = htonl (lcp_pair->lip_vif_index);

  clib_strncpy ((char *)mp->host_tap_name,
		(char *)lcp_pair->lip_host_name, 64 - 1);

  vl_api_send_msg(reg, (u8 *) mp);
}

walk_rc_t
lcp_itf_pair_walk_send_cb(index_t api, void *ctx)
{
  vl_api_lcp_itf_pair_dump_t *mp = ctx;
  vl_api_registration_t *reg;
  lcp_itf_pair_t *lcp_pair;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return WALK_STOP;

  lcp_pair = lcp_itf_pair_get (api);
  if (!lcp_pair)
    return WALK_STOP;

  send_lcp_itf_pair_details (reg, mp->context, lcp_pair);
  return WALK_CONTINUE;
}


static void
vl_api_lcp_itf_pair_dump_t_handler (vl_api_lcp_itf_pair_dump_t *mp)
{
  u32 sw_if_index;
  index_t api;

  sw_if_index = ntohl (mp->sw_if_index);
  if (sw_if_index == ~0)
    {
      lcp_itf_pair_walk (lcp_itf_pair_walk_send_cb, (void *) mp);
    }
  else
    {
      api = lcp_itf_pair_find_by_phy (sw_if_index);
      lcp_itf_pair_walk_send_cb(api, (void *)mp);
    }
}


/*
 * Set up the API message handling tables
 */
#include <linux-cp/lcp.api.c>

clib_error_t *
lcp_plugin_api_hookup (vlib_main_t * vm)
{
  lcp_main_t *lcpm = &lcp_main;

  /* Ask for a correctly-sized block of API message decode slots */
  lcpm->msg_id_base = setup_message_id_table ();

  return 0;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
