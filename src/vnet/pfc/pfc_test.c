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
} pfc_test_main_t;

pfc_test_main_t pfc_test_main;

#define __plugin_msg_base pfc_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>
uword unformat_sw_if_index (unformat_input_t *input, va_list *args);

/* Declare message IDs */
#include <vnet/pfc/pfc.api_enum.h>
#include <vnet/pfc/pfc.api_types.h>
#include <vlibmemory/vlib.api_types.h>

static int
api_pfc_sys_configure (vat_main_t *vam)
{
  u32 pause_time = 0, rxq = 0, rx_tc = 0;
  u32 mode = 0, txq = 0, tx_tc = 0;
  unformat_input_t *i = vam->input;
  vl_api_pfc_sys_configure_t *mp;
  u32 msg_size = sizeof (*mp);
  u8 sw_if_idx_set = 0;
  u32 sw_if_idx = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "mode %u", &mode))
	;
      else if (unformat (i, "txq %u", &txq))
	;
      else if (unformat (i, "tx_tc %u", &tx_tc))
	;
      else if (unformat (i, "pause_time %u", &pause_time))
	;
      else if (unformat (i, "rxq %u", &rxq))
	;
      else if (unformat (i, "rx_tc %u", &rx_tc))
	;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set)
    return -EINVAL;

  M (PFC_SYS_CONFIGURE, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->mode = clib_host_to_net_u32 (mode);
  mp->txq = clib_host_to_net_u32 (txq);
  mp->tx_tc = clib_host_to_net_u32 (tx_tc);
  mp->pause_time = clib_host_to_net_u32 (pause_time);
  mp->rxq = clib_host_to_net_u32 (rxq);
  mp->rx_tc = clib_host_to_net_u32 (rx_tc);

  S (mp);
  W (ret);
  return ret;
}

static int
api_pfc_sys_get_capabilities (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_pfc_sys_get_capabilities_t *mp;
  u32 msg_size = sizeof (*mp);
  u8 sw_if_idx_set = 0;
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

  M (PFC_SYS_GET_CAPABILITIES, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);

  S (mp);
  W (ret);
  return ret;
}

static int
api_pfc_sys_disable_pause_frame_flow_ctrl (vat_main_t *vam)
{
  vl_api_pfc_sys_disable_pause_frame_flow_ctrl_t *mp;
  unformat_input_t *i = vam->input;
  u32 sw_if_idx = 0, disable = 0;
  u32 msg_size = sizeof (*mp);
  u8 sw_if_idx_set = 0;
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_idx %u", &sw_if_idx))
	sw_if_idx_set = 1;
      else if (unformat (i, "disable %u", &disable))
	;
      else
	{
	  clib_warning ("Invalid input, unknown parameter");
	  return -EINVAL;
	}
    }

  if (!sw_if_idx_set)
    return -EINVAL;

  M (PFC_SYS_DISABLE_PAUSE_FRAME_FLOW_CTRL, mp);

  mp->sw_if_idx = clib_host_to_net_u32 (sw_if_idx);
  mp->disable = clib_host_to_net_u32 (disable);

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_pfc_sys_configure_reply_t_handler (vl_api_pfc_sys_configure_reply_t *mp)
{
  vat_main_t *vam = pfc_test_main.vat_main;
  if (mp->retval < 0)
    clib_warning ("PFC configure failed: %d", mp->retval);

  vam->result_ready = 1;
}

static void
vl_api_pfc_sys_get_capabilities_reply_t_handler (
  vl_api_pfc_sys_get_capabilities_reply_t *mp)
{
  vat_main_t *vam = pfc_test_main.vat_main;
  if (mp->retval < 0)
    clib_warning ("PFC capability get failed: %d", mp->retval);

  vam->result_ready = 1;
}

static void
vl_api_pfc_sys_disable_pause_frame_flow_ctrl_reply_t_handler (
  vl_api_pfc_sys_disable_pause_frame_flow_ctrl_reply_t *mp)
{
  vat_main_t *vam = pfc_test_main.vat_main;
  if (mp->retval < 0)
    clib_warning ("Pause frame disable failed: %d", mp->retval);

  vam->result_ready = 1;
}

#include <vnet/pfc/pfc.api_test.c>
