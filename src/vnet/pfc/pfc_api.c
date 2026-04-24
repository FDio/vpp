/*
 * Copyright (c) 2025 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <stddef.h>
#include <vnet/vnet.h>
#include <vpp/app/version.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/pfc/pfc.api_enum.h>
#include <vnet/pfc/pfc.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 pfc_base_msg_id;
#define REPLY_MSG_ID_BASE pfc_base_msg_id

#include <vlibapi/api_helper_macros.h>

void
vl_api_pfc_sys_configure_t_handler (vl_api_pfc_sys_configure_t *mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw =
    vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));
  vl_api_pfc_sys_configure_reply_t *rmp;
  pfc_params_t params = { 0 };
  int rv = -1;

  params.mode = clib_net_to_host_u32 (mp->mode);
  params.rx_pause.txq = clib_net_to_host_u32 (mp->txq);
  params.rx_pause.tc = clib_net_to_host_u32 (mp->tx_tc);
  params.tx_pause.pause_time = clib_net_to_host_u32 (mp->pause_time);
  params.tx_pause.rxq = clib_net_to_host_u32 (mp->rxq);
  params.tx_pause.tc = clib_net_to_host_u32 (mp->rx_tc);

  rv = pfc_sys_configure (sw->hw_if_index, &params);

  REPLY_MACRO (VL_API_PFC_SYS_CONFIGURE_REPLY);
}

void
vl_api_pfc_sys_get_capabilities_t_handler (
  vl_api_pfc_sys_get_capabilities_t *mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw =
    vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));
  vl_api_pfc_sys_get_capabilities_reply_t *rmp;
  pfc_capa_params_t capa = { 0 };
  int rv = -1;

  rv = pfc_sys_get_capabilities (sw->hw_if_index, &capa);

  REPLY_MACRO2 (VL_API_PFC_SYS_GET_CAPABILITIES_REPLY, ({
		  rmp->mode = clib_host_to_net_u32 (capa.mode);
		  rmp->tc_max = clib_host_to_net_u32 (capa.tc_max);
		}));
}

void
vl_api_pfc_sys_disable_pause_frame_flow_ctrl_t_handler (
  vl_api_pfc_sys_disable_pause_frame_flow_ctrl_t *mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw =
    vnet_get_sup_sw_interface (vnm, clib_net_to_host_u32 (mp->sw_if_idx));
  vl_api_pfc_sys_disable_pause_frame_flow_ctrl_reply_t *rmp;
  int rv = -1;

  rv = pfc_sys_disable_pause_frame_flow_ctrl (
    sw->hw_if_index, clib_host_to_net_u32 (mp->disable));

  REPLY_MACRO (VL_API_PFC_SYS_DISABLE_PAUSE_FRAME_FLOW_CTRL_REPLY);
}

#include <vnet/pfc/pfc.api.c>

static clib_error_t *
pfc_api_init (vlib_main_t *vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  pfc_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (pfc_api_init);
