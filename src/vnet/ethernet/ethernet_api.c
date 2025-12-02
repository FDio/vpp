/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vnet/ethernet/ethernet.h>

#include <vnet/api_errno.h>
#include <vlibmemory/api.h>

#include <vnet/ethernet/ethernet.api_enum.h>
#include <vnet/ethernet/ethernet.api_types.h>

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static u16 msg_id_base;

void
vl_api_ethernet_set_default_sw_mtu_t_handler (
  vl_api_ethernet_set_default_sw_mtu_t *mp)
{
  vl_api_ethernet_set_default_sw_mtu_reply_t *rmp;
  int rv = 0;

  if (mp->mtu < 64)
    rv = VNET_API_ERROR_INVALID_VALUE;
  else
    ethernet_main.default_mtu = mp->mtu;

  REPLY_MACRO_END (VL_API_ETHERNET_SET_DEFAULT_SW_MTU_REPLY);
}

#include <vnet/ethernet/ethernet.api.c>

static clib_error_t *
ethernet_api_hookup (vlib_main_t *vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (ethernet_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
