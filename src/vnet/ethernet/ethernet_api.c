/*
 *------------------------------------------------------------------
 * ethernet_api.c - ethernet api
 *
 * Copyright (c) 2025 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vlibapi/api_types.h>
#include <vlibmemory/api.h>

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static u16 msg_id_base;

vpe_api_main_t vpe_api_main;

#include <vnet/ethernet/ethernet.api.c>

static void
vl_api_ethernet_set_default_sw_mtu_t_handler (vl_api_ethernet_set_default_sw_mtu_t * mp)
{
  vl_api_ethernet_set_default_sw_mtu_reply_t *rmp;
  int rv = 0;

  if (mp->mtu < 64)
    rv = VNET_API_ERROR_INVALID_VALUE;
  else
    ethernet_main.default_mtu = mp->mtu;

  REPLY_MACRO_END(VL_API_ETHERNET_SET_DEFAULT_SW_MTU_REPLY);
}

static clib_error_t *
ethernet_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  /* Mark these APIs as autoendian */
  vl_api_set_msg_autoendian (
    am, REPLY_MSG_ID_BASE + VL_API_ETHERNET_SET_DEFAULT_SW_MTU, 1);

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
