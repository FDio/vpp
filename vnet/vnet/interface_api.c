/*
 *------------------------------------------------------------------
 * interface_api.c - vnet interface api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/ethernet/ethernet.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                             \
_(SW_INTERFACE_SET_FLAGS, sw_interface_set_flags)       \
_(SW_INTERFACE_SET_MTU, sw_interface_set_mtu)

static void
vl_api_sw_interface_set_flags_t_handler (vl_api_sw_interface_set_flags_t * mp)
{
  vl_api_sw_interface_set_flags_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = 0;
  clib_error_t *error;
  u16 flags;

  VALIDATE_SW_IF_INDEX (mp);

  flags = mp->admin_up_down ? VNET_SW_INTERFACE_FLAG_ADMIN_UP : 0;

  error = vnet_sw_interface_set_flags (vnm, ntohl (mp->sw_if_index), flags);
  if (error)
    {
      rv = -1;
      clib_error_report (error);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_FLAGS_REPLY);
}

static void
vl_api_sw_interface_set_mtu_t_handler (vl_api_sw_interface_set_mtu_t * mp)
{
  vl_api_sw_interface_set_mtu_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 flags = ETHERNET_INTERFACE_FLAG_MTU;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u16 mtu = ntohs (mp->mtu);
  ethernet_main_t *em = &ethernet_main;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, sw_if_index);
  ethernet_interface_t *eif = ethernet_get_interface (em, sw_if_index);

  if (!eif)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto bad_sw_if_index;
    }

  if (mtu < hi->min_supported_packet_bytes)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto bad_sw_if_index;
    }

  if (mtu > hi->max_supported_packet_bytes)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto bad_sw_if_index;
    }

  if (hi->max_packet_bytes != mtu)
    {
      hi->max_packet_bytes = mtu;
      ethernet_set_flags (vnm, sw_if_index, flags);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_MTU_REPLY);
}


/*
 * vpe_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_interface;
#undef _
}

static clib_error_t *
interface_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (interface_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
