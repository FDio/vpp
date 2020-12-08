/*
 *------------------------------------------------------------------
 * multi_txq_api.c - Multi Transmit Queues Per Worker Api
 *
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vnet/multi-txq/multi_txq.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs /* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun /* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_feature_multi_txq_api_msg                                     \
  _ (FEATURE_MULTI_TXQ_ENABLE_DISABLE, feature_multi_txq_enable_disable)

static void
vl_api_feature_multi_txq_enable_disable_t_handler (
  vl_api_feature_multi_txq_enable_disable_t *mp)
{
  vl_api_feature_multi_txq_enable_disable_reply_t *rmp;
  int rv = 0;
  u32 number_of_txqs = 1;

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->enable_disable)
    number_of_txqs = ntohl (mp->number_of_txqs);
  rv = vnet_sw_interface_multi_txq_enable_disable (
    ntohl (mp->sw_if_index), number_of_txqs, mp->enable_disable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_FEATURE_MULTI_TXQ_ENABLE_DISABLE_REPLY);
}

#define vl_msg_name_crc_list
#include <vnet/multi-txq/multi_txq.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t *am)
{
#define _(id, n, crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_multi_txq;
#undef _
}

static clib_error_t *
feature_multi_txq_api_hookup (vlib_main_t *vm)
{
  api_main_t *am = vlibapi_get_main ();

#define _(N, n)                                                               \
  vl_msg_api_set_handlers (VL_API_##N, #n, vl_api_##n##_t_handler,            \
			   vl_noop_handler, vl_api_##n##_t_endian,            \
			   vl_api_##n##_t_print, sizeof (vl_api_##n##_t), 1);
  foreach_feature_multi_txq_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (feature_multi_txq_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
