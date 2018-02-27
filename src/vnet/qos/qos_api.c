/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <vnet/api_errno.h>

#include <vnet/qos/qos_record.h>
#include <vnet/qos/qos_mark.h>
#include <vnet/qos/qos_egress_map.h>

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


#define foreach_qos_api_msg                                             \
  _(QOS_RECORD_ENABLE_DISABLE, qos_record_enable_disable)               \
  _(QOS_EGRESS_MAP_DELETE, qos_egress_map_delete)                       \
  _(QOS_EGRESS_MAP_UPDATE, qos_egress_map_update)                       \
  _(QOS_MARK_ENABLE_DISABLE, qos_mark_enable_disable)

void
vl_api_qos_record_enable_disable_t_handler (vl_api_qos_record_enable_disable_t
					    * mp)
{
  vl_api_qos_record_enable_disable_reply_t *rmp;
  int rv = 0;

  if (mp->input_source > QOS_N_SOURCES)
    rv = VNET_API_ERROR_INVALID_VALUE;
  else
    {
      if (mp->enable)
	rv = qos_record_enable (ntohl (mp->sw_if_index), mp->input_source);
      else
	rv = qos_record_disable (ntohl (mp->sw_if_index), mp->input_source);
    }

  REPLY_MACRO (VL_API_QOS_RECORD_ENABLE_DISABLE_REPLY);
}

void
vl_api_qos_egress_map_update_t_handler (vl_api_qos_egress_map_update_t * mp)
{
  vl_api_qos_egress_map_update_reply_t *rmp;
  qos_source_t qs;
  int rv = 0;

  FOR_EACH_QOS_SOURCE (qs)
  {
    qos_egress_map_update (ntohl (mp->map_id), qs, &mp->rows[qs].outputs[0]);
  }

  REPLY_MACRO (VL_API_QOS_EGRESS_MAP_UPDATE_REPLY);
}

void
vl_api_qos_egress_map_delete_t_handler (vl_api_qos_egress_map_delete_t * mp)
{
  vl_api_qos_egress_map_delete_reply_t *rmp;
  int rv = 0;

  qos_egress_map_delete (ntohl (mp->map_id));

  REPLY_MACRO (VL_API_QOS_EGRESS_MAP_DELETE_REPLY);
}

void
  vl_api_qos_mark_enable_disable_t_handler
  (vl_api_qos_mark_enable_disable_t * mp)
{
  vl_api_qos_mark_enable_disable_reply_t *rmp;
  int rv = 0;

  if (mp->output_source > QOS_N_SOURCES)
    rv = VNET_API_ERROR_INVALID_VALUE;
  else
    {
      if (mp->enable)
	rv = qos_mark_enable (ntohl (mp->sw_if_index),
			      mp->output_source, ntohl (mp->map_id));
      else
	rv = qos_mark_disable (ntohl (mp->sw_if_index), mp->output_source);
    }

  REPLY_MACRO (VL_API_QOS_MARK_ENABLE_DISABLE_REPLY);
}

#define vl_msg_name_crc_list
#include <vnet/qos/qos.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_qos;
#undef _
}

static clib_error_t *
qos_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_qos_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (qos_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
