/*
 *------------------------------------------------------------------
 * sctp_api.c - vnet sctp-layer API
 *
 * Copyright (c) 2018 SUSE LLC.
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

#include <vnet/sctp/sctp.h>

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

#define foreach_sctp_api_msg                                    \
_(SCTP_ADD_SRC_DST_CONNECTION, sctp_add_src_dst_connection)		\
_(SCTP_DEL_SRC_DST_CONNECTION, sctp_del_src_dst_connection)		\
_(SCTP_CONFIG, sctp_config)

static void
  vl_api_sctp_add_src_dst_connection_t_handler
  (vl_api_sctp_add_src_dst_connection_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_sctp_add_src_dst_connection_reply_t *rmp;
  int rv;

  if (mp->is_ipv6)
    rv = sctp_sub_connection_add_ip6
      (vm,
       (ip6_address_t *) mp->src_address, (ip6_address_t *) mp->dst_address);
  else
    rv = sctp_sub_connection_add_ip4
      (vm,
       (ip4_address_t *) mp->src_address, (ip4_address_t *) mp->dst_address);

  REPLY_MACRO (VL_API_SCTP_ADD_SRC_DST_CONNECTION_REPLY);
}

static void
  vl_api_sctp_del_src_dst_connection_t_handler
  (vl_api_sctp_del_src_dst_connection_t * mp)
{
  vl_api_sctp_del_src_dst_connection_reply_t *rmp;
  int rv;

  if (mp->is_ipv6)
    rv = sctp_sub_connection_del_ip6
      ((ip6_address_t *) mp->src_address, (ip6_address_t *) mp->dst_address);
  else
    rv = sctp_sub_connection_del_ip4
      ((ip4_address_t *) mp->src_address, (ip4_address_t *) mp->dst_address);

  REPLY_MACRO (VL_API_SCTP_ADD_SRC_DST_CONNECTION_REPLY);
}

static void
vl_api_sctp_config_t_handler (vl_api_sctp_config_t * mp)
{
  sctp_user_configuration_t config;
  vl_api_sctp_config_reply_t *rmp;
  int rv;

  config.never_delay_sack = mp->never_delay_sack;
  config.never_bundle = mp->never_bundle;
  rv = sctp_configure (config);

  REPLY_MACRO (VL_API_SCTP_CONFIG_REPLY);
}

#define vl_msg_name_crc_list
#include <vnet/sctp/sctp.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_sctp;
#undef _
}

static clib_error_t *
sctp_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_sctp_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (sctp_api_hookup);

void
sctp_api_reference (void)
{
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
