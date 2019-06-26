/*
 *------------------------------------------------------------------
 * sctp_api.c - sctp-layer API
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

#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <sctp/sctp.h>

#include <sctp/sctp_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <sctp/sctp_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <sctp/sctp_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <sctp/sctp_all_api_h.h>
#undef vl_printfun

#define vl_api_version(n,v) static u32 api_version=(v);
#include <sctp/sctp_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE sctp_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

#define foreach_sctp_plugin_api_msg					\
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
#include <sctp/sctp_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (sctp_main_t * sm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_sctp;
#undef _
}

clib_error_t *
sctp_plugin_api_hookup (vlib_main_t * vm)
{
  sctp_main_t *sm = &sctp_main;
  api_main_t *am = &api_main;
  u8 *name;

  /* Construct the API name */
  name = format (0, "sctp_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sctp_main.msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_sctp_plugin_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (sm, am);
  vec_free (name);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
