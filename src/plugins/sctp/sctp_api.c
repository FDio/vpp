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

#include <sctp/sctp.api_enum.h>
#include <sctp/sctp.api_types.h>

#define REPLY_MSG_ID_BASE sctp_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

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

#include <sctp/sctp.api.c>
clib_error_t *
sctp_plugin_api_hookup (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  sctp_main.msg_id_base = setup_message_id_table ();

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
