/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/sfdp/sfdp.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <sfdp_services/base/classifier_input/classifier_input.h>
#include <sfdp_services/base/classifier_input/classifier_input.api_enum.h>
#include <sfdp_services/base/classifier_input/classifier_input.api_types.h>

#define REPLY_MSG_ID_BASE scim->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_sfdp_classifier_input_set_table_t_handler (vl_api_sfdp_classifier_input_set_table_t *mp)
{
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;
  u32 table_index = ntohl (mp->table_index);
  u8 is_del = mp->is_del;
  int rv = 0;

  rv = sfdp_classifier_input_set_table (table_index, is_del);

  vl_api_sfdp_classifier_input_set_table_reply_t *rmp;
  REPLY_MACRO (VL_API_SFDP_CLASSIFIER_INPUT_SET_TABLE_REPLY);
}

static void
vl_api_sfdp_classifier_input_add_del_session_t_handler (
  vl_api_sfdp_classifier_input_add_del_session_t *mp)
{
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;
  u32 tenant_id = ntohl (mp->tenant_id);
  u32 match_len = ntohl (mp->match_len);
  u8 is_del = mp->is_del;

  int rv = sfdp_classifier_input_add_del_session (tenant_id, mp->match, match_len, is_del);

  vl_api_sfdp_classifier_input_add_del_session_reply_t *rmp;
  REPLY_MACRO (VL_API_SFDP_CLASSIFIER_INPUT_ADD_DEL_SESSION_REPLY);
}

static void
vl_api_sfdp_classifier_input_enable_disable_t_handler (
  vl_api_sfdp_classifier_input_enable_disable_t *mp)
{
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;
  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  u8 is_disable = mp->is_disable;
  u8 is_ip6 = mp->is_ip6;
  int rv = 0;

  rv = sfdp_classifier_input_enable_disable_interface (sw_if_index, !is_disable, is_ip6);

  vl_api_sfdp_classifier_input_enable_disable_reply_t *rmp;
  REPLY_MACRO (VL_API_SFDP_CLASSIFIER_INPUT_ENABLE_DISABLE_REPLY);
}

#include <sfdp_services/base/classifier_input/classifier_input.api.c>
static clib_error_t *
sfdp_classifier_input_api_hookup (vlib_main_t *vm)
{
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;
  scim->msg_id_base = setup_message_id_table ();
  return 0;
}
VLIB_API_INIT_FUNCTION (sfdp_classifier_input_api_hookup);
