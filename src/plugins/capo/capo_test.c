/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 */
/*
 *------------------------------------------------------------------
 * acl_test.c - test harness plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip.h>
#include <arpa/inet.h>

#include <vnet/ip/ip_format_fns.h>
#include <vnet/ethernet/ethernet_format_fns.h>

#define __plugin_msg_base capo_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

uword unformat_sw_if_index (unformat_input_t *input, va_list *args);

/* Declare message IDs */
#include <capo/capo.api_enum.h>
#include <capo/capo.api_types.h>
#define vl_endianfun /* define message structures */
#include <capo/capo.api.h>
#undef vl_endianfun

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} capo_test_main_t;

capo_test_main_t capo_test_main;

/* NAME: capo_get_version_reply */
static void
vl_api_capo_get_version_reply_t_handler (vl_api_capo_get_version_reply_t *mp)
{
  vat_main_t *vam = capo_test_main.vat_main;
  clib_warning ("Calico Policy plugin version: %d.%d", ntohl (mp->major),
		ntohl (mp->minor));
  vam->result_ready = 1;
}

/* NAME: capo_control_ping_reply */
static void
vl_api_capo_control_ping_reply_t_handler (vl_api_capo_control_ping_reply_t *mp)
{
  vat_main_t *vam = capo_test_main.vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }
}

/* NAME: ipset_create_reply */
static void
vl_api_capo_ipset_create_reply_t_handler (vl_api_capo_ipset_create_reply_t *mp)
{
  vat_main_t *vam = capo_test_main.vat_main;
  clib_warning ("Got ipset_create_reply...");
  vam->result_ready = 1;
}

/* NAME: rule_create_reply */
static void
vl_api_capo_rule_create_reply_t_handler (vl_api_capo_rule_create_reply_t *mp)
{
  vat_main_t *vam = capo_test_main.vat_main;
  clib_warning ("Got rule_create_reply...");
  vam->result_ready = 1;
}

/* NAME: policy_create_reply */
static void
vl_api_capo_policy_create_reply_t_handler (
  vl_api_capo_policy_create_reply_t *mp)
{
  vat_main_t *vam = capo_test_main.vat_main;
  clib_warning ("Got policy_create_reply...");
  vam->result_ready = 1;
}

/* NAME: capo_get_version */

static int
api_capo_get_version (vat_main_t *vam)
{
  capo_test_main_t *cptm = &capo_test_main;
  unformat_input_t *i = vam->input;
  vl_api_capo_get_version_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CAPO_GET_VERSION + cptm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* FIXME: do something here */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* NAME: capo_control_ping */

static int
api_capo_control_ping (vat_main_t *vam)
{
  capo_test_main_t *cptm = &capo_test_main;
  unformat_input_t *i = vam->input;
  vl_api_capo_control_ping_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CAPO_CONTROL_PING + cptm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* FIXME: do something here */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* NAME: ipset_create */

static int
api_capo_ipset_create (vat_main_t *vam)
{
  capo_test_main_t *cptm = &capo_test_main;
  unformat_input_t *i = vam->input;
  vl_api_capo_ipset_create_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CAPO_IPSET_CREATE + cptm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* FIXME: do something here */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* NAME: ipset_add_del_members */

static int
api_capo_ipset_add_del_members (vat_main_t *vam)
{
  capo_test_main_t *cptm = &capo_test_main;
  unformat_input_t *i = vam->input;
  vl_api_capo_ipset_add_del_members_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id =
    ntohs (VL_API_CAPO_IPSET_ADD_DEL_MEMBERS + cptm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* FIXME: do something here */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* NAME: ipset_delete */

static int
api_capo_ipset_delete (vat_main_t *vam)
{
  capo_test_main_t *cptm = &capo_test_main;
  unformat_input_t *i = vam->input;
  vl_api_capo_ipset_delete_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CAPO_IPSET_DELETE + cptm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* FIXME: do something here */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* NAME: rule_create */

static int
api_capo_rule_create (vat_main_t *vam)
{
  capo_test_main_t *cptm = &capo_test_main;
  unformat_input_t *i = vam->input;
  vl_api_capo_rule_create_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CAPO_RULE_CREATE + cptm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* FIXME: do something here */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* NAME: rule_update */

static int
api_capo_rule_update (vat_main_t *vam)
{
  capo_test_main_t *cptm = &capo_test_main;
  unformat_input_t *i = vam->input;
  vl_api_capo_rule_update_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CAPO_RULE_UPDATE + cptm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* FIXME: do something here */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* NAME: rule_delete */

static int
api_capo_rule_delete (vat_main_t *vam)
{
  capo_test_main_t *cptm = &capo_test_main;
  unformat_input_t *i = vam->input;
  vl_api_capo_rule_delete_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CAPO_RULE_DELETE + cptm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* FIXME: do something here */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* NAME: policy_create */

static int
api_capo_policy_create (vat_main_t *vam)
{
  capo_test_main_t *cptm = &capo_test_main;
  unformat_input_t *i = vam->input;
  vl_api_capo_policy_create_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CAPO_POLICY_CREATE + cptm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* FIXME: do something here */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* NAME: policy_update */

static int
api_capo_policy_update (vat_main_t *vam)
{
  capo_test_main_t *cptm = &capo_test_main;
  unformat_input_t *i = vam->input;
  vl_api_capo_policy_update_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CAPO_POLICY_UPDATE + cptm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* FIXME: do something here */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* NAME: policy_delete */

static int
api_capo_policy_delete (vat_main_t *vam)
{
  capo_test_main_t *cptm = &capo_test_main;
  unformat_input_t *i = vam->input;
  vl_api_capo_policy_delete_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CAPO_POLICY_DELETE + cptm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* FIXME: do something here */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* NAME: configure_policies */

static int
api_capo_configure_policies (vat_main_t *vam)
{
  capo_test_main_t *cptm = &capo_test_main;
  unformat_input_t *i = vam->input;
  vl_api_capo_configure_policies_t *mp;
  u32 msg_size = sizeof (*mp);
  int ret;

  vam->result_ready = 0;
  mp = vl_msg_api_alloc_as_if_client (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CAPO_CONFIGURE_POLICIES + cptm->msg_id_base);
  mp->client_index = vam->my_client_index;

  /* FIXME: do something here */

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define VL_API_LOCAL_SETUP_MESSAGE_ID_TABLE local_setup_message_id_table
static void
local_setup_message_id_table (vat_main_t *vam)
{
  // hash_set_mem (vam->function_by_name, "acl_add_replace_from_file",
  // api_capo_acl_add_replace_from_file); hash_set_mem (vam->help_by_name,
  // "acl_add_replace_from_file", "filename <file> [permit]
  // [append-default-permit]");
}

#include <capo/capo.api_test.c>
