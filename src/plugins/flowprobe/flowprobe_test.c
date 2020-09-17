/*
 * flowprobe.c - skeleton vpp-api-test plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <flowprobe/flowprobe.h>

#define __plugin_msg_base flowprobe_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/**
 * @file vpp_api_test plugin
 */

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <flowprobe/flowprobe.api_enum.h>
#include <flowprobe/flowprobe.api_types.h>
#include <vpp/api/vpe.api_types.h>

typedef struct
{
    /** API message ID base */
  u16 msg_id_base;
  u32 ping_id;
    /** vat_main_t pointer */
  vat_main_t *vat_main;
} flowprobe_test_main_t;

flowprobe_test_main_t flowprobe_test_main;

static int
api_flowprobe_tx_interface_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  int enable_disable = 1;
  u8 which = FLOW_VARIANT_IP4;
  u32 sw_if_index = ~0;
  vl_api_flowprobe_tx_interface_add_del_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "disable"))
	enable_disable = 0;
      else if (unformat (i, "ip4"))
	which = FLOW_VARIANT_IP4;
      else if (unformat (i, "ip6"))
	which = FLOW_VARIANT_IP6;
      else if (unformat (i, "l2"))
	which = FLOW_VARIANT_L2;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name / explicit sw_if_index number \n");
      return -99;
    }

  /* Construct the API message */
  M (FLOWPROBE_TX_INTERFACE_ADD_DEL, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = enable_disable;
  mp->which = which;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_flowprobe_params (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  u32 active_timer = ~0;
  u32 passive_timer = ~0;
  vl_api_flowprobe_params_t *mp;
  int ret;
  u8 record_flags = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "active %d", &active_timer))
	;
      else if (unformat (i, "passive %d", &passive_timer))
	;
      else if (unformat (i, "record"))
	while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	  {
	    if (unformat (i, "l2"))
	      record_flags |= FLOWPROBE_RECORD_FLAG_L2;
	    else if (unformat (i, "l3"))
	      record_flags |= FLOWPROBE_RECORD_FLAG_L3;
	    else if (unformat (i, "l4"))
	      record_flags |= FLOWPROBE_RECORD_FLAG_L4;
	    else
	      break;
	  }
      else
	break;
    }

  if (passive_timer > 0 && active_timer > passive_timer)
    {
      errmsg ("Passive timer has to be greater than active one...\n");
      return -99;
    }

  /* Construct the API message */
  M (FLOWPROBE_PARAMS, mp);
  mp->record_flags = record_flags;
  mp->active_timer = ntohl (active_timer);
  mp->passive_timer = ntohl (passive_timer);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

static int
api_flowprobe_feature_dump (vat_main_t * vam)
{
  flowprobe_test_main_t *fm = &flowprobe_test_main;
  vl_api_flowprobe_feature_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;
  /* Construct the API message */
  M (FLOWPROBE_FEATURE_DUMP, mp);

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  if (!fm->ping_id)
    fm->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (fm->ping_id);
  mp_ping->client_index = vam->my_client_index;
  fformat (vam->ofp, "Sending ping id=%d\n", fm->ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_flowprobe_feature_details_t_handler (vl_api_flowprobe_feature_details_t
					    * mp)
{
  vat_main_t *vam = flowprobe_test_main.vat_main;

  fformat (vam->ofp, " interface %d ", mp->sw_if_index);

  if (mp->which == FLOW_VARIANT_IP4)
    fformat (vam->ofp, "ip4");
  else if (mp->which == FLOW_VARIANT_L2)
    fformat (vam->ofp, "l2");
  else if (mp->which == FLOW_VARIANT_IP6)
    fformat (vam->ofp, "ip6");

  fformat (vam->ofp, "\n");

  return;
}

static int
api_flowprobe_params_dump (vat_main_t * vam)
{
  flowprobe_test_main_t *fm = &flowprobe_test_main;
  vl_api_flowprobe_params_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;
  /* Construct the API message */
  M (FLOWPROBE_PARAMS_DUMP, mp);

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  if (!fm->ping_id)
    fm->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (fm->ping_id);
  mp_ping->client_index = vam->my_client_index;
  fformat (vam->ofp, "Sending ping id=%d\n", fm->ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void vl_api_flowprobe_params_details_t_handler
  (vl_api_flowprobe_params_details_t * mp)
{
  vat_main_t *vam = flowprobe_test_main.vat_main;

  if (mp->record_flags & FLOWPROBE_RECORD_FLAG_L2)
    fformat (vam->ofp, " l2");
  if (mp->record_flags & FLOWPROBE_RECORD_FLAG_L3)
    fformat (vam->ofp, " l3");
  if (mp->record_flags & FLOWPROBE_RECORD_FLAG_L4)
    fformat (vam->ofp, " l4");
  if (mp->active_timer != (u32) ~ 0)
    fformat (vam->ofp, " active: %d", mp->active_timer);
  if (mp->passive_timer != (u32) ~ 0)
    fformat (vam->ofp, " passive: %d", mp->passive_timer);
  fformat (vam->ofp, "\n");

  return;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#include <flowprobe/flowprobe.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
