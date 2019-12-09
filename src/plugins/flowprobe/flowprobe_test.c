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

typedef struct
{
    /** API message ID base */
  u16 msg_id_base;
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
