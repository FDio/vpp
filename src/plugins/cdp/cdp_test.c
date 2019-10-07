/*
 * cdp.c - vpp-api-test cdp protocol plug-in
 *
 * Copyright (c) 2011-2018 by Cisco and/or its affiliates.
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

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <cdp/cdp.api_enum.h>
#include <cdp/cdp.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} cdp_test_main_t;

cdp_test_main_t cdp_test_main;

#define __plugin_msg_base cdp_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                                       \
_(CDP_ENABLE_DISABLE_REPLY, cdp_enable_disable_reply)

static int
api_cdp_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  int enable_disable = 1;
  vl_api_cdp_enable_disable_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "disable"))
	enable_disable = 0;
      else if (unformat (i, "enable"))
	enable_disable = 1;
      else
	break;
    }

  /* Construct the API message */
  M (CDP_ENABLE_DISABLE, mp);
  mp->enable_disable = enable_disable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#include <cdp/cdp.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
