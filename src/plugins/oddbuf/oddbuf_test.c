/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 by Cisco and/or its affiliates.
 */

/* oddbuf.c - awkward chained buffer geometry test tool */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <stdbool.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <oddbuf/oddbuf.api_enum.h>
#include <oddbuf/oddbuf.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} oddbuf_test_main_t;

oddbuf_test_main_t oddbuf_test_main;

#define __plugin_msg_base oddbuf_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

static int
api_oddbuf_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  int enable_disable = 1;
  u32 sw_if_index = ~0;
  vl_api_oddbuf_enable_disable_t *mp;
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
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name / explicit sw_if_index number \n");
      return -99;
    }

  /* Construct the API message */
  M (ODDBUF_ENABLE_DISABLE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable_disable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#include <oddbuf/oddbuf.api_test.c>
