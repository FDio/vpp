/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

/* mdata.c - buffer metadata change tracker vpp-api-test plug-in */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <stdbool.h>

#define __plugin_msg_base mdata_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <mdata/mdata.api_enum.h>
#include <mdata/mdata.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} mdata_test_main_t;

mdata_test_main_t mdata_test_main;

static int
api_mdata_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  int enable_disable = 1;
  vl_api_mdata_enable_disable_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "disable"))
	enable_disable = 0;
      else
	break;
    }

  /* Construct the API message */
  M (MDATA_ENABLE_DISABLE, mp);
  mp->enable_disable = enable_disable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/*
 * List of messages that the mdata test plugin sends,
 * and that the data plane plugin processes
 */
#include <mdata/mdata.api_test.c>
