/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

/*
 * gso_api.c - Generic Segmentation Offload api
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/gso/gso.h>

#include <vnet/format_fns.h>
#include <vnet/gso/gso.api_enum.h>
#include <vnet/gso/gso.api_types.h>

#define REPLY_MSG_ID_BASE gso_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
  vl_api_feature_gso_enable_disable_t_handler
  (vl_api_feature_gso_enable_disable_t * mp)
{
  vl_api_feature_gso_enable_disable_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    vnet_sw_interface_gso_enable_disable (ntohl (mp->sw_if_index),
					  mp->enable_disable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_FEATURE_GSO_ENABLE_DISABLE_REPLY);
}

#include <vnet/gso/gso.api.c>

static clib_error_t *
feature_gso_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  gso_main.msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (feature_gso_api_hookup);
