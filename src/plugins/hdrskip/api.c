/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <hdrskip/hdrskip.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <hdrskip/hdrskip.api_enum.h>
#include <hdrskip/hdrskip.api_types.h>

#define REPLY_MSG_ID_BASE hsm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_hdrskip_input_enable_disable_t_handler
  (vl_api_hdrskip_input_enable_disable_t *mp)
{
  vl_api_hdrskip_input_enable_disable_reply_t *rmp;
  hdrskip_main_t *hsm = &hdrskip_main;
  u32 sw_if_index;
  u32 skip_bytes;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  skip_bytes = clib_net_to_host_u32 (mp->skip_bytes);

  rv = hdrskip_input_enable_disable (hsm, sw_if_index,
				     (int) mp->enable_disable,
				     skip_bytes, 1);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_HDRSKIP_INPUT_ENABLE_DISABLE_REPLY);
}

static void
vl_api_hdrskip_output_enable_disable_t_handler
  (vl_api_hdrskip_output_enable_disable_t *mp)
{
  vl_api_hdrskip_output_enable_disable_reply_t *rmp;
  hdrskip_main_t *hsm = &hdrskip_main;
  u32 sw_if_index;
  u32 restore_bytes;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  restore_bytes = clib_net_to_host_u32 (mp->restore_bytes);

  rv = hdrskip_output_enable_disable (hsm, sw_if_index,
				      (int) mp->enable_disable,
				      restore_bytes, 1);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_HDRSKIP_OUTPUT_ENABLE_DISABLE_REPLY);
}

#include <hdrskip/hdrskip.api.c>

static clib_error_t *
hdrskip_api_hookup (vlib_main_t *vm)
{
  hdrskip_main_t *hsm = &hdrskip_main;

  hsm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (hdrskip_api_hookup);
