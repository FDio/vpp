/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <tracenode/tracenode.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <tracenode/tracenode.api_enum.h>
#include <tracenode/tracenode.api_types.h>

#define REPLY_MSG_ID_BASE (tnm->msg_id_base)
#include <vlibapi/api_helper_macros.h>

static void
vl_api_tracenode_enable_disable_t_handler (
  vl_api_tracenode_enable_disable_t *mp)
{
  tracenode_main_t *tnm = &tracenode_main;
  vl_api_tracenode_enable_disable_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = tracenode_feature_enable_disable (ntohl (mp->sw_if_index), mp->is_pcap,
					 mp->enable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_TRACENODE_ENABLE_DISABLE_REPLY);
}

#include <tracenode/tracenode.api.c>

clib_error_t *
tracenode_plugin_api_hookup (vlib_main_t *vm)
{
  tracenode_main_t *tnm = &tracenode_main;

  /* ask for a correctly-sized block of API message decode slots */
  tnm->msg_id_base = setup_message_id_table ();

  return 0;
}
