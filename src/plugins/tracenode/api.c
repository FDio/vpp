/*
 * Copyright (c) 2023 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <tracenode/tracenode.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <tracenode/tracenode.api_enum.h>
#include <tracenode/tracenode.api_types.h>

#define REPLY_MSG_ID_BASE (tnm->msg_id_base)
#include <vlibapi/api_helper_macros.h>

static void
vl_api_tracenode_feature_t_handler (vl_api_tracenode_feature_t *mp)
{
  tracenode_main_t *tnm = &tracenode_main;
  vl_api_tracenode_feature_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = vnet_enable_disable_tracenode_feature (ntohl (mp->sw_if_index),
					      mp->is_pcap, mp->enable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_TRACENODE_FEATURE_REPLY);
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */