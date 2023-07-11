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
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <tracenode/tracenode.h>
#include <vnet/feature/feature.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

#include <tracenode/tracenode.api_enum.h>
#include <tracenode/tracenode.api_types.h>

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static u16 msg_id_base;

static void
vl_api_tracenode_feature_t_handler (vl_api_tracenode_feature_t *mp)
{
  vl_api_tracenode_feature_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  u32 sw_if_index = ntohl (mp->sw_if_index);

  vnet_enable_disable_tracenode_feature (sw_if_index, mp->is_pcap, mp->enable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_TRACENODE_FEATURE_REPLY);
}

/* API definitions */
#include <tracenode/tracenode.api.c>

static clib_error_t *
tracenode_init (vlib_main_t *vm)
{
  /* Add our API messages to the global name_crc hash table */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (tracenode_init);
/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Tracing packet node",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
