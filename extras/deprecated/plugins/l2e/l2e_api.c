/*
 *------------------------------------------------------------------
 * l2e_api.c - layer 2 emulation api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vpp/app/version.h>

#include <l2e/l2e.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <l2e/l2e.api_enum.h>
#include <l2e/l2e.api_types.h>

#include <vlibapi/api_helper_macros.h>

#define L2E_MSG_BASE l2em->msg_id_base

static void
vl_api_l2_emulation_t_handler (vl_api_l2_emulation_t * mp)
{
  l2_emulation_main_t *l2em = &l2_emulation_main;
  vl_api_l2_emulation_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (mp->enable)
    l2_emulation_enable (sw_if_index);
  else
    l2_emulation_disable (sw_if_index);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2_EMULATION_REPLY + L2E_MSG_BASE);
}

#include <l2e/l2e.api.c>
static clib_error_t *
l2e_init (vlib_main_t * vm)
{
  l2_emulation_main_t *l2em = &l2_emulation_main;

  /* Ask for a correctly-sized block of API message decode slots */
  l2em->msg_id_base = setup_message_id_table ();

  return (NULL);
}

VLIB_API_INIT_FUNCTION (l2e_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Layer 2 (L2) Emulation",
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
