/*
 * tmc.c - skeleton vpp engine plug-in
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>	/* VLIB_PLUGIN_REGISTER */
#include <tmc/tmc.h>
#include <tmc/tmc.api_enum.h>
#include <tmc/tmc.api_types.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>	/* VPP_BUILD_VER */


#define REPLY_MSG_ID_BASE tmc_base_msg_id
#include <vlibapi/api_helper_macros.h>

/**
 * Base message ID for the plugin
 */
static u32 tmc_base_msg_id;

/* API message handler */
static void vl_api_tmc_enable_disable_t_handler
  (vl_api_tmc_enable_disable_t * mp)
{
  vl_api_tmc_enable_disable_reply_t *rmp;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->is_enable)
    rv = tmc_enable (ntohl (mp->sw_if_index), ntohs (mp->mss));
  else
    rv = tmc_disable (ntohl (mp->sw_if_index));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_TMC_ENABLE_DISABLE_REPLY);
}

/* API definitions */
#include <vnet/format_fns.h>
#include <tmc/tmc.api.c>

/* Set up the API message handling tables */
static clib_error_t *
tmc_plugin_api_hookup (vlib_main_t * vm)
{
  tmc_base_msg_id = setup_message_id_table ();

  return 0;
}

static clib_error_t *
tmc_api_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  error = tmc_plugin_api_hookup (vm);

  return error;
}

VLIB_INIT_FUNCTION (tmc_api_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "TCP MSS clamping (tmc) plugin",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
