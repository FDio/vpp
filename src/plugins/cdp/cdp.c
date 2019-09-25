/*
 * cdp.c - cdp protocol plug-in
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <cdp/cdp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <cdp/cdp.api_enum.h>
#include <cdp/cdp.api_types.h>

#define REPLY_MSG_ID_BASE cm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* Action function shared between message handler and debug CLI */

int
cdp_enable_disable (cdp_main_t * cm, int enable_disable)
{
  int rv = 0;

  if (enable_disable)
    {
      vnet_cdp_create_periodic_process (cm);
      vlib_process_signal_event (cm->vlib_main, cm->cdp_process_node_index,
				 CDP_EVENT_ENABLE, 0);
    }
  else
    {
      vnet_cdp_create_periodic_process (cm);
      vlib_process_signal_event (cm->vlib_main, cm->cdp_process_node_index,
				 CDP_EVENT_DISABLE, 0);
    }
  cm->enabled = enable_disable;

  return rv;
}

static clib_error_t *
cdp_command_fn (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  cdp_main_t *cm = &cdp_main;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "enable"))
	enable_disable = 1;
      else
	break;
    }

  rv = cdp_enable_disable (cm, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "cdp_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cdp_command, static) =
{
  .path = "cdp",
  .short_help = "cdp enable | disable",
  .function = cdp_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_cdp_enable_disable_t_handler
  (vl_api_cdp_enable_disable_t * mp)
{
  vl_api_cdp_enable_disable_reply_t *rmp;
  cdp_main_t *cm = &cdp_main;
  int rv;

  rv = cdp_enable_disable (cm, (int) (mp->enable_disable));

  REPLY_MACRO (VL_API_CDP_ENABLE_DISABLE_REPLY);
}

#include <cdp/cdp.api.c>
static clib_error_t *
cdp_init (vlib_main_t * vm)
{
  cdp_main_t *cm = &cdp_main;

  cm->vlib_main = vm;

  /* Ask for a correctly-sized block of API message decode slots */
  cm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (cdp_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Cisco Discovery Protocol (CDP)",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
