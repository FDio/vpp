;;; plugin-main-skel.el - vpp engine plug-in "main.c" skeleton
;;;
;;; Copyright (c) 2016 Cisco and/or its affiliates.
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at:
;;;
;;;     http://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions and
;;; limitations under the License.

(require 'skeleton)

(define-skeleton skel-plugin-main
"Insert a plug-in 'main.c' skeleton "
nil
'(if (not (boundp 'plugin-name))
     (setq plugin-name (read-string "Plugin name: ")))
'(setq PLUGIN-NAME (upcase plugin-name))
'(setq capital-oh-en "ON")
'(setq main-p (concat (substring plugin-name 0 1) "mp"))
"/*
 * " plugin-name ".c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
 * Licensed under the Apache License, Version 2.0 (the \"License\");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an \"AS IS\" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <" plugin-name "/" plugin-name ".h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <" plugin-name "/" plugin-name ".api_enum.h>
#include <" plugin-name "/" plugin-name ".api_types.h>

#define REPLY_MSG_ID_BASE " main-p "->msg_id_base
#include <vlibapi/api_helper_macros.h>

" plugin-name "_main_t " plugin-name "_main;

/* Action function shared between message handler and debug CLI */

int " plugin-name "_enable_disable (" plugin-name "_main_t * " main-p ", u32 sw_if_index,
                                   int enable_disable)
{
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (" main-p "->vnet_main->interface_main.sw_interfaces,
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (" main-p "->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  " plugin-name "_create_periodic_process (" main-p ");

  vnet_feature_enable_disable (\"device-input\", \"" plugin-name "\",
                               sw_if_index, enable_disable, 0, 0);

  /* Send an event to enable/disable the periodic scanner process */
  vlib_process_signal_event (" main-p "->vlib_main,
                             " main-p"->periodic_node_index,
                             " PLUGIN-NAME"_EVENT_PERIODIC_ENABLE_DISABLE,
                            (uword)enable_disable);
  return rv;
}

static clib_error_t *
" plugin-name "_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  " plugin-name "_main_t * " main-p " = &" plugin-name "_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, \"disable\"))
        enable_disable = 0;
      else if (unformat (input, \"%U\", unformat_vnet_sw_interface,
                         " main-p "->vnet_main, &sw_if_index))
        ;
      else
        break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, \"Please specify an interface...\");

  rv = " plugin-name "_enable_disable (" main-p ", sw_if_index, enable_disable);

  switch(rv)
    {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return
      (0, \"Invalid interface, only works on physical ports\");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, \"Device driver doesn't support redirection\");
    break;

  default:
    return clib_error_return (0, \"" plugin-name "_enable_disable returned %d\",
                              rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (" plugin-name "_enable_disable_command, static) =
{
  .path = \"" plugin-name " enable-disable\",
  .short_help =
  \"" plugin-name " enable-disable <interface-name> [disable]\",
  .function = " plugin-name "_enable_disable_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_" plugin-name "_enable_disable_t_handler
(vl_api_" plugin-name "_enable_disable_t * mp)
{
  vl_api_" plugin-name "_enable_disable_reply_t * rmp;
  " plugin-name "_main_t * " main-p " = &" plugin-name "_main;
  int rv;

  rv = " plugin-name "_enable_disable (" main-p ", ntohl(mp->sw_if_index),
                                      (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_" PLUGIN-NAME "_ENABLE_DISABLE_REPLY);
}

/* API definitions */
#include <" plugin-name "/" plugin-name ".api.c>

static clib_error_t * " plugin-name "_init (vlib_main_t * vm)
{
  " plugin-name "_main_t * " main-p " = &" plugin-name "_main;
  clib_error_t * error = 0;

  " main-p "->vlib_main = vm;
  " main-p "->vnet_main = vnet_get_main();

  /* Add our API messages to the global name_crc hash table */
  " main-p "->msg_id_base = setup_message_id_table ();

  return error;
}

VLIB_INIT_FUNCTION (" plugin-name "_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (" plugin-name ", static) =
{
  .arc_name = \"device-input\",
  .node_name = \"" plugin-name "\",
  .runs_before = VNET_FEATURES (\"ethernet-input\"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = \"" plugin-name " plugin description goes here\",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: " capital-oh-en "
 *
 * Local Variables:
 * eval: (c-set-style \"gnu\")
 * End:
 */
")
