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

/* define message IDs */
#include <" plugin-name "/" plugin-name "_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <" plugin-name "/" plugin-name "_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <" plugin-name "/" plugin-name "_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <" plugin-name "/" plugin-name "_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <" plugin-name "/" plugin-name "_all_api_h.h>
#undef vl_api_version

/*
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */

#define REPLY_MACRO(t)                                          \\
do {                                                            \\
    unix_shared_memory_queue_t * q =                            \\
    vl_api_client_index_to_input_queue (mp->client_index);      \\
    if (!q)                                                     \\
        return;                                                 \\
                                                                \\
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \\
    rmp->_vl_msg_id = ntohs((t)+sm->msg_id_base);               \\
    rmp->context = mp->context;                                 \\
    rmp->retval = ntohl(rv);                                    \\
                                                                \\
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \\
} while(0);


/* List of message types that this plugin understands */

#define foreach_" plugin-name "_plugin_api_msg                           \\
_(" PLUGIN-NAME "_ENABLE_DISABLE, " plugin-name "_enable_disable)

/* Action function shared between message handler and debug CLI */

int " plugin-name "_enable_disable (" plugin-name "_main_t * sm, u32 sw_if_index,
                                   int enable_disable)
{
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (sm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable (\"device-input\", \"" plugin-name "\",
                               sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
" plugin-name "_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  " plugin-name "_main_t * sm = &" plugin-name "_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat (input, \"disable\"))
        enable_disable = 0;
      else if (unformat (input, \"%U\", unformat_vnet_sw_interface,
                         sm->vnet_main, &sw_if_index))
        ;
      else
        break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, \"Please specify an interface...\");

  rv = " plugin-name "_enable_disable (sm, sw_if_index, enable_disable);

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
  " plugin-name "_main_t * sm = &" plugin-name "_main;
  int rv;

  rv = " plugin-name "_enable_disable (sm, ntohl(mp->sw_if_index),
                                      (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_" PLUGIN-NAME "_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
" plugin-name "_plugin_api_hookup (vlib_main_t *vm)
{
  " plugin-name "_main_t * sm = &" plugin-name "_main;
#define _(N,n)                                                  \\
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \\
                           #n,					\\
                           vl_api_##n##_t_handler,              \\
                           vl_noop_handler,                     \\
                           vl_api_##n##_t_endian,               \\
                           vl_api_##n##_t_print,                \\
                           sizeof(vl_api_##n##_t), 1);
    foreach_" plugin-name "_plugin_api_msg;
#undef _

    return 0;
}

#define vl_msg_name_crc_list
#include <" plugin-name "/" plugin-name "_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (" plugin-name "_main_t * sm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_" plugin-name" ;
#undef _
}

static clib_error_t * " plugin-name "_init (vlib_main_t * vm)
{
  " plugin-name "_main_t * sm = &" plugin-name "_main;
  clib_error_t * error = 0;
  u8 * name;

  name = format (0, \"" plugin-name "_%08x%c\", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = " plugin-name "_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (sm, &api_main);

  vec_free(name);

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

