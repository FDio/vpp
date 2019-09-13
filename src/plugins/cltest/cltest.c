/*
 * cltest.c - Classifier-based packet trace filter
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <cltest/cltest.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

/* define message IDs */
#include <cltest/cltest_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <cltest/cltest_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <cltest/cltest_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <cltest/cltest_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <cltest/cltest_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE cmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

cltest_main_t cltest_main;

/* List of message types that this plugin understands */

#define foreach_cltest_plugin_api_msg                           \
_(CLTEST_ENABLE_DISABLE, cltest_enable_disable)

/* Action function shared between message handler and debug CLI */

int
cltest_enable_disable (cltest_main_t * cmp, u32 sw_if_index,
		       int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (cmp->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (cmp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("device-input", "cltest",
			       sw_if_index, enable_disable, 0, 0);
  return rv;
}

static clib_error_t *
cltest_enable_disable_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  cltest_main_t *cmp = &cltest_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 cmp->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = cltest_enable_disable (cmp, sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "cltest_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cltest_enable_disable_command, static) =
{
  .path = "cltest enable-disable",
  .short_help =
  "cltest enable-disable <interface-name> [disable]",
  .function = cltest_enable_disable_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_cltest_enable_disable_t_handler
  (vl_api_cltest_enable_disable_t * mp)
{
  vl_api_cltest_enable_disable_reply_t *rmp;
  cltest_main_t *cmp = &cltest_main;
  int rv;

  rv = cltest_enable_disable (cmp, ntohl (mp->sw_if_index),
			      (int) (mp->enable_disable));

  REPLY_MACRO (VL_API_CLTEST_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
cltest_plugin_api_hookup (vlib_main_t * vm)
{
  cltest_main_t *cmp = &cltest_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + cmp->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_cltest_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <cltest/cltest_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (cltest_main_t * cmp, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + cmp->msg_id_base);
  foreach_vl_msg_name_crc_cltest;
#undef _
}

static clib_error_t *
cltest_init (vlib_main_t * vm)
{
  cltest_main_t *cmp = &cltest_main;
  clib_error_t *error = 0;
  u8 *name;

  cmp->vlib_main = vm;
  cmp->vnet_main = vnet_get_main ();

  name = format (0, "cltest_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  cmp->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = cltest_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (cmp, &api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (cltest_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (cltest, static) =
{
  .arc_name = "device-input",
  .node_name = "cltest",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Classifier-based packet trace filter function tester",
  .default_disabled = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
