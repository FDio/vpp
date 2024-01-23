/*
 * pvti.c - skeleton vpp engine plug-in
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
#include <vnet/plugin/plugin.h>
#include <pvti/pvti.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <pvti/pvti.api_enum.h>
#include <pvti/pvti.api_types.h>

#include <pvti/pvti_if.h>

#define REPLY_MSG_ID_BASE pmp->msg_id_base
#include <vlibapi/api_helper_macros.h>
#include <vnet/ip/ip_format_fns.h>

pvti_main_t pvti_main;

/* Action function shared between message handler and debug CLI */

int
pvti_enable_disable (pvti_main_t *pmp, u32 sw_if_index, int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (pmp->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (pmp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  pvti_create_periodic_process (pmp);

  vnet_feature_enable_disable ("device-input", "pvti", sw_if_index,
			       enable_disable, 0, 0);

  /* Send an event to enable/disable the periodic scanner process */
  vlib_process_signal_event (pmp->vlib_main, pmp->periodic_node_index,
			     PVTI_EVENT_PERIODIC_ENABLE_DISABLE,
			     (uword) enable_disable);
  return rv;
}

static clib_error_t *
pvti_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  pvti_main_t *pmp = &pvti_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 pmp->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = pvti_enable_disable (pmp, sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (
	0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "pvti_enable_disable returned %d", rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (pvti_enable_disable_command, static) = {
  .path = "pvti enable-disable",
  .short_help = "pvti enable-disable <interface-name> [disable]",
  .function = pvti_enable_disable_command_fn,
};

static clib_error_t *
pvti_interface_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  // pvti_main_t * pmp = &pvti_main;
  u32 sw_if_index = ~0;
  // int enable_disable = 1;
  int rv = 0;
  ip_address_t peer_ip = { 0 };
  ip_address_t local_ip = { 0 };
  u32 peer_port;
  u32 local_port = 12345;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "peer %U %d", unformat_ip_address, &peer_ip,
		    &peer_port))
	;
      else
	break;
    }
  /*
    if (sw_if_index == ~0)
      return clib_error_return (0, "Please specify an interface...");
   */

  rv =
    pvti_if_create (&local_ip, local_port, &peer_ip, peer_port, &sw_if_index);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (
	0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "pvti_enable_disable returned %d", rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (pvti_interface_create_command, static) = {
  .path = "pvti interface create",
  .short_help =
    "pvti interface create peer <remote-ip> <remote-port> <local-port>",
  .function = pvti_interface_create_command_fn,
};

static clib_error_t *
pvti_show_interface_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  pvti_if_t *pvti_if;
  vec_foreach (pvti_if, pvti_main.if_pool)
    {
      int index = pvti_if - pvti_main.if_pool;
      vlib_cli_output (vm, "%U", format_pvti_if, index);
    };
  return 0;
}

VLIB_CLI_COMMAND (pvti_show_interface_command, static) = {
  .path = "show pvti interface",
  .short_help = "show pvti interface",
  .function = pvti_show_interface_command_fn,
};

/* API definitions */
//#include <pvti/pvti.api.c>
//
//
void pvti_api_init ();

static clib_error_t *
pvti_init (vlib_main_t *vm)
{
  pvti_main_t *pmp = &pvti_main;
  clib_error_t *error = 0;
  clib_warning ("pvti init");

  pmp->vlib_main = vm;
  pmp->vnet_main = vnet_get_main ();

  pvti_api_init ();
  return error;
}

VLIB_INIT_FUNCTION (pvti_init);

VNET_FEATURE_INIT (pvti, static) = {
  .arc_name = "device-input",
  .node_name = "pvti",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "pvti plugin description goes here",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
