/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>
#include <vapi/vapi.h>

#include <vapi/memclnt.api.vapi.h>
#include <vapi/vlib.api.vapi.h>
#include <vapi/vpe.api.vapi.h>

/*
 * Example of how to call the VPP binary API from an internal API client.
 * Using the VAPI C language binding.
 */

DEFINE_VAPI_MSG_IDS_VPE_API_JSON;

vapi_ctx_t ctx;
bool connected = false;

/*
 * Connect an VPP binary API client to VPP API
 */
static int
connect_to_vpp (void)
{
  if (vapi_ctx_alloc (&ctx) != VAPI_OK)
    {
      clib_warning ("ctx_alloc failed");
      return -1;
    }
  if (vapi_connect_from_vpp (ctx, "apifromplugin", 64, 32, VAPI_MODE_NONBLOCKING,
		     true) != VAPI_OK)
    {
      clib_warning ("vapi_connect failed");
      return -1;
    }

  clib_warning ("Connected to VPP");
  return 0;
}

/*
 * Gets called when the show_version_reply message is received
 */
vapi_error_e
show_version_cb (vapi_ctx_t ctx, void *caller_ctx, vapi_error_e rv,
		 bool is_last, vapi_payload_show_version_reply *p)
{
  if (rv != VAPI_OK)
    clib_warning ("Return value: %d", rv);
  vlib_cli_output (
    vlib_get_main (),
    "show_version_reply: program: `%s', version: `%s', build directory: "
    "`%s', build date: `%s'\n",
    p->program, p->version, p->build_directory, p->build_date);
  return VAPI_OK;
}

static clib_error_t *
test_api_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  int called;
  if (!connected)
    {
      if (connect_to_vpp () != 0)
	return clib_error_return (0, "API connection failed");
      connected = true;
    }
  vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
  vapi_error_e rv = vapi_show_version (ctx, sv, show_version_cb, &called);
  if (rv != VAPI_OK)
    return clib_error_return (0, "API call failed");
  return 0;
}

VLIB_CLI_COMMAND (test_api_command, static) = {
  .path = "test api command",
  .short_help = "test api command",
  .function = test_api_command_fn,
};

VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Call an API from plugin example",
  .default_disabled = 0,
};
