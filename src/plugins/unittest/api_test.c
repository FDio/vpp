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

/*
 * Connect an VPP binary API client to VPP API
 */
static vapi_ctx_t
connect_to_vpp (void)
{
  vapi_ctx_t ctx;
  if (vapi_ctx_alloc (&ctx) != VAPI_OK)
    {
      clib_warning ("ctx_alloc failed");
      return 0;
    }
  if (vapi_connect_from_vpp (ctx, "apifromplugin", 64, 32, VAPI_MODE_BLOCKING,
			     true) != VAPI_OK)
    {
      clib_warning ("vapi_connect failed");
      vapi_ctx_free (ctx);
      return 0;
    }
  return ctx;
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
  fformat (
    stdout,
    "show_version_reply: program: `%s', version: `%s', build directory: "
    "`%s', build date: `%s'\n",
    p->program, p->version, p->build_directory, p->build_date);
  return VAPI_OK;
}

static void *
api_show_version_blocking_fn (void *args)
{
  vapi_ctx_t ctx;

  if ((ctx = connect_to_vpp ()) == 0)
    return clib_error_return (0, "API connection failed");

  int called;
  vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
  vapi_error_e vapi_rv = vapi_show_version (ctx, sv, show_version_cb, &called);
  if (vapi_rv != VAPI_OK)
    clib_warning ("call failed");

  vapi_disconnect_from_vpp (ctx);
  vapi_ctx_free (ctx);

  return 0;
}

static clib_error_t *
test_api_test_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  /* Run call in a pthread */
  pthread_t thread;
  int rv = pthread_create (&thread, NULL, api_show_version_blocking_fn, 0);
  if (rv)
    {
      return clib_error_return (0, "API call failed");
    }
  return 0;
}

VLIB_CLI_COMMAND (test_api_command, static) = {
  .path = "test api internal",
  .short_help = "test internal api client",
  .function = test_api_test_command_fn,
};
