/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vlibmemory/api.h>
#include <vpp/api/vpe.api_enum.h>
#include <vpp/api/vpe.api_types.h>

#include <vnet/api_errno.h>

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

static u32
find_msg_id (char *msg)
{
  api_main_t *am = vlibapi_get_main ();
  hash_pair_t *hp;

  hash_foreach_pair (hp, am->msg_index_by_name_and_crc, ({
		       char *key = (char *) hp->key; // key format: name_crc
		       int msg_name_len = strlen (key) - 9; // ignore crc
		       if (strlen (msg) == msg_name_len &&
			   strncmp (msg, (char *) hp->key, msg_name_len) == 0)
			 {
			   return (u32) hp->value[0];
			 }
		     }));
  return 0;
}

typedef struct
{
  /* API client index to be used when calling API from main thread */
  u32 api_client_index;
} internal_api_main_t;

internal_api_main_t internal_api_main;
u32
internal_api_get_client_index ()
{
  return (&internal_api_main)->api_client_index;
}
/*
 * We create a unique client registration for all the internal calls.
 * The client index is hardcoded to prevent interfering with other client
 * indexes. The reference to the regisration is available from the main
 * thread in am->my_registration.
 * This registration doesn't use shared memory queues. API calls are direct
 * calls and repys are processed synchronously.
 *
 * We introduced a new type to prevent VPP from sending pings to itself.
 *
 * Registrating the unique client could be done globally (VPP init).
 */
u32
internal_api_register_client ()
{
  api_main_t *am = vlibapi_get_main ();
  u32 client_index;
  vl_api_registration_t *regp =
    clib_mem_alloc (sizeof (vl_api_registration_t));
  clib_memset (regp, 0, sizeof (*regp));
  regp->registration_type = REGISTRATION_TYPE_INTERNAL;
  client_index = (1 << 30);
  regp->name = (u8 *) "INTERNAL_API_CLIENT";
  am->my_registration = regp;
  return client_index;
}

int
sh_version_api_call ()
{
  u32 api_client_index = internal_api_get_client_index ();
  vl_api_show_version_t *mp =
    vl_msg_api_alloc (sizeof (vl_api_show_version_t));
  int rv;
  /* Check that we are in main thread */
  ASSERT (vlib_get_thread_index () == 0);
  mp->_vl_msg_id = htons (find_msg_id ("show_version"));
  mp->client_index = api_client_index;
  mp->context = 0;

  vl_msg_api_handler ((void *) mp, vl_msg_api_max_length (mp));

  vl_api_registration_t *rp =
    vl_api_client_index_to_registration (api_client_index);
  if (!rp)
    {
      clib_warning ("Internal API client not registered");
      return VNET_API_ERROR_INVALID_REGISTRATION;
    }
  vl_api_show_version_reply_t *rpm = (vl_api_show_version_reply_t *) rp->buf;
  if (!rpm || rpm->_vl_msg_id != ntohs (find_msg_id ("show_version_reply")))
    {
      clib_warning ("No API answer received");
      return VNET_API_ERROR_INVALID_REGISTRATION;
    }
  rv = rpm->retval;
  if (rv != 0)
    clib_warning ("Return value: %d", rv);
  vlib_cli_output (
    vlib_get_main (),
    "show_version_reply: program: `%s', version: `%s', build directory: "
    "`%s', build date: `%s'\n",
    rpm->program, rpm->version, rpm->build_directory, rpm->build_date);
  vl_msg_api_free (rpm);
  return rv;
}

static clib_error_t *
test_api_internal_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  int rv = sh_version_api_call ();
  if (rv != 0)
    return clib_error_return (0, "API call failed");
  return 0;
}
VLIB_CLI_COMMAND (test_api_command, static) = {
  .path = "test api internal",
  .short_help = "test api internal",
  .function = test_api_internal_fn,
};

static clib_error_t *
internal_api_init (vlib_main_t *vm)
{
  /* initialize binary API */
  (&internal_api_main)->api_client_index = internal_api_register_client ();

  return 0;
}

VLIB_INIT_FUNCTION (internal_api_init);
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Call an internal API example",
  .default_disabled = 0,
};