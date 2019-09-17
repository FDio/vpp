/*
 * builtinurl.c - skeleton vpp engine plug-in
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
#include <builtinurl/builtinurl.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

/* define message IDs */
#include <builtinurl/builtinurl_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <builtinurl/builtinurl_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <builtinurl/builtinurl_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <builtinurl/builtinurl_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <builtinurl/builtinurl_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE bmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

builtinurl_main_t builtinurl_main;

/* List of message types that this plugin understands */

#define foreach_builtinurl_plugin_api_msg                           \
_(BUILTINURL_ENABLE, builtinurl_enable)

/* Action function shared between message handler and debug CLI */

int
builtinurl_enable (builtinurl_main_t * bmp)
{
  void (*fp) (void *, char *, int);

  if (bmp->initialized)
    return 0;

  /* Look up the builtin URL registration handler */
  fp = vlib_get_plugin_symbol
    ("http_static_plugin.so", "http_static_server_register_builtin_handler");

  /* Most likely, the http_static plugin isn't loaded. Done. */
  if (fp == 0)
    return VNET_API_ERROR_NO_SUCH_TABLE;

  bmp->register_handler = fp;
  builtinurl_handler_init (bmp);
  bmp->initialized = 1;

  return 0;
}

static clib_error_t *
builtinurl_enable_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  builtinurl_main_t *bmp = &builtinurl_main;

  int rv;

  rv = builtinurl_enable (bmp);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_TABLE:
      return clib_error_return
	(0, "http_static_server_register_builtin_handler undefined");
      break;

    default:
      return clib_error_return (0, "builtinurl_enable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (builtinurl_enable_command, static) =
{
  .path = "builtinurl enable",
  .short_help = "Turn on builtin http/https GET and POST urls",
  .function = builtinurl_enable_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_builtinurl_enable_t_handler
  (vl_api_builtinurl_enable_t * mp)
{
  vl_api_builtinurl_enable_reply_t *rmp;
  builtinurl_main_t *bmp = &builtinurl_main;
  int rv;

  rv = builtinurl_enable (bmp);

  REPLY_MACRO (VL_API_BUILTINURL_ENABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
builtinurl_plugin_api_hookup (vlib_main_t * vm)
{
  builtinurl_main_t *bmp = &builtinurl_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + bmp->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_builtinurl_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <builtinurl/builtinurl_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (builtinurl_main_t * bmp, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + bmp->msg_id_base);
  foreach_vl_msg_name_crc_builtinurl;
#undef _
}

static clib_error_t *
builtinurl_init (vlib_main_t * vm)
{
  builtinurl_main_t *bmp = &builtinurl_main;
  clib_error_t *error = 0;
  u8 *name;

  bmp->vlib_main = vm;
  bmp->vnet_main = vnet_get_main ();

  name = format (0, "builtinurl_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  bmp->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = builtinurl_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (bmp, &api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (builtinurl_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "vpp built-in URL support",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
