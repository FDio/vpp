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
#include <vnet/plugin/plugin.h>
#include <tmc/tmc.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <tmc/tmc_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <tmc/tmc_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <tmc/tmc_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <tmc/tmc_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <tmc/tmc_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE tmc_base_msg_id
#include <vlibapi/api_helper_macros.h>

/**
 * Base message ID fot the plugin
 */
static u32 tmc_base_msg_id;

/* List of message types that this plugin understands */

#define foreach_tmc_plugin_api_msg                           \
_(MY_API_MSG, my_api_msg)

/* API message handler */
static void
vl_api_my_api_msg_t_handler (vl_api_my_api_msg_t * mp)
{
  vl_api_my_api_msg_reply_t *rmp;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  rv = 0;

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_MY_API_MSG_REPLY);
}

#define vl_msg_name_crc_list
#include <tmc/tmc_all_api_h.h>
#undef vl_msg_name_crc_list

/* Set up the API message handling tables */
static clib_error_t *
tmc_plugin_api_hookup (vlib_main_t * vm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + tmc_base_msg_id),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_tmc_plugin_api_msg;
#undef _

  return 0;
}

static void
setup_message_id_table (api_main_t * apim)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (apim, #n "_" #crc, id + tmc_base_msg_id);
  foreach_vl_msg_name_crc_tmc;
#undef _
}

static clib_error_t *
tmc_api_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;

  u8 *name = format (0, "tmc_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  tmc_base_msg_id = vl_msg_api_get_msg_ids ((char *) name,
					    VL_MSG_FIRST_AVAILABLE);

  error = tmc_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (&api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (tmc_api_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "TCP MSS Clamping",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
