/*
 * http_static.c - skeleton vpp engine plug-in
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
#include <http_static/http_static.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

/* define message IDs */
#include <http_static/http_static_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <http_static/http_static_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <http_static/http_static_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <http_static/http_static_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <http_static/http_static_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE hmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

http_static_main_t http_static_main;

/* List of message types that this plugin understands */

#define foreach_http_static_plugin_api_msg                           \
_(HTTP_STATIC_ENABLE, http_static_enable)

/* API message handler */
static void vl_api_http_static_enable_t_handler
  (vl_api_http_static_enable_t * mp)
{
  vl_api_http_static_enable_reply_t *rmp;
  http_static_main_t *hmp = &http_static_main;
  int rv;

  mp->uri[ARRAY_LEN (mp->uri) - 1] = 0;
  mp->www_root[ARRAY_LEN (mp->www_root) - 1] = 0;

  rv = http_static_server_enable_api
    (ntohl (mp->fifo_size), ntohl (mp->cache_size_limit),
     ntohl (mp->prealloc_fifos),
     ntohl (mp->private_segment_size), mp->www_root, mp->uri);

  REPLY_MACRO (VL_API_HTTP_STATIC_ENABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
http_static_plugin_api_hookup (vlib_main_t * vm)
{
  http_static_main_t *hmp = &http_static_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + hmp->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_http_static_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <http_static/http_static_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (http_static_main_t * hmp, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n  #crc, id + hmp->msg_id_base);
  foreach_vl_msg_name_crc_http_static;
#undef _
}

static clib_error_t *
http_static_init (vlib_main_t * vm)
{
  http_static_main_t *hmp = &http_static_main;
  clib_error_t *error = 0;
  u8 *name;

  hmp->vlib_main = vm;
  hmp->vnet_main = vnet_get_main ();

  name = format (0, "http_static_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  hmp->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = http_static_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (hmp, &api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (http_static_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "http static server plugin"
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
