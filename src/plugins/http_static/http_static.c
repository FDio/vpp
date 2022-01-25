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
#include <http_static/http_static.api_enum.h>
#include <http_static/http_static.api_types.h>

#include <vpp/api/types.h>

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

#define REPLY_MSG_ID_BASE hmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

http_static_main_t http_static_main;

/* API message handler */
static void vl_api_http_static_enable_t_handler
  (vl_api_http_static_enable_t * mp)
{
  vl_api_http_static_enable_reply_t *rmp;
  http_static_main_t *hmp = &http_static_main;
  int rv;

  mp->uri[ARRAY_LEN (mp->uri) - 1] = 0;
  mp->www_root[ARRAY_LEN (mp->www_root) - 1] = 0;

  rv =
    hss_enable_api (ntohl (mp->fifo_size), ntohl (mp->cache_size_limit),
		    ntohl (mp->prealloc_fifos),
		    ntohl (mp->private_segment_size), mp->www_root, mp->uri);

  REPLY_MACRO (VL_API_HTTP_STATIC_ENABLE_REPLY);
}

#include <http_static/http_static.api.c>
static clib_error_t *
http_static_init (vlib_main_t * vm)
{
  http_static_main_t *hmp = &http_static_main;

  hmp->vlib_main = vm;
  hmp->vnet_main = vnet_get_main ();

  /* Ask for a correctly-sized block of API message decode slots */
  hmp->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (http_static_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "HTTP Static Server"
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
