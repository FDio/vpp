/* Copyright (c) 2021 Cisco and/or its affiliates.
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
 * limitations under the License. */

#include <vlib/vlib.h>
#include <vnet/fib/fib_api.h>
#include <vnet/ip/ip_format_fns.h>
#include <vlibmemory/api.h>
#include <vlibapi/api.h>

#define REPLY_MSG_ID_BASE (im->msg_id_base)
#include <vlibapi/api_helper_macros.h>

#include "ip_session_redirect.api_enum.h"
#include "ip_session_redirect.api_types.h"

#include "ip_session_redirect.h"

static void
vl_api_ip_session_redirect_add_t_handler (vl_api_ip_session_redirect_add_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  vl_api_ip_session_redirect_add_reply_t *rmp;
  fib_route_path_t *rpaths = 0;
  u8 *match = 0;
  int rv = 0;

  if (mp->n_paths <= 0)
    {
      rv = VNET_API_ERROR_NO_PATHS_IN_ROUTE;
      goto err;
    }

  for (int i = 0; i < mp->n_paths; i++)
    {
      fib_route_path_t rpath;
      if ((rv = fib_api_path_decode (&mp->paths[i], &rpath)))
	goto err;
      vec_add1 (rpaths, rpath);
    }

  vec_add (match, mp->match, mp->match_len);
  rv = ip_session_redirect_add (vm, ntohl (mp->table_index), match, rpaths,
				mp->is_punt);
  vec_free (match);

err:
  vec_free (rpaths);
  REPLY_MACRO (VL_API_IP_SESSION_REDIRECT_ADD_REPLY);
}

static void
vl_api_ip_session_redirect_del_t_handler (vl_api_ip_session_redirect_del_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  vl_api_ip_session_redirect_del_reply_t *rmp;
  u8 *match = 0;
  int rv;

  vec_add (match, mp->match, mp->match_len);
  rv = ip_session_redirect_del (vm, ntohl (mp->table_index), match);
  vec_free (match);

  REPLY_MACRO (VL_API_IP_SESSION_REDIRECT_DEL_REPLY);
}

#include "ip_session_redirect.api.c"
static clib_error_t *
ip_session_redirect_plugin_api_hookup (vlib_main_t *vm)
{
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  im->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (ip_session_redirect_plugin_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
