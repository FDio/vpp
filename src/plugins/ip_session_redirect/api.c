/* Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#define REPLY_MSG_ID_BASE vl_api_ip_sesion_redirect_msg_id_base
#include <vlibapi/api_helper_macros.h>

#include "ip_session_redirect.api_enum.h"
#include "ip_session_redirect.api_types.h"

#include "ip_session_redirect.h"

static u16 vl_api_ip_sesion_redirect_msg_id_base;

static int
vl_api_ip_session_redirect_add (u32 table_index, u32 opaque_index,
				vl_api_fib_path_nh_proto_t proto, int is_punt,
				u8 *match, int match_len,
				vl_api_fib_path_t *paths, int n_paths)
{
  vlib_main_t *vm = vlib_get_main ();
  fib_route_path_t *paths_ = 0;
  dpo_proto_t proto_;
  u8 *match_ = 0;
  int rv = 0;

  if (n_paths <= 0)
    {
      rv = VNET_API_ERROR_NO_PATHS_IN_ROUTE;
      goto err0;
    }

  for (int i = 0; i < n_paths; i++)
    {
      fib_route_path_t path;
      if ((rv = fib_api_path_decode (&paths[i], &path)))
	goto err1;
      vec_add1 (paths_, path);
    }

  if (~0 == proto)
    proto_ = paths_[0].frp_proto;
  else
    fib_api_path_nh_proto_to_dpo (ntohl (proto), &proto_);

  vec_add (match_, match, match_len);
  rv = ip_session_redirect_add (vm, ntohl (table_index), ntohl (opaque_index),
				proto_, is_punt, match_, paths_);
  vec_free (match_);

err1:
  vec_free (paths_);
err0:
  return rv;
}

static void
vl_api_ip_session_redirect_add_t_handler (vl_api_ip_session_redirect_add_t *mp)
{
  vl_api_ip_session_redirect_add_reply_t *rmp;
  int rv = vl_api_ip_session_redirect_add (
    mp->table_index, mp->opaque_index, ~0 /* proto */, mp->is_punt, mp->match,
    mp->match_len, mp->paths, mp->n_paths);
  REPLY_MACRO (VL_API_IP_SESSION_REDIRECT_ADD_REPLY)
}

static void
vl_api_ip_session_redirect_add_v2_t_handler (
  vl_api_ip_session_redirect_add_v2_t *mp)
{
  vl_api_ip_session_redirect_add_v2_reply_t *rmp;
  int rv = vl_api_ip_session_redirect_add (
    mp->table_index, mp->opaque_index, mp->proto, mp->is_punt, mp->match,
    mp->match_len, mp->paths, mp->n_paths);
  REPLY_MACRO (VL_API_IP_SESSION_REDIRECT_ADD_V2_REPLY)
}

static void
vl_api_ip_session_redirect_del_t_handler (vl_api_ip_session_redirect_del_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
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
  vl_api_ip_sesion_redirect_msg_id_base = setup_message_id_table ();
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
