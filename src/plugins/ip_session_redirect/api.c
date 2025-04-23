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
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_api.h>
#include <vnet/ip/ip_format_fns.h>
#include <vnet/classify/vnet_classify.h>
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

static void
send_ip_session_redirect_details (vl_api_registration_t *reg, u32 table_index,
				  u32 context)
{
  ip_session_redirect_main_t *im = &ip_session_redirect_main;
  ip_session_redirect_t *ipr;
  ip_session_redirect_t *iprs = im->pool;

  pool_foreach (ipr, iprs)
    {
      if (~0 == table_index || ipr->table_index == table_index)
	{
	  vl_api_ip_session_redirect_details_t *rmp;
	  vl_api_fib_path_t *fp;
	  fib_route_path_t *rpath;
	  fib_path_encode_ctx_t walk_ctx = {
	    .rpaths = NULL,
	  };
	  u8 n_paths = fib_path_list_get_n_paths (ipr->pl);
	  /* match_len is computed without table index at the end of the match
	   * string */
	  u32 match_len = vec_len (ipr->match_and_table_index) - 4;

	  rmp = vl_msg_api_alloc (sizeof (*rmp) +
				  sizeof (rmp->paths[0]) * n_paths);
	  clib_memset (rmp, 0, sizeof (*rmp));
	  rmp->_vl_msg_id =
	    ntohs (REPLY_MSG_ID_BASE + VL_API_IP_SESSION_REDIRECT_DETAILS);
	  rmp->context = context;
	  rmp->opaque_index = htonl (ipr->opaque_index);
	  rmp->table_index = htonl (ipr->table_index);
	  rmp->match_length = htonl (match_len);
	  rmp->is_punt = ipr->is_punt;
	  rmp->is_ip6 = ipr->is_ip6;
	  clib_memcpy (rmp->match, ipr->match_and_table_index, match_len);
	  rmp->n_paths = n_paths;
	  fp = rmp->paths;
	  rmp->retval = 0;

	  fib_path_list_walk_w_ext (ipr->pl, NULL, fib_path_encode, &walk_ctx);
	  vec_foreach (rpath, walk_ctx.rpaths)
	    {
	      fib_api_path_encode (rpath, fp);
	      fp++;
	    }

	  vl_api_send_msg (reg, (u8 *) rmp);
	}
    }
}

static void
vl_api_ip_session_redirect_dump_t_handler (
  vl_api_ip_session_redirect_dump_t *mp)
{
  vl_api_registration_t *reg;
  u32 table_index = ntohl (mp->table_index);
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == 0)
    return;

  send_ip_session_redirect_details (reg, table_index, mp->context);
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
