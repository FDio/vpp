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
#include <vnet/classify/vnet_classify.h>
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#define __plugin_msg_base ip_session_redirect_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>
/* declare message IDs */
#include "ip_session_redirect.api_enum.h"
#include "ip_session_redirect.api_types.h"
#include "ip_session_redirect.h"

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} ip_session_redirect_test_main_t;

ip_session_redirect_test_main_t ip_session_redirect_test_main;

static int
api_ip_session_redirect_add_parse (vat_main_t *vam, u32 *table_index,
				   u32 *opaque_index, dpo_proto_t *proto,
				   int *is_punt, u8 **match,
				   fib_route_path_t **paths)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  fib_route_path_t path;

  *table_index = ~0;
  *opaque_index = ~0;
  *proto = DPO_PROTO_IP4;
  *is_punt = 0;
  *match = 0;
  *paths = 0;

  while (unformat_check_input (vam->input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (vam->input, "punt"))
	*is_punt = 1;
      else if (unformat (vam->input, "table %u", table_index))
	;
      else if (unformat (vam->input, "opaque-index %u", opaque_index))
	;
      else if (unformat (vam->input, "match %U", unformat_classify_match, cm,
			 match, *table_index))
	;
      else if (unformat (vam->input, "via %U", unformat_fib_route_path, &path,
			 proto))
	vec_add1 (*paths, path);
      else
	{
	  clib_warning ("unknown input `%U'", format_unformat_error,
			vam->input);
	  return -99;
	}
    }

  return 0;
}

static int
api_ip_session_redirect_add (vat_main_t *vam)
{
  vl_api_ip_session_redirect_add_t *mp;
  fib_route_path_t *paths;
  dpo_proto_t proto;
  u32 opaque_index;
  u32 table_index;
  int is_punt;
  int ret, i;
  u8 *match;

  ret = api_ip_session_redirect_add_parse (vam, &table_index, &opaque_index,
					   &proto, &is_punt, &match, &paths);
  if (ret)
    goto err;

  M2 (IP_SESSION_REDIRECT_ADD, mp, vec_len (paths) * sizeof (mp->paths[0]));

  mp->table_index = htonl (table_index);
  mp->opaque_index = htonl (opaque_index);
  mp->is_punt = is_punt;
  memcpy_s (mp->match, sizeof (mp->match), match, vec_len (match));
  mp->n_paths = vec_len (paths);
  vec_foreach_index (i, paths)
    fib_api_path_encode (&paths[i], &mp->paths[i]);

  S (mp);
  W (ret);

err:
  vec_free (match);
  vec_free (paths);
  return ret;
}

static int
api_ip_session_redirect_add_v2 (vat_main_t *vam)
{
  vl_api_ip_session_redirect_add_v2_t *mp;
  fib_route_path_t *paths;
  dpo_proto_t proto;
  u32 opaque_index;
  u32 table_index;
  int is_punt;
  int ret, i;
  u8 *match;

  ret = api_ip_session_redirect_add_parse (vam, &table_index, &opaque_index,
					   &proto, &is_punt, &match, &paths);
  if (ret)
    goto err;

  M2 (IP_SESSION_REDIRECT_ADD_V2, mp, vec_len (paths) * sizeof (mp->paths[0]));

  mp->table_index = htonl (table_index);
  mp->opaque_index = htonl (opaque_index);
  mp->proto = fib_api_path_dpo_proto_to_nh (proto);
  mp->is_punt = is_punt;
  memcpy_s (mp->match, sizeof (mp->match), match, vec_len (match));
  mp->n_paths = vec_len (paths);
  vec_foreach_index (i, paths)
    fib_api_path_encode (&paths[i], &mp->paths[i]);

  S (mp);
  W (ret);

err:
  vec_free (match);
  vec_free (paths);
  return ret;
}

static int
api_ip_session_redirect_del (vat_main_t *vam)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  vl_api_ip_session_redirect_del_t *mp;
  u32 table_index = ~0;
  u8 *match = 0;
  int ret;

  while (unformat_check_input (vam->input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (vam->input, "table %u", &table_index))
	;
      else if (unformat (vam->input, "match %U", unformat_classify_match, cm,
			 &match, table_index))
	;
      else
	{
	  clib_warning ("unknown input '%U'", format_unformat_error,
			vam->input);
	  return -99;
	}
    }

  M2 (IP_SESSION_REDIRECT_DEL, mp, vec_len (match));

  mp->table_index = htonl (table_index);
  mp->match_len = htonl (vec_len (match));
  clib_memcpy (mp->match, match, vec_len (match));

  S (mp);
  W (ret);

  return ret;
}

#include "ip_session_redirect.api_test.c"

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
