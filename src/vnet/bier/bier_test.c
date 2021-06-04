/*
 *------------------------------------------------------------------
 * bier_test.c
 *
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
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip_types.h>
#include <vnet/mpls/mpls_types.h>
#include <vnet/ip/ip_format_fns.h>
#include <vpp/api/types.h>

typedef struct
{
  u32 msg_id_base;
  vat_main_t *vat_main;
} bier_test_main_t;

static bier_test_main_t bier_test_main;

#define __plugin_msg_base bier_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

#include <vnet/bier/bier.api_enum.h>
#include <vnet/bier/bier.api_types.h>

#define foreach_unimplemented_handler                                         \
  _ (bier_table_details)                                                      \
  _ (bier_route_details)                                                      \
  _ (bier_imp_add_reply)                                                      \
  _ (bier_imp_details)                                                        \
  _ (bier_disp_table_details)                                                 \
  _ (bier_disp_entry_details)

#define _(n)                                                                  \
  static void vl_api_##n##_t_handler (vl_api_##n##_t *mp) {}
foreach_unimplemented_handler
#undef _

#define foreach_unimplemented_api_call                                        \
  _ (bier_table_dump)                                                         \
  _ (bier_route_dump)                                                         \
  _ (bier_imp_add)                                                            \
  _ (bier_imp_del)                                                            \
  _ (bier_imp_dump)                                                           \
  _ (bier_disp_table_add_del)                                                 \
  _ (bier_disp_table_dump)                                                    \
  _ (bier_disp_entry_add_del)                                                 \
  _ (bier_disp_entry_dump)

#define _(n)                                                                  \
  static int api_##n (vat_main_t *vam) { return -1; }
  foreach_unimplemented_api_call
#undef _

  static int
  api_bier_route_add_del (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bier_route_add_del_t *mp;
  u8 is_add = 1;
  u32 set = 0, sub_domain = 0, hdr_len = 3, bp = 0;
  ip4_address_t v4_next_hop_address;
  ip6_address_t v6_next_hop_address;
  u8 next_hop_set = 0;
  u8 next_hop_proto_is_ip4 = 1;
  mpls_label_t next_hop_out_label = MPLS_LABEL_INVALID;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_ip4_address, &v4_next_hop_address))
	{
	  next_hop_proto_is_ip4 = 1;
	  next_hop_set = 1;
	}
      else if (unformat (i, "%U", unformat_ip6_address, &v6_next_hop_address))
	{
	  next_hop_proto_is_ip4 = 0;
	  next_hop_set = 1;
	}
      if (unformat (i, "sub-domain %d", &sub_domain))
	;
      else if (unformat (i, "set %d", &set))
	;
      else if (unformat (i, "hdr-len %d", &hdr_len))
	;
      else if (unformat (i, "bp %d", &bp))
	;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "out-label %d", &next_hop_out_label))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!next_hop_set || (MPLS_LABEL_INVALID == next_hop_out_label))
    {
      errmsg ("next hop / label set\n");
      return -99;
    }
  if (0 == bp)
    {
      errmsg ("bit=position not set\n");
      return -99;
    }

  /* Construct the API message */
  M2 (BIER_ROUTE_ADD_DEL, mp, sizeof (vl_api_fib_path_t));

  mp->br_is_add = is_add;
  mp->br_route.br_tbl_id.bt_set = set;
  mp->br_route.br_tbl_id.bt_sub_domain = sub_domain;
  mp->br_route.br_tbl_id.bt_hdr_len_id = hdr_len;
  mp->br_route.br_bp = ntohs (bp);
  mp->br_route.br_n_paths = 1;
  mp->br_route.br_paths[0].n_labels = 1;
  mp->br_route.br_paths[0].label_stack[0].label = ntohl (next_hop_out_label);
  mp->br_route.br_paths[0].proto =
    (next_hop_proto_is_ip4 ? FIB_API_PATH_NH_PROTO_IP4 :
			     FIB_API_PATH_NH_PROTO_IP6);

  if (next_hop_proto_is_ip4)
    {
      clib_memcpy (&mp->br_route.br_paths[0].nh.address.ip4,
		   &v4_next_hop_address, sizeof (v4_next_hop_address));
    }
  else
    {
      clib_memcpy (&mp->br_route.br_paths[0].nh.address.ip6,
		   &v6_next_hop_address, sizeof (v6_next_hop_address));
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return (ret);
}

static int
api_bier_table_add_del (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bier_table_add_del_t *mp;
  u8 is_add = 1;
  u32 set = 0, sub_domain = 0, hdr_len = 3;
  mpls_label_t local_label = MPLS_LABEL_INVALID;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sub-domain %d", &sub_domain))
	;
      else if (unformat (i, "set %d", &set))
	;
      else if (unformat (i, "label %d", &local_label))
	;
      else if (unformat (i, "hdr-len %d", &hdr_len))
	;
      else if (unformat (i, "add"))
	is_add = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (MPLS_LABEL_INVALID == local_label)
    {
      errmsg ("missing label\n");
      return -99;
    }

  /* Construct the API message */
  M (BIER_TABLE_ADD_DEL, mp);

  mp->bt_is_add = is_add;
  mp->bt_label = ntohl (local_label);
  mp->bt_tbl_id.bt_set = set;
  mp->bt_tbl_id.bt_sub_domain = sub_domain;
  mp->bt_tbl_id.bt_hdr_len_id = hdr_len;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return (ret);
}

#include <vnet/bier/bier.api_test.c>

VAT_REGISTER_FEATURE_FUNCTION (vat_bier_plugin_register);
