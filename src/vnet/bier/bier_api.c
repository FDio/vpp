/*
 *------------------------------------------------------------------
 * bier_api.c - vnet BIER api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/api_errno.h>
#include <vnet/bier/bier_table.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_bier_api_msg                                            \
_(BIER_TABLE_ADD_DEL, bier_table_add_del)                               \
_(BIER_ROUTE_ADD_DEL, bier_route_add_del)

void
vl_api_bier_table_add_del_t_handler (vl_api_bier_table_add_del_t * mp)
{
  vl_api_bier_table_add_del_reply_t *rmp;
  vnet_main_t *vnm;
  int rv;

  vnm = vnet_get_main ();
  vnm->api_errno = 0;

  bier_table_id_t bti = {
    .bti_set = mp->bt_set,
    .bti_sub_domain = mp->bt_sub_domain,
    .bti_hdr_len = mp->bt_bit_header_length,
    .bti_type = BIER_TABLE_MPLS_SPF,
    .bti_ecmp = BIER_ECMP_TABLE_ID_MAIN,
  };

  if (mp->bt_is_add)
    {
      bier_table_create(&bti, ntohl(mp->bt_label));
    }
  else
    {
      bier_table_delete(&bti);
    }

  rv = vnm->api_errno;

  REPLY_MACRO (VL_API_BIER_TABLE_ADD_DEL_REPLY);
}

void
vl_api_bier_route_add_del_t_handler (vl_api_bier_route_add_del_t * mp)
{
  vl_api_bier_route_add_del_reply_t *rmp;
  vnet_main_t *vnm;
  bier_bp_t bp;
  int rv = 0;

  vnm = vnet_get_main ();
  vnm->api_errno = 0;

  bier_table_id_t bti = {
    .bti_set = mp->br_set,
    .bti_sub_domain = mp->br_sub_domain,
    .bti_hdr_len = mp->br_bit_header_length,
    .bti_type = BIER_TABLE_MPLS_SPF,
    .bti_ecmp = BIER_ECMP_TABLE_ID_MAIN,
  };
  fib_route_path_t brp = {
      .frp_flags = FIB_ROUTE_PATH_BIER_FMASK,
  };
  vec_add1(brp.frp_label_stack,
           ntohl(mp->br_next_hop_out_label));

  bp = ntohs(mp->br_bp);

  if (0 == bp || bp > 0xffff)
    {
      rv = -1;
      goto done;
    }

  if (mp->br_next_hop_proto_is_ip4)
    {
      clib_memcpy (&brp.frp_addr.ip4, mp->br_next_hop,
                   sizeof (brp.frp_addr.ip4));
    }
  else
    {
      clib_memcpy (&brp.frp_addr.ip6, mp->br_next_hop,
                   sizeof (brp.frp_addr.ip6));
    }

  if (mp->br_is_add)
    {
      bier_table_route_add(&bti, ntohs(mp->br_bp), &brp);
    }
  else
    {
      bier_table_route_remove(&bti, ntohs(mp->br_bp), &brp);
    }

 done:
  rv = (rv == 0) ? vnm->api_errno : rv;

  REPLY_MACRO (VL_API_BIER_ROUTE_ADD_DEL_REPLY);
}

#define vl_msg_name_crc_list
#include <vnet/bier/bier.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_bier;
#undef _
}

static clib_error_t *
bier_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_bier_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (bier_api_hookup);
