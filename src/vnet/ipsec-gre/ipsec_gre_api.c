/*
 *------------------------------------------------------------------
 * ipsec_gre_api.c - ipsec_gre api
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

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/ipsec-gre/ipsec_gre.h>

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

#define foreach_vpe_api_msg                             \
_(IPSEC_GRE_ADD_DEL_TUNNEL, ipsec_gre_add_del_tunnel)                   \
_(IPSEC_GRE_TUNNEL_DUMP, ipsec_gre_tunnel_dump)

static void
vl_api_ipsec_gre_add_del_tunnel_t_handler (vl_api_ipsec_gre_add_del_tunnel_t *
					   mp)
{
  vl_api_ipsec_gre_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  vnet_ipsec_gre_add_del_tunnel_args_t _a, *a = &_a;
  u32 sw_if_index = ~0;

  /* Check src & dst are different */
  if (memcmp (mp->src_address, mp->dst_address, 4) == 0)
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }

  clib_memset (a, 0, sizeof (*a));

  /* ip addresses sent in network byte order */
  clib_memcpy (&(a->src), mp->src_address, 4);
  clib_memcpy (&(a->dst), mp->dst_address, 4);
  a->is_add = mp->is_add;
  a->lsa = ntohl (mp->local_sa_id);
  a->rsa = ntohl (mp->remote_sa_id);

  rv = vnet_ipsec_gre_add_del_tunnel (a, &sw_if_index);

out:
    /* *INDENT-OFF* */
    REPLY_MACRO2(VL_API_GRE_ADD_DEL_TUNNEL_REPLY,
    ({
        rmp->sw_if_index = ntohl (sw_if_index);
    }));
    /* *INDENT-ON* */
}

static void send_ipsec_gre_tunnel_details
  (ipsec_gre_tunnel_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_ipsec_gre_tunnel_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_IPSEC_GRE_TUNNEL_DETAILS);
  clib_memcpy (rmp->src_address, &(t->tunnel_src), 4);
  clib_memcpy (rmp->dst_address, &(t->tunnel_dst), 4);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->local_sa_id = htonl (t->local_sa_id);
  rmp->remote_sa_id = htonl (t->remote_sa_id);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void vl_api_ipsec_gre_tunnel_dump_t_handler
  (vl_api_ipsec_gre_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;
  ipsec_gre_main_t *igm = &ipsec_gre_main;
  ipsec_gre_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
        /* *INDENT-OFF* */
        pool_foreach (t, igm->tunnels,
        ({
            send_ipsec_gre_tunnel_details(t, reg, mp->context);
        }));
        /* *INDENT-ON* */
    }
  else
    {
      if ((sw_if_index >= vec_len (igm->tunnel_index_by_sw_if_index)) ||
	  (~0 == igm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &igm->tunnels[igm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_ipsec_gre_tunnel_details (t, reg, mp->context);
    }
}

/*
 * ipsec_gre_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_ipsec_gre;
#undef _
}

static clib_error_t *
ipsec_gre_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (ipsec_gre_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
