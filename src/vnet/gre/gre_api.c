/*
 *------------------------------------------------------------------
 * gre_api.c - gre api
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

#include <vnet/gre/gre.h>
#include <vnet/fib/fib_table.h>

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
_(GRE_ADD_DEL_TUNNEL, gre_add_del_tunnel)               \
_(GRE_TUNNEL_DUMP, gre_tunnel_dump)

static void vl_api_gre_add_del_tunnel_t_handler
  (vl_api_gre_add_del_tunnel_t * mp)
{
  vl_api_gre_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  vnet_gre_add_del_tunnel_args_t _a, *a = &_a;
  u32 outer_fib_id;
  u32 p;
  u32 sw_if_index = ~0;

  p = fib_table_find (!mp->is_ipv6 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6,
		      ntohl (mp->outer_fib_id));
  if (p == ~0)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }
  outer_fib_id = p;

  /* Check src & dst are different */
  if ((mp->is_ipv6 && memcmp (mp->src_address, mp->dst_address, 16) == 0) ||
      (!mp->is_ipv6 && memcmp (mp->src_address, mp->dst_address, 4) == 0))
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  memset (a, 0, sizeof (*a));

  a->is_add = mp->is_add;
  a->teb = mp->teb;
  a->is_ipv6 = mp->is_ipv6;

  /* ip addresses sent in network byte order */
  if (!mp->is_ipv6)
    {
      clib_memcpy (&(a->src.ip4), mp->src_address, 4);
      clib_memcpy (&(a->dst.ip4), mp->dst_address, 4);
    }
  else
    {
      clib_memcpy (&(a->src.ip6), mp->src_address, 16);
      clib_memcpy (&(a->dst.ip6), mp->dst_address, 16);
    }

  a->outer_fib_id = outer_fib_id;
  rv = vnet_gre_add_del_tunnel (a, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GRE_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void send_gre_tunnel_details
  (gre_tunnel_t * t, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_gre_tunnel_details_t *rmp;
  u8 is_ipv6 = t->tunnel_dst.fp_proto == FIB_PROTOCOL_IP6 ? 1 : 0;
  fib_table_t *ft;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_GRE_TUNNEL_DETAILS);
  if (!is_ipv6)
    {
      clib_memcpy (rmp->src_address, &(t->tunnel_src.ip4.as_u8), 4);
      clib_memcpy (rmp->dst_address, &(t->tunnel_dst.fp_addr.ip4.as_u8), 4);
      ft = fib_table_get (t->outer_fib_index, FIB_PROTOCOL_IP4);
      rmp->outer_fib_id = ft->ft_table_id;
    }
  else
    {
      clib_memcpy (rmp->src_address, &(t->tunnel_src.ip6.as_u8), 16);
      clib_memcpy (rmp->dst_address, &(t->tunnel_dst.fp_addr.ip6.as_u8), 16);
      ft = fib_table_get (t->outer_fib_index, FIB_PROTOCOL_IP6);
      rmp->outer_fib_id = ft->ft_table_id;
    }
  rmp->teb = (GRE_TUNNEL_TYPE_TEB == t->type);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;
  rmp->is_ipv6 = is_ipv6;

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_gre_tunnel_dump_t_handler (vl_api_gre_tunnel_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  gre_main_t *gm = &gre_main;
  gre_tunnel_t *t;
  u32 sw_if_index;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, gm->tunnels,
      ({
        send_gre_tunnel_details(t, q, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if ((sw_if_index >= vec_len (gm->tunnel_index_by_sw_if_index)) ||
	  (~0 == gm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &gm->tunnels[gm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_gre_tunnel_details (t, q, mp->context);
    }
}

/*
 * gre_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
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
  foreach_vl_msg_name_crc_gre;
#undef _
}

static clib_error_t *
gre_api_hookup (vlib_main_t * vm)
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

VLIB_API_INIT_FUNCTION (gre_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
