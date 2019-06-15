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
#include <vnet/ip/ip_types_api.h>

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
_(GRE_TUNNEL_ADD_DEL, gre_tunnel_add_del)               \
_(GRE_TUNNEL_DUMP, gre_tunnel_dump)

static int
gre_tunnel_type_decode (vl_api_gre_tunnel_type_t in, gre_tunnel_type_t * out)
{
  in = clib_net_to_host_u32 (in);

  switch (in)
    {
    case GRE_API_TUNNEL_TYPE_L3:
      *out = GRE_TUNNEL_TYPE_L3;
      return (0);
    case GRE_API_TUNNEL_TYPE_TEB:
      *out = GRE_TUNNEL_TYPE_TEB;
      return (0);
    case GRE_API_TUNNEL_TYPE_ERSPAN:
      *out = GRE_TUNNEL_TYPE_ERSPAN;
      return (0);
    }

  return (VNET_API_ERROR_INVALID_VALUE);
}

static vl_api_gre_tunnel_type_t
gre_tunnel_type_encode (gre_tunnel_type_t in)
{
  vl_api_gre_tunnel_type_t out = GRE_API_TUNNEL_TYPE_L3;

  switch (in)
    {
    case GRE_TUNNEL_TYPE_L3:
      out = GRE_API_TUNNEL_TYPE_L3;
      break;
    case GRE_TUNNEL_TYPE_TEB:
      out = GRE_API_TUNNEL_TYPE_TEB;
      break;
    case GRE_TUNNEL_TYPE_ERSPAN:
      out = GRE_API_TUNNEL_TYPE_ERSPAN;
      break;
    }

  out = clib_net_to_host_u32 (out);

  return (out);
}

static void vl_api_gre_tunnel_add_del_t_handler
  (vl_api_gre_tunnel_add_del_t * mp)
{
  vnet_gre_tunnel_add_del_args_t _a = { }, *a = &_a;
  vl_api_gre_tunnel_add_del_reply_t *rmp;
  u32 sw_if_index = ~0;
  ip46_type_t itype[2];
  int rv = 0;

  itype[0] = ip_address_decode (&mp->tunnel.src, &a->src);
  itype[1] = ip_address_decode (&mp->tunnel.dst, &a->dst);

  if (itype[0] != itype[1])
    {
      rv = VNET_API_ERROR_INVALID_PROTOCOL;
      goto out;
    }

  if (ip46_address_is_equal (&a->src, &a->dst))
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }

  rv = gre_tunnel_type_decode (mp->tunnel.type, &a->type);

  if (rv)
    goto out;

  a->is_add = mp->is_add;
  a->is_ipv6 = (itype[0] == IP46_TYPE_IP6);
  a->instance = ntohl (mp->tunnel.instance);
  a->session_id = ntohs (mp->tunnel.session_id);
  a->outer_fib_id = ntohl (mp->tunnel.outer_fib_id);

  rv = vnet_gre_tunnel_add_del (a, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GRE_TUNNEL_ADD_DEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void send_gre_tunnel_details
  (gre_tunnel_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_gre_tunnel_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_GRE_TUNNEL_DETAILS);

  ip_address_encode (&t->tunnel_src, IP46_TYPE_ANY, &rmp->tunnel.src);
  ip_address_encode (&t->tunnel_dst.fp_addr, IP46_TYPE_ANY, &rmp->tunnel.dst);

  rmp->tunnel.outer_fib_id =
    htonl (fib_table_get_table_id
	   (t->outer_fib_index, t->tunnel_dst.fp_proto));

  rmp->tunnel.type = gre_tunnel_type_encode (t->type);
  rmp->tunnel.instance = htonl (t->user_instance);
  rmp->tunnel.sw_if_index = htonl (t->sw_if_index);
  rmp->tunnel.session_id = htons (t->session_id);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_gre_tunnel_dump_t_handler (vl_api_gre_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;
  gre_main_t *gm = &gre_main;
  gre_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, gm->tunnels,
      ({
        send_gre_tunnel_details(t, reg, mp->context);
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
      send_gre_tunnel_details (t, reg, mp->context);
    }
}

/*
 * gre_api_hookup
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
