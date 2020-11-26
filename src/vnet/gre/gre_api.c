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
#include <vnet/tunnel/tunnel_types_api.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/gre/gre.api_enum.h>
#include <vnet/gre/gre.api_types.h>

#define REPLY_MSG_ID_BASE gre_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static int
gre_tunnel_type_decode (vl_api_gre_tunnel_type_t in, gre_tunnel_type_t * out)
{
  switch (in)
    {
#define _(n, v)                                           \
      case GRE_API_TUNNEL_TYPE_##n:                       \
        *out = GRE_TUNNEL_TYPE_##n;                       \
        return (0);
      foreach_gre_tunnel_type
#undef _
    }

  return (VNET_API_ERROR_INVALID_VALUE);
}

static vl_api_gre_tunnel_type_t
gre_tunnel_type_encode (gre_tunnel_type_t in)
{
  vl_api_gre_tunnel_type_t out = GRE_API_TUNNEL_TYPE_L3;

  switch (in)
    {
#define _(n, v)                                           \
      case GRE_TUNNEL_TYPE_##n:                           \
        out = GRE_API_TUNNEL_TYPE_##n;                    \
        break;
      foreach_gre_tunnel_type
#undef _
    }

  return (out);
}

static void vl_api_gre_tunnel_add_del_t_handler
  (vl_api_gre_tunnel_add_del_t * mp)
{
  vnet_gre_tunnel_add_del_args_t _a = { }, *a = &_a;
  vl_api_gre_tunnel_add_del_reply_t *rmp;
  tunnel_encap_decap_flags_t flags;
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

  rv = tunnel_mode_decode (mp->tunnel.mode, &a->mode);

  if (rv)
    goto out;

  rv = tunnel_encap_decap_flags_decode (mp->tunnel.flags, &flags);

  if (rv)
    goto out;

  a->is_add = mp->is_add;
  a->is_ipv6 = (itype[0] == IP46_TYPE_IP6);
  a->instance = ntohl (mp->tunnel.instance);
  a->session_id = ntohs (mp->tunnel.session_id);
  a->outer_table_id = ntohl (mp->tunnel.outer_table_id);
  a->flags = flags;

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
  (gre_tunnel_t * t, vl_api_gre_tunnel_dump_t * mp)
{
  vl_api_gre_tunnel_details_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO_DETAILS2(VL_API_GRE_TUNNEL_DETAILS,
  ({
    ip_address_encode (&t->tunnel_src, IP46_TYPE_ANY, &rmp->tunnel.src);
    ip_address_encode (&t->tunnel_dst.fp_addr, IP46_TYPE_ANY, &rmp->tunnel.dst);

    rmp->tunnel.outer_table_id =
      htonl (fib_table_get_table_id
             (t->outer_fib_index, t->tunnel_dst.fp_proto));

    rmp->tunnel.type = gre_tunnel_type_encode (t->type);
    rmp->tunnel.mode = tunnel_mode_encode (t->mode);
    rmp->tunnel.instance = htonl (t->user_instance);
    rmp->tunnel.sw_if_index = htonl (t->sw_if_index);
    rmp->tunnel.session_id = htons (t->session_id);
  }));
  /* *INDENT-ON* */
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
        send_gre_tunnel_details(t, mp);
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
      send_gre_tunnel_details (t, mp);
    }
}

/*
 * gre_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
/* API definitions */
#include <vnet/format_fns.h>
#include <vnet/gre/gre.api.c>

static clib_error_t *
gre_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  gre_main.msg_id_base = setup_message_id_table ();

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
