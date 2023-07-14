/*
 * ipip_api.c - ipip api
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 */

#include <vlibmemory/api.h>
#include <vnet/api_errno.h>
#include <vnet/fib/fib_table.h>
#include <vnet/interface.h>
#include <vnet/ipip/ipip.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/tunnel/tunnel_types_api.h>

#include <vnet/ipip/ipip.api_enum.h>
#include <vnet/ipip/ipip.api_types.h>

#define REPLY_MSG_ID_BASE im->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_ipip_add_tunnel_t_handler (vl_api_ipip_add_tunnel_t * mp)
{
  ipip_main_t *im = &ipip_main;
  vl_api_ipip_add_tunnel_reply_t *rmp;
  int rv = 0;
  u32 fib_index, sw_if_index = ~0;
  tunnel_encap_decap_flags_t flags;
  ip46_address_t src, dst;
  ip46_type_t itype[2];
  tunnel_mode_t mode;

  itype[0] = ip_address_decode (&mp->tunnel.src, &src);
  itype[1] = ip_address_decode (&mp->tunnel.dst, &dst);

  if (itype[0] != itype[1])
    {
      rv = VNET_API_ERROR_INVALID_PROTOCOL;
      goto out;
    }

  if (ip46_address_is_equal (&src, &dst))
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }

  rv = tunnel_encap_decap_flags_decode (mp->tunnel.flags, &flags);

  if (rv)
    goto out;

  rv = tunnel_mode_decode (mp->tunnel.mode, &mode);

  if (rv)
    goto out;

  fib_index = fib_table_find (fib_proto_from_ip46 (itype[0]),
			      ntohl (mp->tunnel.table_id));

  if (~0 == fib_index)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
    }
  else
    {
      rv = ipip_add_tunnel ((itype[0] == IP46_TYPE_IP6 ?
			     IPIP_TRANSPORT_IP6 :
			     IPIP_TRANSPORT_IP4),
			    ntohl (mp->tunnel.instance), &src, &dst,
			    fib_index, flags,
			    ip_dscp_decode (mp->tunnel.dscp), mode,
			    &sw_if_index);
    }

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_IPIP_ADD_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl(sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_ipip_del_tunnel_t_handler (vl_api_ipip_del_tunnel_t * mp)
{
  ipip_main_t *im = &ipip_main;
  vl_api_ipip_del_tunnel_reply_t *rmp;

  int rv = ipip_del_tunnel (ntohl (mp->sw_if_index));

  REPLY_MACRO (VL_API_IPIP_DEL_TUNNEL_REPLY);
}

static vl_api_tunnel_mode_t
ipip_tunnel_mode_encode (ipip_mode_t mode)
{
  switch (mode)
    {
    case IPIP_MODE_P2P:
      return TUNNEL_API_MODE_P2P;
    case IPIP_MODE_P2MP:
      return TUNNEL_API_MODE_MP;
    case IPIP_MODE_6RD:
      return TUNNEL_API_MODE_P2P;
    default:
      return TUNNEL_API_MODE_P2P;
    }
}

static void
send_ipip_tunnel_details (ipip_tunnel_t * t, vl_api_ipip_tunnel_dump_t * mp)
{
  ipip_main_t *im = &ipip_main;
  vl_api_ipip_tunnel_details_t *rmp;
  bool is_ipv6 = t->transport == IPIP_TRANSPORT_IP6 ? true : false;
  fib_table_t *ft;

  ft = fib_table_get (t->fib_index,
		      (is_ipv6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4));

  /* *INDENT-OFF* */
  REPLY_MACRO_DETAILS2(VL_API_IPIP_TUNNEL_DETAILS,
  ({
    ip_address_encode (&t->tunnel_src, IP46_TYPE_ANY, &rmp->tunnel.src);
    ip_address_encode (&t->tunnel_dst, IP46_TYPE_ANY, &rmp->tunnel.dst);
    rmp->tunnel.table_id = htonl (ft->ft_table_id);
    rmp->tunnel.instance = htonl (t->user_instance);
    rmp->tunnel.sw_if_index = htonl (t->sw_if_index);
    rmp->tunnel.dscp = ip_dscp_encode(t->dscp);
    rmp->tunnel.flags = tunnel_encap_decap_flags_encode(t->flags);
    rmp->tunnel.mode = ipip_tunnel_mode_encode (t->mode);
  }));
    /* *INDENT-ON* */
}

static void
vl_api_ipip_tunnel_dump_t_handler (vl_api_ipip_tunnel_dump_t * mp)
{
  ipip_main_t *im = &ipip_main;
  ipip_tunnel_t *t;
  u32 sw_if_index;

  sw_if_index = ntohl (mp->sw_if_index);

  if (sw_if_index == ~0)
    {
    /* *INDENT-OFF* */
    pool_foreach (t, im->tunnels)
     {
      send_ipip_tunnel_details(t, mp);
    }
    /* *INDENT-ON* */
    }
  else
    {
      t = ipip_tunnel_db_find_by_sw_if_index (sw_if_index);
      if (t)
	send_ipip_tunnel_details (t, mp);
    }
}

static void
vl_api_ipip_6rd_add_tunnel_t_handler (vl_api_ipip_6rd_add_tunnel_t * mp)
{
  ipip_main_t *im = &ipip_main;
  vl_api_ipip_6rd_add_tunnel_reply_t *rmp;
  u32 sixrd_tunnel_index, ip4_fib_index, ip6_fib_index;
  int rv;

  sixrd_tunnel_index = ~0;
  ip4_fib_index = fib_table_find (FIB_PROTOCOL_IP4, ntohl (mp->ip4_table_id));
  ip6_fib_index = fib_table_find (FIB_PROTOCOL_IP6, ntohl (mp->ip6_table_id));

  if (~0 == ip4_fib_index || ~0 == ip6_fib_index)

    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
    }
  else
    {
      rv = sixrd_add_tunnel ((ip6_address_t *) & mp->ip6_prefix.address,
			     mp->ip6_prefix.len,
			     (ip4_address_t *) & mp->ip4_prefix.address,
			     mp->ip4_prefix.len,
			     (ip4_address_t *) & mp->ip4_src,
			     mp->security_check,
			     ip4_fib_index, ip6_fib_index,
			     &sixrd_tunnel_index);
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_IPIP_6RD_ADD_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = htonl (sixrd_tunnel_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_ipip_6rd_del_tunnel_t_handler (vl_api_ipip_6rd_del_tunnel_t * mp)
{
  ipip_main_t *im = &ipip_main;
  vl_api_ipip_6rd_del_tunnel_reply_t *rmp;

  int rv = sixrd_del_tunnel (ntohl (mp->sw_if_index));

  REPLY_MACRO (VL_API_IPIP_6RD_DEL_TUNNEL_REPLY);
}

/*
 * ipip_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
/* API definitions */
#include <vnet/format_fns.h>
#include <vnet/ipip/ipip.api.c>

static clib_error_t *
ipip_api_hookup (vlib_main_t * vm)
{
  ipip_main_t *im = &ipip_main;

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  im->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (ipip_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
