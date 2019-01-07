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
#include <vnet/vnet_msg_enum.h>
#include <vnet/ip/ip_types_api.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output(handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg			\
  _(IPIP_ADD_TUNNEL, ipip_add_tunnel)		\
  _(IPIP_DEL_TUNNEL, ipip_del_tunnel)		\
  _(IPIP_6RD_ADD_TUNNEL, ipip_6rd_add_tunnel)	\
  _(IPIP_6RD_DEL_TUNNEL, ipip_6rd_del_tunnel)	\
  _(IPIP_TUNNEL_DUMP, ipip_tunnel_dump)

static void
vl_api_ipip_add_tunnel_t_handler (vl_api_ipip_add_tunnel_t * mp)
{
  vl_api_ipip_add_tunnel_reply_t *rmp;
  int rv = 0;
  u32 fib_index, sw_if_index = ~0;
  ip46_address_t src, dst;
  ip46_type_t itype;

  itype = ip_address_decode (&mp->src_address, &src);
  itype = ip_address_decode (&mp->dst_address, &dst);
  fib_index = fib_table_find (fib_proto_from_ip46 (itype),
			      ntohl (mp->table_id));

  if (fib_index == ~0)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
    }
  else
    {
      rv =
	ipip_add_tunnel ((itype ==
			  IP46_TYPE_IP6 ? IPIP_TRANSPORT_IP6 :
			  IPIP_TRANSPORT_IP4), ntohl (mp->instance), &src,
			 &dst, fib_index, mp->tc_tos, &sw_if_index);
    }

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
  vl_api_ipip_del_tunnel_reply_t *rmp;

  int rv = ipip_del_tunnel (ntohl (mp->sw_if_index));

  REPLY_MACRO (VL_API_IPIP_DEL_TUNNEL_REPLY);
}

static void
send_ipip_tunnel_details (ipip_tunnel_t * t,
			  vl_api_registration_t * reg, u32 context)
{
  vl_api_ipip_tunnel_details_t *rmp;
  ip46_type_t itype = (ip46_address_is_ip4 (&t->tunnel_src) ?
		       IP46_TYPE_IP4 : IP46_TYPE_IP6);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_IPIP_TUNNEL_DETAILS);

  ip_address_encode (&t->tunnel_src, itype, &rmp->src_address);
  ip_address_encode (&t->tunnel_dst, itype, &rmp->dst_address);
  rmp->fib_index =
    htonl (fib_table_get_table_id (t->fib_index,
				   fib_proto_from_ip46 (itype)));
  rmp->instance = htonl (t->user_instance);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_ipip_tunnel_dump_t_handler (vl_api_ipip_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;
  ipip_main_t *gm = &ipip_main;
  ipip_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (sw_if_index == ~0)
    {
    /* *INDENT-OFF* */
    pool_foreach(t, gm->tunnels,
                 ({ send_ipip_tunnel_details(t, reg, mp->context); }));
    /* *INDENT-ON* */
    }
  else
    {
      t = ipip_tunnel_db_find_by_sw_if_index (sw_if_index);
      if (t)
	send_ipip_tunnel_details (t, reg, mp->context);
    }
}

static void
vl_api_ipip_6rd_add_tunnel_t_handler (vl_api_ipip_6rd_add_tunnel_t * mp)
{
  vl_api_ipip_6rd_add_tunnel_reply_t *rmp;
  u32 sixrd_tunnel_index, ip4_fib_index, ip6_fib_index;
  int rv;

  ip4_fib_index = fib_table_find (FIB_PROTOCOL_IP4, ntohl (mp->ip4_table_id));
  ip6_fib_index = fib_table_find (FIB_PROTOCOL_IP6, ntohl (mp->ip6_table_id));

  if (~0 == ip4_fib_index || ~0 == ip6_fib_index)

    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
    }
  else
    {
      rv = sixrd_add_tunnel ((ip6_address_t *) & mp->ip6_prefix.prefix,
			     mp->ip6_prefix.len,
			     (ip4_address_t *) & mp->ip4_prefix.prefix,
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
  vl_api_ipip_6rd_del_tunnel_reply_t *rmp;

  int rv = sixrd_del_tunnel (ntohl (mp->sw_if_index));

  REPLY_MACRO (VL_API_IPIP_6RD_DEL_TUNNEL_REPLY);
}

/*
 * ipip_api_hookup
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
#define _(id, n, crc) vl_msg_api_add_msg_name_crc(am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_ipip;
#undef _
}

static clib_error_t *
ipip_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N, n)                                                                \
  vl_msg_api_set_handlers(VL_API_##N, #n, vl_api_##n##_t_handler,              \
                          vl_noop_handler, vl_api_##n##_t_endian,              \
                          vl_api_##n##_t_print, sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

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
