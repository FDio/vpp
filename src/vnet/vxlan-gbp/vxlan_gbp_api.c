/*
 *------------------------------------------------------------------
 * vxlan_gbp_api.c - vxlan gbp api
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
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/vxlan-gbp/vxlan_gbp.h>
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
_(SW_INTERFACE_SET_VXLAN_GBP_BYPASS, sw_interface_set_vxlan_gbp_bypass)         \
_(VXLAN_GBP_TUNNEL_ADD_DEL, vxlan_gbp_tunnel_add_del)                           \
_(VXLAN_GBP_TUNNEL_DUMP, vxlan_gbp_tunnel_dump)

static void
  vl_api_sw_interface_set_vxlan_gbp_bypass_t_handler
  (vl_api_sw_interface_set_vxlan_gbp_bypass_t * mp)
{
  vl_api_sw_interface_set_vxlan_gbp_bypass_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  vnet_int_vxlan_gbp_bypass_mode (sw_if_index, mp->is_ipv6, mp->enable);
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_VXLAN_GBP_BYPASS_REPLY);
}

static void vl_api_vxlan_gbp_tunnel_add_del_t_handler
  (vl_api_vxlan_gbp_tunnel_add_del_t * mp)
{
  vl_api_vxlan_gbp_tunnel_add_del_reply_t *rmp;
  ip46_address_t src, dst;
  ip46_type_t itype;
  int rv = 0;
  u32 fib_index;

  itype = ip_address_decode (&mp->tunnel.src, &src);
  itype = ip_address_decode (&mp->tunnel.dst, &dst);

  fib_index = fib_table_find (fib_proto_from_ip46 (itype),
			      ntohl (mp->tunnel.encap_table_id));
  if (fib_index == ~0)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  vnet_vxlan_gbp_tunnel_add_del_args_t a = {
    .is_add = mp->is_add,
    .is_ip6 = (itype == IP46_TYPE_IP6),
    .instance = ntohl (mp->tunnel.instance),
    .mcast_sw_if_index = ntohl (mp->tunnel.mcast_sw_if_index),
    .encap_fib_index = fib_index,
    .decap_next_index = ntohl (mp->tunnel.decap_next_index),
    .vni = ntohl (mp->tunnel.vni),
    .dst = dst,
    .src = src,
  };

  /* Check src & dst are different */
  if (ip46_address_cmp (&a.dst, &a.src) == 0)
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  if (ip46_address_is_multicast (&a.dst) &&
      !vnet_sw_if_index_is_api_valid (a.mcast_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto out;
    }

  u32 sw_if_index = ~0;
  rv = vnet_vxlan_gbp_tunnel_add_del (&a, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_VXLAN_GBP_TUNNEL_ADD_DEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void send_vxlan_gbp_tunnel_details
  (vxlan_gbp_tunnel_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_vxlan_gbp_tunnel_details_t *rmp;
  ip46_type_t itype = (ip46_address_is_ip4 (&t->dst) ?
		       IP46_TYPE_IP4 : IP46_TYPE_IP6);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_VXLAN_GBP_TUNNEL_DETAILS);

  ip_address_encode (&t->src, itype, &rmp->tunnel.src);
  ip_address_encode (&t->dst, itype, &rmp->tunnel.dst);
  rmp->tunnel.encap_table_id =
    fib_table_get_table_id (t->encap_fib_index, fib_proto_from_ip46 (itype));

  rmp->tunnel.instance = htonl (t->user_instance);
  rmp->tunnel.mcast_sw_if_index = htonl (t->mcast_sw_if_index);
  rmp->tunnel.vni = htonl (t->vni);
  rmp->tunnel.decap_next_index = htonl (t->decap_next_index);
  rmp->tunnel.sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void vl_api_vxlan_gbp_tunnel_dump_t_handler
  (vl_api_vxlan_gbp_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;
  vxlan_gbp_main_t *vxm = &vxlan_gbp_main;
  vxlan_gbp_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, vxm->tunnels,
      ({
        send_vxlan_gbp_tunnel_details(t, reg, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if ((sw_if_index >= vec_len (vxm->tunnel_index_by_sw_if_index)) ||
	  (~0 == vxm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &vxm->tunnels[vxm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_vxlan_gbp_tunnel_details (t, reg, mp->context);
    }
}

/*
 * vpe_api_hookup
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
  foreach_vl_msg_name_crc_vxlan_gbp;
#undef _
}

static clib_error_t *
vxlan_gbp_api_hookup (vlib_main_t * vm)
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

VLIB_API_INIT_FUNCTION (vxlan_gbp_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
