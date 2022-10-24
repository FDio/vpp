/*
 *------------------------------------------------------------------
 * vxlan_api.c - vxlan api
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
#include <vnet/feature/feature.h>
#include <vxlan/vxlan.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/udp/udp_local.h>
#include <vnet/format_fns.h>
#include <vxlan/vxlan.api_enum.h>
#include <vxlan/vxlan.api_types.h>

static u16 msg_id_base;

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_vxlan_offload_rx_t_handler (vl_api_vxlan_offload_rx_t * mp)
{
  vl_api_vxlan_offload_rx_reply_t *rmp;
  int rv = 0;
  u32 hw_if_index = ntohl (mp->hw_if_index);
  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (!vnet_hw_interface_is_valid (vnet_get_main (), hw_if_index))
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto err;
    }
  VALIDATE_SW_IF_INDEX (mp);

  u32 t_index = vnet_vxlan_get_tunnel_index (sw_if_index);
  if (t_index == ~0)
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX_2;
      goto err;
    }

  vxlan_main_t *vxm = &vxlan_main;
  vxlan_tunnel_t *t = pool_elt_at_index (vxm->tunnels, t_index);
  if (!ip46_address_is_ip4 (&t->dst))
    {
      rv = VNET_API_ERROR_INVALID_ADDRESS_FAMILY;
      goto err;
    }

  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw_if = vnet_get_hw_interface (vnm, hw_if_index);
  ip4_main_t *im = &ip4_main;
  u32 rx_fib_index =
    vec_elt (im->fib_index_by_sw_if_index, hw_if->sw_if_index);

  if (t->encap_fib_index != rx_fib_index)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto err;
    }

  if (vnet_vxlan_add_del_rx_flow (hw_if_index, t_index, mp->enable))
    {
      rv = VNET_API_ERROR_UNSPECIFIED;
      goto err;
    }
  BAD_SW_IF_INDEX_LABEL;
err:

  REPLY_MACRO (VL_API_VXLAN_OFFLOAD_RX_REPLY);
}

static void
  vl_api_sw_interface_set_vxlan_bypass_t_handler
  (vl_api_sw_interface_set_vxlan_bypass_t * mp)
{
  vl_api_sw_interface_set_vxlan_bypass_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  vnet_int_vxlan_bypass_mode (sw_if_index, mp->is_ipv6, mp->enable);
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_VXLAN_BYPASS_REPLY);
}

static int
vxlan_add_del_tunnel_clean_input (vnet_vxlan_add_del_tunnel_args_t *a,
				  u32 encap_vrf_id)
{
  a->is_ip6 = !ip46_address_is_ip4 (&a->src);

  a->encap_fib_index = fib_table_find (fib_ip_proto (a->is_ip6), encap_vrf_id);
  if (a->encap_fib_index == ~0)
    {
      return VNET_API_ERROR_NO_SUCH_FIB;
    }

  if (ip46_address_is_ip4 (&a->src) != ip46_address_is_ip4 (&a->dst))
    {
      return VNET_API_ERROR_INVALID_VALUE;
    }

  /* Check src & dst are different */
  if (ip46_address_cmp (&a->dst, &a->src) == 0)
    {
      return VNET_API_ERROR_SAME_SRC_DST;
    }
  if (ip46_address_is_multicast (&a->dst) &&
      !vnet_sw_if_index_is_api_valid (a->mcast_sw_if_index))
    {
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }
  return 0;
}

static void
vl_api_vxlan_add_del_tunnel_t_handler (vl_api_vxlan_add_del_tunnel_t *mp)
{
  vl_api_vxlan_add_del_tunnel_reply_t *rmp;
  u32 sw_if_index = ~0;
  int rv = 0;

  vnet_vxlan_add_del_tunnel_args_t a = {
    .is_add = mp->is_add,
    .instance = ntohl (mp->instance),
    .mcast_sw_if_index = ntohl (mp->mcast_sw_if_index),
    .decap_next_index = ntohl (mp->decap_next_index),
    .vni = ntohl (mp->vni),
  };
  ip_address_decode (&mp->src_address, &a.src);
  ip_address_decode (&mp->dst_address, &a.dst);

  rv = vxlan_add_del_tunnel_clean_input (&a, ntohl (mp->encap_vrf_id));
  if (rv)
    goto out;
  a.dst_port = a.is_ip6 ? UDP_DST_PORT_vxlan6 : UDP_DST_PORT_vxlan,
  a.src_port = a.is_ip6 ? UDP_DST_PORT_vxlan6 : UDP_DST_PORT_vxlan,
  rv = vnet_vxlan_add_del_tunnel (&a, &sw_if_index);

out:
  REPLY_MACRO2(VL_API_VXLAN_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
}

static void
vl_api_vxlan_add_del_tunnel_v2_t_handler (vl_api_vxlan_add_del_tunnel_v2_t *mp)
{
  vl_api_vxlan_add_del_tunnel_v2_reply_t *rmp;
  u32 sw_if_index = ~0;
  int rv = 0;

  vnet_vxlan_add_del_tunnel_args_t a = {
    .is_add = mp->is_add,
    .instance = ntohl (mp->instance),
    .mcast_sw_if_index = ntohl (mp->mcast_sw_if_index),
    .decap_next_index = ntohl (mp->decap_next_index),
    .vni = ntohl (mp->vni),
    .dst_port = ntohs (mp->dst_port),
    .src_port = ntohs (mp->src_port),
  };

  ip_address_decode (&mp->src_address, &a.src);
  ip_address_decode (&mp->dst_address, &a.dst);

  rv = vxlan_add_del_tunnel_clean_input (&a, ntohl (mp->encap_vrf_id));
  if (rv)
    goto out;
  rv = vnet_vxlan_add_del_tunnel (&a, &sw_if_index);
out:
  REPLY_MACRO2 (VL_API_VXLAN_ADD_DEL_TUNNEL_V2_REPLY,
		({ rmp->sw_if_index = ntohl (sw_if_index); }));
}

static void
vl_api_vxlan_add_del_tunnel_v3_t_handler (vl_api_vxlan_add_del_tunnel_v3_t *mp)
{
  vl_api_vxlan_add_del_tunnel_v3_reply_t *rmp;
  u32 sw_if_index = ~0;
  int rv = 0;

  vnet_vxlan_add_del_tunnel_args_t a = {
    .is_add = mp->is_add,
    .instance = ntohl (mp->instance),
    .mcast_sw_if_index = ntohl (mp->mcast_sw_if_index),
    .decap_next_index = ntohl (mp->decap_next_index),
    .vni = ntohl (mp->vni),
    .dst_port = ntohs (mp->dst_port),
    .src_port = ntohs (mp->src_port),
    .is_l3 = mp->is_l3,
  };

  ip_address_decode (&mp->src_address, &a.src);
  ip_address_decode (&mp->dst_address, &a.dst);

  rv = vxlan_add_del_tunnel_clean_input (&a, ntohl (mp->encap_vrf_id));
  if (rv)
    goto out;
  rv = vnet_vxlan_add_del_tunnel (&a, &sw_if_index);
out:
  REPLY_MACRO2 (VL_API_VXLAN_ADD_DEL_TUNNEL_V3_REPLY,
		({ rmp->sw_if_index = ntohl (sw_if_index); }));
}

static void send_vxlan_tunnel_details
  (vxlan_tunnel_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_vxlan_tunnel_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_VXLAN_TUNNEL_DETAILS);

  ip_address_encode (&t->src, IP46_TYPE_ANY, &rmp->src_address);
  ip_address_encode (&t->dst, IP46_TYPE_ANY, &rmp->dst_address);

  if (ip46_address_is_ip4 (&t->dst))
    rmp->encap_vrf_id = htonl (im4->fibs[t->encap_fib_index].ft_table_id);
  else
    rmp->encap_vrf_id = htonl (im6->fibs[t->encap_fib_index].ft_table_id);

  rmp->instance = htonl (t->user_instance);
  rmp->mcast_sw_if_index = htonl (t->mcast_sw_if_index);
  rmp->vni = htonl (t->vni);
  rmp->decap_next_index = htonl (t->decap_next_index);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void vl_api_vxlan_tunnel_dump_t_handler
  (vl_api_vxlan_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;
  vxlan_main_t *vxm = &vxlan_main;
  vxlan_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      pool_foreach (t, vxm->tunnels)
        send_vxlan_tunnel_details(t, reg, mp->context);
    }
  else
    {
      if ((sw_if_index >= vec_len (vxm->tunnel_index_by_sw_if_index)) ||
	  (~0 == vxm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &vxm->tunnels[vxm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_vxlan_tunnel_details (t, reg, mp->context);
    }
}

static void
send_vxlan_tunnel_v2_details (vxlan_tunnel_t *t, vl_api_registration_t *reg,
			      u32 context)
{
  vl_api_vxlan_tunnel_v2_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_VXLAN_TUNNEL_V2_DETAILS);

  ip_address_encode (&t->src, IP46_TYPE_ANY, &rmp->src_address);
  ip_address_encode (&t->dst, IP46_TYPE_ANY, &rmp->dst_address);
  rmp->src_port = htons (t->src_port);
  rmp->dst_port = htons (t->dst_port);

  if (ip46_address_is_ip4 (&t->dst))
    rmp->encap_vrf_id = htonl (im4->fibs[t->encap_fib_index].ft_table_id);
  else
    rmp->encap_vrf_id = htonl (im6->fibs[t->encap_fib_index].ft_table_id);

  rmp->instance = htonl (t->user_instance);
  rmp->mcast_sw_if_index = htonl (t->mcast_sw_if_index);
  rmp->vni = htonl (t->vni);
  rmp->decap_next_index = htonl (t->decap_next_index);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_vxlan_tunnel_v2_dump_t_handler (vl_api_vxlan_tunnel_v2_dump_t *mp)
{
  vl_api_registration_t *reg;
  vxlan_main_t *vxm = &vxlan_main;
  vxlan_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      pool_foreach (t, vxm->tunnels)
	send_vxlan_tunnel_v2_details (t, reg, mp->context);
    }
  else
    {
      if ((sw_if_index >= vec_len (vxm->tunnel_index_by_sw_if_index)) ||
	  (~0 == vxm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &vxm->tunnels[vxm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_vxlan_tunnel_v2_details (t, reg, mp->context);
    }
}

#include <vxlan/vxlan.api.c>
static clib_error_t *
vxlan_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

  vl_api_increase_msg_trace_size (am, VL_API_VXLAN_ADD_DEL_TUNNEL,
				  16 * sizeof (u32));

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (vxlan_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
