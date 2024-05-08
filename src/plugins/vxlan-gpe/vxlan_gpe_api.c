/*
 *------------------------------------------------------------------
 * vxlan_gpe_api.c - vxlan_gpe api
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
#include <vxlan-gpe/vxlan_gpe.h>
#include <vnet/fib/fib_table.h>
#include <vnet/format_fns.h>

#include <vnet/ip/ip_types_api.h>
#include <vxlan-gpe/vxlan_gpe.api_enum.h>
#include <vxlan-gpe/vxlan_gpe.api_types.h>

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static u16 msg_id_base;

static void
  vl_api_sw_interface_set_vxlan_gpe_bypass_t_handler
  (vl_api_sw_interface_set_vxlan_gpe_bypass_t * mp)
{
  vl_api_sw_interface_set_vxlan_gpe_bypass_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  vnet_int_vxlan_gpe_bypass_mode (sw_if_index, mp->is_ipv6, mp->enable);
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_VXLAN_GPE_BYPASS_REPLY);
}

static void
  vl_api_vxlan_gpe_add_del_tunnel_t_handler
  (vl_api_vxlan_gpe_add_del_tunnel_t * mp)
{
  vl_api_vxlan_gpe_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  vnet_vxlan_gpe_add_del_tunnel_args_t _a, *a = &_a;
  u32 encap_fib_index, decap_fib_index;
  u8 protocol;
  uword *p;
  ip4_main_t *im = &ip4_main;
  u32 sw_if_index = ~0;

  p = hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }
  encap_fib_index = p[0];

  protocol = mp->protocol;

  /* Interpret decap_vrf_id as an opaque if sending to other-than-ip4-input */
  if (protocol == VXLAN_GPE_INPUT_NEXT_IP4_INPUT)
    {
      p = hash_get (im->fib_index_by_table_id, ntohl (mp->decap_vrf_id));
      if (!p)
	{
	  rv = VNET_API_ERROR_NO_SUCH_INNER_FIB;
	  goto out;
	}
      decap_fib_index = p[0];
    }
  else
    {
      decap_fib_index = ntohl (mp->decap_vrf_id);
    }


  clib_memset (a, 0, sizeof (*a));

  a->is_add = mp->is_add;
  ip_address_decode (&mp->local, &a->local);
  ip_address_decode (&mp->remote, &a->remote);

  /* Check src & dst are different */
  if (ip46_address_is_equal (&a->local, &a->remote))
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }

  a->is_ip6 = !ip46_address_is_ip4 (&a->local);
  a->mcast_sw_if_index = ntohl (mp->mcast_sw_if_index);
  a->encap_fib_index = encap_fib_index;
  a->decap_fib_index = decap_fib_index;
  a->protocol = protocol;
  a->vni = ntohl (mp->vni);
  rv = vnet_vxlan_gpe_add_del_tunnel (a, &sw_if_index);

out:
  REPLY_MACRO2(VL_API_VXLAN_GPE_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
}

static void
vl_api_vxlan_gpe_add_del_tunnel_v2_t_handler (
  vl_api_vxlan_gpe_add_del_tunnel_v2_t *mp)
{
  vl_api_vxlan_gpe_add_del_tunnel_v2_reply_t *rmp;
  int rv = 0;
  vnet_vxlan_gpe_add_del_tunnel_args_t _a, *a = &_a;
  u32 encap_fib_index, decap_fib_index;
  u8 protocol;
  uword *p;
  ip4_main_t *im = &ip4_main;
  u32 sw_if_index = ~0;

  p = hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }
  encap_fib_index = p[0];

  protocol = mp->protocol;

  /* Interpret decap_vrf_id as an opaque if sending to other-than-ip4-input */
  if (protocol == VXLAN_GPE_INPUT_NEXT_IP4_INPUT)
    {
      p = hash_get (im->fib_index_by_table_id, ntohl (mp->decap_vrf_id));
      if (!p)
	{
	  rv = VNET_API_ERROR_NO_SUCH_INNER_FIB;
	  goto out;
	}
      decap_fib_index = p[0];
    }
  else
    {
      decap_fib_index = ntohl (mp->decap_vrf_id);
    }

  clib_memset (a, 0, sizeof (*a));

  a->is_add = mp->is_add;
  ip_address_decode (&mp->local, &a->local);
  ip_address_decode (&mp->remote, &a->remote);

  /* Check src & dst are different */
  if (ip46_address_is_equal (&a->local, &a->remote))
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }

  a->local_port = ntohs (mp->local_port);
  a->remote_port = ntohs (mp->remote_port);
  a->is_ip6 = !ip46_address_is_ip4 (&a->local);
  a->mcast_sw_if_index = ntohl (mp->mcast_sw_if_index);
  a->encap_fib_index = encap_fib_index;
  a->decap_fib_index = decap_fib_index;
  a->protocol = protocol;
  a->vni = ntohl (mp->vni);
  rv = vnet_vxlan_gpe_add_del_tunnel (a, &sw_if_index);

out:
  REPLY_MACRO2 (VL_API_VXLAN_GPE_ADD_DEL_TUNNEL_V2_REPLY,
		({ rmp->sw_if_index = ntohl (sw_if_index); }));
}

static void send_vxlan_gpe_tunnel_details
  (vxlan_gpe_tunnel_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_vxlan_gpe_tunnel_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !(t->flags & VXLAN_GPE_TUNNEL_IS_IPV4);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (REPLY_MSG_ID_BASE + VL_API_VXLAN_GPE_TUNNEL_DETAILS);

  ip_address_encode (&t->local, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &rmp->local);
  ip_address_encode (&t->remote, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &rmp->remote);

  if (ip46_address_is_ip4 (&t->local))
    {
      rmp->encap_vrf_id = htonl (im4->fibs[t->encap_fib_index].ft_table_id);
      rmp->decap_vrf_id = htonl (im4->fibs[t->decap_fib_index].ft_table_id);
    }
  else
    {
      rmp->encap_vrf_id = htonl (im6->fibs[t->encap_fib_index].ft_table_id);
      rmp->decap_vrf_id = htonl (im6->fibs[t->decap_fib_index].ft_table_id);
    }
  rmp->mcast_sw_if_index = htonl (t->mcast_sw_if_index);
  rmp->vni = htonl (t->vni);
  rmp->protocol = t->protocol;
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void vl_api_vxlan_gpe_tunnel_dump_t_handler
  (vl_api_vxlan_gpe_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;
  vxlan_gpe_main_t *vgm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      pool_foreach (t, vgm->tunnels)
	{
	  send_vxlan_gpe_tunnel_details (t, reg, mp->context);
	}
    }
  else
    {
      if ((sw_if_index >= vec_len (vgm->tunnel_index_by_sw_if_index)) ||
	  (~0 == vgm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &vgm->tunnels[vgm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_vxlan_gpe_tunnel_details (t, reg, mp->context);
    }
}

static void
send_vxlan_gpe_tunnel_v2_details (vxlan_gpe_tunnel_t *t,
				  vl_api_registration_t *reg, u32 context)
{
  vl_api_vxlan_gpe_tunnel_v2_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !(t->flags & VXLAN_GPE_TUNNEL_IS_IPV4);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (REPLY_MSG_ID_BASE + VL_API_VXLAN_GPE_TUNNEL_V2_DETAILS);

  ip_address_encode (&t->local, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &rmp->local);
  ip_address_encode (&t->remote, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &rmp->remote);
  rmp->local_port = htons (t->local_port);
  rmp->remote_port = htons (t->remote_port);

  if (ip46_address_is_ip4 (&t->local))
    {
      rmp->encap_vrf_id = htonl (im4->fibs[t->encap_fib_index].ft_table_id);
      rmp->decap_vrf_id = htonl (im4->fibs[t->decap_fib_index].ft_table_id);
    }
  else
    {
      rmp->encap_vrf_id = htonl (im6->fibs[t->encap_fib_index].ft_table_id);
      rmp->decap_vrf_id = htonl (im6->fibs[t->decap_fib_index].ft_table_id);
    }
  rmp->mcast_sw_if_index = htonl (t->mcast_sw_if_index);
  rmp->vni = htonl (t->vni);
  rmp->protocol = t->protocol;
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_vxlan_gpe_tunnel_v2_dump_t_handler (
  vl_api_vxlan_gpe_tunnel_v2_dump_t *mp)
{
  vl_api_registration_t *reg;
  vxlan_gpe_main_t *vgm = &vxlan_gpe_main;
  vxlan_gpe_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      pool_foreach (t, vgm->tunnels)
	{
	  send_vxlan_gpe_tunnel_v2_details (t, reg, mp->context);
	}
    }
  else
    {
      if ((sw_if_index >= vec_len (vgm->tunnel_index_by_sw_if_index)) ||
	  (~0 == vgm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &vgm->tunnels[vgm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_vxlan_gpe_tunnel_v2_details (t, reg, mp->context);
    }
}

#include <vxlan-gpe/vxlan_gpe.api.c>

static clib_error_t *
vxlan_gpe_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

  vl_api_increase_msg_trace_size (am, VL_API_VXLAN_GPE_ADD_DEL_TUNNEL,
				  17 * sizeof (u32));

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (vxlan_gpe_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
