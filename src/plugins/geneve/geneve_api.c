/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 SUSE LLC.
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>

#include <geneve/geneve.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <geneve/geneve.api_enum.h>
#include <geneve/geneve.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 geneve_base_msg_id;
#define REPLY_MSG_ID_BASE geneve_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
  vl_api_sw_interface_set_geneve_bypass_t_handler
  (vl_api_sw_interface_set_geneve_bypass_t * mp)
{
  vl_api_sw_interface_set_geneve_bypass_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  vnet_int_geneve_bypass_mode (sw_if_index, mp->is_ipv6, mp->enable);
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_GENEVE_BYPASS_REPLY);
}

static void vl_api_geneve_add_del_tunnel_t_handler
  (vl_api_geneve_add_del_tunnel_t * mp)
{
  vl_api_geneve_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ~0;
  ip4_main_t *im = &ip4_main;

  uword *p = hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  vnet_geneve_add_del_tunnel_args_t a = {
    .is_add = mp->is_add,
    .is_ip6 = mp->remote_address.af,
    .mcast_sw_if_index = ntohl (mp->mcast_sw_if_index),
    .encap_fib_index = p[0],
    .decap_next_index = ntohl (mp->decap_next_index),
    .vni = ntohl (mp->vni),
  };

  ip_address_decode (&mp->remote_address, &a.remote);
  ip_address_decode (&mp->local_address, &a.local);

  /* Check src & dst are different */
  if (ip46_address_cmp (&a.remote, &a.local) == 0)
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  if (ip46_address_is_multicast (&a.remote) &&
      !vnet_sw_if_index_is_api_valid (a.mcast_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto out;
    }

  rv = vnet_geneve_add_del_tunnel (&a, &sw_if_index);

out:
  REPLY_MACRO2(VL_API_GENEVE_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
}

static void vl_api_geneve_add_del_tunnel2_t_handler
  (vl_api_geneve_add_del_tunnel2_t * mp)
{
  vl_api_geneve_add_del_tunnel2_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ~0;
  ip4_main_t *im = &ip4_main;

  uword *p = hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  vnet_geneve_add_del_tunnel_args_t a = {
    .is_add = mp->is_add,
    .is_ip6 = mp->remote_address.af,
    .mcast_sw_if_index = ntohl (mp->mcast_sw_if_index),
    .encap_fib_index = p[0],
    .decap_next_index = ntohl (mp->decap_next_index),
    .vni = ntohl (mp->vni),
    .l3_mode = mp->l3_mode,
  };

  ip_address_decode (&mp->remote_address, &a.remote);
  ip_address_decode (&mp->local_address, &a.local);

  /* Check src & dst are different */
  if (ip46_address_cmp (&a.remote, &a.local) == 0)
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  if (ip46_address_is_multicast (&a.remote) &&
      !vnet_sw_if_index_is_api_valid (a.mcast_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto out;
    }

  rv = vnet_geneve_add_del_tunnel (&a, &sw_if_index);

out:
  REPLY_MACRO2(VL_API_GENEVE_ADD_DEL_TUNNEL2_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
}

static void send_geneve_tunnel_details
  (geneve_tunnel_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_geneve_tunnel_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !ip46_address_is_ip4 (&t->remote);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_GENEVE_TUNNEL_DETAILS + REPLY_MSG_ID_BASE);
  ip_address_encode (&t->local, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &rmp->src_address);
  ip_address_encode (&t->remote, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &rmp->dst_address);
  rmp->encap_vrf_id =
    htonl (is_ipv6 ? im6->fibs[t->encap_fib_index].
	   ft_table_id : im4->fibs[t->encap_fib_index].ft_table_id);

  rmp->mcast_sw_if_index = htonl (t->mcast_sw_if_index);
  rmp->vni = htonl (t->vni);
  rmp->decap_next_index = htonl (t->decap_next_index);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void vl_api_geneve_tunnel_dump_t_handler
  (vl_api_geneve_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;
  geneve_main_t *vxm = &geneve_main;
  geneve_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      pool_foreach (t, vxm->tunnels)
       {
        send_geneve_tunnel_details(t, reg, mp->context);
      }
    }
  else
    {
      if ((sw_if_index >= vec_len (vxm->tunnel_index_by_sw_if_index)) ||
	  (~0 == vxm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &vxm->tunnels[vxm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_geneve_tunnel_details (t, reg, mp->context);
    }
}

/*
 * geneve_api_hookup
 * Add geneve's API message handlers to the table.
 */
/* API definitions */
#include <vnet/format_fns.h>
#include <geneve/geneve.api.c>

static clib_error_t *
geneve_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  geneve_base_msg_id = setup_message_id_table ();

  vl_api_increase_msg_trace_size (
    am, VL_API_GENEVE_ADD_DEL_TUNNEL + REPLY_MSG_ID_BASE, 16 * sizeof (u32));

  return 0;
}

VLIB_API_INIT_FUNCTION (geneve_api_hookup);

#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "GENEVE Tunnels",
};
