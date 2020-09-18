/*
 *------------------------------------------------------------------
 * l2tp_api.c - l2tpv3 api
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
#include <l2tp/l2tp.h>
#include <vnet/ip/ip_types_api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <l2tp/l2tp.api_enum.h>
#include <l2tp/l2tp.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 l2tp_base_msg_id;
#define REPLY_MSG_ID_BASE l2tp_base_msg_id

#include <vlibapi/api_helper_macros.h>

static void
send_sw_if_l2tpv3_tunnel_details (vpe_api_main_t * am,
				  vl_api_registration_t * reg,
				  l2t_session_t * s,
				  l2t_main_t * lm, u32 context)
{
  vl_api_sw_if_l2tpv3_tunnel_details_t *mp;
  u8 *if_name = NULL;
  vnet_sw_interface_t *si = NULL;

  si = vnet_get_hw_sw_interface (lm->vnet_main, s->hw_if_index);

  if_name = format (if_name, "%U",
		    format_vnet_sw_interface_name, lm->vnet_main, si);

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id =
    ntohs (VL_API_SW_IF_L2TPV3_TUNNEL_DETAILS + REPLY_MSG_ID_BASE);
  strncpy ((char *) mp->interface_name, (char *) if_name,
	   ARRAY_LEN (mp->interface_name) - 1);
  mp->sw_if_index = ntohl (si->sw_if_index);
  mp->local_session_id = s->local_session_id;
  mp->remote_session_id = s->remote_session_id;
  mp->local_cookie[0] = s->local_cookie[0];
  mp->local_cookie[1] = s->local_cookie[1];
  mp->remote_cookie = s->remote_cookie;
  ip_address_encode ((ip46_address_t *) & s->client_address, IP46_TYPE_IP6,
		     &mp->client_address);
  ip_address_encode ((ip46_address_t *) & s->our_address, IP46_TYPE_IP6,
		     &mp->our_address);
  mp->l2_sublayer_present = s->l2_sublayer_present;
  mp->context = context;

  vl_api_send_msg (reg, (u8 *) mp);
}


static void
vl_api_sw_if_l2tpv3_tunnel_dump_t_handler (vl_api_sw_if_l2tpv3_tunnel_dump_t *
					   mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  l2t_main_t *lm = &l2t_main;
  vl_api_registration_t *reg;
  l2t_session_t *session;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (session, lm->sessions,
  ({
    send_sw_if_l2tpv3_tunnel_details (am, reg, session, lm, mp->context);
  }));
  /* *INDENT-ON* */
}

static void vl_api_l2tpv3_create_tunnel_t_handler
  (vl_api_l2tpv3_create_tunnel_t * mp)
{
  vl_api_l2tpv3_create_tunnel_reply_t *rmp;
  l2t_main_t *lm = &l2t_main;
  u32 sw_if_index = (u32) ~ 0;
  int rv;
  ip46_address_t client, our;

  if (mp->our_address.af == ADDRESS_IP4)
    {
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      goto out;
    }

  u32 encap_fib_index;

  if (mp->encap_vrf_id != ~0)
    {
      uword *p;
      ip6_main_t *im = &ip6_main;
      if (!
	  (p =
	   hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id))))
	{
	  rv = VNET_API_ERROR_NO_SUCH_FIB;
	  goto out;
	}
      encap_fib_index = p[0];
    }
  else
    {
      encap_fib_index = ~0;
    }

  ip_address_decode (&mp->client_address, &client);
  ip_address_decode (&mp->our_address, &our);

  rv = create_l2tpv3_ipv6_tunnel (lm,
				  &client.ip6,
				  &our.ip6,
				  ntohl (mp->local_session_id),
				  ntohl (mp->remote_session_id),
				  clib_net_to_host_u64 (mp->local_cookie),
				  clib_net_to_host_u64 (mp->remote_cookie),
				  mp->l2_sublayer_present,
				  encap_fib_index, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_L2TPV3_CREATE_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void vl_api_l2tpv3_set_tunnel_cookies_t_handler
  (vl_api_l2tpv3_set_tunnel_cookies_t * mp)
{
  vl_api_l2tpv3_set_tunnel_cookies_reply_t *rmp;
  l2t_main_t *lm = &l2t_main;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  rv = l2tpv3_set_tunnel_cookies (lm, ntohl (mp->sw_if_index),
				  clib_net_to_host_u64 (mp->new_local_cookie),
				  clib_net_to_host_u64
				  (mp->new_remote_cookie));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2TPV3_SET_TUNNEL_COOKIES_REPLY);
}

static void vl_api_l2tpv3_interface_enable_disable_t_handler
  (vl_api_l2tpv3_interface_enable_disable_t * mp)
{
  int rv;
  vnet_main_t *vnm = vnet_get_main ();
  vl_api_l2tpv3_interface_enable_disable_reply_t *rmp;

  VALIDATE_SW_IF_INDEX (mp);

  rv = l2tpv3_interface_enable_disable
    (vnm, ntohl (mp->sw_if_index), mp->enable_disable);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2TPV3_INTERFACE_ENABLE_DISABLE_REPLY);
}

static void vl_api_l2tpv3_set_lookup_key_t_handler
  (vl_api_l2tpv3_set_lookup_key_t * mp)
{
  int rv = 0;
  l2t_main_t *lm = &l2t_main;
  vl_api_l2tpv3_set_lookup_key_reply_t *rmp;

  if (mp->key > L2T_LOOKUP_KEY_API_SESSION_ID)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }

  lm->lookup_type = (ip6_to_l2_lookup_t) mp->key;

out:
  REPLY_MACRO (VL_API_L2TPV3_SET_LOOKUP_KEY_REPLY);
}

/*
 * l2tp_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#include <l2tp/l2tp.api.c>

static clib_error_t *
l2tp_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  l2tp_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (l2tp_api_hookup);

#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Layer 2 Tunneling Protocol v3 (L2TP)",
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
