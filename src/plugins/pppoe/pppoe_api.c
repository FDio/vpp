/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Intel and/or its affiliates.
 */

/*
 * pppoe_api.c - pppoe api
 */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>
#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>


#include <pppoe/pppoe.h>

#include <vnet/format_fns.h>
#include <pppoe/pppoe.api_enum.h>
#include <pppoe/pppoe.api_types.h>

#define REPLY_MSG_ID_BASE pem->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void vl_api_pppoe_add_del_session_t_handler
  (vl_api_pppoe_add_del_session_t * mp)
{
  vl_api_pppoe_add_del_session_reply_t *rmp;
  int rv = 0;
  u32 decap_fib_index;
  u32 sw_if_index = ~0;
  ip4_main_t *im = &ip4_main;
  pppoe_main_t *pem = &pppoe_main;

  uword *p = hash_get (im->fib_index_by_table_id, ntohl (mp->decap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_INNER_FIB;
      goto out;
    }
  decap_fib_index = p[0];

  vnet_pppoe_add_del_session_args_t a = {
    .is_add = mp->is_add,
    .decap_fib_index = decap_fib_index,
    .session_id = ntohs (mp->session_id),
  };
  ip_address_decode (&mp->client_ip, &a.client_ip);
  clib_memcpy (a.client_mac, mp->client_mac, 6);

  rv = vnet_pppoe_add_del_session (&a, &sw_if_index);

out:
  REPLY_MACRO2(VL_API_PPPOE_ADD_DEL_SESSION_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
}

static void send_pppoe_session_details
  (pppoe_session_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_pppoe_session_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !ip46_address_is_ip4 (&t->client_ip);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_PPPOE_SESSION_DETAILS);
  ip_address_encode (&t->client_ip, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &rmp->client_ip);

  if (is_ipv6)
    {
      rmp->decap_vrf_id = htonl (im6->fibs[t->decap_fib_index].ft_table_id);
    }
  else
    {
      rmp->decap_vrf_id = htonl (im4->fibs[t->decap_fib_index].ft_table_id);
    }
  rmp->session_id = htons (t->session_id);
  rmp->encap_if_index = htonl (t->encap_if_index);
  clib_memcpy (rmp->local_mac, t->local_mac, 6);
  clib_memcpy (rmp->client_mac, t->client_mac, 6);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_pppoe_session_dump_t_handler (vl_api_pppoe_session_dump_t * mp)
{
  vl_api_registration_t *reg;
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      pool_foreach (t, pem->sessions)
       {
        send_pppoe_session_details(t, reg, mp->context);
      }
    }
  else
    {
      if ((sw_if_index >= vec_len (pem->session_index_by_sw_if_index)) ||
	  (~0 == pem->session_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &pem->sessions[pem->session_index_by_sw_if_index[sw_if_index]];
      send_pppoe_session_details (t, reg, mp->context);
    }
}

static void
vl_api_pppoe_add_del_cp_t_handler (vl_api_pppoe_add_del_cp_t * mp)
{
  vl_api_pppoe_add_del_cp_reply_t *rmp;
  i32 rv = 0;
  pppoe_main_t *pem = &pppoe_main;

  rv = pppoe_add_del_cp (ntohl (mp->sw_if_index), mp->is_add);

  REPLY_MACRO(VL_API_PPPOE_ADD_DEL_CP_REPLY);
}

static void
vl_api_pppoe_add_sub_session_t_handler (vl_api_pppoe_add_sub_session_t *mp)
{
  vl_api_pppoe_add_sub_session_reply_t *rmp;
  pppoe_main_t *pem = &pppoe_main;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = 0;
  u32 sw_if_index = ~0;
  u32 decap_vrf_id = ntohl (mp->decap_vrf_id);
  u32 unnumbered_sw_if_index = ntohl (mp->unnumbered_sw_if_index);
  u16 mtu = ntohs (mp->mtu);
  u32 decap_fib_index;
  fib_protocol_t fproto;
  ip46_address_t client_ip;
  u8 is_ip6;

  clib_memset (&client_ip, 0, sizeof (client_ip));
  ip_address_decode (&mp->client_address, &client_ip);
  is_ip6 = !ip46_address_is_ip4 (&client_ip);
  fproto = is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4;

  /* Resolve the subscriber VRF to a FIB index in the client's family. */
  decap_fib_index = fib_table_find (fproto, decap_vrf_id);
  if (~0 == decap_fib_index)
    {
      rv = VNET_API_ERROR_NO_SUCH_INNER_FIB;
      goto out;
    }

  /*
   * (a) Create the session.  vnet_pppoe_add_del_session() also brings the
   *     session interface admin-up and installs the reverse client route
   *     (/32 or /128) into decap_fib_index.
   */
  vnet_pppoe_add_del_session_args_t a = {
    .is_add = 1,
    .is_ip6 = is_ip6,
    .decap_fib_index = decap_fib_index,
    .session_id = ntohs (mp->session_id),
    .client_ip = client_ip,
  };
  clib_memcpy (a.client_mac, mp->client_mac, 6);

  rv = vnet_pppoe_add_del_session (&a, &sw_if_index);
  if (rv != 0)
    goto out;

  /* (b) Ensure the session interface is admin-up (idempotent). */
  vnet_sw_interface_set_flags (vnm, sw_if_index, VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  /* (f) Drop the auto-installed reverse route if the caller opted out. */
  if (!mp->install_route)
    pppoe_session_reverse_route_del (decap_fib_index, &client_ip, is_ip6, sw_if_index);

  /*
   * (c) Place the session interface in the subscriber VRF for whichever
   *     address families exist.  Must precede the unnumbered step: once the
   *     interface borrows an address, ip_table_bind refuses to move it.
   */
  if (decap_vrf_id != 0)
    {
      if (~0 != fib_table_find (FIB_PROTOCOL_IP4, decap_vrf_id))
	{
	  rv = ip_table_bind (FIB_PROTOCOL_IP4, sw_if_index, decap_vrf_id);
	  if (rv != 0)
	    goto out;
	}
      if (~0 != fib_table_find (FIB_PROTOCOL_IP6, decap_vrf_id))
	{
	  rv = ip_table_bind (FIB_PROTOCOL_IP6, sw_if_index, decap_vrf_id);
	  if (rv != 0)
	    goto out;
	}
    }

  /* (d) Enforce the negotiated PPPoE MRU as the L3 MTU. */
  if (mtu != 0)
    vnet_sw_interface_set_mtu (vnm, sw_if_index, mtu);

  /*
   * (e) Enable L3 input on the session by borrowing the loopback/core
   *     interface's address.  Without this VPP leaves ip4-not-enabled in the
   *     arc and blackholes decapsulated subscriber traffic.
   */
  if (~0 != unnumbered_sw_if_index)
    {
      rv =
	vnet_sw_interface_update_unnumbered (sw_if_index, unnumbered_sw_if_index, 1 /* enable */);
      if (rv != 0)
	goto out;
    }

out:
  /* (g) Return the new session interface index. */
  REPLY_MACRO2 (VL_API_PPPOE_ADD_SUB_SESSION_REPLY, ({ rmp->sw_if_index = ntohl (sw_if_index); }));
}

#include <pppoe/pppoe.api.c>
static clib_error_t *
pppoe_api_hookup (vlib_main_t * vm)
{
  pppoe_main_t *pem = &pppoe_main;

  pem->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (pppoe_api_hookup);
