/*
 *------------------------------------------------------------------
 * pppoe_api.c - pppoe api
 *
 * Copyright (c) 2017 Intel and/or its affiliates.
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

  u32 sw_if_index = ~0;
  rv = vnet_pppoe_add_del_session (&a, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_PPPOE_ADD_DEL_SESSION_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
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
      /* *INDENT-OFF* */
      pool_foreach (t, pem->sessions,
      ({
        send_pppoe_session_details(t, reg, mp->context);
      }));
      /* *INDENT-ON* */
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

#include <pppoe/pppoe.api.c>
static clib_error_t *
pppoe_api_hookup (vlib_main_t * vm)
{
  pppoe_main_t *pem = &pppoe_main;

  pem->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (pppoe_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
