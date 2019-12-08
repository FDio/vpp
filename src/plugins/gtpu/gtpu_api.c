/*
 *------------------------------------------------------------------
 * gtpu_api.c - gtpu api
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

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <gtpu/gtpu.h>

#include <vnet/format_fns.h>
#include <gtpu/gtpu.api_enum.h>
#include <gtpu/gtpu.api_types.h>

#define REPLY_MSG_ID_BASE gtm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
  vl_api_sw_interface_set_gtpu_bypass_t_handler
  (vl_api_sw_interface_set_gtpu_bypass_t * mp)
{
  vl_api_sw_interface_set_gtpu_bypass_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  gtpu_main_t *gtm = &gtpu_main;

  VALIDATE_SW_IF_INDEX (mp);

  vnet_int_gtpu_bypass_mode (sw_if_index, mp->is_ipv6, mp->enable);
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_GTPU_BYPASS_REPLY);
}

static void vl_api_gtpu_add_del_tunnel_t_handler
  (vl_api_gtpu_add_del_tunnel_t * mp)
{
  vl_api_gtpu_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  ip4_main_t *im = &ip4_main;
  gtpu_main_t *gtm = &gtpu_main;

  uword *p = hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  vnet_gtpu_add_del_tunnel_args_t a = {
    .is_add = mp->is_add,
    .mcast_sw_if_index = ntohl (mp->mcast_sw_if_index),
    .encap_fib_index = p[0],
    .decap_next_index = ntohl (mp->decap_next_index),
    .teid = ntohl (mp->teid),
  };
  ip_address_decode (&mp->dst_address, &a.dst);
  ip_address_decode (&mp->src_address, &a.src);

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
  rv = vnet_gtpu_add_del_tunnel (&a, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_GTPU_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void send_gtpu_tunnel_details
  (gtpu_tunnel_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_gtpu_tunnel_details_t *rmp;
  gtpu_main_t *gtm = &gtpu_main;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !ip46_address_is_ip4 (&t->dst);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_GTPU_TUNNEL_DETAILS + gtm->msg_id_base);

  ip_address_encode (&t->src, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &rmp->src_address);
  ip_address_encode (&t->dst, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &rmp->dst_address);

  rmp->encap_vrf_id =
    is_ipv6 ? htonl (im6->fibs[t->encap_fib_index].ft_table_id) :
    htonl (im4->fibs[t->encap_fib_index].ft_table_id);
  rmp->mcast_sw_if_index = htonl (t->mcast_sw_if_index);
  rmp->teid = htonl (t->teid);
  rmp->decap_next_index = htonl (t->decap_next_index);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_gtpu_tunnel_dump_t_handler (vl_api_gtpu_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;
  gtpu_main_t *gtm = &gtpu_main;
  gtpu_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, gtm->tunnels,
      ({
        send_gtpu_tunnel_details(t, reg, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if ((sw_if_index >= vec_len (gtm->tunnel_index_by_sw_if_index)) ||
	  (~0 == gtm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &gtm->tunnels[gtm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_gtpu_tunnel_details (t, reg, mp->context);
    }
}

#include <gtpu/gtpu.api.c>
static clib_error_t *
gtpu_api_hookup (vlib_main_t * vm)
{
  gtpu_main_t *gtm = &gtpu_main;

  gtm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (gtpu_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
