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
vl_api_gtpu_offload_rx_t_handler (vl_api_gtpu_offload_rx_t * mp)
{
  vl_api_gtpu_offload_rx_reply_t *rmp;
  int rv = 0;
  vl_api_interface_index_t hw_if_index = ntohl (mp->hw_if_index);
  vl_api_interface_index_t sw_if_index = ntohl (mp->sw_if_index);

  if (!vnet_hw_interface_is_valid (vnet_get_main (), hw_if_index))
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto err;
    }
  VALIDATE_SW_IF_INDEX (mp);

  u32 t_index = vnet_gtpu_get_tunnel_index (sw_if_index);
  if (t_index == ~0)
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX_2;
      goto err;
    }

  gtpu_main_t *gtm = &gtpu_main;
  gtpu_tunnel_t *t = pool_elt_at_index (gtm->tunnels, t_index);
  if (!ip46_address_is_ip4 (&t->dst))
    {
      rv = VNET_API_ERROR_INVALID_ADDRESS_FAMILY;
      goto err;
    }

  if ((t->decap_next_index != GTPU_INPUT_NEXT_IP4_INPUT) &&
      (t->decap_next_index != GTPU_INPUT_NEXT_IP6_INPUT))
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

  if (vnet_gtpu_add_del_rx_flow (hw_if_index, t_index, mp->enable))
    {
      rv = VNET_API_ERROR_UNSPECIFIED;
      goto err;
    }
  BAD_SW_IF_INDEX_LABEL;
err:

  REPLY_MACRO (VL_API_GTPU_OFFLOAD_RX_REPLY);
}

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
  gtpu_main_t *gtm = &gtpu_main;

  vnet_gtpu_add_mod_del_tunnel_args_t a = {
    .opn = mp->is_add ? GTPU_ADD_TUNNEL : GTPU_DEL_TUNNEL,
    .mcast_sw_if_index = ntohl (mp->mcast_sw_if_index),
    .decap_next_index = ntohl (mp->decap_next_index),
    .teid = ntohl (mp->teid),
    .tteid = ntohl (mp->tteid),
    .pdu_extension = 0,
    .qfi = 0,
    .is_forwarding = 0,
    .forwarding_type = 0,
  };
  ip_address_decode (&mp->dst_address, &a.dst);
  ip_address_decode (&mp->src_address, &a.src);

  u8 is_ipv6 = !ip46_address_is_ip4 (&a.dst);
  a.encap_fib_index = fib_table_find (fib_ip_proto (is_ipv6),
				      ntohl (mp->encap_vrf_id));
  if (a.encap_fib_index == ~0)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

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
  rv = vnet_gtpu_add_mod_del_tunnel (&a, &sw_if_index);

out:
  REPLY_MACRO2(VL_API_GTPU_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
}

static void
vl_api_gtpu_add_del_tunnel_v2_t_handler (vl_api_gtpu_add_del_tunnel_v2_t *mp)
{
  vl_api_gtpu_add_del_tunnel_v2_reply_t *rmp;
  int rv = 0;
  vlib_counter_t result_rx;
  vlib_counter_t result_tx;
  gtpu_main_t *gtm = &gtpu_main;

  vnet_gtpu_add_mod_del_tunnel_args_t a = {
    .opn = mp->is_add ? GTPU_ADD_TUNNEL : GTPU_DEL_TUNNEL,
    .mcast_sw_if_index = ntohl (mp->mcast_sw_if_index),
    .decap_next_index = ntohl (mp->decap_next_index),
    .teid = ntohl (mp->teid),
    .tteid = ntohl (mp->tteid),
    .pdu_extension = mp->pdu_extension ? 1 : 0,
    .qfi = mp->qfi,
    .is_forwarding = 0,
    .forwarding_type = 0,
  };
  ip_address_decode (&mp->dst_address, &a.dst);
  ip_address_decode (&mp->src_address, &a.src);

  u8 is_ipv6 = !ip46_address_is_ip4 (&a.dst);
  a.encap_fib_index =
    fib_table_find (fib_ip_proto (is_ipv6), ntohl (mp->encap_vrf_id));
  if (a.encap_fib_index == ~0)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

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
  rv = vnet_gtpu_add_mod_del_tunnel (&a, &sw_if_index);
  get_combined_counters (sw_if_index, &result_rx, &result_tx);

out:
  REPLY_MACRO2 (
    VL_API_GTPU_ADD_DEL_TUNNEL_V2_REPLY, ({
      rmp->sw_if_index = ntohl (sw_if_index);
      rmp->counters.packets_rx = clib_net_to_host_u64 (result_rx.packets);
      rmp->counters.packets_tx = clib_net_to_host_u64 (result_tx.packets);
      rmp->counters.bytes_rx = clib_net_to_host_u64 (result_rx.bytes);
      rmp->counters.bytes_tx = clib_net_to_host_u64 (result_tx.bytes);
    }));
}

static void vl_api_gtpu_tunnel_update_tteid_t_handler
  (vl_api_gtpu_tunnel_update_tteid_t * mp)
{
  vl_api_gtpu_tunnel_update_tteid_reply_t *rmp;
  int rv = 0;
  gtpu_main_t *gtm = &gtpu_main;

  vnet_gtpu_add_mod_del_tunnel_args_t a = {
    .opn = GTPU_UPD_TTEID,
    .teid = ntohl (mp->teid),
    .tteid = ntohl (mp->tteid),
  };
  ip_address_decode (&mp->dst_address, &a.dst);

  u8 is_ipv6 = !ip46_address_is_ip4 (&a.dst);
  a.encap_fib_index = fib_table_find (fib_ip_proto (is_ipv6),
				      ntohl (mp->encap_vrf_id));
  if (a.encap_fib_index == ~0)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  rv = vnet_gtpu_add_mod_del_tunnel (&a, 0);

out:
  REPLY_MACRO (VL_API_GTPU_TUNNEL_UPDATE_TTEID_REPLY);
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
  rmp->tteid = htonl (t->tteid);
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
      pool_foreach (t, gtm->tunnels)
       {
        send_gtpu_tunnel_details(t, reg, mp->context);
       }
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

static void
send_gtpu_tunnel_details_v2 (gtpu_tunnel_t *t, vl_api_registration_t *reg,
			     u32 context)
{
  vl_api_gtpu_tunnel_v2_details_t *rmp;
  vlib_counter_t result_rx;
  vlib_counter_t result_tx;
  gtpu_main_t *gtm = &gtpu_main;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !ip46_address_is_ip4 (&t->dst);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_GTPU_TUNNEL_V2_DETAILS + gtm->msg_id_base);

  ip_address_encode (&t->src, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &rmp->src_address);
  ip_address_encode (&t->dst, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &rmp->dst_address);

  rmp->encap_vrf_id = is_ipv6 ?
			      htonl (im6->fibs[t->encap_fib_index].ft_table_id) :
			      htonl (im4->fibs[t->encap_fib_index].ft_table_id);
  rmp->mcast_sw_if_index = htonl (t->mcast_sw_if_index);
  rmp->teid = htonl (t->teid);
  rmp->tteid = htonl (t->tteid);
  rmp->decap_next_index = htonl (t->decap_next_index);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;
  rmp->pdu_extension = t->pdu_extension;
  rmp->qfi = t->qfi;
  rmp->is_forwarding = t->is_forwarding;
  rmp->forwarding_type = htonl (t->forwarding_type);

  get_combined_counters (t->sw_if_index, &result_rx, &result_tx);
  rmp->counters.packets_rx = clib_net_to_host_u64 (result_rx.packets);
  rmp->counters.packets_tx = clib_net_to_host_u64 (result_tx.packets);
  rmp->counters.bytes_rx = clib_net_to_host_u64 (result_rx.bytes);
  rmp->counters.bytes_tx = clib_net_to_host_u64 (result_tx.bytes);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_gtpu_tunnel_v2_dump_t_handler (vl_api_gtpu_tunnel_v2_dump_t *mp)
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
      pool_foreach (t, gtm->tunnels)
	{
	  send_gtpu_tunnel_details_v2 (t, reg, mp->context);
	}
    }
  else
    {
      if ((sw_if_index >= vec_len (gtm->tunnel_index_by_sw_if_index)) ||
	  (~0 == gtm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &gtm->tunnels[gtm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_gtpu_tunnel_details_v2 (t, reg, mp->context);
    }
}

static void
vl_api_gtpu_add_del_forward_t_handler (vl_api_gtpu_add_del_forward_t *mp)
{
  vl_api_gtpu_add_del_forward_reply_t *rmp;
  int rv = 0;
  gtpu_main_t *gtm = &gtpu_main;

  vnet_gtpu_add_mod_del_tunnel_args_t a = {
    .opn = mp->is_add ? GTPU_ADD_TUNNEL : GTPU_DEL_TUNNEL,
    .mcast_sw_if_index = 0,
    .decap_next_index = ntohl (mp->decap_next_index),
    .teid = 0,
    .tteid = 0,
    .pdu_extension = 0,
    .qfi = 0,
    .is_forwarding = 1,
    .forwarding_type = ntohl (mp->forwarding_type),
  };
  ip_address_decode (&mp->dst_address, &a.dst);
  /* Will be overwritten later */
  ip_address_decode (&mp->dst_address, &a.src);

  u8 is_ipv6 = !ip46_address_is_ip4 (&a.dst);
  a.encap_fib_index =
    fib_table_find (fib_ip_proto (is_ipv6), ntohl (mp->encap_vrf_id));

  if (a.encap_fib_index == ~0)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  if (ip46_address_is_multicast (&a.dst) &&
      !vnet_sw_if_index_is_api_valid (a.mcast_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto out;
    }

  u32 sw_if_index = ~0;
  rv = vnet_gtpu_add_del_forwarding (&a, &sw_if_index);

out:
  REPLY_MACRO2 (VL_API_GTPU_ADD_DEL_FORWARD_REPLY,
		({ rmp->sw_if_index = ntohl (sw_if_index); }));
}

static void
vl_api_gtpu_get_transfer_counts_t_handler (
  vl_api_gtpu_get_transfer_counts_t *mp)
{
  vl_api_gtpu_get_transfer_counts_reply_t *rmp;
  int rv = 0;
  vlib_counter_t result_rx;
  vlib_counter_t result_tx;
  gtpu_main_t *gtm = &gtpu_main;
  u32 count = 0;
  u32 sw_if_index;
  u32 capacity = ntohl (mp->capacity);
  u32 sw_if_index_start = ntohl (mp->sw_if_index_start);
  int extra_size = sizeof (rmp->tunnels[0]) * capacity;

  if (sw_if_index_start >= vec_len (gtm->tunnel_index_by_sw_if_index))
    {
      capacity = 0;
      extra_size = 0;
    }
  sw_if_index = sw_if_index_start;

  REPLY_MACRO4 (
    VL_API_GTPU_GET_TRANSFER_COUNTS_REPLY, extra_size, ({
      for (; count < capacity; sw_if_index++)
	{
	  if (sw_if_index >= vec_len (gtm->tunnel_index_by_sw_if_index))
	    {
	      // No more tunnels
	      break;
	    }
	  if (~0 == gtm->tunnel_index_by_sw_if_index[sw_if_index])
	    {
	      // Skip inactive/deleted tunnel
	      continue;
	    }
	  rmp->tunnels[count].sw_if_index = htonl (sw_if_index);
	  rmp->tunnels[count].reserved = 0;

	  get_combined_counters (sw_if_index, &result_rx, &result_tx);
	  rmp->tunnels[count].counters.packets_rx =
	    clib_net_to_host_u64 (result_rx.packets);
	  rmp->tunnels[count].counters.packets_tx =
	    clib_net_to_host_u64 (result_tx.packets);
	  rmp->tunnels[count].counters.bytes_rx =
	    clib_net_to_host_u64 (result_rx.bytes);
	  rmp->tunnels[count].counters.bytes_tx =
	    clib_net_to_host_u64 (result_tx.bytes);
	  count++;
	}
      rmp->count = htonl (count);
    }));
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
