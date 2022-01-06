/*
 *------------------------------------------------------------------
 * interface_api.c - vnet interface api
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
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>
#include <vnet/api_errno.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/l2/l2_vtr.h>
#include <vnet/fib/fib_api.h>
#include <vnet/mfib/mfib_table.h>
#include <vlibapi/api_types.h>

#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <interface.api_enum.h>
#include <interface.api_types.h>

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static u16 msg_id_base;

vpe_api_main_t vpe_api_main;

#define foreach_vpe_api_msg                                                   \
  _ (SW_INTERFACE_SET_FLAGS, sw_interface_set_flags)                          \
  _ (SW_INTERFACE_SET_PROMISC, sw_interface_set_promisc)                      \
  _ (HW_INTERFACE_SET_MTU, hw_interface_set_mtu)                              \
  _ (SW_INTERFACE_SET_MTU, sw_interface_set_mtu)                              \
  _ (WANT_INTERFACE_EVENTS, want_interface_events)                            \
  _ (SW_INTERFACE_DUMP, sw_interface_dump)                                    \
  _ (SW_INTERFACE_ADD_DEL_ADDRESS, sw_interface_add_del_address)              \
  _ (SW_INTERFACE_SET_RX_MODE, sw_interface_set_rx_mode)                      \
  _ (SW_INTERFACE_RX_PLACEMENT_DUMP, sw_interface_rx_placement_dump)          \
  _ (SW_INTERFACE_TX_PLACEMENT_GET, sw_interface_tx_placement_get)            \
  _ (SW_INTERFACE_SET_RX_PLACEMENT, sw_interface_set_rx_placement)            \
  _ (SW_INTERFACE_SET_TX_PLACEMENT, sw_interface_set_tx_placement)            \
  _ (SW_INTERFACE_SET_TABLE, sw_interface_set_table)                          \
  _ (SW_INTERFACE_GET_TABLE, sw_interface_get_table)                          \
  _ (SW_INTERFACE_SET_UNNUMBERED, sw_interface_set_unnumbered)                \
  _ (SW_INTERFACE_CLEAR_STATS, sw_interface_clear_stats)                      \
  _ (SW_INTERFACE_TAG_ADD_DEL, sw_interface_tag_add_del)                      \
  _ (SW_INTERFACE_ADD_DEL_MAC_ADDRESS, sw_interface_add_del_mac_address)      \
  _ (SW_INTERFACE_SET_MAC_ADDRESS, sw_interface_set_mac_address)              \
  _ (SW_INTERFACE_GET_MAC_ADDRESS, sw_interface_get_mac_address)              \
  _ (CREATE_VLAN_SUBIF, create_vlan_subif)                                    \
  _ (CREATE_SUBIF, create_subif)                                              \
  _ (DELETE_SUBIF, delete_subif)                                              \
  _ (CREATE_LOOPBACK, create_loopback)                                        \
  _ (CREATE_LOOPBACK_INSTANCE, create_loopback_instance)                      \
  _ (DELETE_LOOPBACK, delete_loopback)                                        \
  _ (INTERFACE_NAME_RENUMBER, interface_name_renumber)                        \
  _ (COLLECT_DETAILED_INTERFACE_STATS, collect_detailed_interface_stats)      \
  _ (SW_INTERFACE_SET_IP_DIRECTED_BROADCAST,                                  \
     sw_interface_set_ip_directed_broadcast)                                  \
  _ (SW_INTERFACE_ADDRESS_REPLACE_BEGIN, sw_interface_address_replace_begin)  \
  _ (SW_INTERFACE_ADDRESS_REPLACE_END, sw_interface_address_replace_end)

static void
vl_api_sw_interface_set_flags_t_handler (vl_api_sw_interface_set_flags_t * mp)
{
  vl_api_sw_interface_set_flags_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = 0;
  clib_error_t *error;
  u16 flags;

  VALIDATE_SW_IF_INDEX (mp);

  flags =
    ((ntohl (mp->flags)) & IF_STATUS_API_FLAG_ADMIN_UP) ?
    VNET_SW_INTERFACE_FLAG_ADMIN_UP : 0;

  error = vnet_sw_interface_set_flags (vnm, ntohl (mp->sw_if_index), flags);
  if (error)
    {
      rv = -1;
      clib_error_report (error);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_FLAGS_REPLY);
}

static void
vl_api_sw_interface_set_promisc_t_handler (
  vl_api_sw_interface_set_promisc_t *mp)
{
  vl_api_sw_interface_set_promisc_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  ethernet_main_t *em = &ethernet_main;
  int rv = 0;
  ethernet_interface_t *eif;
  vnet_sw_interface_t *swif;
  u32 flags, sw_if_index;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);
  swif = vnet_get_sw_interface (vnm, sw_if_index);
  eif = ethernet_get_interface (em, swif->hw_if_index);
  if (!eif)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  flags = mp->promisc_on ? ETHERNET_INTERFACE_FLAG_ACCEPT_ALL : 0;
  rv = ethernet_set_flags (vnm, swif->hw_if_index, flags);

done:
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_PROMISC_REPLY);
}

static void
vl_api_hw_interface_set_mtu_t_handler (vl_api_hw_interface_set_mtu_t * mp)
{
  vl_api_hw_interface_set_mtu_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u16 mtu = ntohs (mp->mtu);
  ethernet_main_t *em = &ethernet_main;
  clib_error_t *err;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
  if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto bad_sw_if_index;
    }

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, si->hw_if_index);
  ethernet_interface_t *eif = ethernet_get_interface (em, si->hw_if_index);

  if (!eif)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto bad_sw_if_index;
    }

  if (mtu < hi->min_supported_packet_bytes)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto bad_sw_if_index;
    }

  if (mtu > hi->max_supported_packet_bytes)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto bad_sw_if_index;
    }

  if ((err = vnet_hw_interface_set_mtu (vnm, si->hw_if_index, mtu)))
    {
      rv = vnet_api_error (err);
      clib_error_free (err);
      goto bad_sw_if_index;
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_HW_INTERFACE_SET_MTU_REPLY);
}

static void
vl_api_sw_interface_set_mtu_t_handler (vl_api_sw_interface_set_mtu_t * mp)
{
  vl_api_sw_interface_set_mtu_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;
  int i;
  u32 per_protocol_mtu[VNET_N_MTU];

  VALIDATE_SW_IF_INDEX (mp);

  for (i = 0; i < VNET_N_MTU; i++)
    {
      per_protocol_mtu[i] = ntohl (mp->mtu[i]);
    }
  vnet_sw_interface_set_protocol_mtu (vnm, sw_if_index, per_protocol_mtu);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_MTU_REPLY);
}

static void
  vl_api_sw_interface_set_ip_directed_broadcast_t_handler
  (vl_api_sw_interface_set_ip_directed_broadcast_t * mp)
{
  vl_api_sw_interface_set_ip_directed_broadcast_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  vnet_sw_interface_ip_directed_broadcast (vnet_get_main (),
					   sw_if_index, mp->enable);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_IP_DIRECTED_BROADCAST_REPLY);
}

static void
send_sw_interface_details (vpe_api_main_t * am,
			   vl_api_registration_t * rp,
			   vnet_sw_interface_t * swif,
			   u8 * interface_name, u32 context)
{
  vnet_hw_interface_t *hi =
    vnet_get_sup_hw_interface (am->vnet_main, swif->sw_if_index);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (am->vnet_main, hi->dev_class_index);

  vl_api_sw_interface_details_t *mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SW_INTERFACE_DETAILS);
  mp->sw_if_index = ntohl (swif->sw_if_index);
  mp->sup_sw_if_index = ntohl (swif->sup_sw_if_index);

  mp->flags |= (swif->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    IF_STATUS_API_FLAG_ADMIN_UP : 0;
  mp->flags |= (hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) ?
    IF_STATUS_API_FLAG_LINK_UP : 0;
  mp->flags = ntohl (mp->flags);

  switch (swif->type)
    {
    case VNET_SW_INTERFACE_TYPE_SUB:
      mp->type = IF_API_TYPE_SUB;
      break;
    case VNET_SW_INTERFACE_TYPE_P2P:
      mp->type = IF_API_TYPE_P2P;
      break;
    case VNET_SW_INTERFACE_TYPE_PIPE:
      mp->type = IF_API_TYPE_PIPE;
      break;
    default:
      mp->type = IF_API_TYPE_HARDWARE;
    }
  mp->type = ntohl (mp->type);

  mp->link_duplex = ntohl (((hi->flags & VNET_HW_INTERFACE_FLAG_DUPLEX_MASK) >>
			    VNET_HW_INTERFACE_FLAG_DUPLEX_SHIFT));
  mp->link_speed = ntohl (hi->link_speed);
  mp->link_mtu = ntohs (hi->max_packet_bytes);
  mp->mtu[VNET_MTU_L3] = ntohl (swif->mtu[VNET_MTU_L3]);
  mp->mtu[VNET_MTU_IP4] = ntohl (swif->mtu[VNET_MTU_IP4]);
  mp->mtu[VNET_MTU_IP6] = ntohl (swif->mtu[VNET_MTU_IP6]);
  mp->mtu[VNET_MTU_MPLS] = ntohl (swif->mtu[VNET_MTU_MPLS]);

  mp->context = context;

  strncpy ((char *) mp->interface_name,
	   (char *) interface_name, ARRAY_LEN (mp->interface_name) - 1);

  if (dev_class && dev_class->name)
    strncpy ((char *) mp->interface_dev_type, (char *) dev_class->name,
	     ARRAY_LEN (mp->interface_dev_type) - 1);

  /* Send the L2 address for ethernet physical intfcs */
  if (swif->sup_sw_if_index == swif->sw_if_index
      && hi->hw_class_index == ethernet_hw_interface_class.index)
    {
      ethernet_main_t *em = ethernet_get_main (am->vlib_main);
      ethernet_interface_t *ei;

      ei = pool_elt_at_index (em->interfaces, hi->hw_instance);
      ASSERT (sizeof (mp->l2_address) >= sizeof (ei->address.mac));
      mac_address_encode (&ei->address.mac, mp->l2_address);
    }
  else if (swif->sup_sw_if_index != swif->sw_if_index)
    {
      vnet_sub_interface_t *sub = &swif->sub;
      mp->sub_id = ntohl (sub->id);
      mp->sub_number_of_tags =
	sub->eth.flags.one_tag + sub->eth.flags.two_tags * 2;
      mp->sub_outer_vlan_id = ntohs (sub->eth.outer_vlan_id);
      mp->sub_inner_vlan_id = ntohs (sub->eth.inner_vlan_id);
      mp->sub_if_flags =
	ntohl (sub->eth.raw_flags & SUB_IF_API_FLAG_MASK_VNET);
    }

  /* vlan tag rewrite data */
  u32 vtr_op = L2_VTR_DISABLED;
  u32 vtr_push_dot1q = 0, vtr_tag1 = 0, vtr_tag2 = 0;

  if (l2vtr_get (am->vlib_main, am->vnet_main, swif->sw_if_index,
		 &vtr_op, &vtr_push_dot1q, &vtr_tag1, &vtr_tag2) != 0)
    {
      // error - default to disabled
      mp->vtr_op = ntohl (L2_VTR_DISABLED);
      clib_warning ("cannot get vlan tag rewrite for sw_if_index %d",
		    swif->sw_if_index);
    }
  else
    {
      mp->vtr_op = ntohl (vtr_op);
      mp->vtr_push_dot1q = ntohl (vtr_push_dot1q);
      mp->vtr_tag1 = ntohl (vtr_tag1);
      mp->vtr_tag2 = ntohl (vtr_tag2);
    }

  /* pbb tag rewrite data */
  ethernet_header_t eth_hdr;
  u32 pbb_vtr_op = L2_VTR_DISABLED;
  u16 outer_tag = 0;
  u16 b_vlanid = 0;
  u32 i_sid = 0;
  clib_memset (&eth_hdr, 0, sizeof (eth_hdr));

  if (!l2pbb_get (am->vlib_main, am->vnet_main, swif->sw_if_index,
		  &pbb_vtr_op, &outer_tag, &eth_hdr, &b_vlanid, &i_sid))
    {
      mp->sub_if_flags |= ntohl (SUB_IF_API_FLAG_DOT1AH);
      mac_address_encode ((mac_address_t *) eth_hdr.dst_address, mp->b_dmac);
      mac_address_encode ((mac_address_t *) eth_hdr.src_address, mp->b_smac);
      mp->b_vlanid = b_vlanid;
      mp->i_sid = i_sid;
    }

  u8 *tag = vnet_get_sw_interface_tag (vnet_get_main (), swif->sw_if_index);
  if (tag)
    strncpy ((char *) mp->tag, (char *) tag, ARRAY_LEN (mp->tag) - 1);

  vl_api_send_msg (rp, (u8 *) mp);
}

static void
vl_api_sw_interface_dump_t_handler (vl_api_sw_interface_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vnet_sw_interface_t *swif;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;
  vl_api_registration_t *rp;
  u32 sw_if_index;

  rp = vl_api_client_index_to_registration (mp->client_index);

  if (rp == 0)
    {
      clib_warning ("Client %d AWOL", mp->client_index);
      return;
    }

  u8 *filter = 0, *name = 0;
  sw_if_index = ntohl (mp->sw_if_index);

  if (!mp->name_filter_valid && sw_if_index != ~0 && sw_if_index != 0)
    {
      /* is it a valid sw_if_index? */
      if (!vnet_sw_if_index_is_api_valid (sw_if_index))
	return;

      swif = vec_elt_at_index (im->sw_interfaces, sw_if_index);

      vec_reset_length (name);
      name =
	format (name, "%U%c", format_vnet_sw_interface_name, am->vnet_main,
		swif, 0);
      send_sw_interface_details (am, rp, swif, name, mp->context);
      vec_free (name);
      return;
    }

  if (mp->name_filter_valid)
    {
      filter = vl_api_from_api_to_new_vec (mp, &mp->name_filter);
      vec_add1 (filter, 0);	/* Ensure it's a C string for strcasecmp() */
    }

  char *strcasestr (char *, char *);	/* lnx hdr file botch */
  /* *INDENT-OFF* */
  pool_foreach (swif, im->sw_interfaces)
   {
    if (!vnet_swif_is_api_visible (swif))
        continue;
    vec_reset_length(name);
    name = format (name, "%U%c", format_vnet_sw_interface_name, am->vnet_main,
                   swif, 0);

    if (filter && !strcasestr((char *) name, (char *) filter))
	continue;

    send_sw_interface_details (am, rp, swif, name, mp->context);
  }
  /* *INDENT-ON* */

  vec_free (name);
  vec_free (filter);
}

static void
  vl_api_sw_interface_add_del_address_t_handler
  (vl_api_sw_interface_add_del_address_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vl_api_sw_interface_add_del_address_reply_t *rmp;
  int rv = 0;
  u32 is_del;
  clib_error_t *error = 0;
  ip46_address_t address;

  VALIDATE_SW_IF_INDEX (mp);

  is_del = mp->is_add == 0;
  vnm->api_errno = 0;

  if (mp->del_all)
    ip_del_all_interface_addresses (vm, ntohl (mp->sw_if_index));
  else if (ip_address_decode (&mp->prefix.address, &address) == IP46_TYPE_IP6)
    error = ip6_add_del_interface_address (vm, ntohl (mp->sw_if_index),
					   (void *) &address.ip6,
					   mp->prefix.len, is_del);
  else
    error = ip4_add_del_interface_address (vm, ntohl (mp->sw_if_index),
					   (void *) &address.ip4,
					   mp->prefix.len, is_del);

  if (error)
    {
      rv = vnm->api_errno;
      clib_error_report (error);
      goto done;
    }

  BAD_SW_IF_INDEX_LABEL;

done:
  REPLY_MACRO (VL_API_SW_INTERFACE_ADD_DEL_ADDRESS_REPLY);
}

static void
vl_api_sw_interface_set_table_t_handler (vl_api_sw_interface_set_table_t * mp)
{
  vl_api_sw_interface_set_table_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 table_id = ntohl (mp->vrf_id);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->is_ipv6)
    rv = ip_table_bind (FIB_PROTOCOL_IP6, sw_if_index, table_id);
  else
    rv = ip_table_bind (FIB_PROTOCOL_IP4, sw_if_index, table_id);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_TABLE_REPLY);
}

void
fib_table_bind (fib_protocol_t fproto, u32 sw_if_index, u32 fib_index)
{
  u32 table_id;

  table_id = fib_table_get_table_id (fib_index, fproto);
  ASSERT (table_id != ~0);

  if (FIB_PROTOCOL_IP6 == fproto)
    {
      /*
       * tell those that are interested that the binding is changing.
       */
      ip6_table_bind_callback_t *cb;
      vec_foreach (cb, ip6_main.table_bind_callbacks)
	cb->function (&ip6_main, cb->function_opaque,
		      sw_if_index,
		      fib_index,
		      ip6_main.fib_index_by_sw_if_index[sw_if_index]);

      /* unlock currently assigned tables */
      if (0 != ip6_main.fib_index_by_sw_if_index[sw_if_index])
	fib_table_unlock (ip6_main.fib_index_by_sw_if_index[sw_if_index],
			  FIB_PROTOCOL_IP6, FIB_SOURCE_INTERFACE);

      if (0 != table_id)
	{
	  /* we need to lock the table now it's inuse */
	  fib_table_lock (fib_index, FIB_PROTOCOL_IP6, FIB_SOURCE_INTERFACE);
	}

      ip6_main.fib_index_by_sw_if_index[sw_if_index] = fib_index;
    }
  else
    {
      /*
       * tell those that are interested that the binding is changing.
       */
      ip4_table_bind_callback_t *cb;
      vec_foreach (cb, ip4_main.table_bind_callbacks)
	cb->function (&ip4_main, cb->function_opaque,
		      sw_if_index,
		      fib_index,
		      ip4_main.fib_index_by_sw_if_index[sw_if_index]);

      /* unlock currently assigned tables */
      if (0 != ip4_main.fib_index_by_sw_if_index[sw_if_index])
	fib_table_unlock (ip4_main.fib_index_by_sw_if_index[sw_if_index],
			  FIB_PROTOCOL_IP4, FIB_SOURCE_INTERFACE);

      if (0 != table_id)
	{
	  /* we need to lock the table now it's inuse */
	  fib_index = fib_table_find_or_create_and_lock (
	    FIB_PROTOCOL_IP4, table_id, FIB_SOURCE_INTERFACE);
	}

      ip4_main.fib_index_by_sw_if_index[sw_if_index] = fib_index;
    }
}

void
mfib_table_bind (fib_protocol_t fproto, u32 sw_if_index, u32 mfib_index)
{
  u32 table_id;

  table_id = mfib_table_get_table_id (mfib_index, fproto);
  ASSERT (table_id != ~0);

  if (FIB_PROTOCOL_IP6 == fproto)
    {
      if (0 != ip6_main.mfib_index_by_sw_if_index[sw_if_index])
	mfib_table_unlock (ip6_main.mfib_index_by_sw_if_index[sw_if_index],
			   FIB_PROTOCOL_IP6, MFIB_SOURCE_INTERFACE);

      if (0 != table_id)
	{
	  /* we need to lock the table now it's inuse */
	  mfib_table_lock (mfib_index, FIB_PROTOCOL_IP6,
			   MFIB_SOURCE_INTERFACE);
	}

      ip6_main.mfib_index_by_sw_if_index[sw_if_index] = mfib_index;
    }
  else
    {
      if (0 != ip4_main.mfib_index_by_sw_if_index[sw_if_index])
	mfib_table_unlock (ip4_main.mfib_index_by_sw_if_index[sw_if_index],
			   FIB_PROTOCOL_IP4, MFIB_SOURCE_INTERFACE);

      if (0 != table_id)
	{
	  /* we need to lock the table now it's inuse */
	  mfib_index = mfib_table_find_or_create_and_lock (
	    FIB_PROTOCOL_IP4, table_id, MFIB_SOURCE_INTERFACE);
	}

      ip4_main.mfib_index_by_sw_if_index[sw_if_index] = mfib_index;
    }
}

int
ip_table_bind (fib_protocol_t fproto, u32 sw_if_index, u32 table_id)
{
  CLIB_UNUSED (ip_interface_address_t * ia);
  u32 fib_index, mfib_index;

  /*
   * This if table does not exist = error is what we want in the end.
   */
  fib_index = fib_table_find (fproto, table_id);
  mfib_index = mfib_table_find (fproto, table_id);

  if (~0 == fib_index || ~0 == mfib_index)
    {
      return (VNET_API_ERROR_NO_SUCH_FIB);
    }

  /*
   * If the interface already has in IP address, then a change int
   * VRF is not allowed. The IP address applied must first be removed.
   * We do not do that automatically here, since VPP has no knowledge
   * of whether those subnets are valid in the destination VRF.
   */
  /* clang-format off */
  foreach_ip_interface_address (FIB_PROTOCOL_IP6 == fproto ?
				&ip6_main.lookup_main : &ip4_main.lookup_main,
				ia, sw_if_index,
				1 /* honor unnumbered */ ,
  ({
    return (VNET_API_ERROR_ADDRESS_FOUND_FOR_INTERFACE);
  }));
  /* clang-format on */

  fib_table_bind (fproto, sw_if_index, fib_index);
  mfib_table_bind (fproto, sw_if_index, mfib_index);

  return (0);
}

static void
send_sw_interface_get_table_reply (vl_api_registration_t * reg,
				   u32 context, int retval, u32 vrf_id)
{
  vl_api_sw_interface_get_table_reply_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id =
    ntohs (REPLY_MSG_ID_BASE + VL_API_SW_INTERFACE_GET_TABLE_REPLY);
  mp->context = context;
  mp->retval = htonl (retval);
  mp->vrf_id = htonl (vrf_id);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_sw_interface_get_table_t_handler (vl_api_sw_interface_get_table_t * mp)
{
  vl_api_registration_t *reg;
  fib_table_t *fib_table = 0;
  u32 sw_if_index = ~0;
  u32 fib_index = ~0;
  u32 table_id = ~0;
  fib_protocol_t fib_proto = FIB_PROTOCOL_IP4;
  int rv = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);

  if (mp->is_ipv6)
    fib_proto = FIB_PROTOCOL_IP6;

  fib_index = fib_table_get_index_for_sw_if_index (fib_proto, sw_if_index);
  if (fib_index != ~0)
    {
      fib_table = fib_table_get (fib_index, fib_proto);
      table_id = fib_table->ft_table_id;
    }

  BAD_SW_IF_INDEX_LABEL;

  send_sw_interface_get_table_reply (reg, mp->context, rv, table_id);
}

static void vl_api_sw_interface_set_unnumbered_t_handler
  (vl_api_sw_interface_set_unnumbered_t * mp)
{
  vl_api_sw_interface_set_unnumbered_reply_t *rmp;
  int rv = 0;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 unnumbered_sw_if_index = ntohl (mp->unnumbered_sw_if_index);

  /*
   * The API message field names are backwards from
   * the underlying data structure names.
   * It's not worth changing them now.
   */
  if (!vnet_sw_interface_is_api_valid (vnm, unnumbered_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto done;
    }

  /* Only check the "use loop0" field when setting the binding */
  if (mp->is_add && !vnet_sw_interface_is_api_valid (vnm, sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX_2;
      goto done;
    }

  rv = vnet_sw_interface_update_unnumbered (unnumbered_sw_if_index,
					    sw_if_index, mp->is_add);
done:
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_UNNUMBERED_REPLY);
}

static void
vl_api_sw_interface_clear_stats_t_handler (vl_api_sw_interface_clear_stats_t *
					   mp)
{
  vl_api_sw_interface_clear_stats_reply_t *rmp;

  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vlib_simple_counter_main_t *sm;
  vlib_combined_counter_main_t *cm;
  int j, n_counters;
  int rv = 0;

  if (mp->sw_if_index != ~0)
    VALIDATE_SW_IF_INDEX (mp);

  n_counters = vec_len (im->combined_sw_if_counters);

  for (j = 0; j < n_counters; j++)
    {
      im = &vnm->interface_main;
      cm = im->combined_sw_if_counters + j;
      if (mp->sw_if_index == (u32) ~ 0)
	vlib_clear_combined_counters (cm);
      else
	vlib_zero_combined_counter (cm, ntohl (mp->sw_if_index));
    }

  n_counters = vec_len (im->sw_if_counters);

  for (j = 0; j < n_counters; j++)
    {
      im = &vnm->interface_main;
      sm = im->sw_if_counters + j;
      if (mp->sw_if_index == (u32) ~ 0)
	vlib_clear_simple_counters (sm);
      else
	vlib_zero_simple_counter (sm, ntohl (mp->sw_if_index));
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_CLEAR_STATS_REPLY);
}

/*
 * Events used for sw_interface_events
 */
enum api_events
{
  API_LINK_STATE_UP_EVENT = 1 << 1,
  API_LINK_STATE_DOWN_EVENT = 1 << 2,
  API_ADMIN_UP_EVENT = 1 << 3,
  API_ADMIN_DOWN_EVENT = 1 << 4,
  API_SW_INTERFACE_ADD_EVENT = 1 << 5,
  API_SW_INTERFACE_DEL_EVENT = 1 << 6,
};

static void
send_sw_interface_event (vpe_api_main_t * am,
			 vpe_client_registration_t * reg,
			 vl_api_registration_t * vl_reg,
			 u32 sw_if_index, enum api_events events)
{
  vl_api_sw_interface_event_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SW_INTERFACE_EVENT);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->client_index = reg->client_index;
  mp->pid = reg->client_pid;
  mp->flags = 0;
  mp->flags |= (events & API_ADMIN_UP_EVENT) ?
    IF_STATUS_API_FLAG_ADMIN_UP : 0;
  mp->flags |= (events & API_LINK_STATE_UP_EVENT) ?
    IF_STATUS_API_FLAG_LINK_UP : 0;
  mp->flags = ntohl (mp->flags);
  mp->deleted = events & API_SW_INTERFACE_DEL_EVENT ? true : false;
  vl_api_send_msg (vl_reg, (u8 *) mp);
}

static uword
link_state_process (vlib_main_t * vm,
		    vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vpe_api_main_t *vam = &vpe_api_main;
  uword *event_by_sw_if_index = 0;
  vpe_client_registration_t *reg;
  int i;
  vl_api_registration_t *vl_reg;
  uword event_type;
  uword *event_data = 0;
  u32 sw_if_index;

  vam->link_state_process_up = 1;

  while (1)
    {
      vlib_process_wait_for_event (vm);

      /* Batch up events */
      while ((event_type = vlib_process_get_events (vm, &event_data)) != ~0)
	{
	  for (i = 0; i < vec_len (event_data); i++)
	    {
	      sw_if_index = event_data[i];
	      vec_validate_init_empty (event_by_sw_if_index, sw_if_index, 0);
	      event_by_sw_if_index[sw_if_index] |= event_type;
	    }
	  vec_reset_length (event_data);
	}

      for (i = 0; i < vec_len (event_by_sw_if_index); i++)
	{
	  if (event_by_sw_if_index[i] == 0)
	    continue;

          /* *INDENT-OFF* */
          pool_foreach (reg, vam->interface_events_registrations)
           {
            vl_reg = vl_api_client_index_to_registration (reg->client_index);
            if (vl_reg)
	      send_sw_interface_event (vam, reg, vl_reg, i, event_by_sw_if_index[i]);
          }
          /* *INDENT-ON* */
	}
      vec_reset_length (event_by_sw_if_index);
    }

  return 0;
}

static clib_error_t *link_up_down_function (vnet_main_t * vm, u32 hw_if_index,
					    u32 flags);
static clib_error_t *admin_up_down_function (vnet_main_t * vm,
					     u32 hw_if_index, u32 flags);
static clib_error_t *sw_interface_add_del_function (vnet_main_t * vm,
						    u32 sw_if_index,
						    u32 flags);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (link_state_process_node,static) = {
  .function = link_state_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "vpe-link-state-process",
};
/* *INDENT-ON* */

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (admin_up_down_function);
VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (link_up_down_function);
VNET_SW_INTERFACE_ADD_DEL_FUNCTION (sw_interface_add_del_function);

static clib_error_t *
link_up_down_function (vnet_main_t * vm, u32 hw_if_index, u32 flags)
{
  vpe_api_main_t *vam = &vpe_api_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vm, hw_if_index);

  if (vam->link_state_process_up)
    {
      enum api_events event = ((flags & VNET_HW_INTERFACE_FLAG_LINK_UP) ?
			       API_LINK_STATE_UP_EVENT :
			       API_LINK_STATE_DOWN_EVENT);
      vlib_process_signal_event (vam->vlib_main,
				 link_state_process_node.index, event,
				 hi->sw_if_index);
    }
  return 0;
}

static clib_error_t *
admin_up_down_function (vnet_main_t * vm, u32 sw_if_index, u32 flags)
{
  vpe_api_main_t *vam = &vpe_api_main;

  /*
   * Note: it's perfectly fair to set a subif admin up / admin down.
   * Note the subtle distinction between this routine and the previous
   * routine.
   */
  if (vam->link_state_process_up)
    {
      enum api_events event = ((flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
			       API_ADMIN_UP_EVENT : API_ADMIN_DOWN_EVENT);
      vlib_process_signal_event (vam->vlib_main,
				 link_state_process_node.index, event,
				 sw_if_index);
    }
  return 0;
}

static clib_error_t *
sw_interface_add_del_function (vnet_main_t * vm, u32 sw_if_index, u32 flags)
{
  vpe_api_main_t *vam = &vpe_api_main;

  if (vam->link_state_process_up)
    {
      enum api_events event =
	flags ? API_SW_INTERFACE_ADD_EVENT : API_SW_INTERFACE_DEL_EVENT;
      vlib_process_signal_event (vam->vlib_main,
				 link_state_process_node.index, event,
				 sw_if_index);
    }
  return 0;
}

static void vl_api_sw_interface_tag_add_del_t_handler
  (vl_api_sw_interface_tag_add_del_t * mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vl_api_sw_interface_tag_add_del_reply_t *rmp;
  int rv = 0;
  u8 *tag;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  if (mp->is_add)
    {
      if (mp->tag[0] == 0)
	{
	  rv = VNET_API_ERROR_INVALID_VALUE;
	  goto out;
	}

      mp->tag[ARRAY_LEN (mp->tag) - 1] = 0;
      tag = format (0, "%s%c", mp->tag, 0);
      vnet_set_sw_interface_tag (vnm, tag, sw_if_index);
    }
  else
    vnet_clear_sw_interface_tag (vnm, sw_if_index);

  BAD_SW_IF_INDEX_LABEL;
out:
  REPLY_MACRO (VL_API_SW_INTERFACE_TAG_ADD_DEL_REPLY);
}

static void vl_api_sw_interface_add_del_mac_address_t_handler
  (vl_api_sw_interface_add_del_mac_address_t * mp)
{
  vl_api_sw_interface_add_del_mac_address_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vnet_hw_interface_t *hi;
  clib_error_t *error;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  /* for subifs, the MAC should be changed on the actual hw if */
  hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  error = vnet_hw_interface_add_del_mac_address (vnm, hi->hw_if_index,
						 mp->addr, mp->is_add);
  if (error)
    {
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      clib_error_report (error);
      goto out;
    }

  BAD_SW_IF_INDEX_LABEL;
out:
  REPLY_MACRO (VL_API_SW_INTERFACE_ADD_DEL_MAC_ADDRESS_REPLY);
}

static void vl_api_sw_interface_set_mac_address_t_handler
  (vl_api_sw_interface_set_mac_address_t * mp)
{
  vl_api_sw_interface_set_mac_address_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vnet_sw_interface_t *si;
  clib_error_t *error;
  int rv = 0;
  mac_address_t mac;

  VALIDATE_SW_IF_INDEX (mp);

  si = vnet_get_sw_interface (vnm, sw_if_index);
  mac_address_decode (mp->mac_address, &mac);
  error =
    vnet_hw_interface_change_mac_address (vnm, si->hw_if_index, (u8 *) & mac);
  if (error)
    {
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      clib_error_report (error);
      goto out;
    }

  BAD_SW_IF_INDEX_LABEL;
out:
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_MAC_ADDRESS_REPLY);
}

static void vl_api_sw_interface_get_mac_address_t_handler
  (vl_api_sw_interface_get_mac_address_t * mp)
{
  vl_api_sw_interface_get_mac_address_reply_t *rmp;
  vl_api_registration_t *reg;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vnet_sw_interface_t *si;
  ethernet_interface_t *eth_if = 0;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  si = vnet_get_sup_sw_interface (vnm, sw_if_index);
  if (si->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
    eth_if = ethernet_get_interface (&ethernet_main, si->hw_if_index);

  BAD_SW_IF_INDEX_LABEL;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id =
    htons (REPLY_MSG_ID_BASE + VL_API_SW_INTERFACE_GET_MAC_ADDRESS_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  if (!rv && eth_if)
    mac_address_encode (&eth_if->address.mac, rmp->mac_address);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_sw_interface_set_interface_name_t_handler (
  vl_api_sw_interface_set_interface_name_t *mp)
{
  vl_api_sw_interface_set_interface_name_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
  clib_error_t *error;
  int rv = 0;

  if (mp->name[0] == 0)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto out;
    }
  if (si == 0)
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto out;
    }

  error = vnet_rename_interface (vnm, si->hw_if_index, (char *) mp->name);
  if (error)
    {
      clib_error_free (error);
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }

out:
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_INTERFACE_NAME_REPLY);
}

static void vl_api_sw_interface_set_rx_mode_t_handler
  (vl_api_sw_interface_set_rx_mode_t * mp)
{
  vl_api_sw_interface_set_rx_mode_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vnet_sw_interface_t *si;
  clib_error_t *error;
  int rv = 0;
  vnet_hw_if_rx_mode rx_mode;

  VALIDATE_SW_IF_INDEX (mp);

  si = vnet_get_sw_interface (vnm, sw_if_index);
  if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto bad_sw_if_index;
    }

  rx_mode = (vnet_hw_if_rx_mode) ntohl (mp->mode);
  error = set_hw_interface_change_rx_mode (vnm, si->hw_if_index,
					   mp->queue_id_valid,
					   ntohl (mp->queue_id),
					   (vnet_hw_if_rx_mode) rx_mode);

  if (error)
    {
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      clib_error_report (error);
      goto out;
    }

  BAD_SW_IF_INDEX_LABEL;
out:
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_RX_MODE_REPLY);
}

static void
send_interface_rx_placement_details (vpe_api_main_t * am,
				     vl_api_registration_t * rp,
				     u32 sw_if_index, u32 worker_id,
				     u32 queue_id, u8 mode, u32 context)
{
  vl_api_sw_interface_rx_placement_details_t *mp;
  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id =
    htons (REPLY_MSG_ID_BASE + VL_API_SW_INTERFACE_RX_PLACEMENT_DETAILS);
  mp->sw_if_index = htonl (sw_if_index);
  mp->queue_id = htonl (queue_id);
  mp->worker_id = htonl (worker_id);
  mp->mode = htonl (mode);
  mp->context = context;

  vl_api_send_msg (rp, (u8 *) mp);
}

static void vl_api_sw_interface_rx_placement_dump_t_handler
  (vl_api_sw_interface_rx_placement_dump_t * mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vpe_api_main_t *am = &vpe_api_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (sw_if_index == ~0)
    {
      vnet_hw_if_rx_queue_t **all_queues = 0;
      vnet_hw_if_rx_queue_t **qptr;
      vnet_hw_if_rx_queue_t *q;
      pool_foreach (q, vnm->interface_main.hw_if_rx_queues)
	vec_add1 (all_queues, q);
      vec_sort_with_function (all_queues, vnet_hw_if_rxq_cmp_cli_api);

      vec_foreach (qptr, all_queues)
	{
	  u32 current_thread = qptr[0]->thread_index;
	  u32 hw_if_index = qptr[0]->hw_if_index;
	  vnet_hw_interface_t *hw_if =
	    vnet_get_hw_interface (vnm, hw_if_index);
	  send_interface_rx_placement_details (
	    am, reg, hw_if->sw_if_index, current_thread, qptr[0]->queue_id,
	    qptr[0]->mode, mp->context);
	}
      vec_free (all_queues);
    }
  else
    {
      int i;
      vnet_sw_interface_t *si;

      if (!vnet_sw_if_index_is_api_valid (sw_if_index))
	{
	  clib_warning ("sw_if_index %u does not exist", sw_if_index);
	  goto bad_sw_if_index;
	}

      si = vnet_get_sw_interface (vnm, sw_if_index);
      if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	{
	  clib_warning ("interface type is not HARDWARE! P2P, PIPE and SUB"
			" interfaces are not supported");
	  goto bad_sw_if_index;
	}

      vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, si->hw_if_index);

      for (i = 0; i < vec_len (hw->rx_queue_indices); i++)
	{
	  vnet_hw_if_rx_queue_t *rxq =
	    vnet_hw_if_get_rx_queue (vnm, hw->rx_queue_indices[i]);
	  send_interface_rx_placement_details (
	    am, reg, hw->sw_if_index, rxq->thread_index, rxq->queue_id,
	    rxq->mode, mp->context);
	}
    }

  BAD_SW_IF_INDEX_LABEL;
}

static void vl_api_sw_interface_set_rx_placement_t_handler
  (vl_api_sw_interface_set_rx_placement_t * mp)
{
  vl_api_sw_interface_set_rx_placement_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vnet_sw_interface_t *si;
  clib_error_t *error = 0;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  si = vnet_get_sw_interface (vnm, sw_if_index);
  if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto bad_sw_if_index;
    }

  error = set_hw_interface_rx_placement (si->hw_if_index,
					 ntohl (mp->queue_id),
					 ntohl (mp->worker_id), mp->is_main);
  if (error)
    {
      rv = VNET_API_ERROR_UNIMPLEMENTED;
      clib_error_report (error);
      goto out;
    }

  BAD_SW_IF_INDEX_LABEL;
out:
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_RX_PLACEMENT_REPLY);
}

static void
send_interface_tx_placement_details (vnet_hw_if_tx_queue_t **all_queues,
				     u32 index, vl_api_registration_t *rp,
				     u32 context)
{
  vnet_main_t *vnm = vnet_get_main ();
  vl_api_sw_interface_tx_placement_details_t *rmp;
  u32 n_bits = 0, v = ~0;
  vnet_hw_if_tx_queue_t **q = vec_elt_at_index (all_queues, index);
  uword *bitmap = q[0]->threads;
  u32 hw_if_index = q[0]->hw_if_index;
  vnet_hw_interface_t *hw_if = vnet_get_hw_interface (vnm, hw_if_index);

  n_bits = clib_bitmap_count_set_bits (bitmap);
  u32 n = n_bits * sizeof (u32);

  /*
   * FIXME: Use the REPLY_MACRO_DETAILS5_END once endian handler is registered
   * and available.
   */
  REPLY_MACRO_DETAILS5 (
    VL_API_SW_INTERFACE_TX_PLACEMENT_DETAILS, n, rp, context, ({
      rmp->sw_if_index = clib_host_to_net_u32 (hw_if->sw_if_index);
      rmp->queue_id = clib_host_to_net_u32 (q[0]->queue_id);
      rmp->shared = q[0]->shared_queue;
      rmp->array_size = clib_host_to_net_u32 (n_bits);

      v = clib_bitmap_first_set (bitmap);
      for (u32 i = 0; i < n_bits; i++)
	{
	  rmp->threads[i] = clib_host_to_net_u32 (v);
	  v = clib_bitmap_next_set (bitmap, v + 1);
	}
    }));
}

static void
vl_api_sw_interface_tx_placement_get_t_handler (
  vl_api_sw_interface_tx_placement_get_t *mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vl_api_sw_interface_tx_placement_get_reply_t *rmp = 0;
  vnet_hw_if_tx_queue_t **all_queues = 0;
  vnet_hw_if_tx_queue_t *q;
  u32 sw_if_index = mp->sw_if_index;
  i32 rv = 0;

  if (pool_elts (vnm->interface_main.hw_if_tx_queues) == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto err;
    }

  if (sw_if_index == ~0)
    {
      pool_foreach (q, vnm->interface_main.hw_if_tx_queues)
	vec_add1 (all_queues, q);
      vec_sort_with_function (all_queues, vnet_hw_if_txq_cmp_cli_api);
    }
  else
    {
      u32 qi = ~0;
      vnet_sw_interface_t *si;

      if (!vnet_sw_if_index_is_api_valid (sw_if_index))
	{
	  clib_warning ("sw_if_index %u does not exist", sw_if_index);
	  rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
	  goto err;
	}

      si = vnet_get_sw_interface (vnm, sw_if_index);
      if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
	{
	  clib_warning ("interface type is not HARDWARE! P2P, PIPE and SUB"
			" interfaces are not supported");
	  rv = VNET_API_ERROR_INVALID_INTERFACE;
	  goto err;
	}

      vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, si->hw_if_index);
      for (qi = 0; qi < vec_len (hw->tx_queue_indices); qi++)
	{
	  q = vnet_hw_if_get_tx_queue (vnm, hw->tx_queue_indices[qi]);
	  vec_add1 (all_queues, q);
	}
    }

  REPLY_AND_DETAILS_VEC_MACRO_END (VL_API_SW_INTERFACE_TX_PLACEMENT_GET_REPLY,
				   all_queues, mp, rmp, rv, ({
				     send_interface_tx_placement_details (
				       all_queues, cursor, rp, mp->context);
				   }));

  vec_free (all_queues);
  return;

err:
  REPLY_MACRO_END (VL_API_SW_INTERFACE_TX_PLACEMENT_GET_REPLY);
}

static void
vl_api_sw_interface_set_tx_placement_t_handler (
  vl_api_sw_interface_set_tx_placement_t *mp)
{
  vl_api_sw_interface_set_tx_placement_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = mp->sw_if_index;
  vnet_sw_interface_t *si;
  uword *bitmap = 0;
  u32 queue_id = ~0;
  u32 size = 0;
  clib_error_t *error = 0;
  int rv = 0;

  VALIDATE_SW_IF_INDEX_END (mp);

  si = vnet_get_sw_interface (vnm, sw_if_index);
  if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto bad_sw_if_index;
    }

  size = mp->array_size;
  for (u32 i = 0; i < size; i++)
    {
      u32 thread_index = mp->threads[i];
      bitmap = clib_bitmap_set (bitmap, thread_index, 1);
    }

  queue_id = mp->queue_id;
  rv = set_hw_interface_tx_queue (si->hw_if_index, queue_id, bitmap);

  switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
      error = clib_error_return (
	0, "please specify valid thread(s) - last thread index %u",
	clib_bitmap_last_set (bitmap));
      break;
    case VNET_API_ERROR_INVALID_QUEUE:
      error = clib_error_return (
	0, "unknown queue %u on interface %s", queue_id,
	vnet_get_hw_interface (vnet_get_main (), si->hw_if_index)->name);
      break;
    default:
      break;
    }

  if (error)
    {
      clib_error_report (error);
      goto out;
    }

  BAD_SW_IF_INDEX_LABEL;
out:
  REPLY_MACRO_END (VL_API_SW_INTERFACE_SET_TX_PLACEMENT_REPLY);
  clib_bitmap_free (bitmap);
}

static void
vl_api_create_vlan_subif_t_handler (vl_api_create_vlan_subif_t * mp)
{
  vl_api_create_vlan_subif_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = (u32) ~ 0;
  vnet_hw_interface_t *hi;
  int rv = 0;
  u32 id;
  vnet_sw_interface_t template;
  uword *p;
  vnet_interface_main_t *im = &vnm->interface_main;
  u64 sup_and_sub_key;
  vl_api_registration_t *reg;
  clib_error_t *error;

  VALIDATE_SW_IF_INDEX (mp);

  hi = vnet_get_sup_hw_interface (vnm, ntohl (mp->sw_if_index));

  if (hi->bond_info == VNET_HW_INTERFACE_BOND_INFO_SLAVE)
    {
      rv = VNET_API_ERROR_BOND_SLAVE_NOT_ALLOWED;
      goto out;
    }

  id = ntohl (mp->vlan_id);
  if (id == 0 || id > 4095)
    {
      rv = VNET_API_ERROR_INVALID_VLAN;
      goto out;
    }

  sup_and_sub_key = ((u64) (hi->sw_if_index) << 32) | (u64) id;

  p = hash_get_mem (im->sw_if_index_by_sup_and_sub, &sup_and_sub_key);
  if (p)
    {
      rv = VNET_API_ERROR_VLAN_ALREADY_EXISTS;
      goto out;
    }

  clib_memset (&template, 0, sizeof (template));
  template.type = VNET_SW_INTERFACE_TYPE_SUB;
  template.flood_class = VNET_FLOOD_CLASS_NORMAL;
  template.sup_sw_if_index = hi->sw_if_index;
  template.sub.id = id;
  template.sub.eth.raw_flags = 0;
  template.sub.eth.flags.one_tag = 1;
  template.sub.eth.outer_vlan_id = id;
  template.sub.eth.flags.exact_match = 1;

  error = vnet_create_sw_interface (vnm, &template, &sw_if_index);
  if (error)
    {
      clib_error_report (error);
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto out;
    }

  u64 *kp = clib_mem_alloc (sizeof (*kp));
  *kp = sup_and_sub_key;

  hash_set (hi->sub_interface_sw_if_index_by_id, id, sw_if_index);
  hash_set_mem (im->sw_if_index_by_sup_and_sub, kp, sw_if_index);

  BAD_SW_IF_INDEX_LABEL;

out:
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons (REPLY_MSG_ID_BASE + VL_API_CREATE_VLAN_SUBIF_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  rmp->sw_if_index = htonl (sw_if_index);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_create_subif_t_handler (vl_api_create_subif_t * mp)
{
  vl_api_create_subif_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sub_sw_if_index = ~0;
  vnet_hw_interface_t *hi;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  hi = vnet_get_sup_hw_interface (vnm, ntohl (mp->sw_if_index));

  if (hi->bond_info == VNET_HW_INTERFACE_BOND_INFO_SLAVE)
    rv = VNET_API_ERROR_BOND_SLAVE_NOT_ALLOWED;
  else
    rv = vnet_create_sub_interface (ntohl (mp->sw_if_index),
				    ntohl (mp->sub_id),
				    ntohl (mp->sub_if_flags),
				    ntohs (mp->inner_vlan_id),
				    ntohs (mp->outer_vlan_id),
				    &sub_sw_if_index);

  BAD_SW_IF_INDEX_LABEL;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CREATE_SUBIF_REPLY,
  ({
    rmp->sw_if_index = ntohl(sub_sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_delete_subif_t_handler (vl_api_delete_subif_t * mp)
{
  vl_api_delete_subif_reply_t *rmp;
  int rv;

  rv = vnet_delete_sub_interface (ntohl (mp->sw_if_index));

  REPLY_MACRO (VL_API_DELETE_SUBIF_REPLY);
}

static void
vl_api_interface_name_renumber_t_handler (vl_api_interface_name_renumber_t *
					  mp)
{
  vl_api_interface_name_renumber_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = vnet_interface_name_renumber
    (ntohl (mp->sw_if_index), ntohl (mp->new_show_dev_instance));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_INTERFACE_NAME_RENUMBER_REPLY);
}

static void
vl_api_create_loopback_t_handler (vl_api_create_loopback_t * mp)
{
  vl_api_create_loopback_reply_t *rmp;
  u32 sw_if_index;
  int rv;
  mac_address_t mac;

  mac_address_decode (mp->mac_address, &mac);
  rv = vnet_create_loopback_interface (&sw_if_index, (u8 *) & mac, 0, 0);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CREATE_LOOPBACK_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void vl_api_create_loopback_instance_t_handler
  (vl_api_create_loopback_instance_t * mp)
{
  vl_api_create_loopback_instance_reply_t *rmp;
  u32 sw_if_index;
  u8 is_specified = mp->is_specified;
  u32 user_instance = ntohl (mp->user_instance);
  int rv;
  mac_address_t mac;

  mac_address_decode (mp->mac_address, &mac);
  rv = vnet_create_loopback_interface (&sw_if_index, (u8 *) & mac,
				       is_specified, user_instance);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_CREATE_LOOPBACK_INSTANCE_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_delete_loopback_t_handler (vl_api_delete_loopback_t * mp)
{
  vl_api_delete_loopback_reply_t *rmp;
  u32 sw_if_index;
  int rv;

  sw_if_index = ntohl (mp->sw_if_index);
  rv = vnet_delete_loopback_interface (sw_if_index);

  REPLY_MACRO (VL_API_DELETE_LOOPBACK_REPLY);
}

static void
  vl_api_collect_detailed_interface_stats_t_handler
  (vl_api_collect_detailed_interface_stats_t * mp)
{
  vl_api_collect_detailed_interface_stats_reply_t *rmp;
  int rv = 0;

  rv =
    vnet_sw_interface_stats_collect_enable_disable (ntohl (mp->sw_if_index),
						    mp->enable_disable);

  REPLY_MACRO (VL_API_COLLECT_DETAILED_INTERFACE_STATS_REPLY);
}

static void
  vl_api_sw_interface_address_replace_begin_t_handler
  (vl_api_sw_interface_address_replace_begin_t * mp)
{
  vl_api_sw_interface_address_replace_begin_reply_t *rmp;
  int rv = 0;

  ip_interface_address_mark ();

  REPLY_MACRO (VL_API_SW_INTERFACE_ADDRESS_REPLACE_BEGIN_REPLY);
}

static void
  vl_api_sw_interface_address_replace_end_t_handler
  (vl_api_sw_interface_address_replace_end_t * mp)
{
  vl_api_sw_interface_address_replace_end_reply_t *rmp;
  int rv = 0;

  ip_interface_address_sweep ();

  REPLY_MACRO (VL_API_SW_INTERFACE_ADDRESS_REPLACE_END_REPLY);
}

/*
 * vpe_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */

pub_sub_handler (interface_events, INTERFACE_EVENTS);

#include <vnet/interface.api.c>
static clib_error_t *
interface_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

  /* Mark these APIs as mp safe */
  am->is_mp_safe[VL_API_SW_INTERFACE_DUMP] = 1;
  am->is_mp_safe[VL_API_SW_INTERFACE_DETAILS] = 1;
  am->is_mp_safe[VL_API_SW_INTERFACE_TAG_ADD_DEL] = 1;
  am->is_mp_safe[VL_API_SW_INTERFACE_SET_INTERFACE_NAME] = 1;

  /* Do not replay VL_API_SW_INTERFACE_DUMP messages */
  am->api_trace_cfg[VL_API_SW_INTERFACE_DUMP].replay_enable = 0;

  /* Mark these APIs as autoendian */
  am->is_autoendian[VL_API_SW_INTERFACE_SET_TX_PLACEMENT] = 1;
  am->is_autoendian[VL_API_SW_INTERFACE_TX_PLACEMENT_GET] = 1;

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (interface_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
