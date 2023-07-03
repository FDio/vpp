/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vpp/api/types.h>

#include <vnet/ip/ip_types_api.h>

#define __plugin_msg_base interface_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <vnet/format_fns.h>
#include <vnet/interface.api_enum.h>
#include <vnet/interface.api_types.h>
#include <vlibmemory/vlib.api_types.h>
#include <vlibmemory/memclnt.api_enum.h>

#define vl_endianfun /* define message structures */
#include <vnet/interface.api.h>
#undef vl_endianfun

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} interface_test_main_t;

static interface_test_main_t interface_test_main;

static int
api_sw_interface_set_flags (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_flags_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 admin_up = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "admin-up"))
	admin_up = 1;
      else if (unformat (i, "admin-down"))
	admin_up = 0;
      else if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_SET_FLAGS, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->flags = ntohl ((admin_up) ? IF_STATUS_API_FLAG_ADMIN_UP : 0);

  /* send it... */
  S (mp);

  /* Wait for a reply, return the good/bad news... */
  W (ret);
  return ret;
}

static int
api_hw_interface_set_mtu (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_hw_interface_set_mtu_t *mp;
  u32 sw_if_index = ~0;
  u32 mtu = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "mtu %d", &mtu))
	;
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (mtu == 0)
    {
      errmsg ("no mtu specified");
      return -99;
    }

  /* Construct the API message */
  M (HW_INTERFACE_SET_MTU, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->mtu = ntohs ((u16) mtu);

  S (mp);
  W (ret);
  return ret;
}

static int
api_sw_interface_tag_add_del (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_tag_add_del_t *mp;
  u32 sw_if_index = ~0;
  u8 *tag = 0;
  u8 enable = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "tag %s", &tag))
	;
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "del"))
	enable = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (enable && (tag == 0))
    {
      errmsg ("no tag specified");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_TAG_ADD_DEL, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = enable;
  if (enable)
    strncpy ((char *) mp->tag, (char *) tag, ARRAY_LEN (mp->tag) - 1);
  vec_free (tag);

  S (mp);
  W (ret);
  return ret;
}

static int
api_sw_interface_add_del_mac_address (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_mac_address_t mac = { 0 };
  vl_api_sw_interface_add_del_mac_address_t *mp;
  u32 sw_if_index = ~0;
  u8 is_add = 1;
  u8 mac_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "%U", unformat_vl_api_mac_address, &mac))
	mac_set++;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (!mac_set)
    {
      errmsg ("missing MAC address");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_ADD_DEL_MAC_ADDRESS, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = is_add;
  clib_memcpy (&mp->addr, &mac, sizeof (mac));

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_sw_interface_details_t_handler (vl_api_sw_interface_details_t *mp)
{
  vat_main_t *vam = &vat_main;
  u8 *s = format (0, "%s%c", mp->interface_name, 0);

  hash_set_mem (vam->sw_if_index_by_interface_name, s,
		ntohl (mp->sw_if_index));

  /* In sub interface case, fill the sub interface table entry */
  if (mp->sw_if_index != mp->sup_sw_if_index)
    {
      sw_interface_subif_t *sub = NULL;

      vec_add2 (vam->sw_if_subif_table, sub, 1);

      vec_validate (sub->interface_name, strlen ((char *) s) + 1);
      strncpy ((char *) sub->interface_name, (char *) s,
	       vec_len (sub->interface_name));
      sub->sw_if_index = ntohl (mp->sw_if_index);
      sub->sub_id = ntohl (mp->sub_id);

      sub->raw_flags = ntohl (mp->sub_if_flags & SUB_IF_API_FLAG_MASK_VNET);

      sub->sub_number_of_tags = mp->sub_number_of_tags;
      sub->sub_outer_vlan_id = ntohs (mp->sub_outer_vlan_id);
      sub->sub_inner_vlan_id = ntohs (mp->sub_inner_vlan_id);

      /* vlan tag rewrite */
      sub->vtr_op = ntohl (mp->vtr_op);
      sub->vtr_push_dot1q = ntohl (mp->vtr_push_dot1q);
      sub->vtr_tag1 = ntohl (mp->vtr_tag1);
      sub->vtr_tag2 = ntohl (mp->vtr_tag2);
    }
}

static int
api_sw_interface_get_mac_address (vat_main_t *vat)
{
  return -1;
}

static void
vl_api_sw_interface_get_mac_address_reply_t_handler (
  vl_api_sw_interface_get_mac_address_reply_t *mp)
{
}

static int
api_sw_interface_add_del_address (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_add_del_address_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 is_add = 1, del_all = 0;
  u32 address_length = 0;
  u8 v4_address_set = 0;
  u8 v6_address_set = 0;
  ip4_address_t v4address;
  ip6_address_t v6address;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del-all"))
	del_all = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "%U/%d", unformat_ip4_address, &v4address,
			 &address_length))
	v4_address_set = 1;
      else if (unformat (i, "%U/%d", unformat_ip6_address, &v6address,
			 &address_length))
	v6_address_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }
  if (v4_address_set && v6_address_set)
    {
      errmsg ("both v4 and v6 addresses set");
      return -99;
    }
  if (!v4_address_set && !v6_address_set && !del_all)
    {
      errmsg ("no addresses set");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_ADD_DEL_ADDRESS, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = is_add;
  mp->del_all = del_all;
  if (v6_address_set)
    {
      mp->prefix.address.af = ADDRESS_IP6;
      clib_memcpy (mp->prefix.address.un.ip6, &v6address, sizeof (v6address));
    }
  else
    {
      mp->prefix.address.af = ADDRESS_IP4;
      clib_memcpy (mp->prefix.address.un.ip4, &v4address, sizeof (v4address));
    }
  mp->prefix.len = address_length;

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}

static int
api_sw_interface_get_table (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_get_table_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 is_ipv6 = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (SW_INTERFACE_GET_TABLE, mp);
  mp->sw_if_index = htonl (sw_if_index);
  mp->is_ipv6 = is_ipv6;

  S (mp);
  W (ret);
  return ret;
}

static int
api_sw_interface_set_rx_mode (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_rx_mode_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  int ret;
  u8 queue_id_valid = 0;
  u32 queue_id;
  vnet_hw_if_rx_mode mode = VNET_HW_IF_RX_MODE_UNKNOWN;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "queue %d", &queue_id))
	queue_id_valid = 1;
      else if (unformat (i, "polling"))
	mode = VNET_HW_IF_RX_MODE_POLLING;
      else if (unformat (i, "interrupt"))
	mode = VNET_HW_IF_RX_MODE_INTERRUPT;
      else if (unformat (i, "adaptive"))
	mode = VNET_HW_IF_RX_MODE_ADAPTIVE;
      else if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }
  if (mode == VNET_HW_IF_RX_MODE_UNKNOWN)
    {
      errmsg ("missing rx-mode");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_SET_RX_MODE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->mode = (vl_api_rx_mode_t) mode;
  mp->queue_id_valid = queue_id_valid;
  mp->queue_id = queue_id_valid ? ntohl (queue_id) : ~0;

  /* send it... */
  S (mp);

  /* Wait for a reply, return the good/bad news... */
  W (ret);
  return ret;
}

static int
api_sw_interface_set_unnumbered (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_unnumbered_t *mp;
  u32 sw_if_index;
  u32 unnum_sw_index = ~0;
  u8 is_add = 1;
  u8 sw_if_index_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "unnum_if_index %d", &unnum_sw_index))
	;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (SW_INTERFACE_SET_UNNUMBERED, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->unnumbered_sw_if_index = ntohl (unnum_sw_index);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_sw_interface_get_table_reply_t_handler (
  vl_api_sw_interface_get_table_reply_t *mp)
{
  vat_main_t *vam = interface_test_main.vat_main;

  fformat (vam->ofp, "%d", ntohl (mp->vrf_id));

  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static int
api_sw_interface_address_replace_begin (vat_main_t *vam)
{
  return -1;
}

static int
api_sw_interface_set_mac_address (vat_main_t *vam)
{
  return -1;
}

static int
api_sw_interface_set_rx_placement (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_rx_placement_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  int ret;
  u8 is_main = 0;
  u32 queue_id, thread_index;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "queue %d", &queue_id))
	;
      else if (unformat (i, "main"))
	is_main = 1;
      else if (unformat (i, "worker %d", &thread_index))
	;
      else if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (is_main)
    thread_index = 0;
  /* Construct the API message */
  M (SW_INTERFACE_SET_RX_PLACEMENT, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->worker_id = ntohl (thread_index);
  mp->queue_id = ntohl (queue_id);
  mp->is_main = is_main;

  /* send it... */
  S (mp);
  /* Wait for a reply, return the good/bad news... */
  W (ret);
  return ret;
}

static int
api_sw_interface_set_tx_placement (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_tx_placement_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  int ret;
  uword *bitmap = 0;
  u32 queue_id, n_bits = 0;
  u32 v;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "queue %d", &queue_id))
	;
      else if (unformat (i, "threads %U", unformat_bitmap_list, &bitmap))
	;
      else if (unformat (i, "mask %U", unformat_bitmap_mask, &bitmap))
	;
      else if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  n_bits = clib_bitmap_count_set_bits (bitmap);
  /* Construct the API message */
  M2 (SW_INTERFACE_SET_TX_PLACEMENT, mp, sizeof (u32) * n_bits);
  mp->sw_if_index = htonl (sw_if_index);
  mp->queue_id = htonl (queue_id);
  mp->array_size = htonl (n_bits);

  v = clib_bitmap_first_set (bitmap);
  for (u32 j = 0; j < n_bits; j++)
    {
      mp->threads[j] = htonl (v);
      v = clib_bitmap_next_set (bitmap, v + 1);
    }

  /* send it... */
  S (mp);
  /* Wait for a reply, return the good/bad news... */
  W (ret);
  clib_bitmap_free (bitmap);
  return ret;
}

static int
api_interface_name_renumber (vat_main_t *vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_interface_name_renumber_t *mp;
  u32 sw_if_index = ~0;
  u32 new_show_dev_instance = ~0;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", api_unformat_sw_if_index, vam,
		    &sw_if_index))
	;
      else if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "new_show_dev_instance %d",
			 &new_show_dev_instance))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (new_show_dev_instance == ~0)
    {
      errmsg ("missing new_show_dev_instance");
      return -99;
    }

  M (INTERFACE_NAME_RENUMBER, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->new_show_dev_instance = ntohl (new_show_dev_instance);

  S (mp);
  W (ret);
  return ret;
}

static int
api_delete_subif (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_delete_subif_t *mp;
  u32 sw_if_index = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	;
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (DELETE_SUBIF, mp);
  mp->sw_if_index = ntohl (sw_if_index);

  S (mp);
  W (ret);
  return ret;
}

static int
api_delete_loopback (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_delete_loopback_t *mp;
  u32 sw_if_index = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (DELETE_LOOPBACK, mp);
  mp->sw_if_index = ntohl (sw_if_index);

  S (mp);
  W (ret);
  return ret;
}

static int
api_create_loopback_instance (vat_main_t *vat)
{
  return -1;
}

static int
api_create_loopback (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_create_loopback_t *mp;
  vl_api_create_loopback_instance_t *mp_lbi;
  u8 mac_address[6];
  u8 mac_set = 0;
  u8 is_specified = 0;
  u32 user_instance = 0;
  int ret;

  clib_memset (mac_address, 0, sizeof (mac_address));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "mac %U", unformat_ethernet_address, mac_address))
	mac_set = 1;
      if (unformat (i, "instance %d", &user_instance))
	is_specified = 1;
      else
	break;
    }

  if (is_specified)
    {
      M (CREATE_LOOPBACK_INSTANCE, mp_lbi);
      mp_lbi->is_specified = is_specified;
      if (is_specified)
	mp_lbi->user_instance = htonl (user_instance);
      if (mac_set)
	clib_memcpy (mp_lbi->mac_address, mac_address, sizeof (mac_address));
      S (mp_lbi);
    }
  else
    {
      /* Construct the API message */
      M (CREATE_LOOPBACK, mp);
      if (mac_set)
	clib_memcpy (mp->mac_address, mac_address, sizeof (mac_address));
      S (mp);
    }

  W (ret);
  return ret;
}

static void
vl_api_create_subif_reply_t_handler (vl_api_create_subif_reply_t *mp)
{
  vat_main_t *vam = interface_test_main.vat_main;
  vam->result_ready = 1;
}

#define foreach_create_subif_bit                                              \
  _ (no_tags)                                                                 \
  _ (one_tag)                                                                 \
  _ (two_tags)                                                                \
  _ (dot1ad)                                                                  \
  _ (exact_match)                                                             \
  _ (default_sub)                                                             \
  _ (outer_vlan_id_any)                                                       \
  _ (inner_vlan_id_any)

#define foreach_create_subif_flag                                             \
  _ (0, "no_tags")                                                            \
  _ (1, "one_tag")                                                            \
  _ (2, "two_tags")                                                           \
  _ (3, "dot1ad")                                                             \
  _ (4, "exact_match")                                                        \
  _ (5, "default_sub")                                                        \
  _ (6, "outer_vlan_id_any")                                                  \
  _ (7, "inner_vlan_id_any")

static int
api_create_subif (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_create_subif_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u32 sub_id;
  u8 sub_id_set = 0;
  u32 __attribute__ ((unused)) no_tags = 0;
  u32 __attribute__ ((unused)) one_tag = 0;
  u32 __attribute__ ((unused)) two_tags = 0;
  u32 __attribute__ ((unused)) dot1ad = 0;
  u32 __attribute__ ((unused)) exact_match = 0;
  u32 __attribute__ ((unused)) default_sub = 0;
  u32 __attribute__ ((unused)) outer_vlan_id_any = 0;
  u32 __attribute__ ((unused)) inner_vlan_id_any = 0;
  u32 tmp;
  u16 outer_vlan_id = 0;
  u16 inner_vlan_id = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sub_id %d", &sub_id))
	sub_id_set = 1;
      else if (unformat (i, "outer_vlan_id %d", &tmp))
	outer_vlan_id = tmp;
      else if (unformat (i, "inner_vlan_id %d", &tmp))
	inner_vlan_id = tmp;

#define _(a) else if (unformat (i, #a)) a = 1;
      foreach_create_subif_bit
#undef _
	else
      {
	clib_warning ("parse error '%U'", format_unformat_error, i);
	return -99;
      }
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (sub_id_set == 0)
    {
      errmsg ("missing sub_id");
      return -99;
    }
  M (CREATE_SUBIF, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->sub_id = ntohl (sub_id);

#define _(a, b) mp->sub_if_flags |= (1 << a);
  foreach_create_subif_flag;
#undef _

  mp->outer_vlan_id = ntohs (outer_vlan_id);
  mp->inner_vlan_id = ntohs (inner_vlan_id);

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_sw_interface_rx_placement_details_t_handler (
  vl_api_sw_interface_rx_placement_details_t *mp)
{
  vat_main_t *vam = interface_test_main.vat_main;
  u32 worker_id = ntohl (mp->worker_id);

  print (vam->ofp, "\n%-11d %-11s %-6d %-5d %-9s", ntohl (mp->sw_if_index),
	 (worker_id == 0) ? "main" : "worker", worker_id, ntohl (mp->queue_id),
	 (mp->mode == 1) ? "polling" :
			   ((mp->mode == 2) ? "interrupt" : "adaptive"));
}

static __clib_unused void
vl_api_sw_interface_tx_placement_details_t_handler (
  vl_api_sw_interface_tx_placement_details_t *mp)
{
  vat_main_t *vam = interface_test_main.vat_main;
  u32 size = ntohl (mp->array_size);
  uword *bitmap = 0;

  for (u32 i = 0; i < size; i++)
    {
      u32 thread_index = ntohl (mp->threads[i]);
      bitmap = clib_bitmap_set (bitmap, thread_index, 1);
    }

  print (vam->ofp, "\n%-11d %-6d %-7s %U", ntohl (mp->sw_if_index),
	 ntohl (mp->queue_id), (mp->shared == 1) ? "yes" : "no",
	 format_bitmap_list, bitmap);
}

static void
vl_api_create_vlan_subif_reply_t_handler (vl_api_create_vlan_subif_reply_t *mp)
{
  vat_main_t *vam = interface_test_main.vat_main;
  vam->result_ready = 1;
}

static void
vl_api_create_loopback_reply_t_handler (vl_api_create_loopback_reply_t *mp)
{
  vat_main_t *vam = interface_test_main.vat_main;
  vam->result_ready = 1;
}

static void
vl_api_create_loopback_instance_reply_t_handler (
  vl_api_create_loopback_instance_reply_t *mp)
{
  vat_main_t *vam = interface_test_main.vat_main;
  vam->result_ready = 1;
}

static int
api_create_vlan_subif (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_create_vlan_subif_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u32 vlan_id;
  u8 vlan_id_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "vlan %d", &vlan_id))
	vlan_id_set = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (vlan_id_set == 0)
    {
      errmsg ("missing vlan_id");
      return -99;
    }
  M (CREATE_VLAN_SUBIF, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->vlan_id = ntohl (vlan_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_collect_detailed_interface_stats (vat_main_t *vam)
{
  return -1;
}

static int
api_sw_interface_rx_placement_dump (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_rx_placement_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set++;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set++;
      else
	break;
    }

  fformat (vam->ofp, "\n%-11s %-11s %-6s %-5s %-4s", "sw_if_index",
	   "main/worker", "thread", "queue", "mode");

  /* Dump Interface rx placement */
  M (SW_INTERFACE_RX_PLACEMENT_DUMP, mp);

  if (sw_if_index_set)
    mp->sw_if_index = htonl (sw_if_index);
  else
    mp->sw_if_index = ~0;

  S (mp);

  /* Use a control ping for synchronization */
  PING (&interface_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_sw_interface_tx_placement_get (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_tx_placement_get_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set++;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set++;
      else
	break;
    }

  fformat (vam->ofp, "\n%-11s %-6s %-7s %-11s", "sw_if_index", "queue",
	   "shared", "threads");

  /* Dump Interface tx placement */
  M (SW_INTERFACE_TX_PLACEMENT_GET, mp);

  if (sw_if_index_set)
    mp->sw_if_index = htonl (sw_if_index);
  else
    mp->sw_if_index = ~0;

  S (mp);

  /* Use a control ping for synchronization */
  PING (&interface_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void
vl_api_sw_interface_tx_placement_get_reply_t_handler ()
{
}

static int
api_sw_interface_clear_stats (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_clear_stats_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	break;
    }

  /* Construct the API message */
  M (SW_INTERFACE_CLEAR_STATS, mp);

  if (sw_if_index_set == 1)
    mp->sw_if_index = ntohl (sw_if_index);
  else
    mp->sw_if_index = ~0;

  /* send it... */
  S (mp);

  /* Wait for a reply, return the good/bad news... */
  W (ret);
  return ret;
}

static int
api_sw_interface_set_table (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_table_t *mp;
  u32 sw_if_index, vrf_id = 0;
  u8 sw_if_index_set = 0;
  u8 is_ipv6 = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "vrf %d", &vrf_id))
	;
      else if (unformat (i, "ipv6"))
	is_ipv6 = 1;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_SET_TABLE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_ipv6 = is_ipv6;
  mp->vrf_id = ntohl (vrf_id);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sw_interface_address_replace_end (vat_main_t *vam)
{
  return -1;
}

static int
api_sw_interface_set_ip_directed_broadcast (vat_main_t *vam)
{
  return -1;
}

static int
api_sw_interface_set_mtu (vat_main_t *vam)
{
  return -1;
}

static int
api_sw_interface_set_promisc (vat_main_t *vam)
{
  return -1;
}

static int
api_want_interface_events (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_want_interface_events_t *mp;
  int enable = -1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "enable"))
	enable = 1;
      else if (unformat (i, "disable"))
	enable = 0;
      else
	break;
    }

  if (enable == -1)
    {
      errmsg ("missing enable|disable");
      return -99;
    }

  M (WANT_INTERFACE_EVENTS, mp);
  mp->enable_disable = enable;

  vam->interface_event_display = enable;

  S (mp);
  W (ret);
  return ret;
}

typedef struct
{
  u8 *name;
  u32 value;
} name_sort_t;

int
api_sw_interface_dump (vat_main_t *vam)
{
  vl_api_sw_interface_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  hash_pair_t *p;
  name_sort_t *nses = 0, *ns;
  sw_interface_subif_t *sub = NULL;
  int ret;

  /* Toss the old name table */
  hash_foreach_pair (p, vam->sw_if_index_by_interface_name, ({
		       vec_add2 (nses, ns, 1);
		       ns->name = (u8 *) (p->key);
		       ns->value = (u32) p->value[0];
		     }));

  hash_free (vam->sw_if_index_by_interface_name);

  vec_foreach (ns, nses)
    vec_free (ns->name);

  vec_free (nses);

  vec_foreach (sub, vam->sw_if_subif_table)
    {
      vec_free (sub->interface_name);
    }
  vec_free (vam->sw_if_subif_table);

  /* recreate the interface name hash table */
  vam->sw_if_index_by_interface_name = hash_create_string (0, sizeof (uword));

  /*
   * Ask for all interface names. Otherwise, the epic catalog of
   * name filters becomes ridiculously long, and vat ends up needing
   * to be taught about new interface types.
   */
  M (SW_INTERFACE_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  PING (&interface_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_sw_interface_set_interface_name (vat_main_t *vam)
{
  return -1;
}

static int
api_pcap_set_filter_function (vat_main_t *vam)
{
  vl_api_pcap_set_filter_function_t *mp;
  int ret;

  M (PCAP_SET_FILTER_FUNCTION, mp);
  S (mp);
  W (ret);
  return ret;
}

static int
api_pcap_trace_on (vat_main_t *vam)
{
  return -1;
}

static int
api_pcap_trace_off (vat_main_t *vam)
{
  return -1;
}

#include <vnet/interface.api_test.c>

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
