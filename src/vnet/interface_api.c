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
#include <vnet/api_errno.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>
#include <vnet/l2/l2_vtr.h>
#include <vnet/vnet_msg_enum.h>
#include <vnet/fib/fib_api.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                                     \
_(SW_INTERFACE_SET_FLAGS, sw_interface_set_flags)               \
_(SW_INTERFACE_SET_MTU, sw_interface_set_mtu)                   \
_(WANT_INTERFACE_EVENTS, want_interface_events)                 \
_(SW_INTERFACE_DUMP, sw_interface_dump)                         \
_(SW_INTERFACE_ADD_DEL_ADDRESS, sw_interface_add_del_address)   \
_(SW_INTERFACE_SET_TABLE, sw_interface_set_table)               \
_(SW_INTERFACE_GET_TABLE, sw_interface_get_table)               \
_(SW_INTERFACE_SET_UNNUMBERED, sw_interface_set_unnumbered)     \
_(SW_INTERFACE_CLEAR_STATS, sw_interface_clear_stats)           \
_(SW_INTERFACE_TAG_ADD_DEL, sw_interface_tag_add_del)

static void
vl_api_sw_interface_set_flags_t_handler (vl_api_sw_interface_set_flags_t * mp)
{
  vl_api_sw_interface_set_flags_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = 0;
  clib_error_t *error;
  u16 flags;

  VALIDATE_SW_IF_INDEX (mp);

  flags = mp->admin_up_down ? VNET_SW_INTERFACE_FLAG_ADMIN_UP : 0;

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
vl_api_sw_interface_set_mtu_t_handler (vl_api_sw_interface_set_mtu_t * mp)
{
  vl_api_sw_interface_set_mtu_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  u32 flags = ETHERNET_INTERFACE_FLAG_MTU;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u16 mtu = ntohs (mp->mtu);
  ethernet_main_t *em = &ethernet_main;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, sw_if_index);
  ethernet_interface_t *eif = ethernet_get_interface (em, sw_if_index);

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

  if (hi->max_packet_bytes != mtu)
    {
      hi->max_packet_bytes = mtu;
      ethernet_set_flags (vnm, sw_if_index, flags);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_MTU_REPLY);
}

static void
send_sw_interface_details (vpe_api_main_t * am,
			   unix_shared_memory_queue_t * q,
			   vnet_sw_interface_t * swif,
			   u8 * interface_name, u32 context)
{
  vl_api_sw_interface_details_t *mp;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;
  u8 *tag;

  hi = vnet_get_sup_hw_interface (am->vnet_main, swif->sw_if_index);

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_DETAILS);
  mp->sw_if_index = ntohl (swif->sw_if_index);
  mp->sup_sw_if_index = ntohl (swif->sup_sw_if_index);
  mp->admin_up_down = (swif->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? 1 : 0;
  mp->link_up_down = (hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) ? 1 : 0;
  mp->link_duplex = ((hi->flags & VNET_HW_INTERFACE_FLAG_DUPLEX_MASK) >>
		     VNET_HW_INTERFACE_FLAG_DUPLEX_SHIFT);
  mp->link_speed = ((hi->flags & VNET_HW_INTERFACE_FLAG_SPEED_MASK) >>
		    VNET_HW_INTERFACE_FLAG_SPEED_SHIFT);
  mp->link_mtu = ntohs (hi->max_packet_bytes);
  mp->context = context;

  strncpy ((char *) mp->interface_name,
	   (char *) interface_name, ARRAY_LEN (mp->interface_name) - 1);

  /* Send the L2 address for ethernet physical intfcs */
  if (swif->sup_sw_if_index == swif->sw_if_index
      && hi->hw_class_index == ethernet_hw_interface_class.index)
    {
      ethernet_main_t *em = ethernet_get_main (am->vlib_main);
      ethernet_interface_t *ei;

      ei = pool_elt_at_index (em->interfaces, hi->hw_instance);
      ASSERT (sizeof (mp->l2_address) >= sizeof (ei->address));
      clib_memcpy (mp->l2_address, ei->address, sizeof (ei->address));
      mp->l2_address_length = ntohl (sizeof (ei->address));
    }
  else if (swif->sup_sw_if_index != swif->sw_if_index)
    {
      vnet_sub_interface_t *sub = &swif->sub;
      mp->sub_id = ntohl (sub->id);
      mp->sub_dot1ad = sub->eth.flags.dot1ad;
      mp->sub_number_of_tags =
	sub->eth.flags.one_tag + sub->eth.flags.two_tags * 2;
      mp->sub_outer_vlan_id = ntohs (sub->eth.outer_vlan_id);
      mp->sub_inner_vlan_id = ntohs (sub->eth.inner_vlan_id);
      mp->sub_exact_match = sub->eth.flags.exact_match;
      mp->sub_default = sub->eth.flags.default_sub;
      mp->sub_outer_vlan_id_any = sub->eth.flags.outer_vlan_id_any;
      mp->sub_inner_vlan_id_any = sub->eth.flags.inner_vlan_id_any;

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
    }

  /* pbb tag rewrite data */
  u32 vtr_op = L2_VTR_DISABLED;
  u16 outer_tag = 0;
  u8 b_dmac[6];
  u8 b_smac[6];
  u16 b_vlanid = 0;
  u32 i_sid = 0;
  memset (b_dmac, 0, sizeof (b_dmac));
  memset (b_smac, 0, sizeof (b_smac));

  if (!l2pbb_get (am->vlib_main, am->vnet_main, swif->sw_if_index,
		  &vtr_op, &outer_tag, b_dmac, b_smac, &b_vlanid, &i_sid))
    {
      mp->sub_dot1ah = 1;
      clib_memcpy (mp->b_dmac, b_dmac, sizeof (b_dmac));
      clib_memcpy (mp->b_smac, b_smac, sizeof (b_smac));
      mp->b_vlanid = b_vlanid;
      mp->i_sid = i_sid;
    }

  tag = vnet_get_sw_interface_tag (vnm, swif->sw_if_index);
  if (tag)
    strncpy ((char *) mp->tag, (char *) tag, ARRAY_LEN (mp->tag) - 1);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_sw_interface_dump_t_handler (vl_api_sw_interface_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vnet_sw_interface_t *swif;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;
  u8 *filter_string = 0, *name_string = 0;
  unix_shared_memory_queue_t *q;
  char *strcasestr (char *, char *);	/* lnx hdr file botch */

  q = vl_api_client_index_to_input_queue (mp->client_index);

  if (q == 0)
    return;

  if (mp->name_filter_valid)
    {
      mp->name_filter[ARRAY_LEN (mp->name_filter) - 1] = 0;
      filter_string = format (0, "%s%c", mp->name_filter, 0);
    }

  /* *INDENT-OFF* */
  pool_foreach (swif, im->sw_interfaces,
  ({
    name_string = format (name_string, "%U%c",
                          format_vnet_sw_interface_name,
                          am->vnet_main, swif, 0);

    if (mp->name_filter_valid == 0 ||
        strcasestr((char *) name_string, (char *) filter_string)) {

      send_sw_interface_details (am, q, swif, name_string, mp->context);
    }
    _vec_len (name_string) = 0;
  }));
  /* *INDENT-ON* */

  vec_free (name_string);
  vec_free (filter_string);
}

static void
  vl_api_sw_interface_add_del_address_t_handler
  (vl_api_sw_interface_add_del_address_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_sw_interface_add_del_address_reply_t *rmp;
  int rv = 0;
  u32 is_del;

  VALIDATE_SW_IF_INDEX (mp);

  is_del = mp->is_add == 0;

  if (mp->del_all)
    ip_del_all_interface_addresses (vm, ntohl (mp->sw_if_index));
  else if (mp->is_ipv6)
    ip6_add_del_interface_address (vm, ntohl (mp->sw_if_index),
				   (void *) mp->address,
				   mp->address_length, is_del);
  else
    ip4_add_del_interface_address (vm, ntohl (mp->sw_if_index),
				   (void *) mp->address,
				   mp->address_length, is_del);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_ADD_DEL_ADDRESS_REPLY);
}

void stats_dslock_with_hint (int hint, int tag) __attribute__ ((weak));
void
stats_dslock_with_hint (int hint, int tag)
{
}

void stats_dsunlock (void) __attribute__ ((weak));
void
stats_dsunlock (void)
{
}

static void
vl_api_sw_interface_set_table_t_handler (vl_api_sw_interface_set_table_t * mp)
{
  int rv = 0;
  u32 table_id = ntohl (mp->vrf_id);
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vl_api_sw_interface_set_table_reply_t *rmp;
  u32 fib_index;

  VALIDATE_SW_IF_INDEX (mp);

  stats_dslock_with_hint (1 /* release hint */ , 4 /* tag */ );

  if (mp->is_ipv6)
    {
      fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6,
						     table_id);

      vec_validate (ip6_main.fib_index_by_sw_if_index, sw_if_index);
      ip6_main.fib_index_by_sw_if_index[sw_if_index] = fib_index;
    }
  else
    {

      fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4,
						     table_id);

      vec_validate (ip4_main.fib_index_by_sw_if_index, sw_if_index);
      ip4_main.fib_index_by_sw_if_index[sw_if_index] = fib_index;
    }
  stats_dsunlock ();

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_TABLE_REPLY);
}

static void
send_sw_interface_get_table_reply (unix_shared_memory_queue_t * q,
				   u32 context, int retval, u32 vrf_id)
{
  vl_api_sw_interface_get_table_reply_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_GET_TABLE_REPLY);
  mp->context = context;
  mp->retval = htonl (retval);
  mp->vrf_id = htonl (vrf_id);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_sw_interface_get_table_t_handler (vl_api_sw_interface_get_table_t * mp)
{
  unix_shared_memory_queue_t *q;
  fib_table_t *fib_table = 0;
  u32 sw_if_index = ~0;
  u32 fib_index = ~0;
  u32 table_id = ~0;
  fib_protocol_t fib_proto = FIB_PROTOCOL_IP4;
  int rv = 0;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
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

  send_sw_interface_get_table_reply (q, mp->context, rv, table_id);
}

static void vl_api_sw_interface_set_unnumbered_t_handler
  (vl_api_sw_interface_set_unnumbered_t * mp)
{
  vl_api_sw_interface_set_unnumbered_reply_t *rmp;
  int rv = 0;
  vnet_sw_interface_t *si;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index, unnumbered_sw_if_index;

  sw_if_index = ntohl (mp->sw_if_index);
  unnumbered_sw_if_index = ntohl (mp->unnumbered_sw_if_index);

  /*
   * The API message field names are backwards from
   * the underlying data structure names.
   * It's not worth changing them now.
   */
  if (pool_is_free_index (vnm->interface_main.sw_interfaces,
			  unnumbered_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto done;
    }

  /* Only check the "use loop0" field when setting the binding */
  if (mp->is_add &&
      pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX_2;
      goto done;
    }

  si = vnet_get_sw_interface (vnm, unnumbered_sw_if_index);

  if (mp->is_add)
    {
      si->flags |= VNET_SW_INTERFACE_FLAG_UNNUMBERED;
      si->unnumbered_sw_if_index = sw_if_index;
      ip4_sw_interface_enable_disable (unnumbered_sw_if_index, 1);
      ip6_sw_interface_enable_disable (unnumbered_sw_if_index, 1);
    }
  else
    {
      si->flags &= ~(VNET_SW_INTERFACE_FLAG_UNNUMBERED);
      si->unnumbered_sw_if_index = (u32) ~ 0;
      ip4_sw_interface_enable_disable (unnumbered_sw_if_index, 0);
      ip6_sw_interface_enable_disable (unnumbered_sw_if_index, 0);
    }

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
  static vnet_main_t **my_vnet_mains;
  int i, j, n_counters;
  int rv = 0;

  if (mp->sw_if_index != ~0)
    VALIDATE_SW_IF_INDEX (mp);

  vec_reset_length (my_vnet_mains);

  for (i = 0; i < vec_len (vnet_mains); i++)
    {
      if (vnet_mains[i])
	vec_add1 (my_vnet_mains, vnet_mains[i]);
    }

  if (vec_len (vnet_mains) == 0)
    vec_add1 (my_vnet_mains, vnm);

  n_counters = vec_len (im->combined_sw_if_counters);

  for (j = 0; j < n_counters; j++)
    {
      for (i = 0; i < vec_len (my_vnet_mains); i++)
	{
	  im = &my_vnet_mains[i]->interface_main;
	  cm = im->combined_sw_if_counters + j;
	  if (mp->sw_if_index == (u32) ~ 0)
	    vlib_clear_combined_counters (cm);
	  else
	    vlib_zero_combined_counter (cm, ntohl (mp->sw_if_index));
	}
    }

  n_counters = vec_len (im->sw_if_counters);

  for (j = 0; j < n_counters; j++)
    {
      for (i = 0; i < vec_len (my_vnet_mains); i++)
	{
	  im = &my_vnet_mains[i]->interface_main;
	  sm = im->sw_if_counters + j;
	  if (mp->sw_if_index == (u32) ~ 0)
	    vlib_clear_simple_counters (sm);
	  else
	    vlib_zero_simple_counter (sm, ntohl (mp->sw_if_index));
	}
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_CLEAR_STATS_REPLY);
}

#define API_LINK_STATE_EVENT 1
#define API_ADMIN_UP_DOWN_EVENT 2

static int
event_data_cmp (void *a1, void *a2)
{
  uword *e1 = a1;
  uword *e2 = a2;

  return (word) e1[0] - (word) e2[0];
}

static void
send_sw_interface_flags (vpe_api_main_t * am,
			 unix_shared_memory_queue_t * q,
			 vnet_sw_interface_t * swif)
{
  vl_api_sw_interface_set_flags_t *mp;
  vnet_main_t *vnm = am->vnet_main;

  vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm,
						       swif->sw_if_index);
  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SW_INTERFACE_SET_FLAGS);
  mp->sw_if_index = ntohl (swif->sw_if_index);

  mp->admin_up_down = (swif->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? 1 : 0;
  mp->link_up_down = (hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) ? 1 : 0;
  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static uword
link_state_process (vlib_main_t * vm,
		    vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vpe_api_main_t *vam = &vpe_api_main;
  vnet_main_t *vnm = vam->vnet_main;
  vnet_sw_interface_t *swif;
  uword *event_data = 0;
  vpe_client_registration_t *reg;
  int i;
  u32 prev_sw_if_index;
  unix_shared_memory_queue_t *q;

  vam->link_state_process_up = 1;

  while (1)
    {
      vlib_process_wait_for_event (vm);

      /* Unified list of changed link or admin state sw_if_indices */
      vlib_process_get_events_with_type
	(vm, &event_data, API_LINK_STATE_EVENT);
      vlib_process_get_events_with_type
	(vm, &event_data, API_ADMIN_UP_DOWN_EVENT);

      /* Sort, so we can eliminate duplicates */
      vec_sort_with_function (event_data, event_data_cmp);

      prev_sw_if_index = ~0;

      for (i = 0; i < vec_len (event_data); i++)
	{
	  /* Only one message per swif */
	  if (prev_sw_if_index == event_data[i])
	    continue;
	  prev_sw_if_index = event_data[i];

          /* *INDENT-OFF* */
          pool_foreach(reg, vam->interface_events_registrations,
          ({
            q = vl_api_client_index_to_input_queue (reg->client_index);
            if (q)
              {
                /* sw_interface may be deleted already */
                if (!pool_is_free_index (vnm->interface_main.sw_interfaces,
                                         event_data[i]))
                  {
                    swif = vnet_get_sw_interface (vnm, event_data[i]);
                    send_sw_interface_flags (vam, q, swif);
                  }
              }
          }));
          /* *INDENT-ON* */
	}
      vec_reset_length (event_data);
    }

  return 0;
}

static clib_error_t *link_up_down_function (vnet_main_t * vm, u32 hw_if_index,
					    u32 flags);
static clib_error_t *admin_up_down_function (vnet_main_t * vm,
					     u32 hw_if_index, u32 flags);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (link_state_process_node,static) = {
  .function = link_state_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "vpe-link-state-process",
};
/* *INDENT-ON* */

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (admin_up_down_function);
VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION (link_up_down_function);

static clib_error_t *
link_up_down_function (vnet_main_t * vm, u32 hw_if_index, u32 flags)
{
  vpe_api_main_t *vam = &vpe_api_main;
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vm, hw_if_index);

  if (vam->link_state_process_up)
    vlib_process_signal_event (vam->vlib_main,
			       link_state_process_node.index,
			       API_LINK_STATE_EVENT, hi->sw_if_index);
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
    vlib_process_signal_event (vam->vlib_main,
			       link_state_process_node.index,
			       API_ADMIN_UP_DOWN_EVENT, sw_if_index);
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

/*
 * vpe_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/interface.api.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_interface;
#undef _
}

pub_sub_handler (interface_events, INTERFACE_EVENTS);

static clib_error_t *
interface_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

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
