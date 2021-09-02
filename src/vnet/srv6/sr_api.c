/*
 *------------------------------------------------------------------
 * sr_api.c - ipv6 segment routing api
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
#include <vnet/srv6/sr.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/format_fns.h>
#include <vnet/srv6/sr.api_enum.h>
#include <vnet/srv6/sr.api_types.h>

#define REPLY_MSG_ID_BASE sr_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void vl_api_sr_localsid_add_del_t_handler
  (vl_api_sr_localsid_add_del_t * mp)
{
  vl_api_sr_localsid_add_del_reply_t *rmp;
  int rv = 0;
  ip46_address_t prefix;
  ip6_address_t localsid;
/*
 * int sr_cli_localsid (char is_del, ip6_address_t *localsid_addr,
 *  char end_psp, u8 behavior, u32 sw_if_index, u32 vlan_index, u32 fib_table,
 *  ip46_address_t *nh_addr, void *ls_plugin_mem)
 */
  if (mp->behavior == SR_BEHAVIOR_X ||
      mp->behavior == SR_BEHAVIOR_DX6 ||
      mp->behavior == SR_BEHAVIOR_DX4 || mp->behavior == SR_BEHAVIOR_DX2)
    VALIDATE_SW_IF_INDEX (mp);

  ip6_address_decode (mp->localsid, &localsid);
  ip_address_decode (&mp->nh_addr, &prefix);

  rv = sr_cli_localsid (mp->is_del,
			&localsid, 128,
			mp->end_psp,
			mp->behavior,
			ntohl (mp->sw_if_index),
			ntohl (mp->vlan_index),
			ntohl (mp->fib_table), &prefix, 0, NULL);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SR_LOCALSID_ADD_DEL_REPLY);
}

static void
vl_api_sr_policy_add_t_handler (vl_api_sr_policy_add_t * mp)
{
  vl_api_sr_policy_add_reply_t *rmp;
  ip6_address_t *segments = 0, *seg;
  ip6_address_t bsid_addr;

  int i;
  for (i = 0; i < mp->sids.num_sids; i++)
    {
      vec_add2 (segments, seg, 1);
      ip6_address_decode (mp->sids.sids[i], seg);
    }

  ip6_address_decode (mp->bsid_addr, &bsid_addr);

/*
 * sr_policy_add (ip6_address_t *bsid, ip6_address_t *segments,
 *                u32 weight, u8 behavior, u32 fib_table, u8 is_encap,
 *                u16 behavior, void *plugin_mem)
 */
  int rv = 0;
  rv = sr_policy_add (&bsid_addr,
		      segments,
		      ntohl (mp->sids.weight),
		      mp->is_spray, ntohl (mp->fib_table), mp->is_encap, 0,
		      NULL);
  vec_free (segments);

  REPLY_MACRO (VL_API_SR_POLICY_ADD_REPLY);
}

static void
vl_api_sr_policy_mod_t_handler (vl_api_sr_policy_mod_t * mp)
{
  vl_api_sr_policy_mod_reply_t *rmp;
  ip6_address_t *segments = 0, *seg;
  ip6_address_t bsid_addr;

  int i;
  for (i = 0; i < mp->sids.num_sids; i++)
    {
      vec_add2 (segments, seg, 1);
      ip6_address_decode (mp->sids.sids[i], seg);
    }

  ip6_address_decode (mp->bsid_addr, &bsid_addr);

  int rv = 0;
/*
 * int
 * sr_policy_mod(ip6_address_t *bsid, u32 index, u32 fib_table,
 *               u8 operation, ip6_address_t *segments, u32 sl_index,
 *               u32 weight, u8 is_encap)
 */
  rv = sr_policy_mod (&bsid_addr,
		      ntohl (mp->sr_policy_index),
		      ntohl (mp->fib_table),
		      mp->operation,
		      segments, ntohl (mp->sl_index),
		      ntohl (mp->sids.weight));
  vec_free (segments);

  REPLY_MACRO (VL_API_SR_POLICY_MOD_REPLY);
}

static void
vl_api_sr_policy_del_t_handler (vl_api_sr_policy_del_t * mp)
{
  vl_api_sr_policy_del_reply_t *rmp;
  int rv = 0;
  ip6_address_t bsid_addr;
/*
 * int
 * sr_policy_del (ip6_address_t *bsid, u32 index)
 */
  ip6_address_decode (mp->bsid_addr, &bsid_addr);
  rv = sr_policy_del (&bsid_addr, ntohl (mp->sr_policy_index));

  REPLY_MACRO (VL_API_SR_POLICY_DEL_REPLY);
}

static void
vl_api_sr_set_encap_source_t_handler (vl_api_sr_set_encap_source_t * mp)
{
  vl_api_sr_set_encap_source_reply_t *rmp;
  int rv = 0;
  ip6_address_t encaps_source;

  ip6_address_decode (mp->encaps_source, &encaps_source);
  sr_set_source (&encaps_source);

  REPLY_MACRO (VL_API_SR_SET_ENCAP_SOURCE_REPLY);
}

static void
vl_api_sr_set_encap_hop_limit_t_handler (vl_api_sr_set_encap_hop_limit_t * mp)
{
  vl_api_sr_set_encap_hop_limit_reply_t *rmp;
  int rv = 0;

  if (mp->hop_limit == 0)
    rv = VNET_API_ERROR_INVALID_VALUE;
  else
    sr_set_hop_limit (mp->hop_limit);

  REPLY_MACRO (VL_API_SR_SET_ENCAP_HOP_LIMIT_REPLY);
}

static void vl_api_sr_steering_add_del_t_handler
  (vl_api_sr_steering_add_del_t * mp)
{
  vl_api_sr_steering_add_del_reply_t *rmp;
  int rv = 0;
  ip6_address_t bsid_addr;
  ip46_address_t prefix_addr;
/*
 * int
 * sr_steering_policy(int is_del, ip6_address_t *bsid, u32 sr_policy_index,
 *  u32 table_id, ip46_address_t *prefix, u32 mask_width, u32 sw_if_index,
 *  u8 traffic_type)
 */

  ip6_address_decode (mp->bsid_addr, &bsid_addr);
  ip_address_decode (&mp->prefix.address, &prefix_addr);

  if (mp->traffic_type == SR_STEER_L2)
    VALIDATE_SW_IF_INDEX (mp);

  rv = sr_steering_policy (mp->is_del,
			   &bsid_addr,
			   ntohl (mp->sr_policy_index),
			   ntohl (mp->table_id),
			   &prefix_addr,
			   mp->prefix.len,
			   ntohl (mp->sw_if_index), mp->traffic_type);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SR_STEERING_ADD_DEL_REPLY);
}

static void send_sr_localsid_details
  (ip6_sr_localsid_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_sr_localsids_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SR_LOCALSIDS_DETAILS);
  ip6_address_encode (&t->localsid, rmp->addr);
  rmp->end_psp = t->end_psp;
  rmp->behavior = t->behavior;
  rmp->fib_table = htonl (t->fib_table);
  rmp->vlan_index = htonl (t->vlan_index);
  ip_address_encode (&t->next_hop, IP46_TYPE_ANY, &rmp->xconnect_nh_addr);

  if (t->behavior == SR_BEHAVIOR_T || t->behavior == SR_BEHAVIOR_DT6)
    rmp->xconnect_iface_or_vrf_table =
      htonl (fib_table_get_table_id (t->sw_if_index, FIB_PROTOCOL_IP6));
  else if (t->behavior == SR_BEHAVIOR_DT4)
    rmp->xconnect_iface_or_vrf_table =
      htonl (fib_table_get_table_id (t->sw_if_index, FIB_PROTOCOL_IP4));
  else
    rmp->xconnect_iface_or_vrf_table = htonl (t->sw_if_index);

  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void vl_api_sr_localsids_dump_t_handler
  (vl_api_sr_localsids_dump_t * mp)
{
  vl_api_registration_t *reg;
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_localsid_t *t;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (t, sm->localsids)
   {
    send_sr_localsid_details(t, reg, mp->context);
  }
  /* *INDENT-ON* */
}

static void send_sr_policies_details
  (ip6_sr_policy_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_sr_policies_details_t *rmp;
  ip6_sr_main_t *sm = &sr_main;

  u32 *sl_index, slidx = 0;
  ip6_sr_sl_t *segment_list = 0;
  ip6_address_t *segment;
  vl_api_srv6_sid_list_t *api_sid_list;

  rmp = vl_msg_api_alloc (sizeof (*rmp) +
			  vec_len (t->segments_lists) *
			  sizeof (vl_api_srv6_sid_list_t));
  clib_memset (rmp, 0,
	       (sizeof (*rmp) +
		vec_len (t->segments_lists) *
		sizeof (vl_api_srv6_sid_list_t)));

  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SR_POLICIES_DETAILS);
  ip6_address_encode (&t->bsid, rmp->bsid);
  rmp->is_encap = t->is_encap;
  rmp->is_spray = t->type;
  rmp->fib_table = htonl (t->fib_table);
  rmp->num_sid_lists = vec_len (t->segments_lists);

  /* Fill in all the segments lists */
  vec_foreach (sl_index, t->segments_lists)
  {
    segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);

    api_sid_list = &rmp->sid_lists[sl_index - t->segments_lists];

    api_sid_list->num_sids = vec_len (segment_list->segments);
    api_sid_list->weight = htonl (segment_list->weight);
    slidx = 0;
    vec_foreach (segment, segment_list->segments)
    {
      ip6_address_encode (segment, api_sid_list->sids[slidx++]);
    }
  }

  rmp->context = context;
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_sr_policies_dump_t_handler (vl_api_sr_policies_dump_t * mp)
{
  vl_api_registration_t *reg;
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_policy_t *t;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (t, sm->sr_policies)
   {
    send_sr_policies_details(t, reg, mp->context);
  }
  /* *INDENT-ON* */
}



static void send_sr_policies_details_with_sl_index
  (ip6_sr_policy_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_sr_policies_with_sl_index_details_t *rmp;
  ip6_sr_main_t *sm = &sr_main;

  u32 *sl_index, slidx = 0;
  ip6_sr_sl_t *segment_list = 0;
  ip6_address_t *segment;
  vl_api_srv6_sid_list_with_sl_index_t *api_sid_list;

  rmp = vl_msg_api_alloc (sizeof (*rmp) +
			  vec_len (t->segments_lists) *
			  sizeof (vl_api_srv6_sid_list_with_sl_index_t));
  clib_memset (rmp, 0,
	       (sizeof (*rmp) +
		vec_len (t->segments_lists) *
		sizeof (vl_api_srv6_sid_list_with_sl_index_t)));

  rmp->_vl_msg_id =
    ntohs (REPLY_MSG_ID_BASE + VL_API_SR_POLICIES_WITH_SL_INDEX_DETAILS);
  ip6_address_encode (&t->bsid, rmp->bsid);
  rmp->is_encap = t->is_encap;
  rmp->is_spray = t->type;
  rmp->fib_table = htonl (t->fib_table);
  rmp->num_sid_lists = vec_len (t->segments_lists);

  /* Fill in all the segments lists */
  vec_foreach (sl_index, t->segments_lists)
  {
    segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);

    api_sid_list = &rmp->sid_lists[sl_index - t->segments_lists];
    api_sid_list->sl_index = htonl (*sl_index);
    api_sid_list->num_sids = vec_len (segment_list->segments);
    api_sid_list->weight = htonl (segment_list->weight);
    slidx = 0;
    vec_foreach (segment, segment_list->segments)
    {
      ip6_address_encode (segment, api_sid_list->sids[slidx++]);
    }
  }

  rmp->context = context;
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
  vl_api_sr_policies_with_sl_index_dump_t_handler
  (vl_api_sr_policies_with_sl_index_dump_t * mp)
{
  vl_api_registration_t *reg;
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_policy_t *t;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (t, sm->sr_policies)
   {
    send_sr_policies_details_with_sl_index(t, reg, mp->context);
  }
  /* *INDENT-ON* */
}

static void send_sr_steering_pol_details
  (ip6_sr_steering_policy_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_sr_steering_pol_details_t *rmp;
  ip6_sr_main_t *sm = &sr_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_SR_STEERING_POL_DETAILS);

  //Get the SR policy BSID
  ip6_sr_policy_t *p;
  p = pool_elt_at_index (sm->sr_policies, t->sr_policy);
  ip6_address_encode (&p->bsid, rmp->bsid);

  //Get the steering
  rmp->traffic_type = t->classify.traffic_type;
  rmp->fib_table = htonl (t->classify.l3.fib_table);
  ip_address_encode (&t->classify.l3.prefix, IP46_TYPE_ANY,
		     &rmp->prefix.address);
  rmp->prefix.len = t->classify.l3.mask_width;

  rmp->sw_if_index = htonl (t->classify.l2.sw_if_index);

  rmp->context = context;
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void vl_api_sr_steering_pol_dump_t_handler
  (vl_api_sr_policies_dump_t * mp)
{
  vl_api_registration_t *reg;
  ip6_sr_main_t *sm = &sr_main;
  ip6_sr_steering_policy_t *t;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (t, sm->steer_policies)
   {
    send_sr_steering_pol_details(t, reg, mp->context);
  }
  /* *INDENT-ON* */
}

#include <vnet/srv6/sr.api.c>
static clib_error_t *
sr_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (sr_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
