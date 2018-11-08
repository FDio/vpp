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

#include <vnet/vnet_msg_enum.h>

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

#define foreach_vpe_api_msg                             \
_(SR_LOCALSID_ADD_DEL, sr_localsid_add_del)             \
_(SR_POLICY_ADD, sr_policy_add)                         \
_(SR_POLICY_MOD, sr_policy_mod)                         \
_(SR_POLICY_DEL, sr_policy_del)                         \
_(SR_STEERING_ADD_DEL, sr_steering_add_del)             \
_(SR_SET_ENCAP_SOURCE, sr_set_encap_source)             \
_(SR_LOCALSIDS_DUMP, sr_localsids_dump)                 \
_(SR_POLICIES_DUMP, sr_policies_dump)                   \
_(SR_STEERING_POL_DUMP, sr_steering_pol_dump)

static void vl_api_sr_localsid_add_del_t_handler
  (vl_api_sr_localsid_add_del_t * mp)
{
  vl_api_sr_localsid_add_del_reply_t *rmp;
  int rv = 0;
/*
 * int sr_cli_localsid (char is_del, ip6_address_t *localsid_addr,
 *  char end_psp, u8 behavior, u32 sw_if_index, u32 vlan_index, u32 fib_table,
 *  ip46_address_t *nh_addr, void *ls_plugin_mem)
 */
  if (mp->behavior == SR_BEHAVIOR_X ||
      mp->behavior == SR_BEHAVIOR_DX6 ||
      mp->behavior == SR_BEHAVIOR_DX4 || mp->behavior == SR_BEHAVIOR_DX2)
    VALIDATE_SW_IF_INDEX (mp);

  ip46_address_t prefix;

  memset (&prefix, 0, sizeof (ip46_address_t));
  if ((mp->nh_addr4[0] | mp->nh_addr4[1] | mp->
       nh_addr4[2] | mp->nh_addr4[3]) != 0)
    memcpy (&prefix.ip4, mp->nh_addr4, sizeof (prefix.ip4));
  else
    memcpy (&prefix.ip6, mp->nh_addr6, sizeof (prefix.ip6));

  rv = sr_cli_localsid (mp->is_del,
			(ip6_address_t *) & mp->localsid,
			mp->end_psp,
			mp->behavior,
			ntohl (mp->sw_if_index),
			ntohl (mp->vlan_index),
			ntohl (mp->fib_table), &prefix, NULL);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SR_LOCALSID_ADD_DEL_REPLY);
}

static void
vl_api_sr_policy_add_t_handler (vl_api_sr_policy_add_t * mp)
{
  vl_api_sr_policy_add_reply_t *rmp;
  ip6_address_t *segments = 0, *seg;
  ip6_address_t *this_address = (ip6_address_t *) mp->sids.sids;

  int i;
  for (i = 0; i < mp->sids.num_sids; i++)
    {
      vec_add2 (segments, seg, 1);
      clib_memcpy (seg->as_u8, this_address->as_u8, sizeof (*this_address));
      this_address++;
    }

/*
 * sr_policy_add (ip6_address_t *bsid, ip6_address_t *segments,
 *                u32 weight, u8 behavior, u32 fib_table, u8 is_encap)
 */
  int rv = 0;
  rv = sr_policy_add ((ip6_address_t *) & mp->bsid_addr,
		      segments,
		      ntohl (mp->sids.weight),
		      mp->type, ntohl (mp->fib_table), mp->is_encap);
  vec_free (segments);

  REPLY_MACRO (VL_API_SR_POLICY_ADD_REPLY);
}

static void
vl_api_sr_policy_mod_t_handler (vl_api_sr_policy_mod_t * mp)
{
  vl_api_sr_policy_mod_reply_t *rmp;

  ip6_address_t *segments = 0, *seg;
  ip6_address_t *this_address = (ip6_address_t *) mp->sids.sids;

  int i;
  for (i = 0; i < mp->sids.num_sids; i++)
    {
      vec_add2 (segments, seg, 1);
      clib_memcpy (seg->as_u8, this_address->as_u8, sizeof (*this_address));
      this_address++;
    }

  int rv = 0;
/*
 * int
 * sr_policy_mod(ip6_address_t *bsid, u32 index, u32 fib_table,
 *               u8 operation, ip6_address_t *segments, u32 sl_index,
 *               u32 weight, u8 is_encap)
 */
  rv = sr_policy_mod ((ip6_address_t *) & mp->bsid_addr,
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
/*
 * int
 * sr_policy_del (ip6_address_t *bsid, u32 index)
 */
  rv = sr_policy_del ((ip6_address_t *) & mp->bsid_addr,
		      ntohl (mp->sr_policy_index));

  REPLY_MACRO (VL_API_SR_POLICY_DEL_REPLY);
}

static void
vl_api_sr_set_encap_source_t_handler (vl_api_sr_set_encap_source_t * mp)
{
  vl_api_sr_set_encap_source_reply_t *rmp;
  int rv = 0;
  sr_set_source ((ip6_address_t *) & mp->encaps_source);

  REPLY_MACRO (VL_API_SR_POLICY_DEL_REPLY);
}

static void vl_api_sr_steering_add_del_t_handler
  (vl_api_sr_steering_add_del_t * mp)
{
  vl_api_sr_steering_add_del_reply_t *rmp;
  int rv = 0;
/*
 * int
 * sr_steering_policy(int is_del, ip6_address_t *bsid, u32 sr_policy_index,
 *  u32 table_id, ip46_address_t *prefix, u32 mask_width, u32 sw_if_index,
 *  u8 traffic_type)
 */
  if (mp->traffic_type == SR_STEER_L2)
    VALIDATE_SW_IF_INDEX (mp);

  rv = sr_steering_policy (mp->is_del,
			   (ip6_address_t *) & mp->bsid_addr,
			   ntohl (mp->sr_policy_index),
			   ntohl (mp->table_id),
			   (ip46_address_t *) & mp->prefix_addr,
			   ntohl (mp->mask_width),
			   ntohl (mp->sw_if_index), mp->traffic_type);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SR_STEERING_ADD_DEL_REPLY);
}

static void send_sr_localsid_details
  (ip6_sr_localsid_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_sr_localsids_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SR_LOCALSIDS_DETAILS);
  clib_memcpy (rmp->addr.addr, &t->localsid, sizeof (ip6_address_t));
  rmp->end_psp = t->end_psp;
  rmp->behavior = htons (t->behavior);
  rmp->fib_table = htonl (t->fib_table);
  rmp->vlan_index = htonl (t->vlan_index);
  if (ip46_address_is_ip4 (&t->next_hop))
    clib_memcpy (rmp->xconnect_nh_addr4, &t->next_hop.ip4,
		 sizeof (ip4_address_t));
  else
    clib_memcpy (rmp->xconnect_nh_addr6, &t->next_hop.ip6,
		 sizeof (ip6_address_t));
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
  pool_foreach (t, sm->localsids,
  ({
    send_sr_localsid_details(t, reg, mp->context);
  }));
  /* *INDENT-ON* */
}

static void send_sr_policies_details
  (ip6_sr_policy_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_sr_policies_details_t *rmp;
  ip6_sr_main_t *sm = &sr_main;

  u32 *sl_index;
  ip6_sr_sl_t *segment_list = 0;
  vl_api_srv6_sid_list_t *write_sid_list;

  rmp = vl_msg_api_alloc (sizeof (*rmp) +
			  vec_len (t->segments_lists) *
			  sizeof (vl_api_srv6_sid_list_t));
  memset (rmp, 0,
	  (sizeof (*rmp) +
	   vec_len (t->segments_lists) * sizeof (vl_api_srv6_sid_list_t)));

  rmp->_vl_msg_id = ntohs (VL_API_SR_POLICIES_DETAILS);
  clib_memcpy (rmp->bsid.addr, &t->bsid, sizeof (ip6_address_t));
  rmp->is_encap = t->is_encap;
  rmp->type = t->type;
  rmp->fib_table = htonl (t->fib_table);
  rmp->num_sid_lists = vec_len (t->segments_lists);

  /* Fill in all the segments lists */
  vec_foreach (sl_index, t->segments_lists)
  {
    segment_list = pool_elt_at_index (sm->sid_lists, *sl_index);
    write_sid_list = &rmp->sid_lists[sl_index - t->segments_lists];
    write_sid_list->num_sids = vec_len (segment_list->segments);
    write_sid_list->weight = htonl (segment_list->weight);
    clib_memcpy (write_sid_list->sids, segment_list->segments,
		 vec_len (segment_list->segments) * sizeof (ip6_address_t));
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
  pool_foreach (t, sm->sr_policies,
  ({
    send_sr_policies_details(t, reg, mp->context);
  }));
  /* *INDENT-ON* */
}

static void send_sr_steering_pol_details
  (ip6_sr_steering_policy_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_sr_steering_pol_details_t *rmp;
  ip6_sr_main_t *sm = &sr_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_SR_STEERING_POL_DETAILS);

  //Get the SR policy BSID
  ip6_sr_policy_t *p;
  p = pool_elt_at_index (sm->sr_policies, t->sr_policy);
  clib_memcpy (rmp->bsid.addr, &p->bsid, sizeof (ip6_address_t));

  //Get the steering
  rmp->traffic_type = t->classify.traffic_type;
  rmp->fib_table = htonl (t->classify.l3.fib_table);
  rmp->mask_width = htonl (t->classify.l3.mask_width);
  if (ip46_address_is_ip4 (&t->classify.l3.prefix))
    clib_memcpy (rmp->prefix_addr, &t->classify.l3.prefix.ip4,
		 sizeof (ip4_address_t));
  else
    clib_memcpy (rmp->prefix_addr, &t->classify.l3.prefix.ip6,
		 sizeof (ip6_address_t));

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
  pool_foreach (t, sm->steer_policies,
  ({
    send_sr_steering_pol_details(t, reg, mp->context);
  }));
  /* *INDENT-ON* */
}

/*
 * sr_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_sr;
#undef _
}

static clib_error_t *
sr_api_hookup (vlib_main_t * vm)
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

VLIB_API_INIT_FUNCTION (sr_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
