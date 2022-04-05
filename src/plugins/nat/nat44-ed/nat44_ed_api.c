/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 *
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
 */
/**
 * @file
 * @brief NAT44 plugin API implementation
 */

#include <vnet/ip/ip_types_api.h>
#include <vlibmemory/api.h>

#include <vnet/fib/fib_table.h>

#include <nat/lib/nat_inlines.h>
#include <nat/lib/ipfix_logging.h>

#include <nat/nat44-ed/nat44_ed.h>

#include <nat/nat44-ed/nat44_ed.api_enum.h>
#include <nat/nat44-ed/nat44_ed.api_types.h>

#include <nat/nat44-ed/nat44_ed_inlines.h>

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* New API calls */

static void
vl_api_nat44_ed_plugin_enable_disable_t_handler (
  vl_api_nat44_ed_plugin_enable_disable_t *mp)
{
  snat_main_t *sm = &snat_main;
  nat44_config_t c = { 0 };
  vl_api_nat44_ed_plugin_enable_disable_reply_t *rmp;
  int rv = 0;

  if (mp->enable)
    {
      if ((mp->flags & NAT44_API_IS_STATIC_MAPPING_ONLY) ||
	  (mp->flags & NAT44_API_IS_CONNECTION_TRACKING))
	{
	  rv = VNET_API_ERROR_UNSUPPORTED;
	}
      else
	{
	  c.sessions = ntohl (mp->sessions);
	  c.inside_vrf = ntohl (mp->inside_vrf);
	  c.outside_vrf = ntohl (mp->outside_vrf);

	  rv = nat44_plugin_enable (c);
	}
    }
  else
    {
      rv = nat44_plugin_disable ();
    }

  REPLY_MACRO (VL_API_NAT44_ED_PLUGIN_ENABLE_DISABLE_REPLY);
}

static void
vl_api_nat44_ed_set_fq_options_t_handler (vl_api_nat44_ed_set_fq_options_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_ed_set_fq_options_reply_t *rmp;
  int rv = 0;
  u32 frame_queue_nelts = ntohl (mp->frame_queue_nelts);
  rv = nat44_ed_set_frame_queue_nelts (frame_queue_nelts);
  REPLY_MACRO (VL_API_NAT44_ED_SET_FQ_OPTIONS_REPLY);
}

static void
vl_api_nat44_ed_show_fq_options_t_handler (
  vl_api_nat44_ed_show_fq_options_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_ed_show_fq_options_reply_t *rmp;
  int rv = 0;
  /* clang-format off */
  REPLY_MACRO2_ZERO (VL_API_NAT44_ED_SHOW_FQ_OPTIONS_REPLY,
  ({
    rmp->frame_queue_nelts = htonl (sm->frame_queue_nelts);
  }));
  /* clang-format on */
}

/* Old API calls hold back because of deprecation
 * nat44_ed replacement should be used */

static void
vl_api_nat_set_workers_t_handler (vl_api_nat_set_workers_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_set_workers_reply_t *rmp;
  int rv = 0;
  uword *bitmap = 0;
  u64 mask;

  mask = clib_net_to_host_u64 (mp->worker_mask);

  if (sm->num_workers < 2)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto send_reply;
    }

  bitmap = clib_bitmap_set_multiple (bitmap, 0, mask, BITS (mask));
  rv = snat_set_workers (bitmap);
  clib_bitmap_free (bitmap);

send_reply:
  REPLY_MACRO (VL_API_NAT_SET_WORKERS_REPLY);
}

static void
send_nat_worker_details (u32 worker_index, vl_api_registration_t * reg,
			 u32 context)
{
  vl_api_nat_worker_details_t *rmp;
  snat_main_t *sm = &snat_main;
  vlib_worker_thread_t *w =
    vlib_worker_threads + worker_index + sm->first_worker_index;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT_WORKER_DETAILS + sm->msg_id_base);
  rmp->context = context;
  rmp->worker_index = htonl (worker_index);
  rmp->lcore_id = htonl (w->cpu_id);
  strncpy ((char *) rmp->name, (char *) w->name, ARRAY_LEN (rmp->name) - 1);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat_worker_dump_t_handler (vl_api_nat_worker_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  u32 *worker_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (worker_index, sm->workers)
    {
      send_nat_worker_details (*worker_index, reg, mp->context);
    }
}

static void
vl_api_nat44_set_session_limit_t_handler (vl_api_nat44_set_session_limit_t *
					  mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_set_session_limit_reply_t *rmp;
  int rv = 0;

  rv = nat44_set_session_limit
    (ntohl (mp->session_limit), ntohl (mp->vrf_id));

  REPLY_MACRO (VL_API_NAT44_SET_SESSION_LIMIT_REPLY);
}

static void
vl_api_nat_ipfix_enable_disable_t_handler (vl_api_nat_ipfix_enable_disable_t *
					   mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ipfix_enable_disable_reply_t *rmp;
  int rv = 0;

  rv = nat_ipfix_logging_enable_disable (mp->enable,
					 clib_host_to_net_u32
					 (mp->domain_id),
					 clib_host_to_net_u16 (mp->src_port));

  REPLY_MACRO (VL_API_NAT_IPFIX_ENABLE_DISABLE_REPLY);
}

static void
vl_api_nat_set_timeouts_t_handler (vl_api_nat_set_timeouts_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_set_timeouts_reply_t *rmp;
  int rv = 0;

  sm->timeouts.udp = ntohl (mp->udp);
  sm->timeouts.tcp.established = ntohl (mp->tcp_established);
  sm->timeouts.tcp.transitory = ntohl (mp->tcp_transitory);
  sm->timeouts.icmp = ntohl (mp->icmp);

  REPLY_MACRO (VL_API_NAT_SET_TIMEOUTS_REPLY);
}

static void
vl_api_nat_set_mss_clamping_t_handler (vl_api_nat_set_mss_clamping_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_set_mss_clamping_reply_t *rmp;
  int rv = 0;

  if (mp->enable)
    sm->mss_clamping = ntohs (mp->mss_value);
  else
    sm->mss_clamping = 0;

  REPLY_MACRO (VL_API_NAT_SET_MSS_CLAMPING_REPLY);
}

static void
vl_api_nat_get_mss_clamping_t_handler (vl_api_nat_get_mss_clamping_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_get_mss_clamping_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_NAT_GET_MSS_CLAMPING_REPLY,
  ({
    rmp->enable = sm->mss_clamping ? 1 : 0;
    rmp->mss_value = htons (sm->mss_clamping);
  }))
}

static void
  vl_api_nat44_add_del_address_range_t_handler
  (vl_api_nat44_add_del_address_range_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_add_del_address_range_reply_t *rmp;
  ip4_address_t this_addr;
  u8 is_add, twice_nat;
  u32 start_host_order, end_host_order;
  u32 vrf_id;
  int i, count;
  int rv = 0;
  u32 *tmp;

  is_add = mp->is_add;
  twice_nat = mp->flags & NAT_API_IS_TWICE_NAT;

  tmp = (u32 *) mp->first_ip_address;
  start_host_order = clib_host_to_net_u32 (tmp[0]);
  tmp = (u32 *) mp->last_ip_address;
  end_host_order = clib_host_to_net_u32 (tmp[0]);

  count = (end_host_order - start_host_order) + 1;

  vrf_id = clib_host_to_net_u32 (mp->vrf_id);

  if (count > 1024)
    nat_log_info ("%U - %U, %d addresses...",
		  format_ip4_address, mp->first_ip_address,
		  format_ip4_address, mp->last_ip_address, count);

  memcpy (&this_addr.as_u8, mp->first_ip_address, 4);

  for (i = 0; i < count; i++)
    {
      if (is_add)
	{
	  rv = nat44_ed_add_address (&this_addr, vrf_id, twice_nat);
	}
      else
	{
	  rv = nat44_ed_del_address (this_addr, twice_nat);
	}

      if (rv)
	goto send_reply;

      increment_v4_address (&this_addr);
    }

send_reply:
  REPLY_MACRO (VL_API_NAT44_ADD_DEL_ADDRESS_RANGE_REPLY);
}

static void
send_nat44_address_details (snat_address_t * a,
			    vl_api_registration_t * reg, u32 context,
			    u8 twice_nat)
{
  vl_api_nat44_address_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT44_ADDRESS_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->ip_address, &(a->addr), 4);
  if (a->fib_index != ~0)
    {
      fib_table_t *fib = fib_table_get (a->fib_index, FIB_PROTOCOL_IP4);
      rmp->vrf_id = ntohl (fib->ft_table_id);
    }
  else
    rmp->vrf_id = ~0;
  if (twice_nat)
    rmp->flags |= NAT_API_IS_TWICE_NAT;
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_address_dump_t_handler (vl_api_nat44_address_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_address_t *a;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (a, sm->addresses)
    send_nat44_address_details (a, reg, mp->context, 0);
  vec_foreach (a, sm->twice_nat_addresses)
    send_nat44_address_details (a, reg, mp->context, 1);
}

static void
  vl_api_nat44_interface_add_del_feature_t_handler
  (vl_api_nat44_interface_add_del_feature_t * mp)
{
  vl_api_nat44_interface_add_del_feature_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  u32 sw_if_index;
  u8 is_inside;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  is_inside = mp->flags & NAT_API_IS_INSIDE;
  sw_if_index = ntohl (mp->sw_if_index);

  if (mp->is_add)
    {
      rv = nat44_ed_add_interface (sw_if_index, is_inside);
    }
  else
    {
      rv = nat44_ed_del_interface (sw_if_index, is_inside);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_NAT44_INTERFACE_ADD_DEL_FEATURE_REPLY);
}

static void
send_nat44_interface_details (snat_interface_t * i,
			      vl_api_registration_t * reg, u32 context)
{
  vl_api_nat44_interface_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT44_INTERFACE_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);

  if (nat44_ed_is_interface_inside (i))
    rmp->flags |= NAT_API_IS_INSIDE;
  if (nat44_ed_is_interface_outside (i))
    rmp->flags |= NAT_API_IS_OUTSIDE;

  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_interface_dump_t_handler (vl_api_nat44_interface_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_interface_t *i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (i, sm->interfaces)
    {
      send_nat44_interface_details (i, reg, mp->context);
    }
}

static void
vl_api_nat44_ed_add_del_output_interface_t_handler (
  vl_api_nat44_ed_add_del_output_interface_t *mp)
{
  vl_api_nat44_ed_add_del_output_interface_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  int rv = 0;

  VALIDATE_SW_IF_INDEX_END (mp);

  if (mp->is_add)
    {
      rv = nat44_ed_add_output_interface (mp->sw_if_index);
    }
  else
    {
      rv = nat44_ed_del_output_interface (mp->sw_if_index);
    }

bad_sw_if_index:
  REPLY_MACRO_END (VL_API_NAT44_ED_ADD_DEL_OUTPUT_INTERFACE_REPLY);
}

#define vl_endianfun
#include <nat/nat44-ed/nat44_ed.api.h>
#undef vl_endianfun
static void
send_nat44_ed_output_interface_details (u32 index, vl_api_registration_t *rp,
					u32 context)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_ed_output_interface_details_t *rmp;
  snat_interface_t *i =
    pool_elt_at_index (sm->output_feature_interfaces, index);

  /* Make sure every field is initiated (or don't skip the clib_memset()) */
  REPLY_MACRO_DETAILS4 (
    VL_API_NAT44_ED_OUTPUT_INTERFACE_DETAILS, rp, context, ({
      rmp->sw_if_index = i->sw_if_index;

      /* Endian hack until apigen registers _details
       * endian functions */
      vl_api_nat44_ed_output_interface_details_t_endian (rmp);
      rmp->_vl_msg_id = htons (rmp->_vl_msg_id);
      rmp->context = htonl (rmp->context);
    }));
}

static void
vl_api_nat44_ed_output_interface_get_t_handler (
  vl_api_nat44_ed_output_interface_get_t *mp)
{
  vl_api_nat44_ed_output_interface_get_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  i32 rv = 0;

  if (pool_elts (sm->output_feature_interfaces) == 0)
    {
      REPLY_MACRO (VL_API_NAT44_ED_OUTPUT_INTERFACE_GET_REPLY);
      return;
    }

  REPLY_AND_DETAILS_MACRO (
    VL_API_NAT44_ED_OUTPUT_INTERFACE_GET_REPLY, sm->output_feature_interfaces,
    ({ send_nat44_ed_output_interface_details (cursor, rp, mp->context); }));
}

static void
  vl_api_nat44_add_del_static_mapping_t_handler
  (vl_api_nat44_add_del_static_mapping_t * mp)
{
  vl_api_nat44_add_del_static_mapping_reply_t *rmp;

  snat_main_t *sm = &snat_main;
  int rv = 0;

  ip4_address_t l_addr, e_addr, pool_addr = { 0 };
  u32 sw_if_index, flags = 0, vrf_id;
  u16 l_port = 0, e_port = 0;
  ip_protocol_t proto = 0;
  u8 *tag = 0;

  memcpy (&l_addr.as_u8, mp->local_ip_address, 4);

  if (mp->flags & NAT_API_IS_ADDR_ONLY)
    {
      flags |= NAT_SM_FLAG_ADDR_ONLY;
    }
  else
    {
      l_port = mp->local_port;
      e_port = mp->external_port;
      proto = mp->protocol;
    }

  if (mp->flags & NAT_API_IS_TWICE_NAT)
    {
      flags |= NAT_SM_FLAG_TWICE_NAT;
    }

  if (mp->flags & NAT_API_IS_SELF_TWICE_NAT)
    {
      flags |= NAT_SM_FLAG_SELF_TWICE_NAT;
    }

  if (mp->flags & NAT_API_IS_OUT2IN_ONLY)
    {
      flags |= NAT_SM_FLAG_OUT2IN_ONLY;
    }

  sw_if_index = clib_net_to_host_u32 (mp->external_sw_if_index);
  if (sw_if_index != ~0)
    {
      flags |= NAT_SM_FLAG_SWITCH_ADDRESS;
    }
  else
    {
      memcpy (&e_addr.as_u8, mp->external_ip_address, 4);
    }

  vrf_id = clib_net_to_host_u32 (mp->vrf_id);

  if (mp->is_add)
    {
      mp->tag[sizeof (mp->tag) - 1] = 0;
      tag = format (0, "%s", mp->tag);
      vec_terminate_c_string (tag);

      rv = nat44_ed_add_static_mapping (l_addr, e_addr, l_port, e_port, proto,
					vrf_id, sw_if_index, flags, pool_addr,
					tag);
      vec_free (tag);
    }
  else
    {
      rv = nat44_ed_del_static_mapping (l_addr, e_addr, l_port, e_port, proto,
					vrf_id, sw_if_index, flags);
    }
  REPLY_MACRO (VL_API_NAT44_ADD_DEL_STATIC_MAPPING_REPLY);
}

static void
  vl_api_nat44_add_del_static_mapping_v2_t_handler
  (vl_api_nat44_add_del_static_mapping_v2_t * mp)
{
  vl_api_nat44_add_del_static_mapping_v2_reply_t *rmp;

  snat_main_t *sm = &snat_main;
  int rv = 0;

  ip4_address_t l_addr, e_addr, pool_addr;
  u32 sw_if_index, flags = 0, vrf_id;
  u16 l_port = 0, e_port = 0;
  ip_protocol_t proto;
  u8 *tag = 0;

  memcpy (&l_addr.as_u8, mp->local_ip_address, 4);
  memcpy (&pool_addr.as_u8, mp->pool_ip_address, 4);

  if (pool_addr.as_u32 != 0)
    {
      flags |= NAT_SM_FLAG_EXACT_ADDRESS;
    }

  if (mp->flags & NAT_API_IS_ADDR_ONLY)
    {
      flags |= NAT_SM_FLAG_ADDR_ONLY;
    }
  else
    {
      l_port = mp->local_port;
      e_port = mp->external_port;
    }

  if (mp->flags & NAT_API_IS_TWICE_NAT)
    {
      flags |= NAT_SM_FLAG_TWICE_NAT;
    }

  if (mp->flags & NAT_API_IS_SELF_TWICE_NAT)
    {
      flags |= NAT_SM_FLAG_SELF_TWICE_NAT;
    }

  if (mp->flags & NAT_API_IS_OUT2IN_ONLY)
    {
      flags |= NAT_SM_FLAG_OUT2IN_ONLY;
    }

  sw_if_index = clib_net_to_host_u32 (mp->external_sw_if_index);
  if (sw_if_index)
    {
      flags |= NAT_SM_FLAG_SWITCH_ADDRESS;
    }
  else
    {
      memcpy (&e_addr.as_u8, mp->external_ip_address, 4);
    }

  proto = mp->protocol;
  vrf_id = clib_net_to_host_u32 (mp->vrf_id);

  if (mp->is_add)
    {
      mp->tag[sizeof (mp->tag) - 1] = 0;
      tag = format (0, "%s", mp->tag);
      vec_terminate_c_string (tag);

      rv = nat44_ed_add_static_mapping (l_addr, e_addr, l_port, e_port, proto,
					vrf_id, sw_if_index, flags, pool_addr,
					tag);
      vec_free (tag);
    }
  else
    {
      rv = nat44_ed_del_static_mapping (l_addr, e_addr, l_port, e_port, proto,
					vrf_id, sw_if_index, flags);
    }
  REPLY_MACRO (VL_API_NAT44_ADD_DEL_STATIC_MAPPING_V2_REPLY);
}

static void
send_nat44_static_mapping_details (snat_static_mapping_t * m,
				   vl_api_registration_t * reg, u32 context)
{
  vl_api_nat44_static_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;
  u32 len = sizeof (*rmp);

  rmp = vl_msg_api_alloc (len);
  clib_memset (rmp, 0, len);
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_STATIC_MAPPING_DETAILS + sm->msg_id_base);

  clib_memcpy (rmp->local_ip_address, &(m->local_addr), 4);
  clib_memcpy (rmp->external_ip_address, &(m->external_addr), 4);
  rmp->external_sw_if_index = ~0;
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->context = context;

  // convert these in new api

  if (is_sm_self_twice_nat (m->flags))
    {
      rmp->flags |= NAT_API_IS_SELF_TWICE_NAT;
    }

  if (is_sm_out2in_only (m->flags))
    {
      rmp->flags |= NAT_API_IS_OUT2IN_ONLY;
    }

  if (is_sm_twice_nat (m->flags))
    {
      rmp->flags |= NAT_API_IS_TWICE_NAT;
    }

  if (is_sm_addr_only (m->flags))
    {
      rmp->flags |= NAT_API_IS_ADDR_ONLY;
    }
  else
    {
      rmp->protocol = m->proto;
      rmp->external_port = m->external_port;
      rmp->local_port = m->local_port;
    }

  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_nat44_static_map_resolve_details (snat_static_mapping_resolve_t *m,
				       vl_api_registration_t *reg, u32 context)
{
  vl_api_nat44_static_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_STATIC_MAPPING_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->local_ip_address, &(m->l_addr), 4);
  rmp->external_sw_if_index = htonl (m->sw_if_index);
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->context = context;

  if (is_sm_twice_nat (m->flags))
    {
      rmp->flags |= NAT_API_IS_TWICE_NAT;
    }

  if (is_sm_addr_only (m->flags))
    {
      rmp->flags |= NAT_API_IS_ADDR_ONLY;
    }
  else
    {
      rmp->protocol = m->proto;
      rmp->external_port = m->e_port;
      rmp->local_port = m->l_port;
    }

  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_static_mapping_dump_t_handler (vl_api_nat44_static_mapping_dump_t
					    * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  snat_static_mapping_resolve_t *rp;
  int j;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (m, sm->static_mappings)
   {
     if (!is_sm_identity_nat (m->flags) && !is_sm_lb (m->flags))
       send_nat44_static_mapping_details (m, reg, mp->context);
  }

  for (j = 0; j < vec_len (sm->sm_to_resolve); j++)
    {
      rp = sm->sm_to_resolve + j;
      if (!is_sm_identity_nat (rp->flags))
	send_nat44_static_map_resolve_details (rp, reg, mp->context);
    }
}

static void
  vl_api_nat44_add_del_identity_mapping_t_handler
  (vl_api_nat44_add_del_identity_mapping_t * mp)
{
  vl_api_nat44_add_del_identity_mapping_reply_t *rmp;

  snat_main_t *sm = &snat_main;
  int rv = 0;

  ip4_address_t addr, pool_addr = { 0 };
  u32 sw_if_index, flags, vrf_id;
  ip_protocol_t proto = 0;
  u16 port = 0;
  u8 *tag = 0;

  flags = NAT_SM_FLAG_IDENTITY_NAT;

  if (mp->flags & NAT_API_IS_ADDR_ONLY)
    {
      flags |= NAT_SM_FLAG_ADDR_ONLY;
    }
  else
    {
      port = mp->port;
      proto = mp->protocol;
    }

  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  if (sw_if_index != ~0)
    {
      flags |= NAT_SM_FLAG_SWITCH_ADDRESS;
    }
  else
    {
      memcpy (&addr.as_u8, mp->ip_address, 4);
    }

  vrf_id = clib_net_to_host_u32 (mp->vrf_id);

  if (mp->is_add)
    {
      mp->tag[sizeof (mp->tag) - 1] = 0;
      tag = format (0, "%s", mp->tag);
      vec_terminate_c_string (tag);

      rv = nat44_ed_add_static_mapping (addr, addr, port, port, proto, vrf_id,
					sw_if_index, flags, pool_addr, tag);
      vec_free (tag);
    }
  else
    {
      rv = nat44_ed_del_static_mapping (addr, addr, port, port, proto, vrf_id,
					sw_if_index, flags);
    }
  REPLY_MACRO (VL_API_NAT44_ADD_DEL_IDENTITY_MAPPING_REPLY);
}

static void
send_nat44_identity_mapping_details (snat_static_mapping_t * m, int index,
				     vl_api_registration_t * reg, u32 context)
{
  vl_api_nat44_identity_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat44_lb_addr_port_t *local = pool_elt_at_index (m->locals, index);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_IDENTITY_MAPPING_DETAILS + sm->msg_id_base);

  if (is_sm_addr_only (m->flags))
    rmp->flags |= NAT_API_IS_ADDR_ONLY;

  clib_memcpy (rmp->ip_address, &(m->local_addr), 4);
  rmp->port = m->local_port;
  rmp->sw_if_index = ~0;
  rmp->vrf_id = htonl (local->vrf_id);
  rmp->protocol = m->proto;
  rmp->context = context;
  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_nat44_identity_map_resolve_details (snat_static_mapping_resolve_t *m,
					 vl_api_registration_t *reg,
					 u32 context)
{
  vl_api_nat44_identity_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_IDENTITY_MAPPING_DETAILS + sm->msg_id_base);

  if (is_sm_addr_only (m->flags))
    rmp->flags = (vl_api_nat_config_flags_t) NAT_API_IS_ADDR_ONLY;

  rmp->port = m->l_port;
  rmp->sw_if_index = htonl (m->sw_if_index);
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->protocol = m->proto;
  rmp->context = context;
  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
  vl_api_nat44_identity_mapping_dump_t_handler
  (vl_api_nat44_identity_mapping_dump_t * mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;
  snat_static_mapping_resolve_t *rp;
  int j;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (m, sm->static_mappings)
    {
      if (is_sm_identity_nat (m->flags) && !is_sm_lb (m->flags))
	{
	  pool_foreach_index (j, m->locals)
	    {
	      send_nat44_identity_mapping_details (m, j, reg, mp->context);
	    }
	}
    }

  for (j = 0; j < vec_len (sm->sm_to_resolve); j++)
    {
      rp = sm->sm_to_resolve + j;
      if (is_sm_identity_nat (rp->flags))
	send_nat44_identity_map_resolve_details (rp, reg, mp->context);
    }
}

static void
  vl_api_nat44_add_del_interface_addr_t_handler
  (vl_api_nat44_add_del_interface_addr_t * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_add_del_interface_addr_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u8 twice_nat;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  twice_nat = mp->flags & NAT_API_IS_TWICE_NAT;

  if (mp->is_add)
    {
      rv = nat44_ed_add_interface_address (sw_if_index, twice_nat);
    }
  else
    {
      rv = nat44_ed_del_interface_address (sw_if_index, twice_nat);
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_NAT44_ADD_DEL_INTERFACE_ADDR_REPLY);
}

static void
send_nat44_interface_addr_details (u32 sw_if_index,
				   vl_api_registration_t * reg, u32 context,
				   u8 twice_nat)
{
  vl_api_nat44_interface_addr_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_INTERFACE_ADDR_DETAILS + sm->msg_id_base);
  rmp->sw_if_index = ntohl (sw_if_index);

  if (twice_nat)
    rmp->flags = (vl_api_nat_config_flags_t) NAT_API_IS_TWICE_NAT;
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_interface_addr_dump_t_handler (vl_api_nat44_interface_addr_dump_t
					    * mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_registration_t *reg;
  snat_address_resolve_t *ap;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (ap, sm->addr_to_resolve)
    {
      send_nat44_interface_addr_details (ap->sw_if_index, reg, mp->context,
					 ap->is_twice_nat);
    }
}

static nat44_lb_addr_port_t *
unformat_nat44_lb_addr_port (vl_api_nat44_lb_addr_port_t *addr_port_pairs,
			     u32 addr_port_pair_num)
{
  u8 i;
  nat44_lb_addr_port_t *lb_addr_port_pairs = 0, lb_addr_port;
  vl_api_nat44_lb_addr_port_t *ap;

  for (i = 0; i < addr_port_pair_num; i++)
    {
      ap = &addr_port_pairs[i];
      clib_memset (&lb_addr_port, 0, sizeof (lb_addr_port));
      clib_memcpy (&lb_addr_port.addr, ap->addr, 4);
      lb_addr_port.port = ap->port;
      lb_addr_port.probability = ap->probability;
      lb_addr_port.vrf_id = clib_net_to_host_u32 (ap->vrf_id);
      vec_add1 (lb_addr_port_pairs, lb_addr_port);
    }

  return lb_addr_port_pairs;
}

static void
vl_api_nat44_add_del_lb_static_mapping_t_handler (
  vl_api_nat44_add_del_lb_static_mapping_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_add_del_lb_static_mapping_reply_t *rmp;
  nat44_lb_addr_port_t *locals = 0;
  ip4_address_t e_addr;
  ip_protocol_t proto;
  u32 flags = 0;
  u8 *tag = 0;
  int rv = 0;

  locals = unformat_nat44_lb_addr_port (mp->locals,
					clib_net_to_host_u32 (mp->local_num));
  clib_memcpy (&e_addr, mp->external_addr, 4);
  proto = mp->protocol;

  if (mp->flags & NAT_API_IS_TWICE_NAT)
    {
      flags |= NAT_SM_FLAG_TWICE_NAT;
    }
  else if (mp->flags & NAT_API_IS_SELF_TWICE_NAT)
    {
      flags |= NAT_SM_FLAG_SELF_TWICE_NAT;
    }

  if (mp->flags & NAT_API_IS_OUT2IN_ONLY)
    {
      flags |= NAT_SM_FLAG_OUT2IN_ONLY;
    }

  if (mp->is_add)
    {
      mp->tag[sizeof (mp->tag) - 1] = 0;
      tag = format (0, "%s", mp->tag);
      vec_terminate_c_string (tag);

      rv = nat44_ed_add_lb_static_mapping (
	e_addr, mp->external_port, proto, locals, flags, tag,
	clib_net_to_host_u32 (mp->affinity));
    }
  else
    {
      rv = nat44_ed_del_lb_static_mapping (e_addr, mp->external_port, proto,
					   flags);
    }

  vec_free (locals);
  vec_free (tag);
  REPLY_MACRO (VL_API_NAT44_ADD_DEL_LB_STATIC_MAPPING_REPLY);
}

static void
vl_api_nat44_lb_static_mapping_add_del_local_t_handler (
  vl_api_nat44_lb_static_mapping_add_del_local_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_lb_static_mapping_add_del_local_reply_t *rmp;
  int rv = 0;
  ip4_address_t e_addr, l_addr;
  ip_protocol_t proto;

  clib_memcpy (&e_addr, mp->external_addr, 4);
  clib_memcpy (&l_addr, mp->local.addr, 4);
  proto = mp->protocol;

  rv = nat44_ed_add_del_lb_static_mapping_local (
    e_addr, mp->external_port, l_addr, mp->local.port, proto,
    clib_net_to_host_u32 (mp->local.vrf_id), mp->local.probability,
    mp->is_add);

  REPLY_MACRO (VL_API_NAT44_LB_STATIC_MAPPING_ADD_DEL_LOCAL_REPLY);
}

static void
send_nat44_lb_static_mapping_details (snat_static_mapping_t *m,
				      vl_api_registration_t *reg, u32 context)
{
  vl_api_nat44_lb_static_mapping_details_t *rmp;
  snat_main_t *sm = &snat_main;
  nat44_lb_addr_port_t *ap;
  vl_api_nat44_lb_addr_port_t *locals;
  u32 local_num = 0;

  rmp = vl_msg_api_alloc (
    sizeof (*rmp) + (pool_elts (m->locals) * sizeof (nat44_lb_addr_port_t)));

  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_LB_STATIC_MAPPING_DETAILS + sm->msg_id_base);

  clib_memcpy (rmp->external_addr, &(m->external_addr), 4);
  rmp->external_port = m->external_port;
  rmp->protocol = m->proto;
  rmp->context = context;

  if (is_sm_self_twice_nat (m->flags))
    {
      rmp->flags |= NAT_API_IS_SELF_TWICE_NAT;
    }

  if (is_sm_out2in_only (m->flags))
    {
      rmp->flags |= NAT_API_IS_OUT2IN_ONLY;
    }

  if (is_sm_twice_nat (m->flags))
    {
      rmp->flags |= NAT_API_IS_TWICE_NAT;
    }

  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  locals = (vl_api_nat44_lb_addr_port_t *) rmp->locals;
  pool_foreach (ap, m->locals)
    {
      clib_memcpy (locals->addr, &(ap->addr), 4);
      locals->port = ap->port;
      locals->probability = ap->probability;
      locals->vrf_id = ntohl (ap->vrf_id);
      locals++;
      local_num++;
    }
  rmp->local_num = ntohl (local_num);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_lb_static_mapping_dump_t_handler (
  vl_api_nat44_lb_static_mapping_dump_t *mp)
{
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_static_mapping_t *m;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (m, sm->static_mappings)
    {
      if (is_sm_lb (m->flags))
	send_nat44_lb_static_mapping_details (m, reg, mp->context);
    }
}

static void
vl_api_nat44_del_session_t_handler (vl_api_nat44_del_session_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_del_session_reply_t *rmp;
  ip4_address_t addr, eh_addr;
  u16 port, eh_port;
  u32 vrf_id;
  int rv = 0;
  u8 is_in;

  memcpy (&addr.as_u8, mp->address, 4);
  port = mp->port;
  vrf_id = clib_net_to_host_u32 (mp->vrf_id);
  memcpy (&eh_addr.as_u8, mp->ext_host_address, 4);
  eh_port = mp->ext_host_port;

  is_in = mp->flags & NAT_API_IS_INSIDE;

  rv = nat44_ed_del_session (sm, &addr, port, &eh_addr, eh_port, mp->protocol,
			     vrf_id, is_in);

  REPLY_MACRO (VL_API_NAT44_DEL_SESSION_REPLY);
}

static void
vl_api_nat44_forwarding_enable_disable_t_handler (
  vl_api_nat44_forwarding_enable_disable_t *mp)
{
  vl_api_nat44_forwarding_enable_disable_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  int rv = 0;
  nat44_ed_forwarding_enable_disable (mp->enable);
  REPLY_MACRO (VL_API_NAT44_FORWARDING_ENABLE_DISABLE_REPLY);
}

static void
vl_api_nat44_show_running_config_t_handler (
  vl_api_nat44_show_running_config_t *mp)
{
  vl_api_nat44_show_running_config_reply_t *rmp;
  snat_main_t *sm = &snat_main;
  nat44_config_t *rc = &sm->rconfig;
  int rv = 0;

  REPLY_MACRO2_ZERO (
    VL_API_NAT44_SHOW_RUNNING_CONFIG_REPLY, ({
      rmp->inside_vrf = htonl (rc->inside_vrf);
      rmp->outside_vrf = htonl (rc->outside_vrf);

      rmp->sessions = htonl (rc->sessions);
      rmp->translation_buckets = htonl (sm->translation_buckets);

      // OBSOLETE
      rmp->users = 0;
      rmp->user_buckets = 0;
      rmp->user_sessions = 0;

      rmp->timeouts.udp = htonl (sm->timeouts.udp);
      rmp->timeouts.tcp_established = htonl (sm->timeouts.tcp.established);
      rmp->timeouts.tcp_transitory = htonl (sm->timeouts.tcp.transitory);
      rmp->timeouts.icmp = htonl (sm->timeouts.icmp);

      rmp->forwarding_enabled = sm->forwarding_enabled == 1;
      // consider how to split functionality between subplugins
      rmp->ipfix_logging_enabled = nat_ipfix_logging_enabled ();
      rmp->flags |= NAT44_IS_ENDPOINT_DEPENDENT;
    }));
}

static void
vl_api_nat44_ed_add_del_vrf_table_t_handler (
  vl_api_nat44_ed_add_del_vrf_table_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_ed_add_del_vrf_table_reply_t *rmp;
  int rv = nat44_ed_add_del_vrf_table (clib_net_to_host_u32 (mp->table_vrf_id),
				       mp->is_add);
  REPLY_MACRO (VL_API_NAT44_ED_ADD_DEL_VRF_TABLE);
}

static void
vl_api_nat44_ed_add_del_vrf_route_t_handler (
  vl_api_nat44_ed_add_del_vrf_route_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_ed_add_del_vrf_route_reply_t *rmp;
  int rv =
    nat44_ed_add_del_vrf_route (clib_net_to_host_u32 (mp->table_vrf_id),
				clib_net_to_host_u32 (mp->vrf_id), mp->is_add);
  REPLY_MACRO (VL_API_NAT44_ED_ADD_DEL_VRF_ROUTE);
}

static void
nat44_ed_vrf_tables_send_details (vl_api_registration_t *rp, u32 context,
				  vrf_table_t *t)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_ed_vrf_tables_details_t *mp;

  u32 *vrf_ids = 0;
  vrf_route_t *r;

  mp = vl_msg_api_alloc_zero (sizeof (*mp) +
			      sizeof (mp->vrf_ids[0]) * vec_len (t->routes));
  mp->_vl_msg_id =
    ntohs (VL_API_NAT44_ED_VRF_TABLES_DETAILS + sm->msg_id_base);
  mp->context = context;
  mp->n_vrf_ids = clib_host_to_net_u32 (vec_len (t->routes));

  pool_foreach (r, t->routes)
    {
      vec_add1 (vrf_ids, r->vrf_id);
    }

  // copy the records
  clib_memcpy (mp->vrf_ids, vrf_ids,
	       sizeof (mp->vrf_ids[0]) * vec_len (t->routes));

  vec_free (vrf_ids);

  // send the message
  vl_api_send_msg (rp, (u8 *) mp);
}

static void
vl_api_nat44_ed_vrf_tables_dump_t_handler (
  vl_api_nat44_ed_vrf_tables_dump_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_registration_t *rp;
  vrf_table_t *t;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  pool_foreach (t, sm->vrf_tables)
    {
      nat44_ed_vrf_tables_send_details (rp, mp->context, t);
    }
}

/* user (internal host) key */
typedef struct
{
  union
  {
    struct
    {
      ip4_address_t addr;
      u32 fib_index;
    };
    u64 as_u64;
  };
} snat_user_key_t;

typedef struct
{
  ip4_address_t addr;
  u32 fib_index;
  u32 nsessions;
  u32 nstaticsessions;
} snat_user_t;

typedef struct
{
  u32 user_buckets;
  snat_user_t *users;
  clib_bihash_8_8_t user_hash;
} user_create_helper_t;

static void
send_nat44_user_details (snat_user_t *u, vl_api_registration_t *reg,
			 u32 context)
{
  vl_api_nat44_user_details_t *rmp;
  snat_main_t *sm = &snat_main;
  ip4_main_t *im = &ip4_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT44_USER_DETAILS + sm->msg_id_base);

  if (!pool_is_free_index (im->fibs, u->fib_index))
    {
      fib_table_t *fib = fib_table_get (u->fib_index, FIB_PROTOCOL_IP4);
      rmp->vrf_id = ntohl (fib->ft_table_id);
    }

  clib_memcpy (rmp->ip_address, &(u->addr), 4);
  rmp->nsessions = ntohl (u->nsessions);
  rmp->nstaticsessions = ntohl (u->nstaticsessions);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
nat_ed_user_create_helper (user_create_helper_t *uch, snat_session_t *s)
{
  snat_user_key_t k;
  k.addr = s->in2out.addr;
  k.fib_index = s->in2out.fib_index;
  clib_bihash_kv_8_8_t key, value;
  key.key = k.as_u64;
  snat_user_t *u;

  if (clib_bihash_search_8_8 (&uch->user_hash, &key, &value))
    {
      pool_get (uch->users, u);
      u->addr = k.addr;
      u->fib_index = k.fib_index;
      u->nsessions = 0;
      u->nstaticsessions = 0;
      key.value = u - uch->users;
      clib_bihash_add_del_8_8 (&uch->user_hash, &key, 1);
    }
  else
    {
      u = pool_elt_at_index (uch->users, value.value);
    }
  if (nat44_ed_is_session_static (s))
    {
      ++u->nstaticsessions;
    }
  else
    {
      ++u->nsessions;
    }
}

u8 *
format_user_kvp (u8 *s, va_list *args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);
  snat_user_key_t k;
  k.as_u64 = v->key;
  s = format (s, "%U fib %d user-index %llu", format_ip4_address, &k.addr,
	      k.fib_index, v->value);
  return s;
}

static void
nat_ed_users_create (snat_main_per_thread_data_t *tsm,
		     user_create_helper_t *uch)
{
  snat_session_t *s;
  clib_bihash_init_8_8 (&uch->user_hash, "users", uch->user_buckets, 0);
  clib_bihash_set_kvp_format_fn_8_8 (&uch->user_hash, format_user_kvp);
  pool_foreach (s, tsm->sessions)
    {
      nat_ed_user_create_helper (uch, s);
    }
}

static void
nat_ed_users_destroy (user_create_helper_t *uch)
{
  pool_free (uch->users);
  clib_bihash_free_8_8 (&uch->user_hash);
}

static void
vl_api_nat44_user_dump_t_handler (vl_api_nat44_user_dump_t * mp)
{
  user_create_helper_t uch;
  vl_api_registration_t *reg;
  snat_main_t *sm = &snat_main;
  snat_main_per_thread_data_t *tsm;
  snat_user_t *u;

  clib_memset (&uch, 0, sizeof (uch));

  uch.user_buckets = nat_calc_bihash_buckets (1024);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (tsm, sm->per_thread_data)
    {
      nat_ed_users_create (tsm, &uch);
      pool_foreach (u, uch.users)
	{
	  send_nat44_user_details (u, reg, mp->context);
	}
      nat_ed_users_destroy (&uch);
    }
}

static void
send_nat44_user_session_details (snat_session_t * s,
				 vl_api_registration_t * reg, u32 context)
{
  vl_api_nat44_user_session_details_t *rmp;
  snat_main_t *sm = &snat_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_USER_SESSION_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->outside_ip_address, (&s->out2in.addr), 4);
  clib_memcpy (rmp->inside_ip_address, (&s->in2out.addr), 4);

  if (nat44_ed_is_session_static (s))
    rmp->flags |= NAT_API_IS_STATIC;

  if (nat44_ed_is_twice_nat_session (s))
    rmp->flags |= NAT_API_IS_TWICE_NAT;

  rmp->flags |= NAT_API_IS_EXT_HOST_VALID;

  rmp->last_heard = clib_host_to_net_u64 ((u64) s->last_heard);
  rmp->total_bytes = clib_host_to_net_u64 (s->total_bytes);
  rmp->total_pkts = ntohl (s->total_pkts);
  rmp->context = context;
  rmp->outside_port = s->out2in.port;
  rmp->inside_port = s->in2out.port;
  rmp->protocol = clib_host_to_net_u16 (s->proto);
  clib_memcpy (rmp->ext_host_address, &s->ext_host_addr, 4);
  rmp->ext_host_port = s->ext_host_port;
  if (nat44_ed_is_twice_nat_session (s))
    {
      clib_memcpy (rmp->ext_host_nat_address, &s->ext_host_nat_addr, 4);
      rmp->ext_host_nat_port = s->ext_host_nat_port;
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_user_session_dump_t_handler (vl_api_nat44_user_session_dump_t *
					  mp)
{
  snat_main_per_thread_data_t *tsm;
  snat_main_t *sm = &snat_main;
  vl_api_registration_t *reg;
  snat_user_key_t ukey;
  snat_session_t *s;
  ip4_header_t ip;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  clib_memcpy (&ukey.addr, mp->ip_address, 4);
  ip.src_address.as_u32 = ukey.addr.as_u32;
  ukey.fib_index = fib_table_find (FIB_PROTOCOL_IP4, ntohl (mp->vrf_id));
  if (sm->num_workers > 1)
    tsm = vec_elt_at_index (
      sm->per_thread_data,
      nat44_ed_get_in2out_worker_index (0, &ip, ukey.fib_index, 0));
  else
    tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

      pool_foreach (s, tsm->sessions) {
        if (s->in2out.addr.as_u32 == ukey.addr.as_u32)
          {
            send_nat44_user_session_details (s, reg, mp->context);
          }
      }
}

static void
send_nat44_user_session_v2_details (snat_session_t *s,
				    vl_api_registration_t *reg, u32 context)
{
  vl_api_nat44_user_session_v2_details_t *rmp;
  snat_main_t *sm = &snat_main;
  vnet_main_t *vnm = vnet_get_main ();
  u64 now = vlib_time_now (vnm->vlib_main);
  u64 sess_timeout_time = 0;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_USER_SESSION_V2_DETAILS + sm->msg_id_base);
  clib_memcpy (rmp->outside_ip_address, (&s->out2in.addr), 4);
  clib_memcpy (rmp->inside_ip_address, (&s->in2out.addr), 4);

  if (nat44_ed_is_session_static (s))
    rmp->flags |= NAT_API_IS_STATIC;

  if (nat44_ed_is_twice_nat_session (s))
    rmp->flags |= NAT_API_IS_TWICE_NAT;

  rmp->flags |= NAT_API_IS_EXT_HOST_VALID;

  rmp->last_heard = clib_host_to_net_u64 ((u64) s->last_heard);
  rmp->total_bytes = clib_host_to_net_u64 (s->total_bytes);
  rmp->total_pkts = ntohl (s->total_pkts);
  rmp->context = context;
  rmp->outside_port = s->out2in.port;
  rmp->inside_port = s->in2out.port;
  rmp->protocol = clib_host_to_net_u16 (s->proto);
  clib_memcpy (rmp->ext_host_address, &s->ext_host_addr, 4);
  rmp->ext_host_port = s->ext_host_port;
  if (nat44_ed_is_twice_nat_session (s))
    {
      clib_memcpy (rmp->ext_host_nat_address, &s->ext_host_nat_addr, 4);
      rmp->ext_host_nat_port = s->ext_host_nat_port;
    }

  sess_timeout_time = s->last_heard + nat44_session_get_timeout (sm, s);
  rmp->is_timed_out = (now >= sess_timeout_time);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_user_session_v2_dump_t_handler (
  vl_api_nat44_user_session_v2_dump_t *mp)
{
  snat_main_per_thread_data_t *tsm;
  snat_main_t *sm = &snat_main;
  vl_api_registration_t *reg;
  snat_user_key_t ukey;
  snat_session_t *s;
  ip4_header_t ip;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  clib_memcpy (&ukey.addr, mp->ip_address, 4);
  ip.src_address.as_u32 = ukey.addr.as_u32;
  ukey.fib_index = fib_table_find (FIB_PROTOCOL_IP4, ntohl (mp->vrf_id));
  if (sm->num_workers > 1)
    tsm = vec_elt_at_index (
      sm->per_thread_data,
      nat44_ed_get_in2out_worker_index (0, &ip, ukey.fib_index, 0));
  else
    tsm = vec_elt_at_index (sm->per_thread_data, sm->num_workers);

  pool_foreach (s, tsm->sessions)
    {
      if (s->in2out.addr.as_u32 == ukey.addr.as_u32)
	{
	  send_nat44_user_session_v2_details (s, reg, mp->context);
	}
    }
}

// DEPRECATED, obsolete messages completely unsupported

static void
vl_api_nat_set_addr_and_port_alloc_alg_t_handler (
  vl_api_nat_set_addr_and_port_alloc_alg_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_set_addr_and_port_alloc_alg_reply_t *rmp;
  int rv = VNET_API_ERROR_UNSUPPORTED;
  REPLY_MACRO (VL_API_NAT_SET_ADDR_AND_PORT_ALLOC_ALG_REPLY);
}

static void
vl_api_nat_get_addr_and_port_alloc_alg_t_handler (
  vl_api_nat_get_addr_and_port_alloc_alg_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_get_addr_and_port_alloc_alg_reply_t *rmp;
  int rv = VNET_API_ERROR_UNSUPPORTED;
  REPLY_MACRO (VL_API_NAT_GET_ADDR_AND_PORT_ALLOC_ALG_REPLY);
}

static void
vl_api_nat_ha_set_listener_t_handler (vl_api_nat_ha_set_listener_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ha_set_listener_reply_t *rmp;
  int rv = VNET_API_ERROR_UNSUPPORTED;
  REPLY_MACRO (VL_API_NAT_HA_SET_LISTENER_REPLY);
}

static void
vl_api_nat_ha_get_listener_t_handler (vl_api_nat_ha_get_listener_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ha_get_listener_reply_t *rmp;
  int rv = VNET_API_ERROR_UNSUPPORTED;
  REPLY_MACRO (VL_API_NAT_HA_GET_LISTENER_REPLY);
}

static void
vl_api_nat_ha_set_failover_t_handler (vl_api_nat_ha_set_failover_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ha_set_failover_reply_t *rmp;
  int rv = VNET_API_ERROR_UNSUPPORTED;
  REPLY_MACRO (VL_API_NAT_HA_SET_FAILOVER_REPLY);
}

static void
vl_api_nat_ha_get_failover_t_handler (vl_api_nat_ha_get_failover_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ha_get_failover_reply_t *rmp;
  int rv = VNET_API_ERROR_UNSUPPORTED;
  REPLY_MACRO (VL_API_NAT_HA_GET_FAILOVER_REPLY);
}

static void
vl_api_nat_ha_flush_t_handler (vl_api_nat_ha_flush_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ha_flush_reply_t *rmp;
  int rv = VNET_API_ERROR_UNSUPPORTED;
  REPLY_MACRO (VL_API_NAT_HA_FLUSH_REPLY);
}

static void
vl_api_nat_ha_resync_t_handler (vl_api_nat_ha_resync_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat_ha_resync_reply_t *rmp;
  int rv = VNET_API_ERROR_UNSUPPORTED;
  REPLY_MACRO (VL_API_NAT_HA_RESYNC_REPLY);
}

static void
vl_api_nat44_del_user_t_handler (vl_api_nat44_del_user_t *mp)
{
  snat_main_t *sm = &snat_main;
  vl_api_nat44_del_user_reply_t *rmp;
  int rv = VNET_API_ERROR_UNSUPPORTED;
  REPLY_MACRO (VL_API_NAT44_DEL_USER_REPLY);
}

/* API definitions */
#include <vnet/format_fns.h>
#include <nat/nat44-ed/nat44_ed.api.c>

/* Set up the API message handling tables */
clib_error_t *
nat44_api_hookup (vlib_main_t * vm)
{
  snat_main_t *sm = &snat_main;
  sm->msg_id_base = setup_message_id_table ();
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
