/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * * Licensed under the Apache License, Version 2.0 (the "License");
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
 * @brief Deterministic NAT (CGN) plugin API implementation
 */

#include <vnet/ip/ip_types_api.h>
#include <nat/det44/det44.h>
#include <nat/det44/det44.api_enum.h>
#include <nat/det44/det44.api_types.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip.h>

#include <vlibmemory/api.h>

#define REPLY_MSG_ID_BASE dm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_det44_add_del_map_t_handler (vl_api_det44_add_del_map_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_det44_add_del_map_reply_t *rmp;
  int rv = 0;
  ip4_address_t in_addr, out_addr;
  clib_memcpy (&in_addr, mp->in_addr, 4);
  clib_memcpy (&out_addr, mp->out_addr, 4);
  rv = snat_det_add_map (&in_addr, mp->in_plen, &out_addr, mp->out_plen, ~0,
			 ~0, ~0, ~0, mp->is_add);
  REPLY_MACRO (VL_API_DET44_ADD_DEL_MAP_REPLY);
}

static void
vl_api_det44_forward_t_handler (vl_api_det44_forward_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_det44_forward_reply_t *rmp;
  int rv = 0;
  u16 lo_port = 0, hi_port = 0;
  snat_det_map_t *m;
  ip4_address_t in_addr, out_addr;

  out_addr.as_u32 = 0;
  clib_memcpy (&in_addr, mp->in_addr, 4);
  m = snat_det_map_by_user (&in_addr);
  if (!m)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }

  snat_det_forward (m, &in_addr, &out_addr, &lo_port);
  hi_port = lo_port + m->ports_per_host - 1;

send_reply:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_DET44_FORWARD_REPLY,
  ({
    rmp->out_port_lo = ntohs (lo_port);
    rmp->out_port_hi = ntohs (hi_port);
    clib_memcpy (rmp->out_addr, &out_addr, 4);
  }))
  /* *INDENT-ON* */
}

static void
vl_api_det44_reverse_t_handler (vl_api_det44_reverse_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_det44_reverse_reply_t *rmp;
  int rv = 0;
  ip4_address_t out_addr, in_addr;
  snat_det_map_t *m;

  in_addr.as_u32 = 0;
  clib_memcpy (&out_addr, mp->out_addr, 4);
  m = snat_det_map_by_out (&out_addr);
  if (!m)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }

  snat_det_reverse (m, &out_addr, htons (mp->out_port), &in_addr);

send_reply:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_DET44_REVERSE_REPLY,
  ({
    clib_memcpy (rmp->in_addr, &in_addr, 4);
  }))
  /* *INDENT-ON* */
}

static void
sent_det44_map_details (snat_det_map_t * m, vl_api_registration_t * reg,
			u32 context)
{
  det44_main_t *dm = &det44_main;
  vl_api_det44_map_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_DET44_MAP_DETAILS + dm->msg_id_base);
  clib_memcpy (rmp->in_addr, &m->in_addr, 4);
  rmp->in_plen = m->in_plen;
  clib_memcpy (rmp->out_addr, &m->out_addr, 4);
  rmp->out_plen = m->out_plen;
  rmp->sharing_ratio = htonl (m->sharing_ratio);
  rmp->ports_per_host = htons (m->ports_per_host);
  rmp->ses_num = htonl (m->ses_num);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_det44_map_dump_t_handler (vl_api_det44_map_dump_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_registration_t *reg;
  snat_det_map_t *m;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  vec_foreach(m, dm->det_maps)
    sent_det44_map_details(m, reg, mp->context);
  /* *INDENT-ON* */
}

static void
vl_api_det44_close_session_out_t_handler (vl_api_det44_close_session_out_t
					  * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_det44_close_session_out_reply_t *rmp;
  ip4_address_t out_addr, ext_addr, in_addr;
  snat_det_out_key_t key;
  snat_det_map_t *m;
  int rv = 0;

  clib_memcpy (&out_addr, mp->out_addr, 4);
  clib_memcpy (&ext_addr, mp->ext_addr, 4);

  m = snat_det_map_by_out (&out_addr);
  if (!m)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }
  snat_det_reverse (m, &ext_addr, ntohs (mp->out_port), &in_addr);
  key.ext_host_addr = ext_addr;
  key.ext_host_port = mp->ext_port;
  key.out_port = mp->out_port;

  u32 count = snat_det_close_ses_by_out (m, &in_addr, key.as_u64);
  if (0 == count)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }

send_reply:
  REPLY_MACRO (VL_API_DET44_CLOSE_SESSION_OUT_REPLY);
}

static void
vl_api_det44_close_session_in_t_handler (vl_api_det44_close_session_in_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_det44_close_session_in_reply_t *rmp;
  ip4_address_t in_addr, ext_addr;
  snat_det_out_key_t key;
  snat_det_map_t *m;
  int rv = 0;

  clib_memcpy (&in_addr, mp->in_addr, 4);
  clib_memcpy (&ext_addr, mp->ext_addr, 4);

  m = snat_det_map_by_user (&in_addr);
  if (!m)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }
  key.ext_host_addr = ext_addr;
  key.ext_host_port = mp->ext_port;
  u32 count = snat_det_close_ses_by_in (m, &in_addr, mp->in_port, key);
  if (0 == count)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }

send_reply:
  REPLY_MACRO (VL_API_DET44_CLOSE_SESSION_OUT_REPLY);
}

static void
send_det44_session_details (snat_det_session_t * s,
			    vl_api_registration_t * reg, u32 context)
{
  det44_main_t *dm = &det44_main;
  vl_api_det44_session_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_DET44_SESSION_DETAILS + dm->msg_id_base);
  rmp->in_port = s->in_port;
  clib_memcpy (rmp->ext_addr, &s->out.ext_host_addr, 4);
  rmp->ext_port = s->out.ext_host_port;
  rmp->out_port = s->out.out_port;
  rmp->state = s->state;
  rmp->expire = ntohl (s->expire);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_det44_session_dump_t_handler (vl_api_det44_session_dump_t * mp)
{
  vl_api_registration_t *reg;
  ip4_address_t user_addr;
  snat_det_map_t *m;
  snat_det_session_t *s, empty_ses;
  u16 i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  clib_memset (&empty_ses, 0, sizeof (empty_ses));
  clib_memcpy (&user_addr, mp->user_addr, 4);
  m = snat_det_map_by_user (&user_addr);
  if (!m)
    return;

  s = m->sessions +
      snat_det_user_ses_offset (m->ses_per_user, &user_addr, m->in_plen);
  for (i = 0; i < DET44_SES_PER_USER; i++)
    {
      if (s->out.as_u64)
	send_det44_session_details (s, reg, mp->context);
      s++;
    }
}

static void
  vl_api_det44_plugin_enable_disable_t_handler
  (vl_api_det44_plugin_enable_disable_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_det44_plugin_enable_disable_reply_t *rmp;
  det44_config_t c = { 0 };
  int rv = 0;
  if (mp->enable)
    {
      c.outside_vrf_id = ntohl (mp->outside_vrf);
      c.inside_vrf_id = ntohl (mp->inside_vrf);
      rv = det44_plugin_enable (c);
    }
  else
    {
      rv = det44_plugin_disable ();
    }
  REPLY_MACRO (VL_API_DET44_PLUGIN_ENABLE_DISABLE_REPLY);
}

static void
  vl_api_det44_interface_add_del_feature_t_handler
  (vl_api_det44_interface_add_del_feature_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_det44_interface_add_del_feature_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;
  VALIDATE_SW_IF_INDEX (mp);
  rv = det44_interface_add_del (sw_if_index, mp->is_inside, !mp->is_add);
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_DET44_INTERFACE_ADD_DEL_FEATURE_REPLY);
}

static void
det44_send_interface_details (det44_interface_t * i,
			      vl_api_registration_t * reg, u32 context)
{
  det44_main_t *dm = &det44_main;
  vl_api_det44_interface_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_DET44_INTERFACE_DETAILS + dm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);
  rmp->is_outside = det44_interface_is_outside (i);
  rmp->is_inside = det44_interface_is_inside (i);
  rmp->context = context;
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_det44_interface_dump_t_handler (vl_api_det44_interface_dump_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_registration_t *reg;
  det44_interface_t *i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (i, dm->interfaces)
   {
    det44_send_interface_details(i, reg, mp->context);
  }
  /* *INDENT-ON* */
}

static void
vl_api_det44_set_timeouts_t_handler (vl_api_det44_set_timeouts_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_det44_set_timeouts_reply_t *rmp;
  nat_timeouts_t timeouts;
  int rv = 0;
  timeouts.udp = ntohl (mp->udp);
  timeouts.tcp.established = ntohl (mp->tcp_established);
  timeouts.tcp.transitory = ntohl (mp->tcp_transitory);
  timeouts.icmp = ntohl (mp->icmp);
  rv = det44_set_timeouts (&timeouts);
  REPLY_MACRO (VL_API_DET44_SET_TIMEOUTS_REPLY);
}

static void
vl_api_det44_get_timeouts_t_handler (vl_api_det44_get_timeouts_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_det44_get_timeouts_reply_t *rmp;
  nat_timeouts_t timeouts;
  int rv = 0;
  timeouts = det44_get_timeouts ();
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_DET44_GET_TIMEOUTS_REPLY,
  ({
    rmp->udp = htonl (timeouts.udp);
    rmp->tcp_established = htonl (timeouts.tcp.established);
    rmp->tcp_transitory = htonl (timeouts.tcp.transitory);
    rmp->icmp = htonl (timeouts.icmp);
  }))
  /* *INDENT-ON* */
}

/*
 * Obsolete deterministic API to be removed
 */

static void
vl_api_nat_det_add_del_map_t_handler (vl_api_nat_det_add_del_map_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_nat_det_add_del_map_reply_t *rmp;
  int rv = 0;
  ip4_address_t in_addr, out_addr;

  clib_memcpy (&in_addr, mp->in_addr, 4);
  clib_memcpy (&out_addr, mp->out_addr, 4);
  rv = snat_det_add_map (&in_addr, mp->in_plen, &out_addr, mp->out_plen, ~0,
			 ~0, ~0, ~0, mp->is_add);
  REPLY_MACRO (VL_API_NAT_DET_ADD_DEL_MAP_REPLY);
}

static void
vl_api_nat_det_forward_t_handler (vl_api_nat_det_forward_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_nat_det_forward_reply_t *rmp;
  int rv = 0;
  u16 lo_port = 0, hi_port = 0;
  snat_det_map_t *m;
  ip4_address_t in_addr, out_addr;

  out_addr.as_u32 = 0;
  clib_memcpy (&in_addr, mp->in_addr, 4);
  m = snat_det_map_by_user (&in_addr);
  if (!m)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }

  snat_det_forward (m, &in_addr, &out_addr, &lo_port);
  hi_port = lo_port + m->ports_per_host - 1;

send_reply:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_DET_FORWARD_REPLY,
  ({
    rmp->out_port_lo = ntohs (lo_port);
    rmp->out_port_hi = ntohs (hi_port);
    clib_memcpy (rmp->out_addr, &out_addr, 4);
  }))
  /* *INDENT-ON* */
}

static void
vl_api_nat_det_reverse_t_handler (vl_api_nat_det_reverse_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_nat_det_reverse_reply_t *rmp;
  int rv = 0;
  ip4_address_t out_addr, in_addr;
  snat_det_map_t *m;

  in_addr.as_u32 = 0;
  clib_memcpy (&out_addr, mp->out_addr, 4);
  m = snat_det_map_by_out (&out_addr);
  if (!m)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }

  snat_det_reverse (m, &out_addr, htons (mp->out_port), &in_addr);

send_reply:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT_DET_REVERSE_REPLY,
  ({
    clib_memcpy (rmp->in_addr, &in_addr, 4);
  }))
  /* *INDENT-ON* */
}

static void
sent_nat_det_map_details (snat_det_map_t * m, vl_api_registration_t * reg,
			  u32 context)
{
  det44_main_t *dm = &det44_main;
  vl_api_nat_det_map_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT_DET_MAP_DETAILS + dm->msg_id_base);
  clib_memcpy (rmp->in_addr, &m->in_addr, 4);
  rmp->in_plen = m->in_plen;
  clib_memcpy (rmp->out_addr, &m->out_addr, 4);
  rmp->out_plen = m->out_plen;
  rmp->sharing_ratio = htonl (m->sharing_ratio);
  rmp->ports_per_host = htons (m->ports_per_host);
  rmp->ses_num = htonl (m->ses_num);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat_det_map_dump_t_handler (vl_api_nat_det_map_dump_t * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_registration_t *reg;
  snat_det_map_t *m;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  vec_foreach(m, dm->det_maps)
    sent_nat_det_map_details(m, reg, mp->context);
  /* *INDENT-ON* */
}

static void
vl_api_nat_det_close_session_out_t_handler (vl_api_nat_det_close_session_out_t
					    * mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_nat_det_close_session_out_reply_t *rmp;
  ip4_address_t out_addr, ext_addr, in_addr;
  snat_det_out_key_t key;
  snat_det_map_t *m;
  int rv = 0;

  clib_memcpy (&out_addr, mp->out_addr, 4);
  clib_memcpy (&ext_addr, mp->ext_addr, 4);

  m = snat_det_map_by_out (&out_addr);
  if (!m)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }
  snat_det_reverse (m, &ext_addr, ntohs (mp->out_port), &in_addr);
  key.ext_host_addr = ext_addr;
  key.ext_host_port = mp->ext_port;
  key.out_port = mp->out_port;
  u32 count = snat_det_close_ses_by_out (m, &in_addr, key.as_u64);
  if (0 == count)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }

send_reply:
  REPLY_MACRO (VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY);
}

static void
vl_api_nat_det_close_session_in_t_handler (vl_api_nat_det_close_session_in_t *
					   mp)
{
  det44_main_t *dm = &det44_main;
  vl_api_nat_det_close_session_in_reply_t *rmp;
  ip4_address_t in_addr, ext_addr;
  snat_det_out_key_t key;
  snat_det_map_t *m;
  int rv = 0;

  clib_memcpy (&in_addr, mp->in_addr, 4);
  clib_memcpy (&ext_addr, mp->ext_addr, 4);

  m = snat_det_map_by_user (&in_addr);
  if (!m)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }
  key.ext_host_addr = ext_addr;
  key.ext_host_port = mp->ext_port;
  u32 count = snat_det_close_ses_by_in (m, &in_addr, mp->in_port, key);
  if (0 == count)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto send_reply;
    }

send_reply:
  REPLY_MACRO (VL_API_NAT_DET_CLOSE_SESSION_OUT_REPLY);
}

static void
send_nat_det_session_details (snat_det_session_t * s,
			      vl_api_registration_t * reg, u32 context)
{
  det44_main_t *dm = &det44_main;
  vl_api_nat_det_session_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT_DET_SESSION_DETAILS + dm->msg_id_base);
  rmp->in_port = s->in_port;
  clib_memcpy (rmp->ext_addr, &s->out.ext_host_addr, 4);
  rmp->ext_port = s->out.ext_host_port;
  rmp->out_port = s->out.out_port;
  rmp->state = s->state;
  rmp->expire = ntohl (s->expire);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat_det_session_dump_t_handler (vl_api_nat_det_session_dump_t * mp)
{
  vl_api_registration_t *reg;
  ip4_address_t user_addr;
  snat_det_map_t *m;
  snat_det_session_t *s, empty_ses;
  u16 i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  clib_memset (&empty_ses, 0, sizeof (empty_ses));
  clib_memcpy (&user_addr, mp->user_addr, 4);
  m = snat_det_map_by_user (&user_addr);
  if (!m)
    return;

  s = m->sessions +
      snat_det_user_ses_offset (m->ses_per_user, &user_addr, m->in_plen);
  for (i = 0; i < m->ses_per_user; i++)
    {
      if (s->out.as_u64)
	send_nat_det_session_details (s, reg, mp->context);
      s++;
    }
}

/* API definitions */
#include <vnet/format_fns.h>
#include <nat/det44/det44.api.c>

/* Set up the API message handling tables */
clib_error_t *
det44_api_hookup (vlib_main_t * vm)
{
  det44_main_t *dm = &det44_main;
  dm->msg_id_base = setup_message_id_table ();
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
