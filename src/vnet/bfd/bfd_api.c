/*
 *------------------------------------------------------------------
 * bfd_api.c - bfd api
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
/**
 * @file
 * @brief BFD binary API implementation
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/bfd/bfd_main.h>
#include <vnet/bfd/bfd_api.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/format_fns.h>
#include <vnet/bfd/bfd.api_enum.h>
#include <vnet/bfd/bfd.api_types.h>

#define REPLY_MSG_ID_BASE bfd_main.msg_id_base
#include <vlibapi/api_helper_macros.h>


pub_sub_handler (bfd_events, BFD_EVENTS);

#define BFD_UDP_API_PARAM_COMMON_CODE                                         \
  ip46_address_t local_addr;                                                  \
  ip46_address_t peer_addr;                                                   \
  ip_address_decode(&mp->local_addr, &local_addr);                             \
  ip_address_decode(&mp->peer_addr, &peer_addr);

#define BFD_UDP_API_PARAM_IS_MH(mp)                                           \
  bfd_main.multihop_enabled && (mp->sw_if_index == ~0)

#define BFD_UDP_API_PARAM_FROM_MP(mp)                                         \
  BFD_UDP_API_PARAM_IS_MH (mp) ? true : false,                                \
    BFD_UDP_API_PARAM_IS_MH (mp) ? ~0 :                                       \
				   clib_net_to_host_u32 (mp->sw_if_index),    \
    &local_addr, &peer_addr

#define COND_VALIDATE_SW_IF_INDEX(mp)                                         \
  do                                                                          \
    {                                                                         \
      if (!(bfd_main.multihop_enabled && mp->sw_if_index == ~0))              \
	{                                                                     \
	  VALIDATE_SW_IF_INDEX (mp)                                           \
	}                                                                     \
    }                                                                         \
  while (0);

static void
vl_api_bfd_udp_add_t_handler (vl_api_bfd_udp_add_t * mp)
{
  vl_api_bfd_udp_add_reply_t *rmp;
  int rv;

  COND_VALIDATE_SW_IF_INDEX (mp);

  BFD_UDP_API_PARAM_COMMON_CODE;

  rv = bfd_udp_add_session (BFD_UDP_API_PARAM_FROM_MP (mp),
			    clib_net_to_host_u32 (mp->desired_min_tx),
			    clib_net_to_host_u32 (mp->required_min_rx),
			    mp->detect_mult, mp->is_authenticated,
			    clib_net_to_host_u32 (mp->conf_key_id),
			    mp->bfd_key_id);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_BFD_UDP_ADD_REPLY);
}

static void
vl_api_bfd_udp_upd_t_handler (vl_api_bfd_udp_add_t *mp)
{
  vl_api_bfd_udp_upd_reply_t *rmp;
  int rv;

  COND_VALIDATE_SW_IF_INDEX (mp);

  BFD_UDP_API_PARAM_COMMON_CODE;

  rv = bfd_udp_upd_session (
    BFD_UDP_API_PARAM_FROM_MP (mp), clib_net_to_host_u32 (mp->desired_min_tx),
    clib_net_to_host_u32 (mp->required_min_rx), mp->detect_mult,
    mp->is_authenticated, clib_net_to_host_u32 (mp->conf_key_id),
    mp->bfd_key_id);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO2 (VL_API_BFD_UDP_UPD_REPLY,
		({ rmp->stats_index = clib_host_to_net_u32 (0); }));
}

static void
vl_api_bfd_udp_mod_t_handler (vl_api_bfd_udp_mod_t * mp)
{
  vl_api_bfd_udp_mod_reply_t *rmp;
  int rv;

  COND_VALIDATE_SW_IF_INDEX (mp);

  BFD_UDP_API_PARAM_COMMON_CODE;

  rv = bfd_udp_mod_session (BFD_UDP_API_PARAM_FROM_MP (mp),
			    clib_net_to_host_u32 (mp->desired_min_tx),
			    clib_net_to_host_u32 (mp->required_min_rx),
			    mp->detect_mult);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_BFD_UDP_MOD_REPLY);
}

static void
vl_api_bfd_udp_del_t_handler (vl_api_bfd_udp_del_t * mp)
{
  vl_api_bfd_udp_del_reply_t *rmp;
  int rv;

  COND_VALIDATE_SW_IF_INDEX (mp);

  BFD_UDP_API_PARAM_COMMON_CODE;

  rv = bfd_udp_del_session (BFD_UDP_API_PARAM_FROM_MP (mp));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_BFD_UDP_DEL_REPLY);
}

void
send_bfd_udp_session_details (vl_api_registration_t * reg, u32 context,
			      bfd_session_t * bs)
{
  if (bs->transport != BFD_TRANSPORT_UDP4 &&
      bs->transport != BFD_TRANSPORT_UDP6)
    {
      return;
    }

  vl_api_bfd_udp_session_details_t *mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_BFD_UDP_SESSION_DETAILS);
  mp->context = context;
  mp->state = clib_host_to_net_u32 (bs->local_state);
  bfd_udp_session_t *bus = &bs->udp;
  bfd_udp_key_t *key = &bus->key;
  if (bs->hop_type == BFD_HOP_TYPE_MULTI)
    {
      mp->sw_if_index = ~0;
    }
  else
    {
      mp->sw_if_index = clib_host_to_net_u32 (key->sw_if_index);
    }
  if ((!bs->auth.is_delayed && bs->auth.curr_key) ||
      (bs->auth.is_delayed && bs->auth.next_key))
    {
      mp->is_authenticated = true;
    }
  if (bs->auth.is_delayed && bs->auth.next_key)
    {
      mp->bfd_key_id = bs->auth.next_bfd_key_id;
      mp->conf_key_id = clib_host_to_net_u32 (bs->auth.next_key->conf_key_id);
    }
  else if (!bs->auth.is_delayed && bs->auth.curr_key)
    {
      mp->bfd_key_id = bs->auth.curr_bfd_key_id;
      mp->conf_key_id = clib_host_to_net_u32 (bs->auth.curr_key->conf_key_id);
    }
  ip_address_encode (&key->local_addr, IP46_TYPE_ANY, &mp->local_addr);
  ip_address_encode (&key->peer_addr, IP46_TYPE_ANY, &mp->peer_addr);

  mp->required_min_rx =
    clib_host_to_net_u32 (bs->config_required_min_rx_usec);
  mp->desired_min_tx = clib_host_to_net_u32 (bs->config_desired_min_tx_usec);
  mp->detect_mult = bs->local_detect_mult;
  vl_api_send_msg (reg, (u8 *) mp);
}

void
send_bfd_udp_session_event (vl_api_registration_t *reg, u32 pid,
			    bfd_session_t *bs)
{
  if (bs->transport != BFD_TRANSPORT_UDP4 &&
      bs->transport != BFD_TRANSPORT_UDP6)
    {
      return;
    }

  vl_api_bfd_udp_session_event_t *mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_BFD_UDP_SESSION_EVENT);
  mp->pid = pid;
  mp->state = clib_host_to_net_u32 (bs->local_state);
  bfd_udp_session_t *bus = &bs->udp;
  bfd_udp_key_t *key = &bus->key;
  if (bs->hop_type == BFD_HOP_TYPE_MULTI)
    {
      mp->sw_if_index = ~0;
    }
  else
    {
      mp->sw_if_index = clib_host_to_net_u32 (key->sw_if_index);
    }
  if ((!bs->auth.is_delayed && bs->auth.curr_key) ||
      (bs->auth.is_delayed && bs->auth.next_key))
    {
      mp->is_authenticated = true;
    }
  if (bs->auth.is_delayed && bs->auth.next_key)
    {
      mp->bfd_key_id = bs->auth.next_bfd_key_id;
      mp->conf_key_id = clib_host_to_net_u32 (bs->auth.next_key->conf_key_id);
    }
  else if (!bs->auth.is_delayed && bs->auth.curr_key)
    {
      mp->bfd_key_id = bs->auth.curr_bfd_key_id;
      mp->conf_key_id = clib_host_to_net_u32 (bs->auth.curr_key->conf_key_id);
    }
  ip_address_encode (&key->local_addr, IP46_TYPE_ANY, &mp->local_addr);
  ip_address_encode (&key->peer_addr, IP46_TYPE_ANY, &mp->peer_addr);

  mp->required_min_rx = clib_host_to_net_u32 (bs->config_required_min_rx_usec);
  mp->desired_min_tx = clib_host_to_net_u32 (bs->config_desired_min_tx_usec);
  mp->detect_mult = bs->local_detect_mult;
  vl_api_send_msg (reg, (u8 *) mp);
}

void
bfd_event (bfd_main_t * bm, bfd_session_t * bs)
{
  vpe_api_main_t *vam = &vpe_api_main;
  vpe_client_registration_t *reg;
  vl_api_registration_t *vl_reg;
  pool_foreach (reg, vam->bfd_events_registrations)  {
    vl_reg = vl_api_client_index_to_registration (reg->client_index);
    if (vl_reg)
      {
	switch (bs->transport)
	  {
	  case BFD_TRANSPORT_UDP4:
	  /* fallthrough */
	  case BFD_TRANSPORT_UDP6:
	    send_bfd_udp_session_event (vl_reg, 0, bs);
	  }
      }
  }
}

static void
vl_api_bfd_udp_session_dump_t_handler (vl_api_bfd_udp_session_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  bfd_session_t *bs = NULL;
  pool_foreach (bs, bfd_main.sessions)  {
    if (bs->transport == BFD_TRANSPORT_UDP4 ||
	bs->transport == BFD_TRANSPORT_UDP6)
      send_bfd_udp_session_details (reg, mp->context, bs);
  }
}

static void
vl_api_bfd_udp_session_set_flags_t_handler (vl_api_bfd_udp_session_set_flags_t
					    * mp)
{
  vl_api_bfd_udp_session_set_flags_reply_t *rmp;
  int rv;

  BFD_UDP_API_PARAM_COMMON_CODE;

  rv = bfd_udp_session_set_flags (vlib_get_main (),
				  BFD_UDP_API_PARAM_FROM_MP (mp),
				  clib_net_to_host_u32 (mp->flags) &
				  IF_STATUS_API_FLAG_ADMIN_UP);

  REPLY_MACRO (VL_API_BFD_UDP_SESSION_SET_FLAGS_REPLY);
}

static void
vl_api_bfd_auth_set_key_t_handler (vl_api_bfd_auth_set_key_t * mp)
{
  vl_api_bfd_auth_set_key_reply_t *rmp;
  int rv = bfd_auth_set_key (clib_net_to_host_u32 (mp->conf_key_id),
			     mp->auth_type, mp->key_len, mp->key);

  REPLY_MACRO (VL_API_BFD_AUTH_SET_KEY_REPLY);
}

static void
vl_api_bfd_auth_del_key_t_handler (vl_api_bfd_auth_del_key_t * mp)
{
  vl_api_bfd_auth_del_key_reply_t *rmp;
  int rv = bfd_auth_del_key (clib_net_to_host_u32 (mp->conf_key_id));

  REPLY_MACRO (VL_API_BFD_AUTH_DEL_KEY_REPLY);
}

static void
vl_api_bfd_auth_keys_dump_t_handler (vl_api_bfd_auth_keys_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  bfd_auth_key_t *key = NULL;
  vl_api_bfd_auth_keys_details_t *rmp = NULL;

  pool_foreach (key, bfd_main.auth_keys)  {
    rmp = vl_msg_api_alloc (sizeof (*rmp));
    clib_memset (rmp, 0, sizeof (*rmp));
    rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_BFD_AUTH_KEYS_DETAILS);
    rmp->context = mp->context;
    rmp->conf_key_id = clib_host_to_net_u32 (key->conf_key_id);
    rmp->auth_type = key->auth_type;
    rmp->use_count = clib_host_to_net_u32 (key->use_count);
    vl_api_send_msg (reg, (u8 *)rmp);
  }
}

static void
vl_api_bfd_udp_auth_activate_t_handler (vl_api_bfd_udp_auth_activate_t * mp)
{
  vl_api_bfd_udp_auth_activate_reply_t *rmp;
  int rv;

  COND_VALIDATE_SW_IF_INDEX (mp);

  BFD_UDP_API_PARAM_COMMON_CODE;

  rv = bfd_udp_auth_activate (BFD_UDP_API_PARAM_FROM_MP (mp),
			      clib_net_to_host_u32 (mp->conf_key_id),
			      mp->bfd_key_id, mp->is_delayed);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_BFD_UDP_AUTH_ACTIVATE_REPLY);
}

static void
vl_api_bfd_udp_auth_deactivate_t_handler (vl_api_bfd_udp_auth_deactivate_t *
					  mp)
{
  vl_api_bfd_udp_auth_deactivate_reply_t *rmp;
  int rv;

  COND_VALIDATE_SW_IF_INDEX (mp);

  BFD_UDP_API_PARAM_COMMON_CODE;

  rv =
    bfd_udp_auth_deactivate (BFD_UDP_API_PARAM_FROM_MP (mp), mp->is_delayed);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_BFD_UDP_AUTH_DEACTIVATE_REPLY);
}

static void
vl_api_bfd_udp_set_echo_source_t_handler (vl_api_bfd_udp_set_echo_source_t *
					  mp)
{
  vl_api_bfd_udp_set_echo_source_reply_t *rmp;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  rv = bfd_udp_set_echo_source (clib_net_to_host_u32 (mp->sw_if_index));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_BFD_UDP_SET_ECHO_SOURCE_REPLY);
}

static void
vl_api_bfd_udp_del_echo_source_t_handler (vl_api_bfd_udp_del_echo_source_t *
					  mp)
{
  vl_api_bfd_udp_del_echo_source_reply_t *rmp;
  int rv;

  rv = bfd_udp_del_echo_source ();

  REPLY_MACRO (VL_API_BFD_UDP_DEL_ECHO_SOURCE_REPLY);
}

static void
vl_api_bfd_udp_get_echo_source_t_handler (vl_api_bfd_udp_get_echo_source_t *
					  mp)
{
  vl_api_bfd_udp_get_echo_source_reply_t *rmp;
  int rv = 0;
  int is_set;
  u32 sw_if_index;
  int have_usable_ip4;
  ip4_address_t ip4;
  int have_usable_ip6;
  ip6_address_t ip6;

  bfd_udp_get_echo_source (&is_set, &sw_if_index, &have_usable_ip4, &ip4,
			   &have_usable_ip6, &ip6);

  REPLY_MACRO2 (VL_API_BFD_UDP_GET_ECHO_SOURCE_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
    if (is_set)
      {
        rmp->is_set = true;
        rmp->sw_if_index = clib_host_to_net_u32 (sw_if_index);
        if (have_usable_ip4)
          {
            rmp->have_usable_ip4 = true;
	    ip4_address_encode(&ip4, rmp->ip4_addr);
          }
        else
          {
            rmp->have_usable_ip4 = false;
          }
        if (have_usable_ip6)
          {
            rmp->have_usable_ip6 = true;
	    ip6_address_encode(&ip6, rmp->ip6_addr);
          }
        else
          {
            rmp->have_usable_ip6 = false;
          }
      }
    else
      {
        rmp->is_set = false;
        rmp->have_usable_ip4 = false;
        rmp->have_usable_ip6 = false;
      }
  }))
}

static void
vl_api_bfd_udp_enable_multihop_t_handler (vl_api_bfd_udp_enable_multihop_t *mp)
{
  vl_api_bfd_udp_enable_multihop_reply_t *rmp;
  int rv = 0;

  bfd_main.multihop_enabled = true;

  REPLY_MACRO (VL_API_BFD_UDP_ENABLE_MULTIHOP_REPLY);
}

#include <vnet/bfd/bfd.api.c>
static clib_error_t *
bfd_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (bfd_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
