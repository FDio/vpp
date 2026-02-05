/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/base/tcp-check/tcp_check.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/format_fns.h>
#include <sfdp_services/base/tcp-check/tcp_check.api_enum.h>
#include <sfdp_services/base/tcp-check/tcp_check.api_types.h>
#include <vlibapi/api_helper_macros.h>

#include <vnet/sfdp/sfdp_types_funcs.h>

static u32
sfdp_tcp_check_session_flags_encode (u32 x)
{
  return clib_host_to_net_u32 (x);
};

static void
sfdp_tcp_send_session_details (vl_api_registration_t *rp, u32 context,
			       u32 session_index, u32 thread_index,
			       sfdp_session_t *session,
			       sfdp_tcp_check_session_state_t *tcp_session)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_tcp_check_main_t *tcp = &sfdp_tcp;
  vl_api_sfdp_tcp_session_details_t *mp;
  sfdp_session_ip46_key_t skey;
  sfdp_tenant_t *tenant;
  sfdp_tenant_id_t tenant_id;
  size_t msg_size;
  u8 n_keys = sfdp_session_n_keys (session);
  tenant = sfdp_tenant_at_index (sfdp, session->tenant_idx);
  tenant_id = tenant->tenant_id;
  msg_size = sizeof (*mp) + sizeof (mp->keys[0]) * n_keys;

  mp = vl_msg_api_alloc_zero (msg_size);
  mp->_vl_msg_id = ntohs (VL_API_SFDP_TCP_SESSION_DETAILS + tcp->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->session_id = clib_host_to_net_u64 (session->session_id);
  mp->thread_index = clib_host_to_net_u32 (thread_index);
  mp->tenant_id = clib_host_to_net_u32 (tenant_id);
  mp->session_idx = clib_host_to_net_u32 (session_index);
  mp->session_type = sfdp_session_type_encode (session->type);
  mp->flags = sfdp_tcp_check_session_flags_encode (tcp_session->flags);
  mp->n_keys = n_keys;
  for (int i = 0; i < n_keys; i++)
    {
      if ((i == 0 &&
	   session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4) ||
	  (i == 1 &&
	   session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4))
	{
	  sfdp_normalise_ip4_key (session, &skey.key4, i);
	  sfdp_session_ip46_key_encode (&skey, IP46_TYPE_IP4, &mp->keys[i]);
	}
      if ((i == 0 &&
	   session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6) ||
	  (i == 1 &&
	   session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6))
	{
	  sfdp_normalise_ip6_key (session, &skey.key6, i);
	  sfdp_session_ip46_key_encode (&skey, IP46_TYPE_IP6, &mp->keys[i]);
	}
    }
  vl_api_send_msg (rp, (u8 *) mp);
}

static void
vl_api_sfdp_tcp_session_dump_t_handler (vl_api_sfdp_tcp_session_dump_t *mp)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_tcp_check_main_t *tcp = &sfdp_tcp;
  sfdp_session_t *session;
  sfdp_tcp_check_session_state_t *tcp_session;
  uword session_index;
  vl_api_registration_t *rp;
  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  sfdp_foreach_session (sfdp, session_index, session)
  {
    if (session->proto != IP_PROTOCOL_TCP)
      continue;
    tcp_session = vec_elt_at_index (tcp->state, session_index);
    sfdp_tcp_send_session_details (rp, mp->context, session_index,
				   session->owning_thread_index, session,
				   tcp_session);
  }
}
#include <sfdp_services/base/tcp-check/tcp_check.api.c>
static clib_error_t *
sfdp_tcp_check_plugin_api_hookup (vlib_main_t *vm)
{
  sfdp_tcp_check_main_t *tcp = &sfdp_tcp;
  tcp->msg_id_base = setup_message_id_table ();
  return 0;
}
VLIB_API_INIT_FUNCTION (sfdp_tcp_check_plugin_api_hookup);
