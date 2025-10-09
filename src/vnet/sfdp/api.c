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

#include <vnet/sfdp/sfdp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/format_fns.h>
#include <vnet/sfdp/sfdp.api_enum.h>
#include <vnet/sfdp/sfdp.api_types.h>
#include <vnet/sfdp/sfdp_types_funcs.h>

#define REPLY_MSG_ID_BASE sfdp->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_sfdp_tenant_add_del_t_handler (vl_api_sfdp_tenant_add_del_t *mp)
{
  sfdp_main_t *sfdp = &sfdp_main;
  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  u32 context_id =
    mp->context_id == ~0 ? tenant_id : clib_net_to_host_u32 (mp->context_id);
  u8 is_del = mp->is_del;
  clib_error_t *err =
    sfdp_tenant_add_del (sfdp, tenant_id, context_id, is_del);
  vl_api_sfdp_tenant_add_del_reply_t *rmp;
  int rv = err ? -1 : 0;
  REPLY_MACRO (VL_API_SFDP_TENANT_ADD_DEL_REPLY);
}

static void
vl_api_sfdp_set_services_t_handler (vl_api_sfdp_set_services_t *mp)
{
  sfdp_main_t *sfdp = &sfdp_main;
  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  sfdp_bitmap_t bitmap = 0;
  u8 idx = 0;
  u8 dir = sfdp_api_direction (mp->dir);
  int rv;
  for (uword i = 0; i < mp->n_services; i++)
    {
      char *cstring = (char *) mp->services[i].data;
      unformat_input_t tmp;
      unformat_init_string (&tmp, cstring,
			    strnlen (cstring, sizeof (mp->services[0].data)));
      rv = unformat_user (&tmp, unformat_sfdp_service, &idx);
      unformat_free (&tmp);
      if (!rv)
	{
	  rv = -1;
	  goto fail;
	}
      bitmap |= (1ULL << idx);
    }
  clib_error_t *err = sfdp_set_services (sfdp, tenant_id, bitmap, dir);
  vl_api_sfdp_set_services_reply_t *rmp;
  rv = err ? -1 : 0;
fail:
  REPLY_MACRO (VL_API_SFDP_SET_SERVICES_REPLY);
}

static void
vl_api_sfdp_set_timeout_t_handler (vl_api_sfdp_set_timeout_t *mp)
{
  sfdp_main_t *sfdp = &sfdp_main;
  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  u32 timeout_id = clib_net_to_host_u32 (mp->timeout_id);
  u32 timeout_value = clib_net_to_host_u32 (mp->timeout_value);
  clib_error_t *err =
    sfdp_set_timeout (sfdp, tenant_id, timeout_id, timeout_value);
  vl_api_sfdp_set_timeout_reply_t *rmp;
  int rv = err ? -1 : 0;
  REPLY_MACRO (VL_API_SFDP_SET_TIMEOUT_REPLY);
}

static void
vl_api_sfdp_set_sp_node_t_handler (vl_api_sfdp_set_sp_node_t *mp)
{
  vl_api_sfdp_set_sp_node_reply_t *rmp;
  sfdp_main_t *sfdp = &sfdp_main;
  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  u8 sp_node = sfdp_api_sp_node (mp->sp_node);
  u32 node_index = clib_net_to_host_u32 (mp->node_index);

  clib_error_t *err = sfdp_set_sp_node (sfdp, tenant_id, sp_node, node_index);
  int rv = err ? -1 : 0;
  REPLY_MACRO (VL_API_SFDP_SET_SP_NODE_REPLY);
}

static void
vl_api_sfdp_set_icmp_error_node_t_handler (
  vl_api_sfdp_set_icmp_error_node_t *mp)
{
  vl_api_sfdp_set_icmp_error_node_reply_t *rmp;
  sfdp_main_t *sfdp = &sfdp_main;
  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  u8 is_ip6 = mp->is_ip6;
  u32 node_index = clib_net_to_host_u32 (mp->node_index);

  clib_error_t *err =
    sfdp_set_icmp_error_node (sfdp, tenant_id, is_ip6, node_index);
  int rv = err ? -1 : 0;
  REPLY_MACRO (VL_API_SFDP_SET_ICMP_ERROR_NODE_REPLY);
}

static vl_api_sfdp_session_state_t
sfdp_session_state_encode (sfdp_session_state_t x)
{
  switch (x)
    {
    case SFDP_SESSION_STATE_FSOL:
      return SFDP_API_SESSION_STATE_FSOL;
    case SFDP_SESSION_STATE_ESTABLISHED:
      return SFDP_API_SESSION_STATE_ESTABLISHED;
    case SFDP_SESSION_STATE_TIME_WAIT:
      return SFDP_API_SESSION_STATE_TIME_WAIT;
    default:
      return -1;
    }
};

static void
sfdp_send_session_details (vl_api_registration_t *rp, u32 context,
			   u32 session_index, u32 thread_index,
			   sfdp_session_t *session)
{
  sfdp_main_t *sfdp = &sfdp_main;
  vlib_main_t *vm = vlib_get_main ();
  vl_api_sfdp_session_details_t *mp;
  sfdp_session_ip46_key_t skey;
  sfdp_tenant_t *tenant;
  u32 tenant_id;
  f64 now = vlib_time_now (vm);
  size_t msg_size;
  u8 n_keys = sfdp_session_n_keys (session);
  tenant = sfdp_tenant_at_index (sfdp, session->tenant_idx);
  tenant_id = tenant->tenant_id;
  msg_size = sizeof (*mp) + sizeof (mp->keys[0]) * n_keys;

  mp = vl_msg_api_alloc_zero (msg_size);
  mp->_vl_msg_id = ntohs (VL_API_SFDP_SESSION_DETAILS + sfdp->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->session_id = clib_host_to_net_u64 (session->session_id);
  mp->thread_index = clib_host_to_net_u32 (thread_index);
  mp->tenant_id = clib_host_to_net_u32 (tenant_id);
  mp->session_idx = clib_host_to_net_u32 (session_index);
  mp->session_type = sfdp_session_type_encode (session->type);
  mp->protocol = ip_proto_encode (session->proto);
  mp->state = sfdp_session_state_encode (session->state);
  mp->remaining_time =
    sfdp->expiry_callbacks.session_remaining_time (session, now);
  mp->forward_bitmap =
    clib_host_to_net_u64 (session->bitmaps[SFDP_FLOW_FORWARD]);
  mp->reverse_bitmap =
    clib_host_to_net_u64 (session->bitmaps[SFDP_FLOW_REVERSE]);
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
vl_api_sfdp_session_dump_t_handler (vl_api_sfdp_session_dump_t *mp)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_session_t *session;
  uword session_index;
  vl_api_registration_t *rp;
  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  sfdp_foreach_session (sfdp, session_index, session)
  {
    sfdp_send_session_details (rp, mp->context, session_index,
			       session->owning_thread_index, session);
  }
}

static void
sfdp_send_tenant_details (vl_api_registration_t *rp, u32 context,
			  u16 tenant_index, sfdp_tenant_t *tenant)
{
  sfdp_main_t *sfdp = &sfdp_main;
  vl_api_sfdp_tenant_details_t *mp;
  sfdp_timeout_t *timeout;

  size_t msg_size;
  msg_size = sizeof (*mp) + SFDP_MAX_TIMEOUTS * sizeof (mp->timeout[0]);

  mp = vl_msg_api_alloc_zero (msg_size);
  mp->_vl_msg_id = ntohs (VL_API_SFDP_TENANT_DETAILS + sfdp->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->context_id = clib_host_to_net_u32 (tenant->context_id);
  mp->index = clib_host_to_net_u32 (tenant_index);
  mp->forward_bitmap =
    clib_host_to_net_u64 (tenant->bitmaps[SFDP_FLOW_FORWARD]);
  mp->reverse_bitmap =
    clib_host_to_net_u64 (tenant->bitmaps[SFDP_FLOW_REVERSE]);
  mp->n_timeout = clib_host_to_net_u32 (SFDP_MAX_TIMEOUTS);
  sfdp_foreach_timeout (sfdp, timeout)
  {
    u32 idx = timeout - sfdp->timeouts;
    mp->timeout[idx] = clib_host_to_net_u32 (tenant->timeouts[idx]);
  }

  vl_api_send_msg (rp, (u8 *) mp);
}

static void
vl_api_sfdp_tenant_dump_t_handler (vl_api_sfdp_tenant_dump_t *mp)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_tenant_t *tenant;
  u16 tenant_index;
  vl_api_registration_t *rp;
  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  pool_foreach_index (tenant_index, sfdp->tenants)
    {
      tenant = sfdp_tenant_at_index (sfdp, tenant_index);
      sfdp_send_tenant_details (rp, mp->context, tenant_index, tenant);
    }
}

#include <vnet/sfdp/sfdp.api.c>
static clib_error_t *
sfdp_plugin_api_hookup (vlib_main_t *vm)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp->msg_id_base = setup_message_id_table ();
  return 0;
}
VLIB_API_INIT_FUNCTION (sfdp_plugin_api_hookup);
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
