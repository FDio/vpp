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

#include <vnet/ip/ip_types_api.h>
#include <vlibmemory/api.h>

#include <vnet/fib/fib_table.h>

#include <nat/lib/nat_inlines.h>
#include <nat/lib/ipfix_logging.h>

#include <nat/nat44-ei/nat44_ei.api_enum.h>
#include <nat/nat44-ei/nat44_ei.api_types.h>

#include <nat/nat44-ei/nat44_ei_ha.h>
#include <nat/nat44-ei/nat44_ei.h>

#define REPLY_MSG_ID_BASE nm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_nat44_ei_show_running_config_t_handler (
  vl_api_nat44_ei_show_running_config_t *mp)
{
  vl_api_nat44_ei_show_running_config_reply_t *rmp;
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_config_t *rc = &nm->rconfig;
  int rv = 0;

  REPLY_MACRO2_ZERO (
    VL_API_NAT44_EI_SHOW_RUNNING_CONFIG_REPLY, ({
      rmp->inside_vrf = htonl (rc->inside_vrf);
      rmp->outside_vrf = htonl (rc->outside_vrf);
      rmp->users = htonl (rc->users);
      rmp->sessions = htonl (rc->sessions);
      rmp->user_sessions = htonl (rc->user_sessions);

      rmp->user_buckets = htonl (nm->user_buckets);
      rmp->translation_buckets = htonl (nm->translation_buckets);

      rmp->timeouts.udp = htonl (nm->timeouts.udp);
      rmp->timeouts.tcp_established = htonl (nm->timeouts.tcp.established);
      rmp->timeouts.tcp_transitory = htonl (nm->timeouts.tcp.transitory);
      rmp->timeouts.icmp = htonl (nm->timeouts.icmp);

      rmp->forwarding_enabled = nm->forwarding_enabled == 1;
      // consider how to split functionality between subplugins
      rmp->ipfix_logging_enabled = nat_ipfix_logging_enabled ();

      if (rc->static_mapping_only)
	rmp->flags |= NAT44_EI_STATIC_MAPPING_ONLY;
      if (rc->connection_tracking)
	rmp->flags |= NAT44_EI_CONNECTION_TRACKING;
      if (rc->out2in_dpo)
	rmp->flags |= NAT44_EI_OUT2IN_DPO;
    }));
}

static void
vl_api_nat44_ei_set_workers_t_handler (vl_api_nat44_ei_set_workers_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_set_workers_reply_t *rmp;
  int rv = 0;
  uword *bitmap = 0;
  u64 mask;

  mask = clib_net_to_host_u64 (mp->worker_mask);

  if (nm->num_workers < 2)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto send_reply;
    }

  bitmap = clib_bitmap_set_multiple (bitmap, 0, mask, BITS (mask));
  rv = nat44_ei_set_workers (bitmap);
  clib_bitmap_free (bitmap);

send_reply:
  REPLY_MACRO (VL_API_NAT44_EI_SET_WORKERS_REPLY);
}

static void
send_nat_worker_details (u32 worker_index, vl_api_registration_t *reg,
			 u32 context)
{
  vl_api_nat44_ei_worker_details_t *rmp;
  nat44_ei_main_t *nm = &nat44_ei_main;
  vlib_worker_thread_t *w =
    vlib_worker_threads + worker_index + nm->first_worker_index;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT44_EI_WORKER_DETAILS + nm->msg_id_base);
  rmp->context = context;
  rmp->worker_index = htonl (worker_index);
  rmp->lcore_id = htonl (w->cpu_id);
  strncpy ((char *) rmp->name, (char *) w->name, ARRAY_LEN (rmp->name) - 1);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_ei_worker_dump_t_handler (vl_api_nat44_ei_worker_dump_t *mp)
{
  vl_api_registration_t *reg;
  nat44_ei_main_t *nm = &nat44_ei_main;
  u32 *worker_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (worker_index, nm->workers)
    {
      send_nat_worker_details (*worker_index, reg, mp->context);
    }
}

static void
vl_api_nat44_ei_set_log_level_t_handler (vl_api_nat44_ei_set_log_level_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_set_log_level_reply_t *rmp;
  int rv = 0;

  if (nm->log_level > NAT_LOG_DEBUG)
    rv = VNET_API_ERROR_UNSUPPORTED;
  else
    nm->log_level = mp->log_level;

  REPLY_MACRO (VL_API_NAT44_EI_SET_LOG_LEVEL_REPLY);
}

static void
vl_api_nat44_ei_plugin_enable_disable_t_handler (
  vl_api_nat44_ei_plugin_enable_disable_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_config_t c = { 0 };
  vl_api_nat44_ei_plugin_enable_disable_reply_t *rmp;
  int rv = 0;

  if (mp->enable)
    {
      c.static_mapping_only = mp->flags & NAT44_EI_STATIC_MAPPING_ONLY;
      c.connection_tracking = mp->flags & NAT44_EI_CONNECTION_TRACKING;
      c.out2in_dpo = mp->flags & NAT44_EI_OUT2IN_DPO;

      c.inside_vrf = ntohl (mp->inside_vrf);
      c.outside_vrf = ntohl (mp->outside_vrf);

      c.users = ntohl (mp->users);

      c.sessions = ntohl (mp->sessions);

      c.user_sessions = ntohl (mp->user_sessions);

      rv = nat44_ei_plugin_enable (c);
    }
  else
    rv = nat44_ei_plugin_disable ();

  REPLY_MACRO (VL_API_NAT44_EI_PLUGIN_ENABLE_DISABLE_REPLY);
}

static void
vl_api_nat44_ei_ipfix_enable_disable_t_handler (
  vl_api_nat44_ei_ipfix_enable_disable_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_ipfix_enable_disable_reply_t *rmp;
  int rv = 0;

  rv = nat_ipfix_logging_enable_disable (mp->enable,
					 clib_host_to_net_u32 (mp->domain_id),
					 clib_host_to_net_u16 (mp->src_port));

  REPLY_MACRO (VL_API_NAT44_EI_IPFIX_ENABLE_DISABLE_REPLY);
}

static void
vl_api_nat44_ei_set_timeouts_t_handler (vl_api_nat44_ei_set_timeouts_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_set_timeouts_reply_t *rmp;
  int rv = 0;

  nm->timeouts.udp = ntohl (mp->udp);
  nm->timeouts.tcp.established = ntohl (mp->tcp_established);
  nm->timeouts.tcp.transitory = ntohl (mp->tcp_transitory);
  nm->timeouts.icmp = ntohl (mp->icmp);

  REPLY_MACRO (VL_API_NAT44_EI_SET_TIMEOUTS_REPLY);
}

static void
vl_api_nat44_ei_set_addr_and_port_alloc_alg_t_handler (
  vl_api_nat44_ei_set_addr_and_port_alloc_alg_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_set_addr_and_port_alloc_alg_reply_t *rmp;
  int rv = 0;
  u16 port_start, port_end;

  switch (mp->alg)
    {
    case NAT44_EI_ADDR_AND_PORT_ALLOC_ALG_DEFAULT:
      nat44_ei_set_alloc_default ();
      break;
    case NAT44_EI_ADDR_AND_PORT_ALLOC_ALG_MAPE:
      nat44_ei_set_alloc_mape (ntohs (mp->psid), mp->psid_offset,
			       mp->psid_length);
      break;
    case NAT44_EI_ADDR_AND_PORT_ALLOC_ALG_RANGE:
      port_start = ntohs (mp->start_port);
      port_end = ntohs (mp->end_port);
      if (port_end <= port_start)
	{
	  rv = VNET_API_ERROR_INVALID_VALUE;
	  goto send_reply;
	}
      nat44_ei_set_alloc_range (port_start, port_end);
      break;
    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
      break;
    }

send_reply:
  REPLY_MACRO (VL_API_NAT44_EI_SET_ADDR_AND_PORT_ALLOC_ALG_REPLY);
}

static void
vl_api_nat44_ei_get_addr_and_port_alloc_alg_t_handler (
  vl_api_nat44_ei_get_addr_and_port_alloc_alg_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_get_addr_and_port_alloc_alg_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_NAT44_EI_GET_ADDR_AND_PORT_ALLOC_ALG_REPLY, ({
		  rmp->alg = nm->addr_and_port_alloc_alg;
		  rmp->psid_offset = nm->psid_offset;
		  rmp->psid_length = nm->psid_length;
		  rmp->psid = htons (nm->psid);
		  rmp->start_port = htons (nm->start_port);
		  rmp->end_port = htons (nm->end_port);
		}))
}

static void
vl_api_nat44_ei_set_mss_clamping_t_handler (
  vl_api_nat44_ei_set_mss_clamping_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_set_mss_clamping_reply_t *rmp;
  int rv = 0;

  if (mp->enable)
    nm->mss_clamping = ntohs (mp->mss_value);
  else
    nm->mss_clamping = 0;

  REPLY_MACRO (VL_API_NAT44_EI_SET_MSS_CLAMPING_REPLY);
}

static void
vl_api_nat44_ei_get_mss_clamping_t_handler (
  vl_api_nat44_ei_get_mss_clamping_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_get_mss_clamping_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_NAT44_EI_GET_MSS_CLAMPING_REPLY, ({
		  rmp->enable = nm->mss_clamping ? 1 : 0;
		  rmp->mss_value = htons (nm->mss_clamping);
		}))
}

static void
vl_api_nat44_ei_ha_set_listener_t_handler (
  vl_api_nat44_ei_ha_set_listener_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_ha_set_listener_reply_t *rmp;
  ip4_address_t addr;
  int rv;

  memcpy (&addr, &mp->ip_address, sizeof (addr));
  rv = nat_ha_set_listener (vlib_get_main (), &addr,
			    clib_net_to_host_u16 (mp->port),
			    clib_net_to_host_u32 (mp->path_mtu));

  REPLY_MACRO (VL_API_NAT44_EI_HA_SET_LISTENER_REPLY);
}

static void
vl_api_nat44_ei_ha_get_listener_t_handler (
  vl_api_nat44_ei_ha_get_listener_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_ha_get_listener_reply_t *rmp;
  int rv = 0;
  ip4_address_t addr;
  u16 port;
  u32 path_mtu;

  nat_ha_get_listener (&addr, &port, &path_mtu);

  REPLY_MACRO2 (VL_API_NAT44_EI_HA_GET_LISTENER_REPLY, ({
		  clib_memcpy (rmp->ip_address, &addr, sizeof (ip4_address_t));
		  rmp->port = clib_host_to_net_u16 (port);
		  rmp->path_mtu = clib_host_to_net_u32 (path_mtu);
		}))
}

static void
vl_api_nat44_ei_ha_set_failover_t_handler (
  vl_api_nat44_ei_ha_set_failover_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_ha_set_failover_reply_t *rmp;
  ip4_address_t addr;
  int rv;

  memcpy (&addr, &mp->ip_address, sizeof (addr));
  rv = nat_ha_set_failover (
    vlib_get_main (), &addr, clib_net_to_host_u16 (mp->port),
    clib_net_to_host_u32 (mp->session_refresh_interval));

  REPLY_MACRO (VL_API_NAT44_EI_HA_SET_FAILOVER_REPLY);
}

static void
vl_api_nat44_ei_ha_get_failover_t_handler (
  vl_api_nat44_ei_ha_get_failover_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_ha_get_failover_reply_t *rmp;
  int rv = 0;
  ip4_address_t addr;
  u16 port;
  u32 session_refresh_interval;

  nat_ha_get_failover (&addr, &port, &session_refresh_interval);

  REPLY_MACRO2 (VL_API_NAT44_EI_HA_GET_FAILOVER_REPLY, ({
		  clib_memcpy (rmp->ip_address, &addr, sizeof (ip4_address_t));
		  rmp->port = clib_host_to_net_u16 (port);
		  rmp->session_refresh_interval =
		    clib_host_to_net_u32 (session_refresh_interval);
		}))
}

static void
vl_api_nat44_ei_ha_flush_t_handler (vl_api_nat44_ei_ha_flush_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_ha_flush_reply_t *rmp;
  int rv = 0;

  nat_ha_flush (0);

  REPLY_MACRO (VL_API_NAT44_EI_HA_FLUSH_REPLY);
}

static void
nat_ha_resync_completed_event_cb (u32 client_index, u32 pid, u32 missed_count)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_registration_t *reg;
  vl_api_nat44_ei_ha_resync_completed_event_t *mp;

  reg = vl_api_client_index_to_registration (client_index);
  if (!reg)
    return;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->client_index = client_index;
  mp->pid = pid;
  mp->missed_count = clib_host_to_net_u32 (missed_count);
  mp->_vl_msg_id =
    ntohs (VL_API_NAT44_EI_HA_RESYNC_COMPLETED_EVENT + nm->msg_id_base);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_nat44_ei_ha_resync_t_handler (vl_api_nat44_ei_ha_resync_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_ha_resync_reply_t *rmp;
  int rv;

  rv = nat_ha_resync (
    mp->client_index, mp->pid,
    mp->want_resync_event ? nat_ha_resync_completed_event_cb : NULL);

  REPLY_MACRO (VL_API_NAT44_EI_HA_RESYNC_REPLY);
}

static void
vl_api_nat44_ei_del_user_t_handler (vl_api_nat44_ei_del_user_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_del_user_reply_t *rmp;
  ip4_address_t addr;
  int rv;
  memcpy (&addr.as_u8, mp->ip_address, 4);
  rv = nat44_ei_user_del (&addr, ntohl (mp->fib_index));
  REPLY_MACRO (VL_API_NAT44_EI_DEL_USER_REPLY);
}

static void
vl_api_nat44_ei_add_del_address_range_t_handler (
  vl_api_nat44_ei_add_del_address_range_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_add_del_address_range_reply_t *rmp;
  ip4_address_t this_addr;
  u8 is_add;
  u32 start_host_order, end_host_order;
  u32 vrf_id;
  int i, count;
  int rv = 0;
  u32 *tmp;

  if (nm->static_mapping_only)
    {
      rv = VNET_API_ERROR_FEATURE_DISABLED;
      goto send_reply;
    }

  is_add = mp->is_add;

  tmp = (u32 *) mp->first_ip_address;
  start_host_order = clib_host_to_net_u32 (tmp[0]);
  tmp = (u32 *) mp->last_ip_address;
  end_host_order = clib_host_to_net_u32 (tmp[0]);

  count = (end_host_order - start_host_order) + 1;

  vrf_id = clib_host_to_net_u32 (mp->vrf_id);

  if (count > 1024)
    nat44_ei_log_info ("%U - %U, %d addresses...", format_ip4_address,
		       mp->first_ip_address, format_ip4_address,
		       mp->last_ip_address, count);

  memcpy (&this_addr.as_u8, mp->first_ip_address, 4);

  for (i = 0; i < count; i++)
    {
      if (is_add)
	rv = nat44_ei_add_address (nm, &this_addr, vrf_id);
      else
	rv = nat44_ei_del_address (nm, this_addr, 0);

      if (rv)
	goto send_reply;

      if (nm->out2in_dpo)
	nat44_ei_add_del_address_dpo (this_addr, is_add);

      increment_v4_address (&this_addr);
    }

send_reply:
  REPLY_MACRO (VL_API_NAT44_EI_ADD_DEL_ADDRESS_RANGE_REPLY);
}

static void
send_nat44_ei_address_details (nat44_ei_address_t *a,
			       vl_api_registration_t *reg, u32 context)
{
  vl_api_nat44_ei_address_details_t *rmp;
  nat44_ei_main_t *nm = &nat44_ei_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT44_EI_ADDRESS_DETAILS + nm->msg_id_base);
  clib_memcpy (rmp->ip_address, &(a->addr), 4);
  if (a->fib_index != ~0)
    {
      fib_table_t *fib = fib_table_get (a->fib_index, FIB_PROTOCOL_IP4);
      rmp->vrf_id = ntohl (fib->ft_table_id);
    }
  else
    rmp->vrf_id = ~0;
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_ei_address_dump_t_handler (vl_api_nat44_ei_address_dump_t *mp)
{
  vl_api_registration_t *reg;
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_address_t *a;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (a, nm->addresses)
    {
      send_nat44_ei_address_details (a, reg, mp->context);
    }
}

static void
vl_api_nat44_ei_interface_add_del_feature_t_handler (
  vl_api_nat44_ei_interface_add_del_feature_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_interface_add_del_feature_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u8 is_del;
  int rv = 0;

  is_del = !mp->is_add;

  VALIDATE_SW_IF_INDEX (mp);

  rv = nat44_ei_interface_add_del (sw_if_index, mp->flags & NAT44_EI_IF_INSIDE,
				   is_del);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_NAT44_EI_INTERFACE_ADD_DEL_FEATURE_REPLY);
}

static void
send_nat44_ei_interface_details (nat44_ei_interface_t *i,
				 vl_api_registration_t *reg, u32 context)
{
  vl_api_nat44_ei_interface_details_t *rmp;
  nat44_ei_main_t *nm = &nat44_ei_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_EI_INTERFACE_DETAILS + nm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);

  if (nat44_ei_interface_is_inside (i))
    rmp->flags |= NAT44_EI_IF_INSIDE;
  if (nat44_ei_interface_is_outside (i))
    rmp->flags |= NAT44_EI_IF_OUTSIDE;

  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_ei_interface_dump_t_handler (vl_api_nat44_ei_interface_dump_t *mp)
{
  vl_api_registration_t *reg;
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_interface_t *i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (i, nm->interfaces)
    {
      send_nat44_ei_interface_details (i, reg, mp->context);
    }
}

static void
vl_api_nat44_ei_interface_add_del_output_feature_t_handler (
  vl_api_nat44_ei_interface_add_del_output_feature_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_interface_add_del_output_feature_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = nat44_ei_interface_add_del_output_feature (
    sw_if_index, mp->flags & NAT44_EI_IF_INSIDE, !mp->is_add);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_NAT44_EI_INTERFACE_ADD_DEL_OUTPUT_FEATURE_REPLY);
}

static void
send_nat44_ei_interface_output_feature_details (nat44_ei_interface_t *i,
						vl_api_registration_t *reg,
						u32 context)
{
  vl_api_nat44_ei_interface_output_feature_details_t *rmp;
  nat44_ei_main_t *nm = &nat44_ei_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_EI_INTERFACE_OUTPUT_FEATURE_DETAILS + nm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);
  rmp->context = context;

  if (nat44_ei_interface_is_inside (i))
    rmp->flags |= NAT44_EI_IF_INSIDE;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_ei_interface_output_feature_dump_t_handler (
  vl_api_nat44_ei_interface_output_feature_dump_t *mp)
{
  vl_api_registration_t *reg;
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_interface_t *i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (i, nm->output_feature_interfaces)
    {
      send_nat44_ei_interface_output_feature_details (i, reg, mp->context);
    }
}

static void
vl_api_nat44_ei_add_del_static_mapping_t_handler (
  vl_api_nat44_ei_add_del_static_mapping_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_add_del_static_mapping_reply_t *rmp;
  ip4_address_t local_addr, external_addr;
  u16 local_port = 0, external_port = 0;
  u32 vrf_id, external_sw_if_index;
  int rv = 0;
  nat_protocol_t proto;
  u8 *tag = 0;

  memcpy (&local_addr.as_u8, mp->local_ip_address, 4);
  memcpy (&external_addr.as_u8, mp->external_ip_address, 4);

  if (!(mp->flags & NAT44_EI_ADDR_ONLY_MAPPING))
    {
      local_port = mp->local_port;
      external_port = mp->external_port;
    }

  vrf_id = clib_net_to_host_u32 (mp->vrf_id);
  external_sw_if_index = clib_net_to_host_u32 (mp->external_sw_if_index);
  proto = ip_proto_to_nat_proto (mp->protocol);

  mp->tag[sizeof (mp->tag) - 1] = 0;
  tag = format (0, "%s", mp->tag);
  vec_terminate_c_string (tag);

  rv = nat44_ei_add_del_static_mapping (
    local_addr, external_addr, local_port, external_port, proto,
    external_sw_if_index, vrf_id, mp->flags & NAT44_EI_ADDR_ONLY_MAPPING, 0,
    tag, mp->is_add);

  vec_free (tag);

  REPLY_MACRO (VL_API_NAT44_EI_ADD_DEL_STATIC_MAPPING_REPLY);
}

static void
send_nat44_ei_static_mapping_details (nat44_ei_static_mapping_t *m,
				      vl_api_registration_t *reg, u32 context)
{
  vl_api_nat44_ei_static_mapping_details_t *rmp;
  nat44_ei_main_t *nm = &nat44_ei_main;
  u32 len = sizeof (*rmp);

  rmp = vl_msg_api_alloc (len);
  clib_memset (rmp, 0, len);
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_EI_STATIC_MAPPING_DETAILS + nm->msg_id_base);

  clib_memcpy (rmp->local_ip_address, &(m->local_addr), 4);
  clib_memcpy (rmp->external_ip_address, &(m->external_addr), 4);
  rmp->external_sw_if_index = ~0;
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->context = context;

  if (nat44_ei_is_addr_only_static_mapping (m))
    {
      rmp->flags |= NAT44_EI_ADDR_ONLY_MAPPING;
    }
  else
    {
      rmp->protocol = nat_proto_to_ip_proto (m->proto);
      rmp->external_port = m->external_port;
      rmp->local_port = m->local_port;
    }

  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_nat44_ei_static_map_resolve_details (nat44_ei_static_map_resolve_t *m,
					  vl_api_registration_t *reg,
					  u32 context)
{
  vl_api_nat44_ei_static_mapping_details_t *rmp;
  nat44_ei_main_t *nm = &nat44_ei_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_EI_STATIC_MAPPING_DETAILS + nm->msg_id_base);
  clib_memcpy (rmp->local_ip_address, &(m->l_addr), 4);
  rmp->external_sw_if_index = htonl (m->sw_if_index);
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->context = context;

  if (m->addr_only)
    {
      rmp->flags |= NAT44_EI_ADDR_ONLY_MAPPING;
    }
  else
    {
      rmp->protocol = nat_proto_to_ip_proto (m->proto);
      rmp->external_port = m->e_port;
      rmp->local_port = m->l_port;
    }
  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_ei_static_mapping_dump_t_handler (
  vl_api_nat44_ei_static_mapping_dump_t *mp)
{
  vl_api_registration_t *reg;
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_static_mapping_t *m;
  nat44_ei_static_map_resolve_t *rp;
  int j;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (m, nm->static_mappings)
    {
      if (!nat44_ei_is_identity_static_mapping (m))
	send_nat44_ei_static_mapping_details (m, reg, mp->context);
    }

  for (j = 0; j < vec_len (nm->to_resolve); j++)
    {
      rp = nm->to_resolve + j;
      if (!rp->identity_nat)
	send_nat44_ei_static_map_resolve_details (rp, reg, mp->context);
    }
}

static void
vl_api_nat44_ei_add_del_identity_mapping_t_handler (
  vl_api_nat44_ei_add_del_identity_mapping_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_add_del_identity_mapping_reply_t *rmp;
  ip4_address_t addr;
  u16 port = 0;
  u32 vrf_id, sw_if_index;
  int rv = 0;
  nat_protocol_t proto = NAT_PROTOCOL_OTHER;
  u8 *tag = 0;

  if (!(mp->flags & NAT44_EI_ADDR_ONLY_MAPPING))
    {
      port = mp->port;
      proto = ip_proto_to_nat_proto (mp->protocol);
    }
  vrf_id = clib_net_to_host_u32 (mp->vrf_id);
  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  if (sw_if_index != ~0)
    addr.as_u32 = 0;
  else
    memcpy (&addr.as_u8, mp->ip_address, 4);
  mp->tag[sizeof (mp->tag) - 1] = 0;
  tag = format (0, "%s", mp->tag);
  vec_terminate_c_string (tag);

  rv = nat44_ei_add_del_static_mapping (
    addr, addr, port, port, proto, sw_if_index, vrf_id,
    mp->flags & NAT44_EI_ADDR_ONLY_MAPPING, 1, tag, mp->is_add);

  vec_free (tag);

  REPLY_MACRO (VL_API_NAT44_EI_ADD_DEL_IDENTITY_MAPPING_REPLY);
}

static void
send_nat44_ei_identity_mapping_details (nat44_ei_static_mapping_t *m,
					int index, vl_api_registration_t *reg,
					u32 context)
{
  vl_api_nat44_ei_identity_mapping_details_t *rmp;
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_lb_addr_port_t *local = pool_elt_at_index (m->locals, index);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_EI_IDENTITY_MAPPING_DETAILS + nm->msg_id_base);

  if (nat44_ei_is_addr_only_static_mapping (m))
    rmp->flags |= NAT44_EI_ADDR_ONLY_MAPPING;

  clib_memcpy (rmp->ip_address, &(m->local_addr), 4);
  rmp->port = m->local_port;
  rmp->sw_if_index = ~0;
  rmp->vrf_id = htonl (local->vrf_id);
  rmp->protocol = nat_proto_to_ip_proto (m->proto);
  rmp->context = context;
  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_nat44_ei_identity_map_resolve_details (nat44_ei_static_map_resolve_t *m,
					    vl_api_registration_t *reg,
					    u32 context)
{
  vl_api_nat44_ei_identity_mapping_details_t *rmp;
  nat44_ei_main_t *nm = &nat44_ei_main;
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_EI_IDENTITY_MAPPING_DETAILS + nm->msg_id_base);

  if (m->addr_only)
    rmp->flags = (vl_api_nat44_ei_config_flags_t) NAT44_EI_ADDR_ONLY_MAPPING;

  rmp->port = m->l_port;
  rmp->sw_if_index = htonl (m->sw_if_index);
  rmp->vrf_id = htonl (m->vrf_id);
  rmp->protocol = nat_proto_to_ip_proto (m->proto);
  rmp->context = context;
  if (m->tag)
    strncpy ((char *) rmp->tag, (char *) m->tag, vec_len (m->tag));

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_ei_identity_mapping_dump_t_handler (
  vl_api_nat44_ei_identity_mapping_dump_t *mp)
{
  vl_api_registration_t *reg;
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_static_mapping_t *m;
  nat44_ei_static_map_resolve_t *rp;
  int j;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (m, nm->static_mappings)
    {
      if (nat44_ei_is_identity_static_mapping (m))
	{
	  pool_foreach_index (j, m->locals)
	    {
	      send_nat44_ei_identity_mapping_details (m, j, reg, mp->context);
	    }
	}
    }

  for (j = 0; j < vec_len (nm->to_resolve); j++)
    {
      rp = nm->to_resolve + j;
      if (rp->identity_nat)
	send_nat44_ei_identity_map_resolve_details (rp, reg, mp->context);
    }
}

static void
vl_api_nat44_ei_add_del_interface_addr_t_handler (
  vl_api_nat44_ei_add_del_interface_addr_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_add_del_interface_addr_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;
  u8 is_del;

  is_del = !mp->is_add;

  VALIDATE_SW_IF_INDEX (mp);

  rv = nat44_ei_add_interface_address (nm, sw_if_index, is_del);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_NAT44_EI_ADD_DEL_INTERFACE_ADDR_REPLY);
}

static void
send_nat44_ei_interface_addr_details (u32 sw_if_index,
				      vl_api_registration_t *reg, u32 context)
{
  vl_api_nat44_ei_interface_addr_details_t *rmp;
  nat44_ei_main_t *nm = &nat44_ei_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_EI_INTERFACE_ADDR_DETAILS + nm->msg_id_base);
  rmp->sw_if_index = ntohl (sw_if_index);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_ei_interface_addr_dump_t_handler (
  vl_api_nat44_ei_interface_addr_dump_t *mp)
{
  vl_api_registration_t *reg;
  nat44_ei_main_t *nm = &nat44_ei_main;
  u32 *i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (i, nm->auto_add_sw_if_indices)
    send_nat44_ei_interface_addr_details (*i, reg, mp->context);
}

static void
send_nat44_ei_user_details (nat44_ei_user_t *u, vl_api_registration_t *reg,
			    u32 context)
{
  vl_api_nat44_ei_user_details_t *rmp;
  nat44_ei_main_t *nm = &nat44_ei_main;
  ip4_main_t *im = &ip4_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT44_EI_USER_DETAILS + nm->msg_id_base);

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
vl_api_nat44_ei_user_dump_t_handler (vl_api_nat44_ei_user_dump_t *mp)
{
  vl_api_registration_t *reg;
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_main_per_thread_data_t *tnm;
  nat44_ei_user_t *u;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach (tnm, nm->per_thread_data)
    {
      pool_foreach (u, tnm->users)
	{
	  send_nat44_ei_user_details (u, reg, mp->context);
	}
    }
}

static void
send_nat44_ei_user_session_details (nat44_ei_session_t *s,
				    vl_api_registration_t *reg, u32 context)
{
  vl_api_nat44_ei_user_session_details_t *rmp;
  nat44_ei_main_t *nm = &nat44_ei_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT44_EI_USER_SESSION_DETAILS + nm->msg_id_base);
  clib_memcpy (rmp->outside_ip_address, (&s->out2in.addr), 4);
  clib_memcpy (rmp->inside_ip_address, (&s->in2out.addr), 4);

  if (nat44_ei_is_session_static (s))
    rmp->flags |= NAT44_EI_STATIC_MAPPING;

  rmp->last_heard = clib_host_to_net_u64 ((u64) s->last_heard);
  rmp->total_bytes = clib_host_to_net_u64 (s->total_bytes);
  rmp->total_pkts = ntohl (s->total_pkts);
  rmp->context = context;
  if (nat44_ei_is_unk_proto_session (s))
    {
      rmp->outside_port = 0;
      rmp->inside_port = 0;
      rmp->protocol = ntohs (s->in2out.port);
    }
  else
    {
      rmp->outside_port = s->out2in.port;
      rmp->inside_port = s->in2out.port;
      rmp->protocol = ntohs (nat_proto_to_ip_proto (s->nat_proto));
    }
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_nat44_ei_user_session_dump_t_handler (
  vl_api_nat44_ei_user_session_dump_t *mp)
{
  vl_api_registration_t *reg;
  nat44_ei_main_t *nm = &nat44_ei_main;
  nat44_ei_main_per_thread_data_t *tnm;
  nat44_ei_session_t *s;
  clib_bihash_kv_8_8_t key, value;
  nat44_ei_user_key_t ukey;
  nat44_ei_user_t *u;
  u32 session_index, head_index, elt_index;
  dlist_elt_t *head, *elt;
  ip4_header_t ip;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  clib_memcpy (&ukey.addr, mp->ip_address, 4);
  ip.src_address.as_u32 = ukey.addr.as_u32;
  ukey.fib_index = fib_table_find (FIB_PROTOCOL_IP4, ntohl (mp->vrf_id));
  key.key = ukey.as_u64;
  if (nm->num_workers > 1)
    tnm = vec_elt_at_index (nm->per_thread_data,
			    nm->worker_in2out_cb (&ip, ukey.fib_index, 0));
  else
    tnm = vec_elt_at_index (nm->per_thread_data, nm->num_workers);

  if (clib_bihash_search_8_8 (&tnm->user_hash, &key, &value))
    return;
  u = pool_elt_at_index (tnm->users, value.value);
  if (!u->nsessions && !u->nstaticsessions)
    return;

  head_index = u->sessions_per_user_list_head_index;
  head = pool_elt_at_index (tnm->list_pool, head_index);
  elt_index = head->next;
  elt = pool_elt_at_index (tnm->list_pool, elt_index);
  session_index = elt->value;
  while (session_index != ~0)
    {
      s = pool_elt_at_index (tnm->sessions, session_index);

      send_nat44_ei_user_session_details (s, reg, mp->context);

      elt_index = elt->next;
      elt = pool_elt_at_index (tnm->list_pool, elt_index);
      session_index = elt->value;
    }
}

static void
vl_api_nat44_ei_del_session_t_handler (vl_api_nat44_ei_del_session_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_del_session_reply_t *rmp;
  ip4_address_t addr, eh_addr;
  u16 port;
  u32 vrf_id;
  int rv = 0;
  u8 is_in;
  nat_protocol_t proto;

  memcpy (&addr.as_u8, mp->address, 4);
  port = mp->port;
  vrf_id = clib_net_to_host_u32 (mp->vrf_id);
  proto = ip_proto_to_nat_proto (mp->protocol);
  memcpy (&eh_addr.as_u8, mp->ext_host_address, 4);

  // is session inside ?
  is_in = mp->flags & NAT44_EI_IF_INSIDE;

  rv = nat44_ei_del_session (nm, &addr, port, proto, vrf_id, is_in);

  REPLY_MACRO (VL_API_NAT44_EI_DEL_SESSION_REPLY);
}

static void
vl_api_nat44_ei_forwarding_enable_disable_t_handler (
  vl_api_nat44_ei_forwarding_enable_disable_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_forwarding_enable_disable_reply_t *rmp;
  int rv = 0;
  u32 *ses_to_be_removed = 0, *ses_index;
  nat44_ei_main_per_thread_data_t *tnm;
  nat44_ei_session_t *s;

  nm->forwarding_enabled = mp->enable != 0;

  if (mp->enable == 0)
    {
      vec_foreach (tnm, nm->per_thread_data)
	{
	  vec_foreach (ses_index, ses_to_be_removed)
	    {
	      s = pool_elt_at_index (tnm->sessions, ses_index[0]);
	      nat44_ei_free_session_data (nm, s, tnm - nm->per_thread_data, 0);
	      nat44_ei_delete_session (nm, s, tnm - nm->per_thread_data);
	    }

	  vec_free (ses_to_be_removed);
	}
    }

  REPLY_MACRO (VL_API_NAT44_EI_FORWARDING_ENABLE_DISABLE_REPLY);
}

static void
vl_api_nat44_ei_set_fq_options_t_handler (vl_api_nat44_ei_set_fq_options_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_set_fq_options_reply_t *rmp;
  int rv = 0;
  u32 frame_queue_nelts = ntohl (mp->frame_queue_nelts);
  rv = nat44_ei_set_frame_queue_nelts (frame_queue_nelts);
  REPLY_MACRO (VL_API_NAT44_EI_SET_FQ_OPTIONS_REPLY);
}

static void
vl_api_nat44_ei_show_fq_options_t_handler (
  vl_api_nat44_ei_show_fq_options_t *mp)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  vl_api_nat44_ei_show_fq_options_reply_t *rmp;
  int rv = 0;
  /* clang-format off */
  REPLY_MACRO2_ZERO (VL_API_NAT44_EI_SHOW_FQ_OPTIONS_REPLY,
  ({
    rmp->frame_queue_nelts = htonl (nm->frame_queue_nelts);
  }));
  /* clang-format on */
}

/* API definitions */
#include <vnet/format_fns.h>
#include <nat/nat44-ei/nat44_ei.api.c>

/* Set up the API message handling tables */
clib_error_t *
nat44_ei_api_hookup (vlib_main_t *vm)
{
  nat44_ei_main_t *nm = &nat44_ei_main;
  nm->msg_id_base = setup_message_id_table ();
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
