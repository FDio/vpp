/*
 *------------------------------------------------------------------
 * dhcp_api.c - dhcp api
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
#include <dhcp/dhcp_proxy.h>
#include <dhcp/client.h>
#include <dhcp/dhcp6_pd_client_dp.h>
#include <dhcp/dhcp6_ia_na_client_dp.h>
#include <dhcp/dhcp6_client_common_dp.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <dhcp/dhcp.api_enum.h>
#include <dhcp/dhcp.api_types.h>

/**
 * Base message ID fot the plugin
 */
static u32 dhcp_base_msg_id;
#define REPLY_MSG_ID_BASE dhcp_base_msg_id

#include <vlibapi/api_helper_macros.h>

#define  DHCP_PLUGIN_VERSION_MAJOR 1
#define  DHCP_PLUGIN_VERSION_MINOR 0

static void
vl_api_dhcp_plugin_get_version_t_handler (vl_api_dhcp_plugin_get_version_t *
					  mp)
{
  vl_api_dhcp_plugin_get_version_reply_t *rmp;
  int msg_size = sizeof (*rmp);
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_DHCP_PLUGIN_GET_VERSION_REPLY + REPLY_MSG_ID_BASE);
  rmp->context = mp->context;
  rmp->major = htonl (DHCP_PLUGIN_VERSION_MAJOR);
  rmp->minor = htonl (DHCP_PLUGIN_VERSION_MINOR);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_dhcp_plugin_control_ping_t_handler (vl_api_dhcp_plugin_control_ping_t *
					   mp)
{
  vl_api_dhcp_plugin_control_ping_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_DHCP_PLUGIN_CONTROL_PING_REPLY,
  ({
    rmp->vpe_pid = ntohl (getpid ());
  }));
  /* *INDENT-ON* */
}

static void
vl_api_dhcp6_duid_ll_set_t_handler (vl_api_dhcp6_duid_ll_set_t * mp)
{
  vl_api_dhcp6_duid_ll_set_reply_t *rmp;
  dhcpv6_duid_ll_string_t *duid;
  int rv = 0;

  duid = (dhcpv6_duid_ll_string_t *) mp->duid_ll;
  if (duid->duid_type != htonl (DHCPV6_DUID_LL))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }
  clib_memcpy (&client_duid, &duid, sizeof (client_duid));

reply:
  REPLY_MACRO (VL_API_DHCP6_DUID_LL_SET_REPLY);
}

static void
vl_api_dhcp_proxy_set_vss_t_handler (vl_api_dhcp_proxy_set_vss_t * mp)
{
  vl_api_dhcp_proxy_set_vss_reply_t *rmp;
  u8 *vpn_ascii_id;
  int rv;

  mp->vpn_ascii_id[sizeof (mp->vpn_ascii_id) - 1] = 0;
  vpn_ascii_id = format (0, "%s", mp->vpn_ascii_id);
  rv =
    dhcp_proxy_set_vss ((mp->is_ipv6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4),
			ntohl (mp->tbl_id), ntohl (mp->vss_type),
			vpn_ascii_id, ntohl (mp->oui), ntohl (mp->vpn_index),
			mp->is_add == 0);

  REPLY_MACRO (VL_API_DHCP_PROXY_SET_VSS_REPLY);
}


static void vl_api_dhcp_proxy_config_t_handler
  (vl_api_dhcp_proxy_config_t * mp)
{
  vl_api_dhcp_proxy_set_vss_reply_t *rmp;
  ip46_address_t src, server;
  int rv = -1;

  if (mp->dhcp_src_address.af != mp->dhcp_server.af)
    {
      rv = VNET_API_ERROR_INVALID_ARGUMENT;
      goto reply;
    }

  ip_address_decode (&mp->dhcp_src_address, &src);
  ip_address_decode (&mp->dhcp_server, &server);

  if (mp->dhcp_src_address.af == ADDRESS_IP4)
    {
      rv = dhcp4_proxy_set_server (&server,
				   &src,
				   (u32) ntohl (mp->rx_vrf_id),
				   (u32) ntohl (mp->server_vrf_id),
				   (int) (mp->is_add == 0));
    }
  else
    {
      rv = dhcp6_proxy_set_server (&server,
				   &src,
				   (u32) ntohl (mp->rx_vrf_id),
				   (u32) ntohl (mp->server_vrf_id),
				   (int) (mp->is_add == 0));
    }

reply:
  REPLY_MACRO (VL_API_DHCP_PROXY_CONFIG_REPLY);
}

static void
vl_api_dhcp_proxy_dump_t_handler (vl_api_dhcp_proxy_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;;

  dhcp_proxy_dump ((mp->is_ip6 == 1 ?
		    FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4), reg, mp->context);
}

void
dhcp_send_details (fib_protocol_t proto,
		   void *opaque, u32 context, dhcp_proxy_t * proxy)
{
  vl_api_dhcp_proxy_details_t *mp;
  vl_api_registration_t *reg = opaque;
  vl_api_dhcp_server_t *v_server;
  dhcp_server_t *server;
  fib_table_t *s_fib;
  dhcp_vss_t *vss;
  u32 count;
  size_t n;

  count = vec_len (proxy->dhcp_servers);
  n = sizeof (*mp) + (count * sizeof (vl_api_dhcp_server_t));
  mp = vl_msg_api_alloc (n);
  if (!mp)
    return;
  clib_memset (mp, 0, n);
  mp->_vl_msg_id = ntohs (VL_API_DHCP_PROXY_DETAILS + REPLY_MSG_ID_BASE);
  mp->context = context;
  mp->count = count;

  mp->is_ipv6 = (proto == FIB_PROTOCOL_IP6);
  mp->rx_vrf_id =
    htonl (dhcp_proxy_rx_table_get_table_id (proto, proxy->rx_fib_index));

  vss = dhcp_get_vss_info (&dhcp_proxy_main, proxy->rx_fib_index, proto);

  if (vss)
    {
      mp->vss_type = ntohl (vss->vss_type);
      if (vss->vss_type == VSS_TYPE_ASCII)
	{
	  u32 id_len = vec_len (vss->vpn_ascii_id);
	  clib_memcpy (mp->vss_vpn_ascii_id, vss->vpn_ascii_id, id_len);
	}
      else if (vss->vss_type == VSS_TYPE_VPN_ID)
	{
	  u32 oui = ((u32) vss->vpn_id[0] << 16) + ((u32) vss->vpn_id[1] << 8)
	    + ((u32) vss->vpn_id[2]);
	  u32 fib_id = ((u32) vss->vpn_id[3] << 24) +
	    ((u32) vss->vpn_id[4] << 16) + ((u32) vss->vpn_id[5] << 8) +
	    ((u32) vss->vpn_id[6]);
	  mp->vss_oui = htonl (oui);
	  mp->vss_fib_id = htonl (fib_id);
	}
    }
  else
    mp->vss_type = VSS_TYPE_INVALID;

  vec_foreach_index (count, proxy->dhcp_servers)
  {
    server = &proxy->dhcp_servers[count];
    v_server = &mp->servers[count];

    s_fib = fib_table_get (server->server_fib_index, proto);

    v_server->server_vrf_id = htonl (s_fib->ft_table_id);

    if (mp->is_ipv6)
      {
	memcpy (&v_server->dhcp_server.un, &server->dhcp_server.ip6, 16);
      }
    else
      {
	/* put the address in the first bytes */
	memcpy (&v_server->dhcp_server.un, &server->dhcp_server.ip4, 4);
      }
  }

  if (mp->is_ipv6)
    {
      memcpy (&mp->dhcp_src_address.un, &proxy->dhcp_src_address.ip6, 16);
    }
  else
    {
      /* put the address in the first bytes */
      memcpy (&mp->dhcp_src_address.un, &proxy->dhcp_src_address.ip4, 4);
    }
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
dhcp_client_lease_encode (vl_api_dhcp_lease_t * lease,
			  const dhcp_client_t * client)
{
  size_t len;
  u8 i;

  lease->is_ipv6 = 0;		// only support IPv6 clients
  lease->sw_if_index = ntohl (client->sw_if_index);
  lease->state = ntohl (client->state);
  len = clib_min (sizeof (lease->hostname) - 1, vec_len (client->hostname));
  clib_memcpy (&lease->hostname, client->hostname, len);
  lease->hostname[len] = 0;

  lease->mask_width = client->installed.subnet_mask_width;
  clib_memcpy (&lease->host_address.un,
	       (u8 *) & client->installed.leased_address,
	       sizeof (ip4_address_t));
  clib_memcpy (&lease->router_address.un,
	       (u8 *) & client->installed.router_address,
	       sizeof (ip4_address_t));

  lease->count = vec_len (client->domain_server_address);
  for (i = 0; i < lease->count; i++)
    clib_memcpy (&lease->domain_server[i].address,
		 (u8 *) & client->domain_server_address[i],
		 sizeof (ip4_address_t));

  clib_memcpy (&lease->host_mac[0], client->client_hardware_address, 6);
}

static void
dhcp_client_data_encode (vl_api_dhcp_client_t * vclient,
			 const dhcp_client_t * client)
{
  size_t len;

  vclient->sw_if_index = ntohl (client->sw_if_index);
  len = clib_min (sizeof (vclient->hostname) - 1, vec_len (client->hostname));
  clib_memcpy (&vclient->hostname, client->hostname, len);
  vclient->hostname[len] = 0;

  len = clib_min (sizeof (vclient->id) - 1,
		  vec_len (client->client_identifier));
  clib_memcpy (&vclient->id, client->client_identifier, len);
  vclient->id[len] = 0;

  if (NULL != client->event_callback)
    vclient->want_dhcp_event = 1;
  else
    vclient->want_dhcp_event = 0;
  vclient->set_broadcast_flag = client->set_broadcast_flag;
  vclient->dscp = ip_dscp_encode (client->dscp);
  vclient->pid = client->pid;
}

static void
dhcp_compl_event_callback (u32 client_index, const dhcp_client_t * client)
{
  vl_api_registration_t *reg;
  vl_api_dhcp_compl_event_t *mp;

  reg = vl_api_client_index_to_registration (client_index);
  if (!reg)
    return;

  mp = vl_msg_api_alloc (sizeof (*mp));
  mp->client_index = client_index;
  mp->pid = client->pid;
  dhcp_client_lease_encode (&mp->lease, client);

  mp->_vl_msg_id = ntohs (VL_API_DHCP_COMPL_EVENT + REPLY_MSG_ID_BASE);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void vl_api_dhcp_client_config_t_handler
  (vl_api_dhcp_client_config_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_dhcp_client_config_reply_t *rmp;
  u32 sw_if_index;
  ip_dscp_t dscp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (&(mp->client));

  sw_if_index = ntohl (mp->client.sw_if_index);
  dscp = ip_dscp_decode (mp->client.dscp);

  rv = dhcp_client_config (mp->is_add,
			   mp->client_index,
			   vm,
			   sw_if_index,
			   mp->client.hostname,
			   mp->client.id,
			   (mp->client.want_dhcp_event ?
			    dhcp_compl_event_callback :
			    NULL),
			   mp->client.set_broadcast_flag,
			   dscp, mp->client.pid);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_DHCP_CLIENT_CONFIG_REPLY);
}

typedef struct dhcp_client_send_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} dhcp_client_send_walk_ctx_t;

static int
send_dhcp_client_entry (const dhcp_client_t * client, void *arg)
{
  dhcp_client_send_walk_ctx_t *ctx;
  vl_api_dhcp_client_details_t *mp;
  u32 count;
  size_t n;

  ctx = arg;

  count = vec_len (client->domain_server_address);
  n = sizeof (*mp) + (count * sizeof (vl_api_domain_server_t));
  mp = vl_msg_api_alloc (n);
  if (!mp)
    return 0;
  clib_memset (mp, 0, n);

  mp->_vl_msg_id = ntohs (VL_API_DHCP_CLIENT_DETAILS + REPLY_MSG_ID_BASE);
  mp->context = ctx->context;

  dhcp_client_data_encode (&mp->client, client);
  dhcp_client_lease_encode (&mp->lease, client);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (1);
}

static void
vl_api_dhcp_client_dump_t_handler (vl_api_dhcp_client_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  dhcp_client_send_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };
  dhcp_client_walk (send_dhcp_client_entry, &ctx);
}

static void
  vl_api_dhcp6_clients_enable_disable_t_handler
  (vl_api_dhcp6_clients_enable_disable_t * mp)
{
  vl_api_dhcp6_clients_enable_disable_reply_t *rmp;
  int rv = 0;

  dhcp6_clients_enable_disable (mp->enable);

  REPLY_MACRO (VL_API_DHCP6_CLIENTS_ENABLE_DISABLE_REPLY);
}

void
  vl_api_want_dhcp6_reply_events_t_handler
  (vl_api_want_dhcp6_reply_events_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_want_dhcp6_reply_events_reply_t *rmp;
  int rv = 0;

  uword *p =
    hash_get (am->dhcp6_reply_events_registration_hash, mp->client_index);
  vpe_client_registration_t *rp;
  if (p)
    {
      if (mp->enable_disable)
	{
	  clib_warning ("pid %d: already enabled...", ntohl (mp->pid));
	  rv = VNET_API_ERROR_INVALID_REGISTRATION;
	  goto reply;
	}
      else
	{
	  rp = pool_elt_at_index (am->dhcp6_reply_events_registrations, p[0]);
	  pool_put (am->dhcp6_reply_events_registrations, rp);
	  hash_unset (am->dhcp6_reply_events_registration_hash,
		      mp->client_index);
	  if (pool_elts (am->dhcp6_reply_events_registrations) == 0)
	    dhcp6_set_publisher_node (~0, DHCP6_DP_REPORT_MAX);
	  goto reply;
	}
    }
  if (mp->enable_disable == 0)
    {
      clib_warning ("pid %d: already disabled...", ntohl (mp->pid));
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto reply;
    }
  pool_get (am->dhcp6_reply_events_registrations, rp);
  rp->client_index = mp->client_index;
  rp->client_pid = ntohl (mp->pid);
  hash_set (am->dhcp6_reply_events_registration_hash, rp->client_index,
	    rp - am->dhcp6_reply_events_registrations);
  dhcp6_set_publisher_node (dhcp6_reply_process_node.index,
			    DHCP6_DP_REPLY_REPORT);

reply:
  REPLY_MACRO (VL_API_WANT_DHCP6_REPLY_EVENTS_REPLY);
}

void
  vl_api_want_dhcp6_pd_reply_events_t_handler
  (vl_api_want_dhcp6_pd_reply_events_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_want_dhcp6_pd_reply_events_reply_t *rmp;
  int rv = 0;

  uword *p =
    hash_get (am->dhcp6_pd_reply_events_registration_hash, mp->client_index);
  vpe_client_registration_t *rp;
  if (p)
    {
      if (mp->enable_disable)
	{
	  clib_warning ("pid %d: already enabled...", ntohl (mp->pid));
	  rv = VNET_API_ERROR_INVALID_REGISTRATION;
	  goto reply;
	}
      else
	{
	  rp =
	    pool_elt_at_index (am->dhcp6_pd_reply_events_registrations, p[0]);
	  pool_put (am->dhcp6_pd_reply_events_registrations, rp);
	  hash_unset (am->dhcp6_pd_reply_events_registration_hash,
		      mp->client_index);
	  if (pool_elts (am->dhcp6_pd_reply_events_registrations) == 0)
	    dhcp6_pd_set_publisher_node (~0, DHCP6_PD_DP_REPORT_MAX);
	  goto reply;
	}
    }
  if (mp->enable_disable == 0)
    {
      clib_warning ("pid %d: already disabled...", ntohl (mp->pid));
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto reply;
    }
  pool_get (am->dhcp6_pd_reply_events_registrations, rp);
  rp->client_index = mp->client_index;
  rp->client_pid = ntohl (mp->pid);
  hash_set (am->dhcp6_pd_reply_events_registration_hash, rp->client_index,
	    rp - am->dhcp6_pd_reply_events_registrations);
  dhcp6_pd_set_publisher_node (dhcp6_pd_reply_process_node.index,
			       DHCP6_PD_DP_REPLY_REPORT);

reply:
  REPLY_MACRO (VL_API_WANT_DHCP6_PD_REPLY_EVENTS_REPLY);
}

void
  vl_api_dhcp6_send_client_message_t_handler
  (vl_api_dhcp6_send_client_message_t * mp)
{
  vl_api_dhcp6_send_client_message_reply_t *rmp;
  dhcp6_send_client_message_params_t params;
  vlib_main_t *vm = vlib_get_main ();
  u32 n_addresses;
  u32 i;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_DHCP6_SEND_CLIENT_MESSAGE_REPLY);

  if (rv != 0)
    return;

  params.sw_if_index = ntohl (mp->sw_if_index);
  params.server_index = ntohl (mp->server_index);
  params.irt = ntohl (mp->irt);
  params.mrt = ntohl (mp->mrt);
  params.mrc = ntohl (mp->mrc);
  params.mrd = ntohl (mp->mrd);
  params.msg_type = ntohl (mp->msg_type);
  params.T1 = ntohl (mp->T1);
  params.T2 = ntohl (mp->T2);
  n_addresses = ntohl (mp->n_addresses);
  params.addresses = 0;
  if (n_addresses > 0)
    vec_validate (params.addresses, n_addresses - 1);
  for (i = 0; i < n_addresses; i++)
    {
      vl_api_dhcp6_address_info_t *ai = &mp->addresses[i];
      dhcp6_send_client_message_params_address_t *addr = &params.addresses[i];
      addr->preferred_lt = ntohl (ai->preferred_time);
      addr->valid_lt = ntohl (ai->valid_time);
      ip6_address_decode (ai->address, &addr->address);
    }

  dhcp6_send_client_message (vm, ntohl (mp->sw_if_index), mp->stop, &params);
}

void
  vl_api_dhcp6_pd_send_client_message_t_handler
  (vl_api_dhcp6_pd_send_client_message_t * mp)
{
  vl_api_dhcp6_pd_send_client_message_reply_t *rmp;
  dhcp6_pd_send_client_message_params_t params;
  vlib_main_t *vm = vlib_get_main ();
  u32 n_prefixes;
  u32 i;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_DHCP6_PD_SEND_CLIENT_MESSAGE_REPLY);

  if (rv != 0)
    return;

  params.sw_if_index = ntohl (mp->sw_if_index);
  params.server_index = ntohl (mp->server_index);
  params.irt = ntohl (mp->irt);
  params.mrt = ntohl (mp->mrt);
  params.mrc = ntohl (mp->mrc);
  params.mrd = ntohl (mp->mrd);
  params.msg_type = ntohl (mp->msg_type);
  params.T1 = ntohl (mp->T1);
  params.T2 = ntohl (mp->T2);
  n_prefixes = ntohl (mp->n_prefixes);
  params.prefixes = 0;
  if (n_prefixes > 0)
    vec_validate (params.prefixes, n_prefixes - 1);
  for (i = 0; i < n_prefixes; i++)
    {
      vl_api_dhcp6_pd_prefix_info_t *pi = &mp->prefixes[i];
      dhcp6_pd_send_client_message_params_prefix_t *pref =
	&params.prefixes[i];
      pref->preferred_lt = ntohl (pi->preferred_time);
      pref->valid_lt = ntohl (pi->valid_time);
      ip6_address_decode (pi->prefix.address, &pref->prefix);
      pref->prefix_length = pi->prefix.len;
    }

  dhcp6_pd_send_client_message (vm, ntohl (mp->sw_if_index), mp->stop,
				&params);
}

static clib_error_t *
call_dhcp6_reply_event_callbacks (void *data,
				  _vnet_dhcp6_reply_event_function_list_elt_t
				  * elt)
{
  clib_error_t *error = 0;

  while (elt)
    {
      error = elt->fp (data);
      if (error)
	return error;
      elt = elt->next_dhcp6_reply_event_function;
    }

  return error;
}

static uword
dhcp6_reply_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		     vlib_frame_t * f)
{
  /* These cross the longjmp  boundary (vlib_process_wait_for_event)
   * and need to be volatile - to prevent them from being optimized into
   * a register - which could change during suspension */

  while (1)
    {
      vlib_process_wait_for_event (vm);
      uword event_type = DHCP6_DP_REPLY_REPORT;
      void *event_data = vlib_process_get_event_data (vm, &event_type);

      int i;
      if (event_type == DHCP6_DP_REPLY_REPORT)
	{
	  address_report_t *events = event_data;
	  for (i = 0; i < vec_len (events); i++)
	    {
	      u32 event_size =
		sizeof (vl_api_dhcp6_reply_event_t) +
		vec_len (events[i].addresses) *
		sizeof (vl_api_dhcp6_address_info_t);
	      vl_api_dhcp6_reply_event_t *event = clib_mem_alloc (event_size);
	      clib_memset (event, 0, event_size);

	      event->sw_if_index = htonl (events[i].body.sw_if_index);
	      event->server_index = htonl (events[i].body.server_index);
	      event->msg_type = events[i].body.msg_type;
	      event->T1 = htonl (events[i].body.T1);
	      event->T2 = htonl (events[i].body.T2);
	      event->inner_status_code =
		htons (events[i].body.inner_status_code);
	      event->status_code = htons (events[i].body.status_code);
	      event->preference = events[i].body.preference;

	      event->n_addresses = htonl (vec_len (events[i].addresses));
	      vl_api_dhcp6_address_info_t *address =
		(typeof (address)) event->addresses;
	      u32 j;
	      for (j = 0; j < vec_len (events[i].addresses); j++)
		{
		  dhcp6_address_info_t *info = &events[i].addresses[j];
		  ip6_address_encode (&info->address, address->address);
		  address->valid_time = htonl (info->valid_time);
		  address->preferred_time = htonl (info->preferred_time);
		  address++;
		}
	      vec_free (events[i].addresses);

	      dhcp6_ia_na_client_public_main_t *dcpm =
		&dhcp6_ia_na_client_public_main;
	      call_dhcp6_reply_event_callbacks (event, dcpm->functions);

	      vpe_client_registration_t *reg;
              /* *INDENT-OFF* */
              pool_foreach(reg, vpe_api_main.dhcp6_reply_events_registrations,
              ({
                vl_api_registration_t *vl_reg;
                vl_reg =
                  vl_api_client_index_to_registration (reg->client_index);
                if (vl_reg && vl_api_can_send_msg (vl_reg))
                  {
                    vl_api_dhcp6_reply_event_t *msg =
                      vl_msg_api_alloc (event_size);
                    clib_memcpy (msg, event, event_size);
                    msg->_vl_msg_id = htons (VL_API_DHCP6_REPLY_EVENT + REPLY_MSG_ID_BASE);
                    msg->client_index = reg->client_index;
                    msg->pid = reg->client_pid;
                    vl_api_send_msg (vl_reg, (u8 *) msg);
                  }
              }));
              /* *INDENT-ON* */

	      clib_mem_free (event);
	    }
	}
      vlib_process_put_event_data (vm, event_data);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dhcp6_reply_process_node) = {
  .function = dhcp6_reply_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "dhcp6-reply-publisher-process",
};
/* *INDENT-ON* */

static clib_error_t *
call_dhcp6_pd_reply_event_callbacks (void *data,
				     _vnet_dhcp6_pd_reply_event_function_list_elt_t
				     * elt)
{
  clib_error_t *error = 0;

  while (elt)
    {
      error = elt->fp (data);
      if (error)
	return error;
      elt = elt->next_dhcp6_pd_reply_event_function;
    }

  return error;
}

static uword
dhcp6_pd_reply_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
			vlib_frame_t * f)
{
  /* These cross the longjmp  boundary (vlib_process_wait_for_event)
   * and need to be volatile - to prevent them from being optimized into
   * a register - which could change during suspension */

  while (1)
    {
      vlib_process_wait_for_event (vm);
      uword event_type = DHCP6_PD_DP_REPLY_REPORT;
      void *event_data = vlib_process_get_event_data (vm, &event_type);

      int i;
      if (event_type == DHCP6_PD_DP_REPLY_REPORT)
	{
	  prefix_report_t *events = event_data;
	  for (i = 0; i < vec_len (events); i++)
	    {
	      u32 event_size =
		sizeof (vl_api_dhcp6_pd_reply_event_t) +
		vec_len (events[i].prefixes) *
		sizeof (vl_api_dhcp6_pd_prefix_info_t);
	      vl_api_dhcp6_pd_reply_event_t *event =
		clib_mem_alloc (event_size);
	      clib_memset (event, 0, event_size);

	      event->sw_if_index = htonl (events[i].body.sw_if_index);
	      event->server_index = htonl (events[i].body.server_index);
	      event->msg_type = events[i].body.msg_type;
	      event->T1 = htonl (events[i].body.T1);
	      event->T2 = htonl (events[i].body.T2);
	      event->inner_status_code =
		htons (events[i].body.inner_status_code);
	      event->status_code = htons (events[i].body.status_code);
	      event->preference = events[i].body.preference;

	      event->n_prefixes = htonl (vec_len (events[i].prefixes));
	      vl_api_dhcp6_pd_prefix_info_t *prefix =
		(typeof (prefix)) event->prefixes;
	      u32 j;
	      for (j = 0; j < vec_len (events[i].prefixes); j++)
		{
		  dhcp6_prefix_info_t *info = &events[i].prefixes[j];
		  ip6_address_encode (&info->prefix, prefix->prefix.address);
		  prefix->prefix.len = info->prefix_length;
		  prefix->valid_time = htonl (info->valid_time);
		  prefix->preferred_time = htonl (info->preferred_time);
		  prefix++;
		}
	      vec_free (events[i].prefixes);

	      dhcp6_pd_client_public_main_t *dpcpm =
		&dhcp6_pd_client_public_main;
	      call_dhcp6_pd_reply_event_callbacks (event, dpcpm->functions);

	      vpe_client_registration_t *reg;
              /* *INDENT-OFF* */
              pool_foreach(reg, vpe_api_main.dhcp6_pd_reply_events_registrations,
              ({
                vl_api_registration_t *vl_reg;
                vl_reg =
                  vl_api_client_index_to_registration (reg->client_index);
                if (vl_reg && vl_api_can_send_msg (vl_reg))
                  {
                    vl_api_dhcp6_pd_reply_event_t *msg =
                      vl_msg_api_alloc (event_size);
                    clib_memcpy (msg, event, event_size);
                    msg->_vl_msg_id = htons (VL_API_DHCP6_PD_REPLY_EVENT + REPLY_MSG_ID_BASE);
                    msg->client_index = reg->client_index;
                    msg->pid = reg->client_pid;
                    vl_api_send_msg (vl_reg, (u8 *) msg);
                  }
              }));
              /* *INDENT-ON* */

	      clib_mem_free (event);
	    }
	}
      vlib_process_put_event_data (vm, event_data);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dhcp6_pd_reply_process_node) = {
  .function = dhcp6_pd_reply_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "dhcp6-pd-reply-publisher-process",
};
/* *INDENT-ON* */

/*
 * dhcp_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#include <dhcp/dhcp.api.c>

static clib_error_t *
dhcp_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  dhcp_base_msg_id = setup_message_id_table ();

  dhcp6_pd_set_publisher_node (dhcp6_pd_reply_process_node.index,
			       DHCP6_PD_DP_REPLY_REPORT);
  dhcp6_set_publisher_node (dhcp6_reply_process_node.index,
			    DHCP6_DP_REPLY_REPORT);

  return 0;
}

VLIB_API_INIT_FUNCTION (dhcp_api_hookup);

#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Dynamic Host Configuration Protocol (DHCP)",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
