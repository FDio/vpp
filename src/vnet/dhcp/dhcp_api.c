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
#include <vnet/dhcp/dhcp_proxy.h>
#include <vnet/dhcp/client.h>
#include <vnet/dhcp/dhcp6_pd_client_dp.h>
#include <vnet/dhcp/dhcp6_ia_na_client_dp.h>
#include <vnet/dhcp/dhcp6_client_common_dp.h>
#include <vnet/fib/fib_table.h>

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

#define foreach_vpe_api_msg                       \
_(DHCP_PROXY_CONFIG,dhcp_proxy_config)            \
_(DHCP_PROXY_DUMP,dhcp_proxy_dump)                \
_(DHCP_PROXY_SET_VSS,dhcp_proxy_set_vss)          \
_(DHCP_CLIENT_CONFIG, dhcp_client_config)         \
_(DHCP_CLIENT_DUMP, dhcp_client_dump)             \
_(WANT_DHCP6_PD_REPLY_EVENTS, want_dhcp6_pd_reply_events)               \
_(DHCP6_PD_SEND_CLIENT_MESSAGE, dhcp6_pd_send_client_message)           \
_(WANT_DHCP6_REPLY_EVENTS, want_dhcp6_reply_events)               \
_(DHCP6_SEND_CLIENT_MESSAGE, dhcp6_send_client_message)           \
_(DHCP6_CLIENTS_ENABLE_DISABLE, dhcp6_clients_enable_disable)     \
_(DHCP6_DUID_LL_SET, dhcp6_duid_ll_set)


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
			ntohl (mp->tbl_id), mp->vss_type, vpn_ascii_id,
			ntohl (mp->oui), ntohl (mp->vpn_index),
			mp->is_add == 0);

  REPLY_MACRO (VL_API_DHCP_PROXY_SET_VSS_REPLY);
}


static void vl_api_dhcp_proxy_config_t_handler
  (vl_api_dhcp_proxy_config_t * mp)
{
  vl_api_dhcp_proxy_set_vss_reply_t *rmp;
  ip46_address_t src, server;
  int rv = -1;

  if (mp->is_ipv6)
    {
      clib_memcpy (&src.ip6, mp->dhcp_src_address, sizeof (src.ip6));
      clib_memcpy (&server.ip6, mp->dhcp_server, sizeof (server.ip6));

      rv = dhcp6_proxy_set_server (&server,
				   &src,
				   (u32) ntohl (mp->rx_vrf_id),
				   (u32) ntohl (mp->server_vrf_id),
				   (int) (mp->is_add == 0));
    }
  else
    {
      ip46_address_reset (&src);
      ip46_address_reset (&server);

      clib_memcpy (&src.ip4, mp->dhcp_src_address, sizeof (src.ip4));
      clib_memcpy (&server.ip4, mp->dhcp_server, sizeof (server.ip4));

      rv = dhcp4_proxy_set_server (&server,
				   &src,
				   (u32) ntohl (mp->rx_vrf_id),
				   (u32) ntohl (mp->server_vrf_id),
				   (int) (mp->is_add == 0));
    }


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
  memset (mp, 0, n);
  mp->_vl_msg_id = ntohs (VL_API_DHCP_PROXY_DETAILS);
  mp->context = context;
  mp->count = count;

  mp->is_ipv6 = (proto == FIB_PROTOCOL_IP6);
  mp->rx_vrf_id =
    htonl (dhcp_proxy_rx_table_get_table_id (proto, proxy->rx_fib_index));

  vss = dhcp_get_vss_info (&dhcp_proxy_main, proxy->rx_fib_index, proto);

  if (vss)
    {
      mp->vss_type = vss->vss_type;
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
	memcpy (v_server->dhcp_server, &server->dhcp_server.ip6, 16);
      }
    else
      {
	/* put the address in the first bytes */
	memcpy (v_server->dhcp_server, &server->dhcp_server.ip4, 4);
      }
  }

  if (mp->is_ipv6)
    {
      memcpy (mp->dhcp_src_address, &proxy->dhcp_src_address.ip6, 16);
    }
  else
    {
      /* put the address in the first bytes */
      memcpy (mp->dhcp_src_address, &proxy->dhcp_src_address.ip4, 4);
    }
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
dhcp_client_lease_encode (vl_api_dhcp_lease_t * lease,
			  const dhcp_client_t * client)
{
  size_t len;

  lease->is_ipv6 = 0;		// only support IPv6 clients
  lease->sw_if_index = ntohl (client->sw_if_index);
  lease->state = client->state;
  len = clib_min (sizeof (lease->hostname) - 1, vec_len (client->hostname));
  clib_memcpy (&lease->hostname, client->hostname, len);
  lease->hostname[len] = 0;

  lease->mask_width = client->subnet_mask_width;
  clib_memcpy (&lease->host_address[0], (u8 *) & client->leased_address, 4);
  clib_memcpy (&lease->router_address[0], (u8 *) & client->router_address, 4);

  if (NULL != client->l2_rewrite)
    clib_memcpy (&lease->host_mac[0], client->l2_rewrite + 6, 6);
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

  mp->_vl_msg_id = ntohs (VL_API_DHCP_COMPL_EVENT);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void vl_api_dhcp_client_config_t_handler
  (vl_api_dhcp_client_config_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_dhcp_client_config_reply_t *rmp;
  u32 sw_if_index;
  int rv = 0;

  sw_if_index = ntohl (mp->client.sw_if_index);
  if (!vnet_sw_if_index_is_api_valid (sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto bad_sw_if_index;
    }

  rv = dhcp_client_config (mp->is_add,
			   mp->client_index,
			   vm,
			   sw_if_index,
			   mp->client.hostname,
			   mp->client.id,
			   (mp->client.want_dhcp_event ?
			    dhcp_compl_event_callback :
			    NULL),
			   mp->client.set_broadcast_flag, mp->client.pid);

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

  ctx = arg;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = ntohs (VL_API_DHCP_CLIENT_DETAILS);
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

/*
 * dhcp_api_hookup
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
  foreach_vl_msg_name_crc_dhcp;
#undef _
}

static clib_error_t *
dhcp_api_hookup (vlib_main_t * vm)
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

  dhcp6_pd_set_publisher_node (dhcp6_pd_reply_process_node.index,
			       DHCP6_PD_DP_REPLY_REPORT);
  dhcp6_set_publisher_node (dhcp6_reply_process_node.index,
			    DHCP6_DP_REPLY_REPORT);

  return 0;
}

VLIB_API_INIT_FUNCTION (dhcp_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
