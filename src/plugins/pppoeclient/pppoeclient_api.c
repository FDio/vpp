/* SPDX-License-Identifier: Apache-2.0 */
/*
 *------------------------------------------------------------------
 * pppoeclient_api.c - pppoe client api
 *
 * Copyright (c) 2017 RaydoNetworks.
 * Copyright (c) 2026 Hi-Jiajun.
 * Copyright (c) 2026 Adapted for latest VPP
 *------------------------------------------------------------------
 */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ip/ip_format_fns.h>
#include <vnet/ethernet/ethernet_types_api.h>
#include <vnet/ethernet/ethernet_format_fns.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>

#include <pppox/pppox.h>
#include <dhcp/dhcp6_ia_na_client_dp.h>
#include <dhcp/dhcp6_pd_client_dp.h>
#include <pppoeclient/pppoeclient.h>
#include <pppoeclient/pppoeclient.api_types.h>
#include <pppoeclient/pppoeclient.api_enum.h>

static pppox_main_t *pppox_main_p = 0;

static pppox_main_t *
pppoeclient_api_get_pppox_main (void)
{
  if (pppox_main_p == 0)
    pppox_main_p = vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_main");

  return pppox_main_p;
}

static void
pppoeclient_copy_api_string (u8 *dst, uword dst_size, const u8 *src)
{
  if (dst == 0 || dst_size == 0)
    return;

  dst[0] = 0;
  if (src == 0 || src[0] == 0)
    return;

  (void) clib_strncpy ((char *) dst, (const char *) src, dst_size - 1);
}

static void
pppoeclient_copy_api_vec_string (u8 *dst, uword dst_size, const u8 *src)
{
  uword n;

  if (dst == 0 || dst_size == 0)
    return;

  dst[0] = 0;
  if (src == 0)
    return;

  n = clib_min (vec_len (src), dst_size - 1);
  if (n == 0)
    return;

  clib_memcpy (dst, src, n);
  dst[n] = 0;
}

static u8 *
pppoeclient_api_dup_fixed_string (const u8 *src, uword src_size)
{
  uword n;
  u8 *dst = 0;

  if (src == 0 || src_size == 0)
    return 0;

  n = clib_strnlen ((const char *) src, src_size);
  if (n == 0)
    return 0;

  vec_validate (dst, n - 1);
  clib_memcpy (dst, src, n);
  return dst;
}

static pppox_virtual_interface_t *
pppoeclient_api_get_detail_virtual_interface (pppoeclient_main_t *pem, pppoe_client_t *c,
					      u32 client_index, u32 *unit, u8 *unit_from_hw)
{
  pppox_main_t *pom = pppoeclient_api_get_pppox_main ();
  pppox_virtual_interface_t *t = 0;

  if (unit)
    *unit = ~0;
  if (unit_from_hw)
    *unit_from_hw = 0;

  if (pom == 0 || c->pppox_sw_if_index == ~0)
    return 0;

  if (c->pppox_sw_if_index < vec_len (pom->virtual_interface_index_by_sw_if_index))
    *unit = pom->virtual_interface_index_by_sw_if_index[c->pppox_sw_if_index];

  if (*unit == ~0)
    {
      vnet_sw_interface_t *sw =
	vnet_get_sw_interface_or_null (pem->vnet_main, c->pppox_sw_if_index);

      if (sw)
	{
	  vnet_hw_interface_t *hi = vnet_get_hw_interface (pem->vnet_main, sw->hw_if_index);
	  *unit = hi->dev_instance;
	  if (unit_from_hw)
	    *unit_from_hw = 1;
	}
    }

  if (*unit != ~0 && *unit < vec_len (pom->virtual_interfaces) &&
      !pool_is_free_index (pom->virtual_interfaces, *unit))
    {
      pppox_virtual_interface_t *candidate = pool_elt_at_index (pom->virtual_interfaces, *unit);

      if (candidate->sw_if_index == c->pppox_sw_if_index &&
	  candidate->pppoe_client_index == client_index)
	t = candidate;
    }

  return t;
}

static u8
pppoeclient_api_get_global_ipv6 (u32 sw_if_index, ip6_address_t *addr, u8 *prefix_len)
{
  ip_lookup_main_t *lm = &ip6_main.lookup_main;
  ip_interface_address_t *ia = 0;

  if (addr)
    ip6_address_set_zero (addr);
  if (prefix_len)
    *prefix_len = 0;

  if (sw_if_index == ~0)
    return 0;

  foreach_ip_interface_address (lm, ia, sw_if_index, 1 /* honor unnumbered */, ({
				  ip6_address_t *candidate =
				    ip_interface_address_get_address (lm, ia);

				  if (ip6_address_is_link_local_unicast (candidate))
				    continue;

				  if (addr)
				    *addr = *candidate;
				  if (prefix_len)
				    *prefix_len = ia->address_length;
				  return 1;
				}));

  return 0;
}

static u8
pppoeclient_api_get_dhcp6_ia_na (u32 sw_if_index, dhcp6_ia_na_client_runtime_t *rt)
{
  static u8 (*func) (u32, dhcp6_ia_na_client_runtime_t *) = 0;
  static u8 attempted = 0;

  if (rt == 0)
    return 0;

  clib_memset (rt, 0, sizeof (*rt));
  if (!attempted)
    {
      func = vlib_get_plugin_symbol ("dhcp_plugin.so", "dhcp6_ia_na_client_get_runtime");
      attempted = 1;
    }

  if (func == 0)
    return 0;

  return (*func) (sw_if_index, rt);
}

static u8
pppoeclient_api_get_dhcp6_pd (u32 sw_if_index, dhcp6_pd_client_runtime_t *rt,
			      dhcp6_pd_active_prefix_runtime_t *prefix_rt,
			      dhcp6_pd_consumer_runtime_t *consumer_rt)
{
  static u8 (*runtime_func) (u32, dhcp6_pd_client_runtime_t *) = 0;
  static u8 (*prefix_func) (u32, dhcp6_pd_active_prefix_runtime_t *) = 0;
  static u8 (*consumer_func) (u32, dhcp6_pd_consumer_runtime_t *) = 0;
  static u8 attempted = 0;
  u8 have_runtime = 0;

  if (rt == 0 || prefix_rt == 0 || consumer_rt == 0)
    return 0;

  clib_memset (rt, 0, sizeof (*rt));
  clib_memset (prefix_rt, 0, sizeof (*prefix_rt));
  clib_memset (consumer_rt, 0, sizeof (*consumer_rt));

  if (!attempted)
    {
      runtime_func = vlib_get_plugin_symbol ("dhcp_plugin.so", "dhcp6_pd_client_get_runtime");
      prefix_func =
	vlib_get_plugin_symbol ("dhcp_plugin.so", "dhcp6_pd_client_get_active_prefix_runtime");
      consumer_func =
	vlib_get_plugin_symbol ("dhcp_plugin.so", "dhcp6_pd_client_get_consumer_runtime");
      attempted = 1;
    }

  if (runtime_func)
    have_runtime = (*runtime_func) (sw_if_index, rt);
  if (prefix_func)
    (void) (*prefix_func) (sw_if_index, prefix_rt);
  if (consumer_func)
    (void) (*consumer_func) (sw_if_index, consumer_rt);

  return have_runtime;
}

/* Handler for pppoeclient_add_del */
static void
vl_api_pppoeclient_add_del_t_handler (vl_api_pppoeclient_add_del_t *mp)
{
  vl_api_pppoeclient_add_del_reply_t *rmp;
  int rv = 0;
  pppoeclient_main_t *pem = &pppoeclient_main;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vnet_pppoeclient_add_del_args_t a = {
    .is_add = mp->is_add,
    .sw_if_index = ntohl (mp->sw_if_index),
    .host_uniq = ntohl (mp->host_uniq),
    .ac_name_filter =
      pppoeclient_api_dup_fixed_string (mp->configured_ac_name, sizeof (mp->configured_ac_name)),
    .service_name = pppoeclient_api_dup_fixed_string (mp->service_name, sizeof (mp->service_name)),
  };

  u32 pppox_sw_if_index = ~0;
  rv = vnet_pppoeclient_add_del (&a, &pppox_sw_if_index);
  vec_free (a.ac_name_filter);
  vec_free (a.service_name);

  /* Create reply */
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_PPPOECLIENT_ADD_DEL_REPLY + pem->msg_id_base);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  rmp->pppox_sw_if_index = htonl (pppox_sw_if_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* Send client details */
static void
send_pppoeclient_details (pppoe_client_t *t, vl_api_registration_t *reg, u32 context)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  vl_api_pppoeclient_details_t *rmp;
  pppox_virtual_interface_t *vif = 0;
  u32 unit = ~0;
  u8 unit_from_hw = 0;
  ip6_address_t observed_local_ip6 = { 0 };
  u8 observed_prefix_len = 0;
  u8 observed_local_present = 0;
  const ip6_address_t *ipv6cp_local_ip6 = &t->ip6_addr;
  const ip6_address_t *ipv6cp_peer_ip6 = &t->ip6_peer_addr;
  dhcp6_ia_na_client_runtime_t dhcp6_ia_na_rt = { 0 };
  dhcp6_pd_client_runtime_t dhcp6_pd_rt = { 0 };
  dhcp6_pd_active_prefix_runtime_t dhcp6_pd_prefix_rt = { 0 };
  dhcp6_pd_consumer_runtime_t dhcp6_pd_consumer_rt = { 0 };
  mac_address_t ac_mac = { 0 };
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_PPPOECLIENT_DETAILS + pem->msg_id_base);
  rmp->context = context;
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->host_uniq = htonl (t->host_uniq);
  rmp->pppox_sw_if_index = htonl (t->pppox_sw_if_index);
  rmp->session_id = htons (t->session_id);
  rmp->client_state = t->state;
  rmp->use_peer_ipv6 = t->use_peer_ipv6;
  rmp->use_peer_dns = t->use_peer_dns;
  rmp->add_default_route4 = t->use_peer_route4;
  rmp->add_default_route6 = t->use_peer_route6;
  rmp->mtu = htonl (t->mtu);
  rmp->mru = htonl (t->mru);
  rmp->timeout = htonl (t->timeout);

  /* Session statistics */
  rmp->total_reconnects = htonl (t->total_reconnects);
  rmp->last_disconnect_reason = t->last_disconnect_reason;
  if (t->state == PPPOE_CLIENT_SESSION && t->session_start_time > 0)
    rmp->session_uptime_seconds =
      htonl ((u32) (vlib_time_now (pem->vlib_main) - t->session_start_time));
  else
    rmp->session_uptime_seconds = 0;

  clib_memcpy (&ac_mac, t->ac_mac_address, sizeof (ac_mac));
  mac_address_encode (&ac_mac, rmp->ac_mac_address);
  pppoeclient_copy_api_vec_string (rmp->ac_name, sizeof (rmp->ac_name), t->ac_name);
  pppoeclient_copy_api_vec_string (rmp->configured_ac_name, sizeof (rmp->configured_ac_name),
				   t->ac_name_filter);
  pppoeclient_copy_api_vec_string (rmp->service_name, sizeof (rmp->service_name), t->service_name);
  pppoeclient_copy_api_vec_string (rmp->auth_user, sizeof (rmp->auth_user), t->username);

  vif =
    pppoeclient_api_get_detail_virtual_interface (pem, t, t - pem->clients, &unit, &unit_from_hw);
  rmp->pppox_unit = htonl (unit);
  if (vif)
    {
      rmp->pppox_session_allocated = vif->pppoe_session_allocated;
      ip4_address_encode ((ip4_address_t *) &vif->our_addr, rmp->ipv4_local);
      ip4_address_encode ((ip4_address_t *) &vif->his_addr, rmp->ipv4_peer);
      if (ip6_address_is_zero (&t->ip6_addr))
	ipv6cp_local_ip6 = &vif->our_ipv6;
      if (ip6_address_is_zero (&t->ip6_peer_addr))
	ipv6cp_peer_ip6 = &vif->his_ipv6;
    }

  ip4_address_encode ((ip4_address_t *) &t->dns1, rmp->peer_dns4_primary);
  ip4_address_encode ((ip4_address_t *) &t->dns2, rmp->peer_dns4_secondary);
  ip6_address_encode (ipv6cp_local_ip6, rmp->ipv6cp_local);
  ip6_address_encode (ipv6cp_peer_ip6, rmp->ipv6cp_peer);

  observed_local_present = pppoeclient_api_get_global_ipv6 (
    t->pppox_sw_if_index, &observed_local_ip6, &observed_prefix_len);
  if (observed_local_present)
    {
      rmp->wan_ipv6_observed = 1;
      rmp->wan_ipv6_prefix_len = observed_prefix_len;
      ip6_address_encode (&observed_local_ip6, rmp->wan_ipv6);
    }
  rmp->peer_host_route6 = !ip6_address_is_zero (ipv6cp_peer_ip6);

  if (pppoeclient_api_get_dhcp6_ia_na (t->pppox_sw_if_index, &dhcp6_ia_na_rt))
    {
      if (dhcp6_ia_na_rt.dns_server_count > 0)
	{
	  rmp->peer_dns6_count = dhcp6_ia_na_rt.dns_server_count;
	  ip6_address_encode (&dhcp6_ia_na_rt.dns_servers[0], rmp->peer_dns6_primary);
	  if (dhcp6_ia_na_rt.dns_server_count > 1)
	    ip6_address_encode (&dhcp6_ia_na_rt.dns_servers[1], rmp->peer_dns6_secondary);
	}
      rmp->dhcp6_ia_na_enabled = dhcp6_ia_na_rt.enabled;
      rmp->dhcp6_ia_na_rebinding = dhcp6_ia_na_rt.rebinding;
      rmp->dhcp6_ia_na_server_index = htonl (dhcp6_ia_na_rt.server_index);
      rmp->dhcp6_ia_na_address_count = htonl (dhcp6_ia_na_rt.address_count);
      rmp->dhcp6_ia_na_t1 = htonl (dhcp6_ia_na_rt.T1);
      rmp->dhcp6_ia_na_t2 = htonl (dhcp6_ia_na_rt.T2);
      rmp->dhcp6_ia_na_t1_remaining = htonl (dhcp6_ia_na_rt.t1_remaining);
      rmp->dhcp6_ia_na_t2_remaining = htonl (dhcp6_ia_na_rt.t2_remaining);
      if (dhcp6_ia_na_rt.first_address_present)
	{
	  rmp->dhcp6_ia_na_first_address_present = 1;
	  ip6_address_encode (&dhcp6_ia_na_rt.first_address, rmp->dhcp6_ia_na_first_address);
	  rmp->dhcp6_ia_na_first_address_preferred_lt =
	    htonl (dhcp6_ia_na_rt.first_address_preferred_lt);
	  rmp->dhcp6_ia_na_first_address_valid_lt = htonl (dhcp6_ia_na_rt.first_address_valid_lt);
	}
    }

  if (pppoeclient_api_get_dhcp6_pd (t->pppox_sw_if_index, &dhcp6_pd_rt, &dhcp6_pd_prefix_rt,
				    &dhcp6_pd_consumer_rt))
    {
      rmp->dhcp6_pd_enabled = dhcp6_pd_rt.enabled;
      rmp->dhcp6_pd_rebinding = dhcp6_pd_rt.rebinding;
      pppoeclient_copy_api_string (rmp->dhcp6_pd_prefix_group, sizeof (rmp->dhcp6_pd_prefix_group),
				   (u8 *) dhcp6_pd_rt.prefix_group);
      rmp->dhcp6_pd_server_index = htonl (dhcp6_pd_rt.server_index);
      rmp->dhcp6_pd_prefix_count = htonl (dhcp6_pd_rt.prefix_count);
      rmp->dhcp6_pd_t1 = htonl (dhcp6_pd_rt.T1);
      rmp->dhcp6_pd_t2 = htonl (dhcp6_pd_rt.T2);
      rmp->dhcp6_pd_t1_remaining = htonl (dhcp6_pd_rt.t1_remaining);
      rmp->dhcp6_pd_t2_remaining = htonl (dhcp6_pd_rt.t2_remaining);

      if (dhcp6_pd_prefix_rt.present)
	{
	  rmp->dhcp6_delegated_prefix.len = dhcp6_pd_prefix_rt.prefix_length;
	  ip6_address_encode (&dhcp6_pd_prefix_rt.prefix, rmp->dhcp6_delegated_prefix.address);
	  rmp->dhcp6_delegated_prefix_present = 1;
	  rmp->dhcp6_delegated_prefix_preferred_lt = htonl (dhcp6_pd_prefix_rt.preferred_lt);
	  rmp->dhcp6_delegated_prefix_valid_lt = htonl (dhcp6_pd_prefix_rt.valid_lt);
	  rmp->dhcp6_delegated_prefix_valid_remaining = htonl (dhcp6_pd_prefix_rt.valid_remaining);
	}

      if (dhcp6_pd_consumer_rt.present)
	{
	  rmp->dhcp6_pd_consumer_present = 1;
	  rmp->dhcp6_pd_consumer_sw_if_index = htonl (dhcp6_pd_consumer_rt.sw_if_index);
	  ip6_address_encode (&dhcp6_pd_consumer_rt.address, rmp->dhcp6_pd_consumer_address);
	  rmp->dhcp6_pd_consumer_prefix_len = dhcp6_pd_consumer_rt.prefix_length;
	  rmp->dhcp6_pd_consumer_count = htonl (dhcp6_pd_consumer_rt.consumer_count);
	}
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

/* Handler for pppoeclient_dump */
static void
vl_api_pppoeclient_dump_t_handler (vl_api_pppoeclient_dump_t *mp)
{
  vl_api_registration_t *reg;
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *t;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == 0)
    {
      return;
    }

  pool_foreach (t, pem->clients)
    {
      if (sw_if_index != ~0 && t->sw_if_index != sw_if_index)
	continue;

      send_pppoeclient_details (t, reg, mp->context);
    }
}

/* Handler for pppoeclient_set_options */
static void
vl_api_pppoeclient_set_options_t_handler (vl_api_pppoeclient_set_options_t *mp)
{
  vl_api_pppoeclient_set_options_reply_t *rmp;
  int rv = 0;
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = ntohl (mp->pppoeclient_index);
  pppoe_client_t *c;
  u8 *username = 0, *password = 0;
  u8 sync_live_auth = 0;
  uword n;

  vl_api_registration_t *reg;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (pool_is_free_index (pem->clients, client_index))
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto reply;
    }

  c = pool_elt_at_index (pem->clients, client_index);

  /* Username */
  n = clib_strnlen ((const char *) mp->username, sizeof (mp->username));
  if (n > 0)
    {
      vec_validate (username, n - 1);
      clib_memcpy (username, mp->username, n);
      vec_free (c->username);
      c->username = username;
      sync_live_auth = 1;
    }

  /* Password */
  n = clib_strnlen ((const char *) mp->password, sizeof (mp->password));
  if (n > 0)
    {
      vec_validate (password, n - 1);
      clib_memcpy (password, mp->password, n);
      vec_free (c->password);
      c->password = password;
      sync_live_auth = 1;
    }

  /* MTU / MRU — clamp to PPPoE maximum (1492) */
  {
    u32 mtu = ntohl (mp->mtu);
    u32 mru = ntohl (mp->mru);
    u32 timeout = ntohl (mp->timeout);
    if (mtu > 0)
      c->mtu = clib_min (mtu, 1492);
    if (mru > 0)
      c->mru = clib_min (mru, 1492);
    if (timeout > 0)
      c->timeout = timeout;
  }

  /* Flags — assign directly so the caller can both set and clear. */
  c->use_peer_dns = !!mp->use_peer_dns;
  c->use_peer_route4 = !!mp->add_default_route4;
  c->use_peer_route6 = !!mp->add_default_route6;

  /* Sync live state */
  rv = sync_pppoe_client_live_default_route4 (c);
  if (rv == 0)
    rv = sync_pppoe_client_live_default_route6 (c);
  if (rv == 0)
    rv = sync_pppoe_client_live_use_peer_dns (c);
  if (rv == 0 && sync_live_auth)
    rv = sync_pppoe_client_live_auth (c);

reply:
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_PPPOECLIENT_SET_OPTIONS_REPLY + pem->msg_id_base);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  vl_api_send_msg (reg, (u8 *) rmp);
}

/* Handler for pppoeclient_session_action */
static void
vl_api_pppoeclient_session_action_t_handler (vl_api_pppoeclient_session_action_t *mp)
{
  vl_api_pppoeclient_session_action_reply_t *rmp;
  int rv = 0;
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = ntohl (mp->pppoeclient_index);

  vl_api_registration_t *reg;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (pool_is_free_index (pem->clients, client_index))
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto reply;
    }

  switch (mp->action)
    {
    case PPPOECLIENT_SESSION_ACTION_RESTART:
      pppoe_client_restart_session (client_index);
      break;
    case PPPOECLIENT_SESSION_ACTION_STOP:
      pppoe_client_stop_session (client_index);
      break;
    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
      break;
    }

reply:
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_PPPOECLIENT_SESSION_ACTION_REPLY + pem->msg_id_base);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  vl_api_send_msg (reg, (u8 *) rmp);
}

/* Include auto-generated API code */
#include <pppoeclient/pppoeclient.api.c>

/* API setup hook */
static clib_error_t *
pppoeclient_api_hookup (vlib_main_t *vm)
{
  pppoeclient_main_t *pem = &pppoeclient_main;

  pem->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (pppoeclient_api_hookup);

/*
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
