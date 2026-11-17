/* SPDX-License-Identifier: Apache-2.0 */
/*
 *------------------------------------------------------------------
 * pppoeclient_api.c - pppoe client api
 *
 * Copyright (c) 2017 RaydoNetworks.
 * Copyright (c) 2026 Jiajun Liang.
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

#include <pppoeclient/pppox/pppox.h>
#include <dhcp/dhcp6_ia_na_client_dp.h>
#include <dhcp/dhcp6_pd_client_dp.h>
#include <pppoeclient/pppoeclient.h>
#include <pppoeclient/pppoeclient.api_types.h>
#include <pppoeclient/pppoeclient.api_enum.h>

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

/* Copy a length-prefixed (not necessarily NUL-terminated) event string into
 * a fixed-size API reply field.  Unlike copy_api_string this never reads
 * past src_len bytes, so it is safe for event structs whose fixed arrays
 * are filled with an exact-length memcpy (no trailing NUL). */
static void
pppoeclient_copy_api_event_string (u8 *dst, uword dst_size, const u8 *src, uword src_len)
{
  uword n;

  if (dst == 0 || dst_size == 0)
    return;

  dst[0] = 0;
  if (src == 0 || src_len == 0)
    return;

  n = clib_min (src_len, dst_size - 1);
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
pppoeclient_api_get_detail_virtual_interface (pppoeclient_main_t *pem, pppoeclient_t *c,
					      u32 client_index, u32 *unit, u8 *unit_from_hw)
{
  pppox_main_t *pom = &pppox_main;
  pppox_virtual_interface_t *t = 0;

  *unit = ~0;
  *unit_from_hw = 0;

  if (c->pppox_sw_if_index == ~0)
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
	  *unit_from_hw = 1;
	}
    }

  if (*unit != ~0 && *unit < vec_len (pom->virtual_interfaces) &&
      !pool_is_free_index (pom->virtual_interfaces, *unit))
    {
      pppox_virtual_interface_t *candidate = pool_elt_at_index (pom->virtual_interfaces, *unit);

      if (candidate->sw_if_index == c->pppox_sw_if_index &&
	  candidate->pppoeclient_index == client_index)
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

  /* foreach_ip_interface_address() dereferences
   * vnet_get_sw_interface() without bounds checking - pre-validate so a
   * stale pppox_sw_if_index cannot index the interface pool out of
   * bounds. */
  if (vnet_get_sw_interface_or_null (pppoeclient_main.vnet_main, sw_if_index) == 0)
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

  /* Accessor returns 0 on success and 1 when the client is not enabled;
   * a snapshot is available either way, rt->enabled carries the state. */
  (void) (*func) (sw_if_index, rt);
  return 1;
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
    {
      (void) (*runtime_func) (sw_if_index, rt);
      have_runtime = 1;
    }
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
  u32 pppox_sw_if_index = ~0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  u32 mtu = ntohl (mp->mtu);
  u32 mru = ntohl (mp->mru);
  u32 timeout = ntohl (mp->timeout);

  if (mp->is_add &&
      ((mtu > 0 && (mtu < 576 || mtu > 0xFFFF)) || (mru > 0 && (mru < 576 || mru > 0xFFFF)) ||
       (timeout > 0 && timeout > 86400) ||
       clib_strnlen ((const char *) mp->username, sizeof (mp->username)) >= sizeof (mp->username) ||
       clib_strnlen ((const char *) mp->password, sizeof (mp->password)) >= sizeof (mp->password)))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }

  vnet_pppoeclient_add_del_args_t a = {
    .is_add = mp->is_add,
    .sw_if_index = ntohl (mp->sw_if_index),
    .host_uniq = ntohl (mp->host_uniq),
    .ac_name_filter =
      pppoeclient_api_dup_fixed_string (mp->configured_ac_name, sizeof (mp->configured_ac_name)),
    .service_name = pppoeclient_api_dup_fixed_string (mp->service_name, sizeof (mp->service_name)),
    .custom_ifname =
      pppoeclient_api_dup_fixed_string (mp->custom_ifname, sizeof (mp->custom_ifname)),
    .username = pppoeclient_api_dup_fixed_string (mp->username, sizeof (mp->username)),
    .password = pppoeclient_api_dup_fixed_string (mp->password, sizeof (mp->password)),
    .mtu = mtu,
    .mru = mru,
    .timeout = timeout,
    .use_peer_dns = !!mp->use_peer_dns,
    .add_default_route4 = !!mp->add_default_route4,
    .add_default_route6 = !!mp->add_default_route6,
  };

  rv = vnet_pppoeclient_add_del (&a, &pppox_sw_if_index);
  vec_free (a.ac_name_filter);
  vec_free (a.service_name);
  vec_free (a.custom_ifname);
  if (a.username)
    clib_memset (a.username, 0, vec_len (a.username));
  vec_free (a.username);
  if (a.password)
    clib_memset (a.password, 0, vec_len (a.password));
  vec_free (a.password);

reply:
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
send_pppoeclient_details (pppoeclient_t *t, vl_api_registration_t *reg, u32 context)
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
  rmp->pppoeclient_index = htonl ((u32) (t - pem->clients));
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->host_uniq = htonl (t->host_uniq);
  rmp->pppox_sw_if_index = htonl (t->pppox_sw_if_index);
  rmp->session_id = htons (t->session_id);
  rmp->client_state = pppoeclient_control_client_state_from_client_state (t->state);
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
  rmp->consecutive_auth_failures = htonl (t->consecutive_auth_failures);
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

static void
send_pppoeclient_control_history_details (pppoeclient_control_event_t *event,
					  vl_api_registration_t *reg, u32 context,
					  u32 pppoeclient_index, u8 orphan)
{
  vl_api_pppoeclient_control_history_details_t *rmp;
  mac_address_t peer_mac = { 0 };
  f64 now = vlib_time_now (pppoeclient_main.vlib_main);
  uword raw_len;
  uword cookie_value_len;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    htons (VL_API_PPPOECLIENT_CONTROL_HISTORY_DETAILS + pppoeclient_main.msg_id_base);
  rmp->context = context;
  rmp->pppoeclient_index = htonl (pppoeclient_index);
  rmp->orphan = orphan;
  f64 age_ms = clib_max (0.0, (now - event->event_time) * 1000.0);
  rmp->age_msec = htonl ((u32) clib_min (age_ms, (f64) ~0U));
  rmp->sw_if_index = htonl (event->sw_if_index);
  rmp->session_id = htons (event->session_id);
  rmp->code = event->code;
  rmp->client_state = event->client_state;
  rmp->disposition = event->disposition;
  rmp->match_reason = event->match_reason;
  rmp->match_score = event->match_score;
  rmp->candidate_count = event->candidate_count;
  rmp->top_match_count = event->top_match_count;
  rmp->top_match_reason = event->top_match_reason;
  rmp->top_match_score = event->top_match_score;
  rmp->host_uniq_present = event->host_uniq_present;
  rmp->host_uniq = htonl (event->host_uniq);
  rmp->cookie_len = htons (event->cookie_len);
  rmp->cookie_value_truncated = event->cookie_value_truncated;
  rmp->error_tag_type = htons (event->error_tag_type);
  rmp->parse_error = event->parse_error;
  rmp->raw_tags_truncated = event->raw_tags_truncated;
  cookie_value_len = clib_min ((uword) event->cookie_value_len, sizeof (rmp->cookie_value));
  rmp->cookie_value_len = htonl ((u32) cookie_value_len);
  raw_len = clib_min ((uword) event->raw_tags_len, sizeof (rmp->raw_tags));
  rmp->raw_tags_len = htonl ((u32) raw_len);

  clib_memcpy (&peer_mac, event->peer_mac, sizeof (peer_mac));
  mac_address_encode (&peer_mac, rmp->peer_mac);
  pppoeclient_copy_api_event_string (rmp->service_name, sizeof (rmp->service_name),
				     event->service_name, event->service_name_len);
  rmp->service_name_truncated = event->service_name_truncated;
  pppoeclient_copy_api_event_string (rmp->ac_name, sizeof (rmp->ac_name), event->ac_name,
				     event->ac_name_len);
  rmp->ac_name_truncated = event->ac_name_truncated;
  if (cookie_value_len > 0)
    clib_memcpy (rmp->cookie_value, event->cookie_value, cookie_value_len);
  if (raw_len > 0)
    clib_memcpy (rmp->raw_tags, event->raw_tags, raw_len);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
pppoeclient_dump_control_history_ring (pppoeclient_control_event_t *history, u8 count, u8 next,
				       vl_api_registration_t *reg, u32 context,
				       u32 pppoeclient_index, u8 orphan)
{
  u8 start, i;

  if (history == 0 || count == 0)
    return;

  start = (next + PPPOECLIENT_CONTROL_HISTORY_LEN - count) % PPPOECLIENT_CONTROL_HISTORY_LEN;
  for (i = 0; i < count; i++)
    {
      u8 index = (start + i) % PPPOECLIENT_CONTROL_HISTORY_LEN;
      send_pppoeclient_control_history_details (&history[index], reg, context, pppoeclient_index,
						orphan);
    }
}

/* Handler for pppoeclient_dump */
static void
vl_api_pppoeclient_dump_t_handler (vl_api_pppoeclient_dump_t *mp)
{
  vl_api_registration_t *reg;
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoeclient_t *t;
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

/* Handler for pppoeclient_control_history_dump */
static void
vl_api_pppoeclient_control_history_dump_t_handler (vl_api_pppoeclient_control_history_dump_t *mp)
{
  vl_api_registration_t *reg;
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = ntohl (mp->pppoeclient_index);
  pppoeclient_t *c;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == 0)
    return;

  if (mp->orphan)
    {
      pppoeclient_dump_control_history_ring (
	&pem->orphan_control_history[0], pem->orphan_control_history_count,
	pem->orphan_control_history_next, reg, mp->context, ~0, 1);
      return;
    }

  if (client_index == ~0)
    {
      pool_foreach (c, pem->clients)
	{
	  pppoeclient_dump_control_history_ring (c->control_history, c->control_history_count,
						 c->control_history_next, reg, mp->context,
						 (u32) (c - pem->clients), 0);
	}
      return;
    }

  if (pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);
  pppoeclient_dump_control_history_ring (c->control_history, c->control_history_count,
					 c->control_history_next, reg, mp->context, client_index,
					 0);
}

/* Handler for pppoeclient_control_history_clear */
static void
vl_api_pppoeclient_control_history_clear_t_handler (vl_api_pppoeclient_control_history_clear_t *mp)
{
  vl_api_pppoeclient_control_history_clear_reply_t *rmp;
  int rv = 0;
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = ntohl (mp->pppoeclient_index);
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->orphan)
    {
      pppoeclient_clear_control_history (pem->orphan_control_history,
					 &pem->orphan_control_history_count,
					 &pem->orphan_control_history_next);
      goto reply;
    }

  if (pool_is_free_index (pem->clients, client_index))
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto reply;
    }

  pppoeclient_t *c = pool_elt_at_index (pem->clients, client_index);
  pppoeclient_clear_control_history (c->control_history, &c->control_history_count,
				     &c->control_history_next);

reply:
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_PPPOECLIENT_CONTROL_HISTORY_CLEAR_REPLY + pem->msg_id_base);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  vl_api_send_msg (reg, (u8 *) rmp);
}

/* Handler for pppoeclient_set_options */
static void
vl_api_pppoeclient_set_options_t_handler (vl_api_pppoeclient_set_options_t *mp)
{
  vl_api_pppoeclient_set_options_reply_t *rmp;
  int rv = 0;
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = ntohl (mp->pppoeclient_index);
  pppoeclient_t *c;
  u8 *username = 0, *password = 0;
  u8 sync_live_auth = 0;
  uword n_user, n_pass;
  u32 mtu, mru, timeout, rediscovery_cooldown;

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

  /* Validate every numeric and string option before touching any client state
   * so a rejected request cannot leave a partially-applied configuration.
   * PPP MTU/MRU are 16-bit on the wire; the actual interface MTU is set by
   * pppd during LCP negotiation (RFC 2516 default is 1492 for standard
   * Ethernet). */
  mtu = ntohl (mp->mtu);
  mru = ntohl (mp->mru);
  timeout = ntohl (mp->timeout);
  rediscovery_cooldown = ntohl (mp->rediscovery_cooldown);
  n_user = clib_strnlen ((const char *) mp->username, sizeof (mp->username));
  n_pass = clib_strnlen ((const char *) mp->password, sizeof (mp->password));
  if ((mtu > 0 && (mtu < 576 || mtu > 0xFFFF)) || (mru > 0 && (mru < 576 || mru > 0xFFFF)))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }
  if ((timeout > 0 && timeout > 86400) || rediscovery_cooldown > 300)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }
  if (n_user >= sizeof (mp->username) || n_pass >= sizeof (mp->password))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }

  /* Username */
  if (n_user > 0)
    {
      vec_validate (username, n_user - 1);
      clib_memcpy (username, mp->username, n_user);
      if (c->username)
	clib_memset (c->username, 0, vec_len (c->username));
      vec_free (c->username);
      c->username = username;
      sync_live_auth = 1;
    }

  /* Password */
  if (n_pass > 0)
    {
      vec_validate (password, n_pass - 1);
      clib_memcpy (password, mp->password, n_pass);
      if (c->password)
	clib_memset (c->password, 0, vec_len (c->password));
      vec_free (c->password);
      c->password = password;
      sync_live_auth = 1;
    }

  if (mtu > 0)
    {
      c->mtu = mtu;
      if (c->pppox_sw_if_index != ~0)
	pppox_set_configured_mtu (c->pppox_sw_if_index, mtu);
    }
  if (mru > 0)
    {
      c->mru = mru;
      /* Propagate to pppox so LCP negotiation requests this MRU, matching
       * the CLI `set pppoe client ... mru` path. */
      if (c->pppox_sw_if_index != ~0)
	pppox_set_configured_mru (c->pppox_sw_if_index, (u16) mru);
    }
  if (timeout > 0)
    c->timeout = timeout;
  if (rediscovery_cooldown > 0)
    c->rediscovery_cooldown = rediscovery_cooldown;

  /* Flags — only overwrite when the caller explicitly opts in via the
   * matching set_* sentinel, so callers can patch one field without
   * clobbering the others. */
  if (mp->set_use_peer_dns)
    c->use_peer_dns = !!mp->use_peer_dns;
  if (mp->set_add_default_route4)
    c->use_peer_route4 = !!mp->add_default_route4;
  if (mp->set_add_default_route6)
    c->use_peer_route6 = !!mp->add_default_route6;

  /* AC-Name filter — clear takes precedence over a new value. */
  if (mp->clear_ac_name)
    {
      vec_free (c->ac_name_filter);
      c->ac_name_filter = 0;
    }
  else
    {
      u8 *filter =
	pppoeclient_api_dup_fixed_string (mp->configured_ac_name, sizeof (mp->configured_ac_name));
      if (filter)
	{
	  vec_free (c->ac_name_filter);
	  c->ac_name_filter = filter;
	}
    }

  /* Service-Name — same precedence rule. */
  if (mp->clear_service_name)
    {
      vec_free (c->service_name);
      c->service_name = 0;
    }
  else
    {
      u8 *name = pppoeclient_api_dup_fixed_string (mp->service_name, sizeof (mp->service_name));
      if (name)
	{
	  vec_free (c->service_name);
	  c->service_name = name;
	}
    }

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
      pppoeclient_restart_session (client_index);
      break;
    case PPPOECLIENT_SESSION_ACTION_STOP:
      pppoeclient_stop_session (client_index);
      break;
    case PPPOECLIENT_SESSION_ACTION_OPEN:
      pppoeclient_open_session (client_index);
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
