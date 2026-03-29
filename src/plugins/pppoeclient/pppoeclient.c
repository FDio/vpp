/* SPDX-License-Identifier: Apache-2.0 */
/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 RaydoNetworks.

 * Copyright (c) 2026 Hi-Jiajun.
 *------------------------------------------------------------------
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/unix/plugin.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip/ip_interface.h>
#include <dhcp/dhcp6_ia_na_client_dp.h>
#include <dhcp/dhcp6_pd_client_dp.h>
#include <ppp/packet.h>
#include <pppox/pppox.h>
#include <pppoeclient/pppoeclient.h>

#include <vppinfra/hash.h>
#include <vppinfra/bihash_template.c>

pppoeclient_main_t pppoeclient_main;
static vlib_node_registration_t pppoe_client_process_node;
static pppox_main_t *pppox_main_p = 0;

static pppox_main_t *
get_pppox_main (void)
{
  if (pppox_main_p == 0)
    pppox_main_p = vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_main");

  return pppox_main_p;
}

static void send_pppoe_pkt (pppoeclient_main_t *pem, pppoe_client_t *c, u8 packet_code,
			    u16 session_id, int is_broadcast);

static void
pppoeclient_dispatch_ref (pppoeclient_main_t *pem, u32 sw_if_index)
{
  vec_validate_init_empty (pem->dispatch_refcount_by_sw_if_index, sw_if_index, 0);
  if (pem->dispatch_refcount_by_sw_if_index[sw_if_index]++ == 0)
    vnet_feature_enable_disable ("device-input", "pppoeclient-dispatch", sw_if_index, 1, 0, 0);
}

static void
pppoeclient_dispatch_unref (pppoeclient_main_t *pem, u32 sw_if_index)
{
  if (sw_if_index >= vec_len (pem->dispatch_refcount_by_sw_if_index))
    return;

  if (pem->dispatch_refcount_by_sw_if_index[sw_if_index] == 0)
    return;

  if (--pem->dispatch_refcount_by_sw_if_index[sw_if_index] == 0)
    vnet_feature_enable_disable ("device-input", "pppoeclient-dispatch", sw_if_index, 0, 0, 0);
}

static void
pppoe_client_clear_runtime_state (pppoe_client_t *c)
{
  c->ip4_addr = 0;
  c->ip4_netmask = 0;
  c->ip4_gateway = 0;
  c->dns1 = 0;
  c->dns2 = 0;
  ip6_address_set_zero (&c->ip6_addr);
  ip6_address_set_zero (&c->ip6_peer_addr);
  c->ipv6_prefix_len = 0;
  c->use_peer_ipv6 = 0;
  c->next_transmit = 0;
  c->retry_count = 0;
  c->lcp_state = 0;
  c->lcp_id = 0;
  c->lcp_nak = 0;
  c->ipcp_state = 0;
  c->ipcp_id = 0;
  c->ipv6cp_state = 0;
  c->ipv6cp_id = 0;
  c->discovery_error = 0;
}

static void
pppoe_client_mark_session_down (pppoe_client_t *c)
{
  pppox_main_t *pom = get_pppox_main ();
  u32 unit = ~0;

  if (pom && c->pppox_sw_if_index != ~0 &&
      c->pppox_sw_if_index < vec_len (pom->virtual_interface_index_by_sw_if_index))
    {
      unit = pom->virtual_interface_index_by_sw_if_index[c->pppox_sw_if_index];
      if (unit != ~0 && !pool_is_free_index (pom->virtual_interfaces, unit))
	{
	  pppox_virtual_interface_t *t = pool_elt_at_index (pom->virtual_interfaces, unit);
	  t->pppoe_session_allocated = 0;
	}
    }
}

static void
pppoe_client_teardown_session (pppoe_client_t *c, u8 send_padt)
{
  pppoeclient_main_t *pem = &pppoeclient_main;

  if (c->session_id)
    {
      if (send_padt)
	send_pppoe_pkt (pem, c, PPPOE_PADT, c->session_id, 0 /* is_broadcast */);
      pppoeclient_delete_session_1 (&pem->session_table, c->sw_if_index, c->ac_mac_address,
				    c->session_id);
      c->session_id = 0;
    }

  pppoe_client_mark_session_down (c);
  pppoe_client_clear_runtime_state (c);
}

int
sync_pppoe_client_live_auth (pppoe_client_t *c)
{
  static int (*pppox_set_auth_func) (u32, u8 *, u8 *) = 0;

  if (c->pppox_sw_if_index == ~0 || c->username == 0 || c->password == 0)
    return 0;

  if (pppox_set_auth_func == 0)
    {
      pppox_set_auth_func = vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_set_auth");
    }

  if (pppox_set_auth_func == 0)
    return VNET_API_ERROR_UNSUPPORTED;

  return (*pppox_set_auth_func) (c->pppox_sw_if_index, c->username, c->password);
}

int
sync_pppoe_client_live_default_route4 (pppoe_client_t *c)
{
  static int (*pppox_set_add_default_route4_func) (u32, u8) = 0;

  if (c->pppox_sw_if_index == ~0)
    return 0;

  if (pppox_set_add_default_route4_func == 0)
    {
      pppox_set_add_default_route4_func =
	vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_set_add_default_route4");
    }

  if (pppox_set_add_default_route4_func == 0)
    return VNET_API_ERROR_UNSUPPORTED;

  return (*pppox_set_add_default_route4_func) (c->pppox_sw_if_index, c->use_peer_route4);
}

int
sync_pppoe_client_live_default_route6 (pppoe_client_t *c)
{
  static int (*pppox_set_add_default_route6_func) (u32, u8) = 0;

  if (c->pppox_sw_if_index == ~0)
    return 0;

  if (pppox_set_add_default_route6_func == 0)
    {
      pppox_set_add_default_route6_func =
	vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_set_add_default_route6");
    }

  if (pppox_set_add_default_route6_func == 0)
    return VNET_API_ERROR_UNSUPPORTED;

  return (*pppox_set_add_default_route6_func) (c->pppox_sw_if_index, c->use_peer_route6);
}

int
sync_pppoe_client_live_use_peer_dns (pppoe_client_t *c)
{
  static int (*pppox_set_use_peer_dns_func) (u32, u8) = 0;

  if (c->pppox_sw_if_index == ~0)
    return 0;

  if (pppox_set_use_peer_dns_func == 0)
    {
      pppox_set_use_peer_dns_func =
	vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_set_use_peer_dns");
    }

  if (pppox_set_use_peer_dns_func == 0)
    return VNET_API_ERROR_UNSUPPORTED;

  return (*pppox_set_use_peer_dns_func) (c->pppox_sw_if_index, c->use_peer_dns);
}

__clib_export void
pppoe_client_set_peer_dns (u32 pppox_sw_if_index, u32 dns1, u32 dns2)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *c;
  u32 client_index;

  if (pppox_sw_if_index == ~0 ||
      pppox_sw_if_index >= vec_len (pem->client_index_by_pppox_sw_if_index))
    return;

  client_index = pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index];
  if (client_index == ~0 || pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);
  c->dns1 = dns1;
  c->dns2 = dns2;
}

__clib_export void
pppoe_client_set_ipv6_state (u32 pppox_sw_if_index, const ip6_address_t *ip6_addr,
			     const ip6_address_t *ip6_peer_addr, u8 prefix_len)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *c;
  u32 client_index;

  if (pppox_sw_if_index == ~0 ||
      pppox_sw_if_index >= vec_len (pem->client_index_by_pppox_sw_if_index))
    return;

  client_index = pem->client_index_by_pppox_sw_if_index[pppox_sw_if_index];
  if (client_index == ~0 || pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);

  if (ip6_addr)
    c->ip6_addr = *ip6_addr;
  else
    ip6_address_set_zero (&c->ip6_addr);

  if (ip6_peer_addr)
    c->ip6_peer_addr = *ip6_peer_addr;
  else
    ip6_address_set_zero (&c->ip6_peer_addr);

  c->ipv6_prefix_len = prefix_len;
  c->use_peer_ipv6 = (prefix_len != 0 && !ip6_address_is_zero (&c->ip6_peer_addr));
}

static void
send_pppoe_pkt (pppoeclient_main_t *pem, pppoe_client_t *c, u8 packet_code, u16 session_id,
		int is_broadcast)
{
  vlib_main_t *vm = pem->vlib_main;
  vnet_main_t *vnm = pem->vnet_main;
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, c->sw_if_index);
  vnet_sw_interface_t *sup_sw = vnet_get_sup_sw_interface (vnm, c->sw_if_index);
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, c->sw_if_index);
  vlib_buffer_t *b;
  u32 bi;
  pppoe_header_t *pppoe;
  u32 *to_next;
  vlib_frame_t *f;

  /* Interface(s) down? */
  if ((hw->flags & VNET_HW_INTERFACE_FLAG_LINK_UP) == 0)
    return;
  if ((sup_sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    return;
  if ((sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    return;

  // Use packet template to get buffer (better performance via buffer reuse)
  void *pkt = vlib_packet_template_get_packet (vm, &pem->packet_template, &bi);
  if (pkt == 0)
    {
      clib_warning ("buffer allocation failure");
      c->next_transmit = 0;
      return;
    }

  /* Build a PPPOE discovery pkt from whole cloth */
  b = vlib_get_buffer (vm, bi);

  ASSERT (b->current_data == 0);

  f = vlib_get_frame_to_node (vm, hw->output_node_index);
  {
    static const u8 broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const u8 *dst_address = is_broadcast ? broadcast_mac : c->ac_mac_address;

    pppoe = pppoeclient_push_l2_header (vnm, c->sw_if_index, b, ETHERNET_TYPE_PPPOE_DISCOVERY,
					hw->hw_address, dst_address);
  }

  pppoe->ver_type = PPPOE_VER_TYPE;
  pppoe->code = packet_code;
  pppoe->session_id = clib_host_to_net_u16 (session_id);
  /*
   * Append the PPPoE discovery tags inline so the final packet layout stays
   * explicit at the call site.
   */
  {
    unsigned char *cursor = (unsigned char *) (pppoe + 1);
    u16 tags_len = 0;

    // add ServiceName tag. zero length means "accept any service" per RFC 2516.
    {
      pppoe_tag_header_t *pppoe_tag = (pppoe_tag_header_t *) cursor;
      u16 service_name_len = c->service_name ? vec_len (c->service_name) : 0;
      pppoe_tag->type = clib_host_to_net_u16 (PPPOE_TAG_SERVICE_NAME);
      pppoe_tag->length = clib_host_to_net_u16 (service_name_len);
      if (service_name_len)
	clib_memcpy ((void *) pppoe_tag->value, c->service_name, service_name_len);

      tags_len += sizeof (pppoe_tag_header_t) + service_name_len;
      cursor += sizeof (pppoe_tag_header_t) + service_name_len;
    }

    // adding HOST-UNIQ tag.
    {
      pppoe_tag_header_t *pppoe_tag = (pppoe_tag_header_t *) cursor;
      pppoe_tag->type = clib_host_to_net_u16 (PPPOE_TAG_HOST_UNIQ);
      // host_uniq is a arbitray binary data we choose.
      pppoe_tag->length = clib_host_to_net_u16 (sizeof (c->host_uniq));
      clib_memcpy ((void *) pppoe_tag->value, (void *) &(c->host_uniq), sizeof (c->host_uniq));

      tags_len += sizeof (pppoe_tag_header_t) + sizeof (c->host_uniq);
      cursor += sizeof (pppoe_tag_header_t) + sizeof (c->host_uniq);
    }

    // attach cookie for padr/pads.
    if ((packet_code == PPPOE_PADR || packet_code == PPPOE_PADS) && c->cookie.type)
      {
	clib_memcpy (cursor, &c->cookie,
		     clib_net_to_host_u16 (c->cookie.length) + sizeof (pppoe_tag_header_t));
	tags_len += clib_net_to_host_u16 (c->cookie.length) + sizeof (pppoe_tag_header_t);
      }

    pppoe->length = clib_host_to_net_u16 (tags_len);
    b->current_length =
      pppoeclient_get_l2_encap_len (vnm, c->sw_if_index) + sizeof (pppoe_header_t) + tags_len;

    /* Safety: ensure we haven't overflowed the single-segment buffer. */
    if (PREDICT_FALSE (b->current_length > vlib_buffer_get_default_data_size (vm)))
      {
	clib_warning ("PPPoE discovery pkt too large (%u > %u), dropping", b->current_length,
		      vlib_buffer_get_default_data_size (vm));
	vlib_buffer_free (vm, &bi, 1);
	vlib_frame_free (vm, f);
	return;
      }
  }

  vnet_buffer (b)->sw_if_index[VLIB_TX] = c->sw_if_index;

  /* Enqueue the packet right now */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, hw->output_node_index, f);
}

static int
pppoeclient_discovery_state (pppoeclient_main_t *pem, pppoe_client_t *c, f64 now)
{
  /*
   * State machine "DISCOVERY" state. Send a PADI packet
   * with exponential back-off: 1s → 2s → 4s → 8s → 16s → 30s (cap).
   */
  send_pppoe_pkt (pem, c, PPPOE_PADI, 0, 1 /* is_broadcast */);

  c->retry_count++;

  f64 backoff;
  if (c->retry_count <= 5)
    backoff = (f64) (1 << (c->retry_count - 1)); /* 1, 2, 4, 8, 16 */
  else
    backoff = 30.0; /* cap at 30s */

  c->next_transmit = now + backoff;
  return 0;
}

static int
pppoeclient_request_state (pppoeclient_main_t *pem, pppoe_client_t *c, f64 now)
{
  /*
   * State machine "REQUEST" state. Send a PADR packet
   * with back-off: 1s → 2s → 4s → 8s, then fall back to DISCOVERY.
   */
  send_pppoe_pkt (pem, c, PPPOE_PADR, 0, 0 /* is_broadcast */);

  c->retry_count++;
  if (c->retry_count > 7)
    {
      c->state = PPPOE_CLIENT_DISCOVERY;
      c->next_transmit = now;
      c->retry_count = 0;
      return 1;
    }

  f64 backoff;
  if (c->retry_count <= 4)
    backoff = (f64) (1 << (c->retry_count - 1)); /* 1, 2, 4, 8 */
  else
    backoff = 8.0; /* cap at 8s for REQUEST */

  c->next_transmit = now + backoff;
  return 0;
}

static f64
pppoe_client_sm (f64 now, f64 timeout, uword pool_index)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *c;

  /* deleted, pooched, yadda yadda yadda */
  if (pool_is_free_index (pem->clients, pool_index))
    return timeout;

  c = pool_elt_at_index (pem->clients, pool_index);

  /* Time for us to do something with this client? */
  if (now < c->next_transmit)
    {
      if (c->next_transmit < now + timeout)
	return c->next_transmit - now;
      return timeout;
    }

again:
  switch (c->state)
    {
    case PPPOE_CLIENT_DISCOVERY: /* send a discover */
      if (pppoeclient_discovery_state (pem, c, now))
	goto again;
      break;

    case PPPOE_CLIENT_REQUEST: /* send a request */
      if (pppoeclient_request_state (pem, c, now))
	goto again;
      break;

    case PPPOE_CLIENT_SESSION: /* session allocated */
      // Nothing to be done here since we have set longest timeout.
      break;

    default:
      clib_warning ("pppoe client %d bogus state %d", c - pem->clients, c->state);
      break;
    }

  if (c->next_transmit < now + timeout)
    return c->next_transmit - now;

  return timeout;
}

static_always_inline void
pppoeclient_client_free_resources (pppoe_client_t *c)
{
  vec_free (c->ac_name);
  vec_free (c->ac_name_filter);
  vec_free (c->service_name);
  vec_free (c->username);
  vec_free (c->password);
}

static uword
pppoe_client_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  f64 timeout = 100.0;
  f64 now;
  uword event_type;
  uword *event_data = 0;
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *c;
  int i;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);

      event_type = vlib_process_get_events (vm, &event_data);

      now = vlib_time_now (vm);
      timeout = 100.0;

      switch (event_type)
	{
	case EVENT_PPPOE_CLIENT_WAKEUP:
	  for (i = 0; i < vec_len (event_data); i++)
	    timeout = pppoe_client_sm (now, timeout, event_data[i]);
	  break;

	case ~0:
	  pool_foreach (c, pem->clients)
	    {
	      timeout = pppoe_client_sm (now, timeout, (uword) (c - pem->clients));
	    };
	  if (pool_elts (pem->clients) == 0)
	    timeout = 100.0;
	  break;
	}

      vec_reset_length (event_data);
    }

  /* NOTREACHED */
  return 0;
}

static_always_inline void
pppoe_client_wakeup (uword client_index)
{
  vlib_process_signal_event_mt (vlib_get_main (), pppoe_client_process_node.index,
				EVENT_PPPOE_CLIENT_WAKEUP, client_index);
}

static_always_inline void pppoeclient_cli_trim_c_string (u8 **s);

__clib_export void
pppoe_client_set_auth (u32 client_index, u8 *username, u8 *password)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *c;
  u8 *new_username = 0;
  u8 *new_password = 0;

  if (pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);

  if (username)
    {
      new_username = vec_dup (username);
      pppoeclient_cli_trim_c_string (&new_username);
    }
  if (password)
    {
      new_password = vec_dup (password);
      pppoeclient_cli_trim_c_string (&new_password);
    }

  vec_free (c->username);
  vec_free (c->password);
  c->username = new_username;
  c->password = new_password;
}

static_always_inline void
pppoeclient_cli_trim_c_string (u8 **s)
{
  if (s == 0 || *s == 0)
    return;

  if (vec_len (*s) > 0 && vec_elt (*s, vec_len (*s) - 1) == 0)
    vec_set_len (*s, vec_len (*s) - 1);
}

VLIB_REGISTER_NODE (pppoe_client_process_node, static) = {
  .function = pppoe_client_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "pppoe-client-process",
  .process_log2_n_stack_bytes = 16,
};

int
parse_pppoe_packet (pppoe_header_t *pppoe, parse_func *func, void *extra)
{
  int len = clib_net_to_host_u16 (pppoe->length);
  unsigned char *payload, *cur_tag;
  u16 tag_type, tag_len;

  if (pppoe->ver_type != PPPOE_VER_TYPE)
    {
      return -1;
    }

  if (len > ETH_JUMBO_LEN - sizeof (pppoe_header_t))
    {
      return -1;
    }

  cur_tag = payload = (unsigned char *) (pppoe + 1);
  while (cur_tag - payload + sizeof (pppoe_tag_header_t) <= len)
    {
      tag_type = clib_net_to_host_u16 (*(u16 *) cur_tag);
      tag_len = clib_net_to_host_u16 (*(u16 *) (cur_tag + 2));
      if (tag_type == PPPOE_TAG_END_OF_LIST)
	{
	  return 0;
	}

      if (tag_len > (u16) (len - (cur_tag - payload) - sizeof (pppoe_tag_header_t)))
	{
	  return -1;
	}
      func (tag_type, tag_len, cur_tag + sizeof (pppoe_tag_header_t), extra);
      cur_tag = cur_tag + sizeof (pppoe_tag_header_t) + tag_len;
    }

  return 0;
}

// extra is not used for host uniq.
void
parse_for_host_uniq (u16 type, u16 len, unsigned char *data, void *extra)
{
  u32 *host_uniq = (u32 *) extra;

  if (type == PPPOE_TAG_HOST_UNIQ && len == sizeof (u32))
    {
      // as we send padi, we do not care about byte order.
      clib_memcpy (host_uniq, data, len);
    }
}

void
parse_pado_tags (u16 type, u16 len, unsigned char *data, void *extra)
{
  pppoe_client_t *c = (pppoe_client_t *) extra;

  switch (type)
    {
    case PPPOE_TAG_SERVICE_NAME:
    case PPPOE_TAG_RELAY_SESSION_ID:
    case PPPOE_TAG_PPP_MAX_PAYLOAD:
      break;
    case PPPOE_TAG_SERVICE_NAME_ERROR:
      if (len > 0)
	clib_warning ("PPPoE Service-Name-Error: %.*s", (int) len, data);
      c->discovery_error = PPPOECLIENT_ERROR_SERVICE_NAME_ERROR;
      break;
    case PPPOE_TAG_AC_SYSTEM_ERROR:
      if (len > 0)
	clib_warning ("PPPoE AC-System-Error: %.*s", (int) len, data);
      c->discovery_error = PPPOECLIENT_ERROR_AC_SYSTEM_ERROR;
      break;
    case PPPOE_TAG_GENERIC_ERROR:
      if (len > 0)
	clib_warning ("PPPoE Generic-Error: %.*s", (int) len, data);
      break;
    case PPPOE_TAG_AC_NAME:
      /* Record AC-Name for debug purposes */
      vec_free (c->ac_name);
      if (len > 0)
	{
	  vec_validate (c->ac_name, len - 1);
	  clib_memcpy (c->ac_name, data, len);
	}
      break;
    case PPPOE_TAG_AC_COOKIE:
      if (len > ETH_JUMBO_LEN)
	break; /* cookie too large, ignore */
      c->cookie.type = clib_host_to_net_u16 (type);
      c->cookie.length = clib_host_to_net_u16 (len);
      clib_memcpy (c->cookie.value, data, len);
      break;
    default:
      break;
    }
}

int
consume_pppoe_discovery_pkt (u32 bi, vlib_buffer_t *b, pppoe_header_t *pppoe)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *c;
  f64 now = vlib_time_now (pem->vlib_main);
  u32 sw_if_index = ~0;
  u32 host_uniq = 0;
  pppoe_client_result_t result;
  u8 packet_code;
  ethernet_header_t *eth_hdr;
  uword client_id = ~0;

  // for pado/pads we locate client through sw_if_index+host_uniq.
  // for padt we locate the established session through ingress if + AC MAC + session id.
  packet_code = pppoe->code;
  switch (pppoe->code)
    {
    case PPPOE_PADO:
    case PPPOE_PADS: // for pads, we still have to lookup client by sw_if_index and host_uniq.
      sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      parse_pppoe_packet (pppoe, parse_for_host_uniq, &host_uniq);
      pppoeclient_lookup_1 (&pem->client_table, sw_if_index, host_uniq, &result);
      if (PREDICT_FALSE (result.fields.client_index == ~0))
	{
	  if (pppoe->code == PPPOE_PADS && host_uniq == 0)
	    {
	      pppoe_client_t *candidate = 0;
	      pppoe_client_t *it;

	      pool_foreach (it, pem->clients)
		{
		  if (it->sw_if_index != sw_if_index || it->state != PPPOE_CLIENT_REQUEST)
		    continue;

		  if (candidate)
		    {
		      candidate = 0;
		      break;
		    }

		  candidate = it;
		}

	      if (candidate)
		{
		  c = candidate;
		  result.fields.client_index = c - pem->clients;
		  break;
		}
	    }

	  return 1;
	}

      /* client may be freed by interface type change */
      if (pool_is_free_index (pem->clients, result.fields.client_index))
	{
	  return 1;
	}

      c = pool_elt_at_index (pem->clients, result.fields.client_index);
      break;
    case PPPOE_PADT:
      vlib_buffer_reset (b);
      eth_hdr = vlib_buffer_get_current (b);
      pppoeclient_lookup_session_1 (&pem->session_table, vnet_buffer (b)->sw_if_index[VLIB_RX],
				    eth_hdr->src_address, clib_net_to_host_u16 (pppoe->session_id),
				    &result);
      if (result.fields.client_index == ~0)
	{
	  return 1;
	}

      /* client may be freed by interface type change */
      if (pool_is_free_index (pem->clients, result.fields.client_index))
	{
	  return 1;
	}

      c = pool_elt_at_index (pem->clients, result.fields.client_index);
      break;
    default:
      return 1;
    }

  switch (c->state)
    {
    case PPPOE_CLIENT_DISCOVERY:
      if (packet_code != PPPOE_PADO)
	{
	  c->next_transmit = now + 5.0;
	  break;
	}

      clib_memset (&c->cookie, 0, sizeof (c->cookie));
      vec_free (c->ac_name);
      c->discovery_error = 0;
      parse_pppoe_packet (pppoe, parse_pado_tags, c);

      /* Drop PADO that carried an error tag (RFC 2516 §5.4) */
      if (c->discovery_error)
	{
	  vlib_node_increment_counter (pem->vlib_main, pppoeclient_discovery_input_node.index,
				       c->discovery_error, 1);
	  break;
	}

      if (c->ac_name_filter &&
	  ((c->ac_name == 0) || (vec_len (c->ac_name_filter) != vec_len (c->ac_name)) ||
	   clib_memcmp (c->ac_name_filter, c->ac_name, vec_len (c->ac_name_filter)) != 0))
	{
	  break;
	}

      vlib_buffer_reset (b);
      eth_hdr = vlib_buffer_get_current (b);

      /* Record the selected AC MAC address for the PADR/session stages. */
      clib_memcpy (c->ac_mac_address, eth_hdr->src_address, 6);

      c->state = PPPOE_CLIENT_REQUEST;
      c->retry_count = 0;
      c->next_transmit = 0; // send immediately.
      /* Poke the client process, which will send the request */
      client_id = c - pem->clients;
      pppoe_client_wakeup (client_id);
      break;
    case PPPOE_CLIENT_REQUEST:
      if (packet_code == PPPOE_PADO)
	{
	  c->next_transmit = now;
	  client_id = c - pem->clients;
	  pppoe_client_wakeup (client_id);
	  break;
	}

      if (packet_code != PPPOE_PADS)
	{
	  c->next_transmit = now + 5.0;
	  break;
	}

      /* Check for error tags in PADS (RFC 2516 §5.4) */
      c->discovery_error = 0;
      parse_pppoe_packet (pppoe, parse_pado_tags, c);
      if (c->discovery_error)
	{
	  vlib_node_increment_counter (pem->vlib_main, pppoeclient_discovery_input_node.index,
				       c->discovery_error, 1);
	  c->state = PPPOE_CLIENT_DISCOVERY;
	  c->retry_count = 0;
	  c->next_transmit = now + 5.0;
	  break;
	}

      c->session_id = clib_net_to_host_u16 (pppoe->session_id);
      // RFC 2516 says session id MUST NOT be zero or 0xFFFF.
      if (c->session_id == 0 || c->session_id == 0xFFFF)
	{
	  // session_id  0 which means that the client is
	  // not accepted by AC, turn to retransmit to
	  // hope the AC will accept us if we are lucky.
	  c->next_transmit = now + 5.0;
	  break;
	}

      pppoeclient_lookup_session_1 (&pem->session_table, c->sw_if_index, c->ac_mac_address,
				    c->session_id, &result);
      if (PREDICT_FALSE (result.fields.client_index != ~0))
	{
	  // the session id is used by other client, turn to
	  // request state to fetch a new session id.
	  c->session_id = 0;
	  c->state = PPPOE_CLIENT_REQUEST;
	  c->retry_count = 0;
	  c->next_transmit = 0; // send immediately.
	  break;
	}
      result.fields.client_index = c - pem->clients;
      pppoeclient_update_session_1 (&pem->session_table, c->sw_if_index, c->ac_mac_address,
				    c->session_id, &result);
      c->state = PPPOE_CLIENT_SESSION;
      c->retry_count = 0;
      c->session_start_time = now;
      // when shift to session stage, just give control to user
      // and ppp control plane.
      c->next_transmit = 1e18;
      // notify pppoe session up.
      static void (*pppox_lower_up_func) (u32) = 0;
      if (pppox_lower_up_func == 0)
	{
	  pppox_lower_up_func = vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_lower_up");
	}
      if (pppox_lower_up_func == 0)
	{
	  pppoeclient_delete_session_1 (&pem->session_table, c->sw_if_index, c->ac_mac_address,
					c->session_id);
	  c->session_id = 0;
	  pppoe_client_clear_runtime_state (c);
	  c->state = PPPOE_CLIENT_DISCOVERY;
	  c->retry_count = 0;
	  c->next_transmit = now;
	  client_id = c - pem->clients;
	  pppoe_client_wakeup (client_id);
	  break;
	}
      (*pppox_lower_up_func) (c->pppox_sw_if_index);
      break;

    case PPPOE_CLIENT_SESSION:
      if (pppoe->code != PPPOE_PADT)
	{
	  break;
	}
      vlib_node_increment_counter (pem->vlib_main, pppoeclient_discovery_input_node.index,
				   PPPOECLIENT_ERROR_PADT_RECEIVED, 1);
      c->last_disconnect_reason = PPPOECLIENT_DISCONNECT_PADT;
      c->total_reconnects++;
      // notify ppp the lower is down, then it will try to reconnect.
      static void (*pppox_lower_down_func) (u32) = 0;
      if (pppox_lower_down_func == 0)
	{
	  pppox_lower_down_func = vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_lower_down");
	}
      if (pppox_lower_down_func)
	(*pppox_lower_down_func) (c->pppox_sw_if_index);
      // delete from session table and clear session_id.
      pppoeclient_delete_session_1 (&pem->session_table, c->sw_if_index, c->ac_mac_address,
				    c->session_id);
      c->session_id = 0;
      pppoe_client_clear_runtime_state (c);
      // move state to discovery and transmit immediately.
      c->next_transmit = 0;
      c->retry_count = 0;
      c->state = PPPOE_CLIENT_DISCOVERY;
      /* Poke the client process, which will send the request */
      client_id = c - pem->clients;
      pppoe_client_wakeup (client_id);
      break;
    default:
      break;
    }

  return 0;
}

static u8 *
format_pppoe_client_state (u8 *s, va_list *va)
{
  pppoe_client_state_t state = va_arg (*va, pppoe_client_state_t);
  char *str = "BOGUS!";

  switch (state)
    {
#define _(a)                                                                                       \
  case a:                                                                                          \
    str = #a;                                                                                      \
    break;
      foreach_pppoe_client_state;
#undef _
    default:
      break;
    }

  s = format (s, "%s", str);
  return s;
}

static pppox_virtual_interface_t *
pppoe_client_get_detail_virtual_interface (pppoeclient_main_t *pem, pppoe_client_t *c,
					   u32 client_index, u32 *unit, u8 *unit_from_hw)
{
  pppox_main_t *pom = get_pppox_main ();
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
pppoe_client_get_detail_global_ipv6 (u32 sw_if_index, ip6_address_t *addr, u8 *prefix_len)
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
pppoe_client_get_detail_dhcp6_ia_na (u32 sw_if_index, dhcp6_ia_na_client_runtime_t *rt)
{
  static u8 (*dhcp6_ia_na_client_get_runtime_func) (u32, dhcp6_ia_na_client_runtime_t *) = 0;
  static u8 attempted = 0;

  if (rt == 0)
    return 0;

  clib_memset (rt, 0, sizeof (*rt));

  if (!attempted)
    {
      dhcp6_ia_na_client_get_runtime_func =
	vlib_get_plugin_symbol ("dhcp_plugin.so", "dhcp6_ia_na_client_get_runtime");
      attempted = 1;
    }

  if (dhcp6_ia_na_client_get_runtime_func == 0)
    return 0;

  return (*dhcp6_ia_na_client_get_runtime_func) (sw_if_index, rt);
}

static u8
pppoe_client_get_detail_dhcp6_pd (u32 sw_if_index, dhcp6_pd_client_runtime_t *rt,
				  dhcp6_pd_active_prefix_runtime_t *prefix_rt)
{
  static u8 (*dhcp6_pd_client_get_runtime_func) (u32, dhcp6_pd_client_runtime_t *) = 0;
  static u8 (*dhcp6_pd_client_get_active_prefix_runtime_func) (
    u32, dhcp6_pd_active_prefix_runtime_t *) = 0;
  static u8 attempted = 0;
  u8 have_runtime = 0;

  if (rt == 0 || prefix_rt == 0)
    return 0;

  clib_memset (rt, 0, sizeof (*rt));
  clib_memset (prefix_rt, 0, sizeof (*prefix_rt));

  if (!attempted)
    {
      dhcp6_pd_client_get_runtime_func =
	vlib_get_plugin_symbol ("dhcp_plugin.so", "dhcp6_pd_client_get_runtime");
      dhcp6_pd_client_get_active_prefix_runtime_func =
	vlib_get_plugin_symbol ("dhcp_plugin.so", "dhcp6_pd_client_get_active_prefix_runtime");
      attempted = 1;
    }

  if (dhcp6_pd_client_get_runtime_func)
    have_runtime = (*dhcp6_pd_client_get_runtime_func) (sw_if_index, rt);
  if (dhcp6_pd_client_get_active_prefix_runtime_func)
    (void) (*dhcp6_pd_client_get_active_prefix_runtime_func) (sw_if_index, prefix_rt);

  return have_runtime;
}

static u8
pppoe_client_get_detail_dhcp6_pd_consumer (u32 sw_if_index, dhcp6_pd_consumer_runtime_t *rt)
{
  static u8 (*dhcp6_pd_client_get_consumer_runtime_func) (u32, dhcp6_pd_consumer_runtime_t *) = 0;
  static u8 attempted = 0;

  if (rt == 0)
    return 0;

  clib_memset (rt, 0, sizeof (*rt));

  if (!attempted)
    {
      dhcp6_pd_client_get_consumer_runtime_func =
	vlib_get_plugin_symbol ("dhcp_plugin.so", "dhcp6_pd_client_get_consumer_runtime");
      attempted = 1;
    }

  if (dhcp6_pd_client_get_consumer_runtime_func == 0)
    return 0;

  return (*dhcp6_pd_client_get_consumer_runtime_func) (sw_if_index, rt);
}

static u8 *
format_ppp_phase_name (u8 *s, va_list *args)
{
  static const char *phase_names[] = {
    "DEAD",    "INITIALIZE", "SERIALCONN", "DORMANT",	 "ESTABLISH", "AUTHENTICATE", "CALLBACK",
    "NETWORK", "RUNNING",    "TERMINATE",  "DISCONNECT", "HOLDOFF",   "MASTER",
  };
  int value = va_arg (*args, int);

  if (value >= 0 && value < ARRAY_LEN (phase_names))
    return format (s, "%s", phase_names[value]);

  return format (s, "%d", value);
}

static u8 *
format_ppp_fsm_state_name (u8 *s, va_list *args)
{
  static const char *fsm_state_names[] = {
    "INITIAL",	"STARTING", "CLOSED",  "STOPPED", "CLOSING",
    "STOPPING", "REQSENT",  "ACKRCVD", "ACKSENT", "OPENED",
  };
  int value = va_arg (*args, int);

  if (value >= 0 && value < ARRAY_LEN (fsm_state_names))
    return format (s, "%s", fsm_state_names[value]);

  return format (s, "%d", value);
}

static void
show_pppoeclient_detail_one (vlib_main_t *vm, pppoe_client_t *c)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = c - pem->clients;
  pppox_virtual_interface_t *t = 0;
  u32 unit = ~0;
  u8 unit_from_hw = 0;
  u8 *session_ac_name = 0;
  u8 *configured_ac_name = 0;
  u8 *configured_service_name = 0;
  u8 *configured_auth_user = 0;
  dhcp6_ia_na_client_runtime_t dhcp6_ia_na_rt;
  dhcp6_pd_client_runtime_t dhcp6_pd_rt;
  dhcp6_pd_active_prefix_runtime_t dhcp6_pd_prefix_rt;
  dhcp6_pd_consumer_runtime_t dhcp6_pd_consumer_rt;
  u8 dhcp6_ia_na_available = 0;
  u8 dhcp6_pd_available = 0;
  u8 dhcp6_pd_consumer_available = 0;

  t = pppoe_client_get_detail_virtual_interface (pem, c, client_index, &unit, &unit_from_hw);

  if (c->ac_name)
    session_ac_name = format (0, "%v", c->ac_name);
  else
    session_ac_name = format (0, "<none>");

  if (c->ac_name_filter && vec_len (c->ac_name_filter) > 0)
    configured_ac_name = format (0, "%v", c->ac_name_filter);
  else
    configured_ac_name = format (0, "<any>");

  if (c->service_name && vec_len (c->service_name) > 0)
    configured_service_name = format (0, "%v", c->service_name);
  else
    configured_service_name = format (0, "<any>");

  if (c->username)
    configured_auth_user = format (0, "%v", c->username);
  else
    configured_auth_user = format (0, "<unset>");

  dhcp6_ia_na_available =
    pppoe_client_get_detail_dhcp6_ia_na (c->pppox_sw_if_index, &dhcp6_ia_na_rt);
  dhcp6_pd_available =
    pppoe_client_get_detail_dhcp6_pd (c->pppox_sw_if_index, &dhcp6_pd_rt, &dhcp6_pd_prefix_rt);
  dhcp6_pd_consumer_available =
    pppoe_client_get_detail_dhcp6_pd_consumer (c->pppox_sw_if_index, &dhcp6_pd_consumer_rt);

  vlib_cli_output (vm, "[%u] access-interface %U host-uniq %u", client_index,
		   format_vnet_sw_if_index_name, pem->vnet_main, c->sw_if_index, c->host_uniq);
  vlib_cli_output (vm, "    runtime session-state %U session-id %u ac-mac %U ac-name %v",
		   format_pppoe_client_state, c->state, c->session_id, format_ethernet_address,
		   c->ac_mac_address, session_ac_name);

  if (t)
    {
      ip6_address_t observed_local_ip6;
      u8 observed_prefix_len = 0;
      u8 observed_local_present = 0;
      const ip6_address_t *ipv6cp_local_ip6 =
	ip6_address_is_zero (&c->ip6_addr) ? &t->our_ipv6 : &c->ip6_addr;
      const ip6_address_t *ipv6cp_peer_ip6 =
	ip6_address_is_zero (&c->ip6_peer_addr) ? &t->his_ipv6 : &c->ip6_peer_addr;
      const char *wan_ipv6_mode = "unset";

      observed_local_present = pppoe_client_get_detail_global_ipv6 (
	c->pppox_sw_if_index, &observed_local_ip6, &observed_prefix_len);

      if (observed_local_present)
	wan_ipv6_mode = "global-address-observed";
      else if (!ip6_address_is_zero (ipv6cp_local_ip6) || !ip6_address_is_zero (ipv6cp_peer_ip6))
	wan_ipv6_mode = "link-local-only";

      vlib_cli_output (vm,
		       "    runtime pppox-interface %U sw-if-index %u unit %u session-allocated %u",
		       format_vnet_sw_if_index_name, pem->vnet_main, c->pppox_sw_if_index,
		       c->pppox_sw_if_index, unit, t->pppoe_session_allocated);
      vlib_cli_output (vm, "    runtime ipv4 local %U peer %U", format_ip4_address, &t->our_addr,
		       format_ip4_address, &t->his_addr);
      if (c->dns1)
	vlib_cli_output (vm, "    runtime peer-dns4 primary %U", format_ip4_address, &c->dns1);
      else
	vlib_cli_output (vm, "    runtime peer-dns4 primary <none>");
      if (c->dns2)
	vlib_cli_output (vm, "    runtime peer-dns4 secondary %U", format_ip4_address, &c->dns2);
      else
	vlib_cli_output (vm, "    runtime peer-dns4 secondary <none>");
      if (dhcp6_ia_na_rt.dns_server_count > 0)
	{
	  vlib_cli_output (vm, "    runtime peer-dns6 primary %U", format_ip6_address,
			   &dhcp6_ia_na_rt.dns_servers[0]);
	  if (dhcp6_ia_na_rt.dns_server_count > 1)
	    vlib_cli_output (vm, "    runtime peer-dns6 secondary %U", format_ip6_address,
			     &dhcp6_ia_na_rt.dns_servers[1]);
	  else
	    vlib_cli_output (vm, "    runtime peer-dns6 secondary <none>");
	}
      else
	vlib_cli_output (vm, "    runtime peer-dns6 <none>");
      vlib_cli_output (vm, "    runtime ipv6cp-link-local local %U peer %U", format_ip6_address,
		       ipv6cp_local_ip6, format_ip6_address, ipv6cp_peer_ip6);
      if (observed_local_present)
	vlib_cli_output (vm, "    runtime wan-ipv6 observed %U/%u", format_ip6_address,
			 &observed_local_ip6, observed_prefix_len);
      else
	vlib_cli_output (vm, "    runtime wan-ipv6 observed <none>");
      vlib_cli_output (
	vm, "    runtime wan-ipv6-mode %s peer-host-route %u default-route4 %u default-route6 %u",
	wan_ipv6_mode, !ip6_address_is_zero (ipv6cp_peer_ip6), c->use_peer_route4,
	c->use_peer_route6);
    }
  else if (unit != ~0)
    {
      vlib_cli_output (vm, "    runtime pppox-interface sw-if-index %u unit %u detail-source %s",
		       c->pppox_sw_if_index, unit, unit_from_hw ? "hw-dev-instance" : "sw-if-map");
      vlib_cli_output (vm, "    runtime peer-dns4 primary <none>");
      vlib_cli_output (vm, "    runtime peer-dns4 secondary <none>");
      vlib_cli_output (vm, "    runtime peer-dns6 <none>");
    }
  else
    {
      vlib_cli_output (vm, "    runtime pppox-interface sw-if-index %u unit unavailable",
		       c->pppox_sw_if_index);
      vlib_cli_output (vm, "    runtime peer-dns4 primary <none>");
      vlib_cli_output (vm, "    runtime peer-dns4 secondary <none>");
      vlib_cli_output (vm, "    runtime peer-dns6 <none>");
    }

  if (dhcp6_ia_na_available)
    {
      if (dhcp6_ia_na_rt.enabled)
	{
	  if (dhcp6_ia_na_rt.T1)
	    vlib_cli_output (vm,
			     "    dhcp6 ia-na enabled addresses %u server-index %u T1 %u (%u "
			     "remaining) T2 %u (%u remaining)%s",
			     dhcp6_ia_na_rt.address_count, dhcp6_ia_na_rt.server_index,
			     dhcp6_ia_na_rt.T1, dhcp6_ia_na_rt.t1_remaining, dhcp6_ia_na_rt.T2,
			     dhcp6_ia_na_rt.t2_remaining,
			     dhcp6_ia_na_rt.rebinding ? " REBINDING" : "");
	  else
	    vlib_cli_output (vm, "    dhcp6 ia-na enabled addresses %u%s",
			     dhcp6_ia_na_rt.address_count,
			     dhcp6_ia_na_rt.rebinding ? " REBINDING" : "");
	  if (dhcp6_ia_na_rt.first_address_present)
	    vlib_cli_output (
	      vm, "    dhcp6 ia-na first-address %U/64 preferred-lifetime %u valid-lifetime %u",
	      format_ip6_address, &dhcp6_ia_na_rt.first_address,
	      dhcp6_ia_na_rt.first_address_preferred_lt, dhcp6_ia_na_rt.first_address_valid_lt);
	}
      else
	vlib_cli_output (vm, "    dhcp6 ia-na disabled");
    }
  else
    vlib_cli_output (vm, "    dhcp6 ia-na <unavailable>");

  if (dhcp6_pd_available)
    {
      if (dhcp6_pd_rt.enabled)
	{
	  if (dhcp6_pd_rt.T1)
	    vlib_cli_output (vm,
			     "    dhcp6 pd enabled prefix-group %s prefixes %u server-index %u T1 "
			     "%u (%u remaining) T2 %u (%u remaining)%s",
			     dhcp6_pd_rt.prefix_group[0] ? dhcp6_pd_rt.prefix_group : "<unset>",
			     dhcp6_pd_rt.prefix_count, dhcp6_pd_rt.server_index, dhcp6_pd_rt.T1,
			     dhcp6_pd_rt.t1_remaining, dhcp6_pd_rt.T2, dhcp6_pd_rt.t2_remaining,
			     dhcp6_pd_rt.rebinding ? " REBINDING" : "");
	  else
	    vlib_cli_output (vm, "    dhcp6 pd enabled prefix-group %s prefixes %u%s",
			     dhcp6_pd_rt.prefix_group[0] ? dhcp6_pd_rt.prefix_group : "<unset>",
			     dhcp6_pd_rt.prefix_count, dhcp6_pd_rt.rebinding ? " REBINDING" : "");

	  if (dhcp6_pd_prefix_rt.present)
	    vlib_cli_output (vm,
			     "    dhcp6 delegated-prefix %U/%u preferred-lifetime %u "
			     "valid-lifetime %u (%u remaining)",
			     format_ip6_address, &dhcp6_pd_prefix_rt.prefix,
			     dhcp6_pd_prefix_rt.prefix_length, dhcp6_pd_prefix_rt.preferred_lt,
			     dhcp6_pd_prefix_rt.valid_lt, dhcp6_pd_prefix_rt.valid_remaining);
	  else
	    vlib_cli_output (vm, "    dhcp6 delegated-prefix <none>");

	  if (dhcp6_pd_consumer_available)
	    {
	      if (dhcp6_pd_consumer_rt.present)
		vlib_cli_output (vm, "    dhcp6 pd downstream %U address %U/%u consumers %u",
				 format_vnet_sw_if_index_name, pem->vnet_main,
				 dhcp6_pd_consumer_rt.sw_if_index, format_ip6_address,
				 &dhcp6_pd_consumer_rt.address, dhcp6_pd_consumer_rt.prefix_length,
				 dhcp6_pd_consumer_rt.consumer_count);
	      else
		vlib_cli_output (vm, "    dhcp6 pd downstream <none>");
	    }
	}
      else
	vlib_cli_output (vm, "    dhcp6 pd disabled");
    }
  else
    vlib_cli_output (vm, "    dhcp6 pd <unavailable>");

  vlib_cli_output (vm,
		   "    stored-config ac-name %v service-name %v auth-user %v use-peer-dns4 %u "
		   "add-default-route4 %u add-default-route6 %u",
		   configured_ac_name, configured_service_name, configured_auth_user,
		   c->use_peer_dns, c->use_peer_route4, c->use_peer_route6);
  if (c->mtu || c->mru || c->timeout)
    vlib_cli_output (vm, "    stored-config mtu %u mru %u timeout %u", c->mtu, c->mru, c->timeout);

  vec_free (session_ac_name);
  vec_free (configured_ac_name);
  vec_free (configured_service_name);
  vec_free (configured_auth_user);
}

static void
show_pppoeclient_debug_one (vlib_main_t *vm, pppoe_client_t *c)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = c - pem->clients;
  pppox_virtual_interface_t *t = 0;
  u32 unit = ~0;
  u8 unit_from_hw = 0;
  u8 *configured_ac_name = 0;
  u8 *configured_service_name = 0;
  u8 *configured_auth_user = 0;
  pppox_ppp_debug_runtime_t ppp_debug_rt;
  static u8 (*pppox_get_ppp_debug_runtime_func) (u32, pppox_ppp_debug_runtime_t *) = 0;
  static u8 attempted = 0;

  t = pppoe_client_get_detail_virtual_interface (pem, c, client_index, &unit, &unit_from_hw);

  if (c->ac_name_filter && vec_len (c->ac_name_filter) > 0)
    configured_ac_name = format (0, "%v", c->ac_name_filter);
  else
    configured_ac_name = format (0, "<any>");

  if (c->service_name && vec_len (c->service_name) > 0)
    configured_service_name = format (0, "%v", c->service_name);
  else
    configured_service_name = format (0, "<any>");

  if (c->username)
    configured_auth_user = format (0, "%v", c->username);
  else
    configured_auth_user = format (0, "<unset>");

  clib_memset (&ppp_debug_rt, 0, sizeof (ppp_debug_rt));
  if (!attempted)
    {
      pppox_get_ppp_debug_runtime_func =
	vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_get_ppp_debug_runtime");
      attempted = 1;
    }
  if (pppox_get_ppp_debug_runtime_func)
    (void) (*pppox_get_ppp_debug_runtime_func) (c->pppox_sw_if_index, &ppp_debug_rt);

  vlib_cli_output (vm, "[%u] access-interface %U host-uniq %u", client_index,
		   format_vnet_sw_if_index_name, pem->vnet_main, c->sw_if_index, c->host_uniq);
  vlib_cli_output (vm, "    pppoe state %U session-id %u pppox-sw-if-index %u",
		   format_pppoe_client_state, c->state, c->session_id, c->pppox_sw_if_index);

  if (t && unit != ~0)
    {
      vlib_cli_output (vm,
		       "    pppox unit %u detail-source %s session-allocated %u delete-pending %u",
		       unit, unit_from_hw ? "hw-dev-instance" : "sw-if-map",
		       t->pppoe_session_allocated, t->delete_pending);
      if (ppp_debug_rt.present)
	{
	  vlib_cli_output (vm, "    ppp phase %U lcp %U ipcp %U ipv6cp %U", format_ppp_phase_name,
			   ppp_debug_rt.phase, format_ppp_fsm_state_name, ppp_debug_rt.lcp_state,
			   format_ppp_fsm_state_name, ppp_debug_rt.ipcp_state,
			   format_ppp_fsm_state_name, ppp_debug_rt.ipv6cp_state);
	  vlib_cli_output (vm, "    ppp timeouts lcp %d ipcp %d ipv6cp %d",
			   ppp_debug_rt.lcp_timeout, ppp_debug_rt.ipcp_timeout,
			   ppp_debug_rt.ipv6cp_timeout);
	  vlib_cli_output (vm,
			   "    ipcp requested default-route4 %u req-dns1 %u req-dns2 %u "
			   "negotiated-dns1 %U negotiated-dns2 %U",
			   ppp_debug_rt.default_route4, ppp_debug_rt.req_dns1,
			   ppp_debug_rt.req_dns2, format_ip4_address, &ppp_debug_rt.negotiated_dns1,
			   format_ip4_address, &ppp_debug_rt.negotiated_dns2);
	}
      else
	vlib_cli_output (vm, "    ppp debug-runtime <unavailable>");
    }
  else
    vlib_cli_output (vm, "    pppox unit unavailable");

  vlib_cli_output (vm,
		   "    stored-config ac-name %v service-name %v auth-user %v use-peer-dns4 %u "
		   "add-default-route4 %u add-default-route6 %u",
		   configured_ac_name, configured_service_name, configured_auth_user,
		   c->use_peer_dns, c->use_peer_route4, c->use_peer_route6);
  vlib_cli_output (vm, "    stored-config mtu %u mru %u timeout %u", c->mtu, c->mru, c->timeout);

  vec_free (configured_ac_name);
  vec_free (configured_service_name);
  vec_free (configured_auth_user);
}

u8 *
format_pppoe_client (u8 *s, va_list *args)
{
  pppoe_client_t *c = va_arg (*args, pppoe_client_t *);
  pppoeclient_main_t *pem = &pppoeclient_main;

  s = format (s,
	      "[%u] sw-if-index %u host-uniq %u pppox-sw-if-index %u state %U session-id %u "
	      "ac-mac-address %U",
	      (u32) (c - pem->clients), c->sw_if_index, c->host_uniq, c->pppox_sw_if_index,
	      format_pppoe_client_state, c->state, c->session_id, format_ethernet_address,
	      c->ac_mac_address);
  return s;
}

__clib_export void
pppoe_client_open_session (u32 client_index)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  vlib_main_t *vm = pem->vlib_main;
  pppoe_client_t *c;

  if (pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);

  c->state = PPPOE_CLIENT_DISCOVERY;
  c->next_transmit = 0;
  c->retry_count = 0;
  vlib_process_signal_event (vm, pppoe_client_process_node.index, EVENT_PPPOE_CLIENT_WAKEUP,
			     c - pem->clients);
}

__clib_export void
pppoe_client_restart_session (u32 client_index)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  vlib_main_t *vm = pem->vlib_main;
  pppoe_client_t *c;

  if (pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);
  c->last_disconnect_reason = PPPOECLIENT_DISCONNECT_ADMIN;
  c->total_reconnects++;
  pppoe_client_teardown_session (c, 1 /* send_padt */);
  c->state = PPPOE_CLIENT_DISCOVERY;
  vlib_process_signal_event (vm, pppoe_client_process_node.index, EVENT_PPPOE_CLIENT_WAKEUP,
			     client_index);
}

__clib_export void
pppoe_client_stop_session (u32 client_index)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *c;

  if (pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);
  c->last_disconnect_reason = PPPOECLIENT_DISCONNECT_ADMIN;
  pppoe_client_teardown_session (c, 1 /* send_padt */);
  c->state = PPPOE_CLIENT_DISCOVERY;
  /* Park the client so the process node does not retransmit PADI.
   * open_session or restart_session will reset next_transmit to 0. */
  c->next_transmit = 1e18;
}

#define foreach_copy_field                                                                         \
  _ (sw_if_index)                                                                                  \
  _ (host_uniq)

int
vnet_pppoeclient_add_del (vnet_pppoeclient_add_del_args_t *a, u32 *pppox_sw_if_index)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *c = 0;
  vlib_main_t *vm = pem->vlib_main;
  vnet_main_t *vnm = pem->vnet_main;
  // u32 is_ip6 = a->is_ip6;
  pppoe_client_result_t result;
  u32 pppox_hw_if_index = ~0;
  vnet_sw_interface_t *sw;

  pppoeclient_lookup_1 (&pem->client_table, a->sw_if_index, a->host_uniq, &result);
  if (a->is_add)
    {
      /* adding a client: client must not already exist */
      if (result.fields.client_index != ~0)
	return VNET_API_ERROR_TUNNEL_EXIST;

      pool_get_aligned (pem->clients, c, CLIB_CACHE_LINE_BYTES);
      clib_memset (c, 0, sizeof (*c));

      /* copy from arg structure */
#define _(x) c->x = a->x;
      foreach_copy_field;
#undef _
      c->ac_name_filter = a->ac_name_filter;
      a->ac_name_filter = 0;
      c->service_name = a->service_name;
      a->service_name = 0;

      sw = vnet_get_sw_interface_or_null (vnm, a->sw_if_index);
      if (sw == NULL)
	{
	  pppoeclient_client_free_resources (c);
	  pool_put (pem->clients, c);
	  return VNET_API_ERROR_INVALID_INTERFACE;
	}
      c->hw_if_index = sw->hw_if_index;

      /* Check if interface is an ethernet hardware interface */
      {
	vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, c->hw_if_index);
	vnet_hw_interface_class_t *hw_class = vnet_get_hw_interface_class (vnm, hw->hw_class_index);
	if (hw_class->index != ethernet_hw_interface_class.index)
	  {
	    pppoeclient_client_free_resources (c);
	    pool_put (pem->clients, c);
	    return VNET_API_ERROR_INVALID_INTERFACE;
	  }
      }

      result.fields.client_index = c - pem->clients;

      /*
       * Allocate the paired PPPoX interface via the exported plugin symbol.
       * VPP plugins do not declare hard dependencies, so this lookup remains
       * explicit here.
       */
      static u32 (*pppox_allocate_interface_func) (u32) = 0;
      if (pppox_allocate_interface_func == 0)
	{
	  pppox_allocate_interface_func =
	    vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_allocate_interface");
	}
      if (pppox_allocate_interface_func == 0)
	{
	  pppoeclient_client_free_resources (c);
	  pool_put (pem->clients, c);
	  return VNET_API_ERROR_UNSUPPORTED;
	}
      pppox_hw_if_index = (*pppox_allocate_interface_func) (result.fields.client_index);
      if (pppox_hw_if_index == ~0)
	{
	  pppoeclient_client_free_resources (c);
	  pool_put (pem->clients, c);
	  return VNET_API_ERROR_LIMIT_EXCEEDED;
	}
      c->pppox_hw_if_index = pppox_hw_if_index;
      vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, pppox_hw_if_index);
      c->pppox_sw_if_index = *pppox_sw_if_index = hi->sw_if_index;

      pppoeclient_update_1 (&pem->client_table, a->sw_if_index, a->host_uniq, &result);
      vec_validate_init_empty (pem->client_index_by_pppox_sw_if_index, *pppox_sw_if_index, ~0);
      pem->client_index_by_pppox_sw_if_index[*pppox_sw_if_index] = result.fields.client_index;
      pppoeclient_dispatch_ref (pem, a->sw_if_index);

      // Add the interface output node to pppoeclient_session_output_node if not.
      // And since there will not much physical interface, once added, it will not
      // be removed.
      {
	vnet_hw_interface_t *phy_hi = vnet_get_hw_interface (vnm, c->hw_if_index);
	u32 edge =
	  vlib_node_get_next (vm, pppoeclient_session_output_node.index, phy_hi->output_node_index);
	if (~0 == edge)
	  {
	    c->hw_output_next_index = vlib_node_add_next (vm, pppoeclient_session_output_node.index,
							  phy_hi->output_node_index);
	  }
	else
	  {
	    c->hw_output_next_index = edge;
	  }
      }
      // dispatch is refcounted per access interface.

#if 0 // let pppox decide.
      // Fire the FSM.
      c->state = PPPOE_CLIENT_DISCOVERY;
      vlib_process_signal_event (vm, pppoe_client_process_node.index,
                                 EVENT_PPPOE_CLIENT_WAKEUP, c - pem->clients);
#endif
    }
  else
    {
      /* deleting a client: client must exist */
      if (result.fields.client_index == ~0)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      c = pool_elt_at_index (pem->clients, result.fields.client_index);

      // free pppox interface first to let LCP have a chance to send
      // out lcp termination and also trigger us to send a PADT.
      // Note above operations should be done synchronously in main
      // thread, otherwise the packet might be lost.
      static u32 (*pppox_free_interface_func) (u32) = 0;
      if (pppox_free_interface_func == 0)
	{
	  pppox_free_interface_func =
	    vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_free_interface");
	}
      if (pppox_free_interface_func == 0)
	return VNET_API_ERROR_UNSUPPORTED;

      pppoeclient_dispatch_unref (pem, a->sw_if_index);
      pppoe_client_stop_session (result.fields.client_index);

      // dispatch is refcounted per access interface.

      (*pppox_free_interface_func) (c->pppox_hw_if_index);

      pppoeclient_delete_1 (&pem->client_table, a->sw_if_index, a->host_uniq);

      pem->client_index_by_pppox_sw_if_index[c->pppox_sw_if_index] = ~0;
      pppoeclient_client_free_resources (c);
      pool_put (pem->clients, c);
    }

  return 0;
}

static clib_error_t *
pppoeclient_add_del_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 sw_if_index = ~0;
  u32 host_uniq = 0;
  u8 host_uniq_set = 0;
  u8 sw_if_index_set = 0;
  int rv;
  pppoeclient_main_t *pem = &pppoeclient_main;
  vnet_pppoeclient_add_del_args_t _a, *a = &_a;
  clib_error_t *error = NULL;
  u32 pppox_sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (line_input, "host-uniq %d", &host_uniq))
	{
	  host_uniq_set = 1;
	}
      else if (unformat (line_input, "sw-if-index %d", &sw_if_index))
	{
	  sw_if_index_set = 1;
	}
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface, pem->vnet_main,
			 &sw_if_index))
	{
	  sw_if_index_set = 1;
	}
      else
	{
	  error = clib_error_return (0, "parse error: '%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

  if (host_uniq_set == 0)
    {
      error = clib_error_return (0, "client host uniq not specified");
      goto done;
    }

  if (sw_if_index_set == 0)
    {
      error = clib_error_return (0, "sw if index not specified");
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));

  a->is_add = is_add;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _

  rv = vnet_pppoeclient_add_del (a, &pppox_sw_if_index);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "client already exists...");
      goto done;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "client does not exist...");
      goto done;

    default:
      error = clib_error_return (0, "vnet_pppoeclient_add_del returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Add or delete a PPPoE client.
 *
 * @cliexpar
 * Example of how to create a PPPoE client:
 * @cliexcmd{create pppoe client GigabitEthernet0/0/0 host-uniq 1234}
 * Example of how to delete a PPPoE client:
 * @cliexcmd{create pppoe client sw-if-index 0 host-uniq 1234 del}
 ?*/
VLIB_CLI_COMMAND (create_pppoeclient_command, static) = {
  .path = "create pppoe client",
  .short_help = "create pppoe client <interface>|sw-if-index <nn> host-uniq <nn> [del]",
  .function = pppoeclient_add_del_command_fn,
};

static clib_error_t *
pppoeclient_restart_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &client_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (client_index == ~0)
    return clib_error_return (0, "please specify client index");

  if (pool_is_free_index (pem->clients, client_index))
    return clib_error_return (0, "invalid client index %u", client_index);

  pppoe_client_restart_session (client_index);
  vlib_cli_output (vm, "PPPoE client %u restarted", client_index);
  return 0;
}

/*?
 * Restart a PPPoE client session (sends PADT, then re-enters discovery).
 *
 * @cliexpar
 * @cliexcmd{pppoe client restart 0}
 ?*/
VLIB_CLI_COMMAND (pppoeclient_restart_command, static) = {
  .path = "pppoe client restart",
  .short_help = "pppoe client restart <client-index>",
  .function = pppoeclient_restart_command_fn,
};

static clib_error_t *
pppoeclient_stop_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &client_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  if (client_index == ~0)
    return clib_error_return (0, "please specify client index");

  if (pool_is_free_index (pem->clients, client_index))
    return clib_error_return (0, "invalid client index %u", client_index);

  pppoe_client_stop_session (client_index);
  vlib_cli_output (vm, "PPPoE client %u stopped", client_index);
  return 0;
}

/*?
 * Stop a PPPoE client session (sends PADT, returns to discovery idle).
 *
 * @cliexpar
 * @cliexcmd{pppoe client stop 0}
 ?*/
VLIB_CLI_COMMAND (pppoeclient_stop_command, static) = {
  .path = "pppoe client stop",
  .short_help = "pppoe client stop <client-index>",
  .function = pppoeclient_stop_command_fn,
};

static clib_error_t *
show_pppoeclient_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *t;

  if (pool_elts (pem->clients) == 0)
    vlib_cli_output (vm, "No pppoe clients configured...");

  pool_foreach (t, pem->clients)
    {
      vlib_cli_output (vm, "%U", format_pppoe_client, t);
    };

  return 0;
}
/*?
 * Display detailed PPPoE client entries.
 *
 * @cliexpar
 * Example of how to display detailed PPPoE client entries:
 * @cliexstart{show pppoe client}
 * [0] host_uniq sw-if-index 0 status ???
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (show_pppoeclient_command, static) = {
  .path = "show pppoe client",
  .short_help = "show pppoe client",
  .function = show_pppoeclient_command_fn,
};
static clib_error_t *
show_pppoeclient_detail_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *t;

  if (pool_elts (pem->clients) == 0)
    {
      vlib_cli_output (vm, "No pppoe clients configured...");
      return 0;
    }

  pool_foreach (t, pem->clients)
    {
      show_pppoeclient_detail_one (vm, t);
    }

  return 0;
}

/*?
 * Display detailed client-side PPPoE session state.
 *
 * @cliexpar
 * Example of how to display PPPoE client-side session details:
 * @cliexstart{show pppoe client detail}
 * [0] sw-if-index 1 (TenGigabitEthernet...) host-uniq 1234
 *     client-state PPPOE_CLIENT_SESSION session-id 4660 ac-mac aa:bb:cc:dd:ee:ff
 *     pppox-sw-if-index 2 (pppox0) pppox-unit 0 session-allocated 1
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (show_pppoeclient_detail_command, static) = {
  .path = "show pppoe client detail",
  .short_help = "show pppoe client detail",
  .function = show_pppoeclient_detail_command_fn,
};
static clib_error_t *
show_pppoeclient_debug_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *t;

  if (pool_elts (pem->clients) == 0)
    {
      vlib_cli_output (vm, "No pppoe clients configured...");
      return 0;
    }

  pool_foreach (t, pem->clients)
    {
      show_pppoeclient_debug_one (vm, t);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_pppoeclient_debug_command, static) = {
  .path = "show pppoe client debug",
  .short_help = "show pppoe client debug",
  .function = show_pppoeclient_debug_command_fn,
};
static clib_error_t *
set_pppoeclient_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *c = NULL;
  u32 client_index = ~0;
  u8 *ac_name = NULL;
  u8 *service_name = NULL;
  u8 *username = NULL;
  u8 *password = NULL;
  u32 mtu = 0;
  u32 mru = 0;
  u32 timeout = 0;
  u8 use_peer_dns = 0;
  u8 add_default_route4 = 0;
  u8 add_default_route6 = 0;
  u8 clear_ac_name = 0;
  u8 clear_service_name = 0;
  u8 sync_live_auth = 0;
  u8 route_or_dns_changed = 0;
  int rv;
  // u32 ip4_addr = 0;
  // u32 ip4_netmask = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &client_index))
	;
      else if (unformat (input, "ac-name any"))
	clear_ac_name = 1;
      else if (unformat (input, "ac-name %s", &ac_name))
	;
      else if (unformat (input, "service-name any"))
	clear_service_name = 1;
      else if (unformat (input, "service-name %s", &service_name))
	;
      else if (unformat (input, "username %s", &username))
	;
      else if (unformat (input, "password %s", &password))
	;
      else if (unformat (input, "mtu %u", &mtu))
	;
      else if (unformat (input, "mru %u", &mru))
	;
      else if (unformat (input, "timeout %u", &timeout))
	;
      else if (unformat (input, "use-peer-dns"))
	use_peer_dns = 1;
      else if (unformat (input, "add-default-route4"))
	add_default_route4 = 1;
      else if (unformat (input, "add-default-route6"))
	add_default_route6 = 1;
      else if (unformat (input, "add-default-route"))
	add_default_route4 = add_default_route6 = 1;
      else if (unformat (input, "use-peer-route"))
	add_default_route4 = add_default_route6 = 1;
      else
	break;
    }

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      vec_free (service_name);
      vec_free (ac_name);
      vec_free (username);
      vec_free (password);
      return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  pppoeclient_cli_trim_c_string (&ac_name);
  pppoeclient_cli_trim_c_string (&service_name);
  pppoeclient_cli_trim_c_string (&username);
  pppoeclient_cli_trim_c_string (&password);

  if (client_index == ~0)
    {
      vec_free (service_name);
      vec_free (ac_name);
      vec_free (username);
      vec_free (password);
      return clib_error_return (0, "please specify client index");
    }

  if (pool_is_free_index (pem->clients, client_index))
    {
      vec_free (service_name);
      vec_free (ac_name);
      vec_free (username);
      vec_free (password);
      return clib_error_return (0, "invalid client index");
    }

  c = pool_elt_at_index (pem->clients, client_index);

  if (username)
    {
      vec_free (c->username);
      c->username = username;
      sync_live_auth = 1;
    }
  if (password)
    {
      vec_free (c->password);
      c->password = password;
      sync_live_auth = 1;
    }
  if (service_name)
    {
      vec_free (c->service_name);
      c->service_name = service_name;
    }
  else if (clear_service_name)
    {
      vec_free (c->service_name);
      c->service_name = 0;
    }
  if (ac_name)
    {
      vec_free (c->ac_name_filter);
      c->ac_name_filter = ac_name;
    }
  else if (clear_ac_name)
    {
      vec_free (c->ac_name_filter);
      c->ac_name_filter = 0;
    }
  if (mtu > 0)
    c->mtu = mtu;
  if (mru > 0)
    c->mru = mru;
  if (timeout > 0)
    c->timeout = timeout;
  if (use_peer_dns)
    {
      c->use_peer_dns = 1;
      route_or_dns_changed = 1;
    }
  if (add_default_route4)
    {
      c->use_peer_route4 = 1;
      route_or_dns_changed = 1;
    }
  if (add_default_route6)
    {
      c->use_peer_route6 = 1;
      route_or_dns_changed = 1;
    }

  rv = sync_pppoe_client_live_default_route4 (c);
  if (rv)
    return clib_error_return (0,
			      "failed to sync live add-default-route4 on pppox sw-if-index %u: %d",
			      c->pppox_sw_if_index, rv);

  rv = sync_pppoe_client_live_default_route6 (c);
  if (rv)
    return clib_error_return (0,
			      "failed to sync live add-default-route6 on pppox sw-if-index %u: %d",
			      c->pppox_sw_if_index, rv);

  rv = sync_pppoe_client_live_use_peer_dns (c);
  if (rv)
    return clib_error_return (0, "failed to sync live use-peer-dns on pppox sw-if-index %u: %d",
			      c->pppox_sw_if_index, rv);

  if (sync_live_auth)
    {
      rv = sync_pppoe_client_live_auth (c);
      if (rv)
	return clib_error_return (0, "failed to sync live auth on pppox sw-if-index %u: %d",
				  c->pppox_sw_if_index, rv);
    }

  if (route_or_dns_changed)
    vlib_cli_output (vm,
		     "PPPoE client %u updated (route/DNS state synced; active session may need "
		     "reconnect for full effect)",
		     client_index);
  else
    vlib_cli_output (vm, "PPPoE client %u updated", client_index);
  return 0;
}
VLIB_CLI_COMMAND (set_pppoeclient_command, static) = {
  .path = "set pppoe client",
  .short_help =
    "set pppoe client <index> [ac-name <name>|ac-name any] [service-name <name>|service-name any] "
    "[username <user>] [password <pass>] [mtu <n>] [mru <n>] [timeout <n>] "
    "[use-peer-dns] [add-default-route | add-default-route4 | add-default-route6]",
  .function = set_pppoeclient_command_fn,
};
clib_error_t *
pppoeclient_init (vlib_main_t *vm)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u8 *packet_data;
  ethernet_header_t *eth;
  pppoe_header_t *pppoe;

  pem->vnet_main = vnet_get_main ();
  pem->vlib_main = vm;

  /* Create the hash table  */
  clib_bihash_init_8_8 (&pem->client_table, "pppoe client table", PPPOE_CLIENT_NUM_BUCKETS,
			PPPOE_CLIENT_MEMORY_SIZE);
  clib_bihash_init_16_8 (&pem->session_table, "pppoe client_session table",
			 PPPOE_CLIENT_NUM_BUCKETS, PPPOE_CLIENT_MEMORY_SIZE);

  /* Initialize packet template for PPPoE discovery packets */
  packet_data = 0;
  vec_validate (packet_data, sizeof (ethernet_header_t) + sizeof (pppoe_header_t) - 1);
  eth = (ethernet_header_t *) packet_data;
  eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_DISCOVERY);
  clib_memset (eth->dst_address, 0, 6);
  clib_memset (eth->src_address, 0, 6);
  pppoe = (pppoe_header_t *) (eth + 1);
  pppoe->ver_type = PPPOE_VER_TYPE;
  pppoe->code = 0;
  pppoe->session_id = 0;
  pppoe->length = 0;

  vlib_packet_template_init (vm, &pem->packet_template, packet_data, vec_len (packet_data), 4,
			     "pppoe-discovery-packet");
  vec_free (packet_data);

  /* Keep ethertype registration disabled for now. VPP allows only one
   * plugin to register a given Ethernet type, so PPPoE ingress currently
   * goes through the device-input feature dispatch path in node.c to
   * coexist with the existing pppoe plugin.
   *
   * ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_DISCOVERY,
   * 				pppoeclient_discovery_input_node.index);
   * ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_SESSION,
   * 				pppoeclient_session_input_node.index);
   */

  return 0;
}

VLIB_INIT_FUNCTION (pppoeclient_init);
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "PPPoEClient",
};
/*
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
