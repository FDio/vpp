/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 RaydoNetworks.

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

static int
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

static int
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

static int
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

static int
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
  vlib_buffer_advance (b, -sizeof (ethernet_header_t));
  ethernet_header_t *e = vlib_buffer_get_current (b);
  e->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_DISCOVERY);
  clib_memcpy (e->src_address, hw->hw_address, sizeof (e->src_address));
  if (is_broadcast)
    {
      memset (e->dst_address, 0xff, sizeof (e->dst_address));
    }
  else
    {
      clib_memcpy (e->dst_address, c->ac_mac_address, sizeof (e->dst_address));
    }

  pppoe = (pppoe_header_t *) (e + 1);
  pppoe->ver_type = PPPOE_VER_TYPE;
  pppoe->code = packet_code;
  pppoe->session_id = clib_host_to_net_u16 (session_id);
  // adding PPPOE tag.
  // TODO: we should make this as helper functions.
  {
    unsigned char *cursor = (unsigned char *) (pppoe + 1);
    u16 tags_len = 0;

    // add empty ServiceName tag.
    {
      pppoe_tag_header_t *pppoe_tag = (pppoe_tag_header_t *) cursor;
      pppoe_tag->type = clib_host_to_net_u16 (PPPOE_TAG_SERVICE_NAME);
      // zero length means we accept any service as specified in RFC 2516.
      pppoe_tag->length = 0;

      tags_len += sizeof (pppoe_tag_header_t);
      cursor += sizeof (pppoe_tag_header_t);
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
    b->current_length = sizeof (ethernet_header_t) + sizeof (pppoe_header_t) + tags_len;
  }

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
   * State machine "DISCOVERY" state. Send a PADI packet,
   * eventually back off the retry rate.
   */
  send_pppoe_pkt (pem, c, PPPOE_PADI, 0, 1 /* is_broadcast */);

  c->retry_count++;
  if (c->retry_count > 10)
    c->next_transmit = now + 5.0;
  else
    c->next_transmit = now + 1.0;
  return 0;
}

static int
pppoeclient_request_state (pppoeclient_main_t *pem, pppoe_client_t *c, f64 now)
{
  /*
   * State machine "REQUEST" state. Send a PADR packet,
   * eventually drop back to the discovery state.
   */
  send_pppoe_pkt (pem, c, PPPOE_PADR, 0, 0 /* is_broadcast */);

  c->retry_count++;
  if (c->retry_count > 7 /* lucky you */)
    {
      c->state = PPPOE_CLIENT_DISCOVERY;
      c->next_transmit = now;
      c->retry_count = 0;
      return 1;
    }
  c->next_transmit = now + 1.0;
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
    return timeout;

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

void vl_api_rpc_call_main_thread (void *fp, u8 *data, u32 data_length);

static void
pppoe_client_proc_callback (uword *client_index)
{
  vlib_main_t *vm = vlib_get_main ();
  ASSERT (vlib_get_thread_index () == 0);
  vlib_process_signal_event (vm, pppoe_client_process_node.index, EVENT_PPPOE_CLIENT_WAKEUP,
			     *client_index);
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
  while (cur_tag - payload < len)
    {
      tag_type = (cur_tag[0] << 8) + cur_tag[1];
      tag_len = (cur_tag[2] << 8) + cur_tag[3];
      if (tag_type == PPPOE_TAG_END_OF_LIST)
	{
	  return 0;
	}

      if ((cur_tag - payload) + tag_len + sizeof (pppoe_tag_header_t) > len)
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
    case PPPOE_TAG_SERVICE_NAME_ERROR:
    case PPPOE_TAG_AC_SYSTEM_ERROR:
    case PPPOE_TAG_GENERIC_ERROR:
      // nothing need to do currently.
      break;
    case PPPOE_TAG_AC_NAME:
      /* Record AC-Name for debug purposes */
      vec_free (c->ac_name);
      vec_validate (c->ac_name, len - 1);
      clib_memcpy (c->ac_name, data, len);
      break;
    case PPPOE_TAG_AC_COOKIE:
      if (len > ETH_JUMBO_LEN)
	break; /* cookie too large, ignore */
      c->cookie.type = htons (type);
      c->cookie.length = htons (len);
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

  // for pado we locate client through sw_if_index+host_uniq.
  // for pads/padt, we locate client through session id.
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
      // if pado we need parse cookie.
      if (pppoe->code == PPPOE_PADO)
	{
	  parse_pppoe_packet (pppoe, parse_pado_tags, c);
	}
      break;
    case PPPOE_PADT:
      pppoeclient_lookup_session_1 (&pem->session_table, clib_net_to_host_u16 (pppoe->session_id),
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

      vlib_buffer_reset (b);
      eth_hdr = vlib_buffer_get_current (b);

      // record the AC mac address which send us pado.
      // XXX: we might also record ac-name if later needed for
      // debug reason.
      clib_memcpy (c->ac_mac_address, eth_hdr->src_address, 6);

      c->state = PPPOE_CLIENT_REQUEST;
      c->retry_count = 0;
      c->next_transmit = 0; // send immediately.
      /* Poke the client process, which will send the request */
      client_id = c - pem->clients;
      vl_api_rpc_call_main_thread (pppoe_client_proc_callback, (u8 *) &client_id, sizeof (uword));
      break;
    case PPPOE_CLIENT_REQUEST:
      if (packet_code != PPPOE_PADS)
	{
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

      pppoeclient_lookup_session_1 (&pem->session_table, c->session_id, &result);
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
      pppoeclient_update_session_1 (&pem->session_table, c->session_id, &result);
      c->state = PPPOE_CLIENT_SESSION;
      c->retry_count = 0;
      // when shift to session stage, just give control to user
      // and ppp control plane.
      c->next_transmit = now + 4294967295.0;
      // notify pppoe session up.
      static void (*pppox_lower_up_func) (u32) = 0;
      if (pppox_lower_up_func == 0)
	{
	  pppox_lower_up_func = vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_lower_up");
	}
      (*pppox_lower_up_func) (c->pppox_sw_if_index);
      break;

    case PPPOE_CLIENT_SESSION:
      if (pppoe->code != PPPOE_PADT)
	{
	  break;
	}
      // notify ppp the lower is down, then it will try to reconnect.
      static void (*pppox_lower_down_func) (u32) = 0;
      if (pppox_lower_down_func == 0)
	{
	  pppox_lower_down_func = vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_lower_down");
	}
      (*pppox_lower_down_func) (c->pppox_sw_if_index);
      // delete from session table and clear session_id.
      pppoeclient_delete_session_1 (&pem->session_table, c->session_id);
      c->session_id = 0;
      // move state to discovery and transmit immediately.
      c->next_transmit = 0;
      c->retry_count = 0;
      c->state = PPPOE_CLIENT_DISCOVERY;
      /* Poke the client process, which will send the request */
      client_id = c - pem->clients;
      vl_api_rpc_call_main_thread (pppoe_client_proc_callback, (u8 *) &client_id, sizeof (uword));
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

  if (*unit != ~0 && *unit < vec_len (pom->virtual_interfaces))
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

static void
show_pppoe_client_detail_one (vlib_main_t *vm, pppoe_client_t *c)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  u32 client_index = c - pem->clients;
  pppox_virtual_interface_t *t = 0;
  u32 unit = ~0;
  u8 unit_from_hw = 0;

  t = pppoe_client_get_detail_virtual_interface (pem, c, client_index, &unit, &unit_from_hw);

  vlib_cli_output (vm, "[%u] sw-if-index %u (%U) host-uniq %u", client_index, c->sw_if_index,
		   format_vnet_sw_if_index_name, pem->vnet_main, c->sw_if_index, c->host_uniq);
  vlib_cli_output (vm, "    client-state %U session-id %u ac-mac %U", format_pppoe_client_state,
		   c->state, c->session_id, format_ethernet_address, c->ac_mac_address);
  if (c->ac_name)
    vlib_cli_output (vm, "    ac-name %v", c->ac_name);
  else
    vlib_cli_output (vm, "    ac-name <none>");
  if (t)
    {
      vlib_cli_output (vm, "    pppox-sw-if-index %u (%U) pppox-unit %u session-allocated %u",
		       c->pppox_sw_if_index, format_vnet_sw_if_index_name, pem->vnet_main,
		       c->pppox_sw_if_index, unit, t->pppoe_session_allocated);
      vlib_cli_output (vm, "    ipv4 local %U peer %U", format_ip4_address, &t->our_addr,
		       format_ip4_address, &t->his_addr);
      {
	ip6_address_t observed_local_ip6;
	u8 observed_prefix_len = 0;
	u8 observed_local_present = 0;
	const ip6_address_t *ipv6cp_local_ip6 =
	  ip6_address_is_zero (&c->ip6_addr) ? &t->our_ipv6 : &c->ip6_addr;
	const ip6_address_t *ipv6cp_peer_ip6 =
	  ip6_address_is_zero (&c->ip6_peer_addr) ? &t->his_ipv6 : &c->ip6_peer_addr;
	const ip6_address_t *local_ip6 = ipv6cp_local_ip6;
	const ip6_address_t *peer_ip6 = ipv6cp_peer_ip6;
	u8 prefix_len = c->ipv6_prefix_len;
	const char *ipv6_source = "unset";

	observed_local_present = pppoe_client_get_detail_global_ipv6 (
	  c->pppox_sw_if_index, &observed_local_ip6, &observed_prefix_len);

	if (observed_local_present)
	  {
	    local_ip6 = &observed_local_ip6;
	    prefix_len = observed_prefix_len;
	    ipv6_source = "pppox-interface-address";
	  }
	else if (!ip6_address_is_zero (local_ip6) || !ip6_address_is_zero (peer_ip6))
	  {
	    if (prefix_len == 0)
	      prefix_len = 64;
	    ipv6_source = "ipv6cp-link-local";
	  }

	vlib_cli_output (vm, "    ipv6 local %U/%u peer %U use-peer-ipv6 %u", format_ip6_address,
			 local_ip6, prefix_len, format_ip6_address, peer_ip6, c->use_peer_ipv6);
	vlib_cli_output (
	  vm, "    ipv6 source %s peer-host-route %u default-route4 %u default-route6 %u",
	  ipv6_source, !ip6_address_is_zero (peer_ip6), c->use_peer_route4, c->use_peer_route6);

	if (observed_local_present &&
	    (!ip6_address_is_zero (ipv6cp_local_ip6) || !ip6_address_is_zero (ipv6cp_peer_ip6)))
	  vlib_cli_output (vm, "    ipv6cp link-local local %U peer %U", format_ip6_address,
			   ipv6cp_local_ip6, format_ip6_address, ipv6cp_peer_ip6);
      }
    }
  else if (unit != ~0)
    vlib_cli_output (vm, "    pppox-sw-if-index %u (%U) pppox-unit %u detail-source %s",
		     c->pppox_sw_if_index, format_vnet_sw_if_index_name, pem->vnet_main,
		     c->pppox_sw_if_index, unit, unit_from_hw ? "hw-dev-instance" : "sw-if-map");
  else
    vlib_cli_output (vm, "    pppox-sw-if-index %u pppox-unit unavailable", c->pppox_sw_if_index);
  if (c->dns1)
    vlib_cli_output (vm, "    peer-dns primary %U", format_ip4_address, &c->dns1);
  else
    vlib_cli_output (vm, "    peer-dns primary <none>");
  if (c->dns2)
    vlib_cli_output (vm, "    peer-dns secondary %U", format_ip4_address, &c->dns2);
  else
    vlib_cli_output (vm, "    peer-dns secondary <none>");
  if (c->username)
    vlib_cli_output (vm,
		     "    auth-user %v mtu %u mru %u timeout %u use-peer-dns %u add-default-route4 "
		     "%u add-default-route6 %u",
		     c->username, c->mtu, c->mru, c->timeout, c->use_peer_dns, c->use_peer_route4,
		     c->use_peer_route6);
  else
    vlib_cli_output (vm,
		     "    auth-user <unset> mtu %u mru %u timeout %u use-peer-dns %u "
		     "add-default-route4 %u add-default-route6 %u",
		     c->mtu, c->mru, c->timeout, c->use_peer_dns, c->use_peer_route4,
		     c->use_peer_route6);
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

  c = pool_elt_at_index (pem->clients, client_index);

  c->state = PPPOE_CLIENT_DISCOVERY;
  c->next_transmit = 0;
  c->retry_count = 0;
  vlib_process_signal_event (vm, pppoe_client_process_node.index, EVENT_PPPOE_CLIENT_WAKEUP,
			     c - pem->clients);

  return;
}

__clib_export void
pppoe_client_close_session (u32 client_index)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  vlib_main_t *vm = pem->vlib_main;
  pppox_main_t *pom = get_pppox_main ();
  pppoe_client_t *c;
  u32 unit = ~0;

  if (pool_is_free_index (pem->clients, client_index))
    return;

  c = pool_elt_at_index (pem->clients, client_index);

  // Try to send a PADT to notify remote AC (note we can't ensure this
  // message is delivered.
  if (c->session_id)
    {
      send_pppoe_pkt (pem, c, PPPOE_PADT, c->session_id, 0 /* is_broadcast */);
      pppoeclient_delete_session_1 (&pem->session_table, c->session_id);
      c->session_id = 0;
    }

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

  c->dns1 = 0;
  c->dns2 = 0;
  ip6_address_set_zero (&c->ip6_addr);
  ip6_address_set_zero (&c->ip6_peer_addr);
  c->ipv6_prefix_len = 0;
  c->use_peer_ipv6 = 0;
  c->next_transmit = 0;
  c->retry_count = 0;
  c->state = PPPOE_CLIENT_DISCOVERY;
  vlib_process_signal_event (vm, pppoe_client_process_node.index, EVENT_PPPOE_CLIENT_WAKEUP,
			     client_index);

  return;
}

#define foreach_copy_field                                                                         \
  _ (sw_if_index)                                                                                  \
  _ (host_uniq)

int
vnet_pppoe_add_del_client (vnet_pppoe_add_del_client_args_t *a, u32 *pppox_sw_if_index)
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
      memset (c, 0, sizeof (*c));

      /* copy from arg structure */
#define _(x) c->x = a->x;
      foreach_copy_field;
#undef _

      // TODO: assure interface is ethernet hardware interface.
      sw = vnet_get_sw_interface_or_null (vnm, a->sw_if_index);
      if (sw == NULL)
	{
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
	    pool_put (pem->clients, c);
	    return VNET_API_ERROR_INVALID_INTERFACE;
	  }
      }

      result.fields.client_index = c - pem->clients;
      pppoeclient_update_1 (&pem->client_table, a->sw_if_index, a->host_uniq, &result);

      // Allocate pppox interface.
      // TODO: vpp does not allow plugin dependencies, we use the hard coded way to do that.
      // finally we should add new cli to pppox plugin and assosicate the pppox virtual interface
      // and pppoeclient.
      static u32 (*pppox_allocate_interface_func) (u32) = 0;
      if (pppox_allocate_interface_func == 0)
	{
	  pppox_allocate_interface_func =
	    vlib_get_plugin_symbol ("pppox_plugin.so", "pppox_allocate_interface");
	}
      if (pppox_allocate_interface_func == 0)
	{
	  return VNET_API_ERROR_UNSUPPORTED;
	}
      pppox_hw_if_index = (*pppox_allocate_interface_func) (result.fields.client_index);
      c->pppox_hw_if_index = pppox_hw_if_index;
      vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, pppox_hw_if_index);
      c->pppox_sw_if_index = *pppox_sw_if_index = hi->sw_if_index;
      vec_validate_init_empty (pem->client_index_by_pppox_sw_if_index, *pppox_sw_if_index, ~0);
      pem->client_index_by_pppox_sw_if_index[*pppox_sw_if_index] = result.fields.client_index;

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
      (*pppox_free_interface_func) (c->pppox_hw_if_index);

      pppoeclient_delete_1 (&pem->client_table, a->sw_if_index, a->host_uniq);

      pem->client_index_by_pppox_sw_if_index[c->pppox_sw_if_index] = ~0;

      pool_put (pem->clients, c);
    }

  return 0;
}

static clib_error_t *
pppoe_add_del_client_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 sw_if_index = ~0;
  u32 host_uniq = 0;
  u8 host_uniq_set = 0;
  u8 sw_if_index_set = 0;
  int rv;
  vnet_pppoe_add_del_client_args_t _a, *a = &_a;
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

  memset (a, 0, sizeof (*a));

  a->is_add = is_add;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _

  rv = vnet_pppoe_add_del_client (a, &pppox_sw_if_index);

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
      error = clib_error_return (0, "vnet_pppoe_add_del_client returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Add or delete a PPPPOE client.
 *
 * @cliexpar
 * Example of how to create a PPPPOE client:
 * @cliexcmd{create pppoe client sw-if-index 0 host-uniq 1323567}
 * Example of how to delete a PPPPOE client:
 * @cliexcmd{create pppoe client sw-if-index 0 host-uniq 1323567 del}
 ?*/
VLIB_CLI_COMMAND (create_pppoe_client_command, static) = {
  .path = "create pppoe client",
  .short_help = "create pppoe client sw-if-index <nn> host-uniq <nn> [del]",
  .function = pppoe_add_del_client_command_fn,
};
static clib_error_t *
show_pppoe_client_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
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
 * Display detailed PPPPOE client entries.
 *
 * @cliexpar
 * Example of how to display detailed PPPPOE client entries:
 * @cliexstart{show pppoe client}
 * [0] host_uniq sw-if-index 0 status ???
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (show_pppoe_client_command, static) = {
  .path = "show pppoe client",
  .short_help = "show pppoe client",
  .function = show_pppoe_client_command_fn,
};
static clib_error_t *
show_pppoe_client_detail_command_fn (vlib_main_t *vm, unformat_input_t *input,
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
      show_pppoe_client_detail_one (vm, t);
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
VLIB_CLI_COMMAND (show_pppoe_client_detail_command, static) = {
  .path = "show pppoe client detail",
  .short_help = "show pppoe client detail",
  .function = show_pppoe_client_detail_command_fn,
};
static clib_error_t *
set_pppoe_client_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *c = NULL;
  u32 client_index = ~0;
  u8 *username = NULL;
  u8 *password = NULL;
  u32 mtu = 0;
  u32 mru = 0;
  u32 timeout = 0;
  u8 use_peer_dns = 0;
  u8 add_default_route4 = 0;
  u8 add_default_route6 = 0;
  u8 sync_live_auth = 0;
  int rv;
  // u32 ip4_addr = 0;
  // u32 ip4_netmask = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &client_index))
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

  if (client_index == ~0)
    return clib_error_return (0, "please specify client index");

  if (pool_is_free_index (pem->clients, client_index))
    return clib_error_return (0, "invalid client index");

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
  if (mtu > 0)
    c->mtu = mtu;
  if (mru > 0)
    c->mru = mru;
  if (timeout > 0)
    c->timeout = timeout;
  if (use_peer_dns)
    c->use_peer_dns = 1;
  if (add_default_route4)
    c->use_peer_route4 = 1;
  if (add_default_route6)
    c->use_peer_route6 = 1;

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

  vlib_cli_output (vm, "PPPoE client %u updated", client_index);
  return 0;
}
VLIB_CLI_COMMAND (set_pppoe_client_command, static) = {
  .path = "set pppoe client",
  .short_help =
    "set pppoe client <index> username <user> password <pass> [mtu <n>] [mru <n>] [timeout <n>] "
    "[use-peer-dns] [add-default-route | add-default-route4 | add-default-route6]",
  .function = set_pppoe_client_command_fn,
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
  BV (clib_bihash_init)
  (&pem->client_table, "pppoe client table", PPPOE_CLIENT_NUM_BUCKETS, PPPOE_CLIENT_MEMORY_SIZE);
  BV (clib_bihash_init)
  (&pem->session_table, "pppoe client_session table", PPPOE_CLIENT_NUM_BUCKETS,
   PPPOE_CLIENT_MEMORY_SIZE);

  /* Initialize packet template for PPPoE discovery packets */
  packet_data = 0;
  vec_validate (packet_data, sizeof (ethernet_header_t) + sizeof (pppoe_header_t) - 1);
  eth = (ethernet_header_t *) packet_data;
  eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_DISCOVERY);
  memset (eth->dst_address, 0, 6);
  memset (eth->src_address, 0, 6);
  pppoe = (pppoe_header_t *) (eth + 1);
  pppoe->ver_type = PPPOE_VER_TYPE;
  pppoe->code = 0;
  pppoe->session_id = 0;
  pppoe->length = 0;

  vlib_packet_template_init (vm, &pem->packet_template, packet_data, vec_len (packet_data), 4,
			     "pppoe-discovery-packet");
  vec_free (packet_data);

  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_DISCOVERY,
				pppoeclient_discovery_input_node.index);
  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_SESSION,
				pppoeclient_session_input_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (pppoeclient_init);
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "PPPoEClient",
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
