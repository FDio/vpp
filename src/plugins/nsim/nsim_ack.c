/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* Optional TCP ACK coalescing. Parsing and flow lookup are entirely outside
 * the protocol-independent batching path unless explicitly configured. */

#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/tcp/tcp_packet.h>
#include <nsim/nsim.h>

typedef struct
{
  ip46_address_t src;
  ip46_address_t dst;
  u32 sw_if_index;
  u16 src_port;
  u16 dst_port;
  u8 is_ip6;
  u8 pad[7];
} nsim_ack_key_t;

STATIC_ASSERT (sizeof (nsim_ack_key_t) == sizeof (((clib_bihash_kv_48_8_t *) 0)->key),
	       "ACK flow key must fill the bihash key");

static_always_inline int
nsim_ack_options_are_safe (const tcp_header_t *tcp, u16 tcp_hlen)
{
  const u8 *option = (const u8 *) (tcp + 1);
  u16 left = tcp_hlen - sizeof (*tcp);

  while (left)
    {
      u8 kind = option[0];

      if (kind == TCP_OPTION_EOL)
	return 1;
      if (kind == TCP_OPTION_NOOP)
	{
	  option++;
	  left--;
	  continue;
	}
      if (left < 2 || option[1] < 2 || option[1] > left)
	return 0;
      /* A newer cumulative ACK supersedes timestamp-only ACKs. Preserve SACK,
       * authentication and all unknown options. */
      if (kind != TCP_OPTION_TIMESTAMP || option[1] != TCP_OPTION_LEN_TIMESTAMP)
	return 0;
      left -= option[1];
      option += option[1];
    }
  return 1;
}

static_always_inline nsim_ack_parse_result_t
nsim_ack_parse_tcp (vlib_buffer_t *b, nsim_ack_info_t *info, u8 *ip, u32 ip_len, u32 ip_hlen,
		    u8 protocol, u8 is_ip6, const ip46_address_t *src, const ip46_address_t *dst,
		    u32 sw_if_index)
{
  tcp_header_t *tcp;
  nsim_ack_key_t *key = (nsim_ack_key_t *) info->kv.key;
  u32 tcp_hlen;

  if (protocol != IP_PROTOCOL_TCP || ip_len < ip_hlen + sizeof (*tcp) ||
      (uword) (ip + ip_hlen + sizeof (*tcp)) >
	(uword) vlib_buffer_get_current (b) + b->current_length)
    return NSIM_ACK_PARSE_NONE;
  tcp = (tcp_header_t *) (ip + ip_hlen);
  tcp_hlen = tcp_header_bytes (tcp);
  if (tcp_hlen < sizeof (*tcp) ||
      (uword) tcp + tcp_hlen > (uword) vlib_buffer_get_current (b) + b->current_length)
    return NSIM_ACK_PARSE_NONE;

  clib_memset (info, 0, sizeof (*info));
  key->src = *src;
  key->dst = *dst;
  key->sw_if_index = sw_if_index;
  key->src_port = tcp->src_port;
  key->dst_port = tcp->dst_port;
  key->is_ip6 = is_ip6;
  info->ack_number = clib_net_to_host_u32 (tcp->ack_number);
  /* Preserve payload, control packets, SACK/DSACK and ECN transitions. The
   * barrier also prevents a later ACK from moving ahead of such a packet. */
  if (ip_len != ip_hlen + tcp_hlen || tcp->flags != TCP_FLAG_ACK ||
      !nsim_ack_options_are_safe (tcp, tcp_hlen))
    return NSIM_ACK_PARSE_BARRIER;
  return NSIM_ACK_PARSE_CANDIDATE;
}

nsim_ack_parse_result_t
nsim_ack_parse (vlib_buffer_t *b, u32 sw_if_index, nsim_ack_info_t *info)
{
  ethernet_header_t *eth = vlib_buffer_get_current (b);
  u8 *current = (u8 *) eth, *ip;
  u32 offset = sizeof (*eth), available = b->current_length;
  u16 type;

  if (available < sizeof (*eth))
    return NSIM_ACK_PARSE_NONE;
  type = clib_net_to_host_u16 (eth->type);
  /* VLAN identifiers are deliberately absent from the compact flow key. Do
   * not risk coalescing identical tuples from separate L2 domains. */
  if (ethernet_frame_is_tagged (type))
    return NSIM_ACK_PARSE_NONE;
  ip = current + offset;

  if (type == ETHERNET_TYPE_IP4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip;
      ip46_address_t src, dst;
      u16 ip_hlen, ip_len;

      if (available < offset + sizeof (*ip4) || ip4->ip_version_and_header_length >> 4 != 4 ||
	  ip4_is_fragment (ip4))
	return NSIM_ACK_PARSE_NONE;
      ip_hlen = ip4_header_bytes (ip4);
      ip_len = clib_net_to_host_u16 (ip4->length);
      if (ip_hlen < sizeof (*ip4) || ip_len > available - offset)
	return NSIM_ACK_PARSE_NONE;
      ip46_address_set_ip4 (&src, &ip4->src_address);
      ip46_address_set_ip4 (&dst, &ip4->dst_address);
      return nsim_ack_parse_tcp (b, info, ip, ip_len, ip_hlen, ip4->protocol, 0, &src, &dst,
				 sw_if_index);
    }
  if (type == ETHERNET_TYPE_IP6)
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip;
      ip6_ext_hdr_chain_t headers;
      ip46_address_t src, dst;
      u32 ip_hlen, ip_len;
      int tcp_index;

      if (available < offset + sizeof (*ip6) ||
	  (clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label) >> 28) != 6)
	return NSIM_ACK_PARSE_NONE;
      ip_len = sizeof (*ip6) + clib_net_to_host_u16 (ip6->payload_length);
      if (ip_len > available - offset)
	return NSIM_ACK_PARSE_NONE;
      src.ip6 = ip6->src_address;
      dst.ip6 = ip6->dst_address;
      tcp_index = ip6_ext_header_walk (b, ip6, IP_PROTOCOL_TCP, &headers);
      if (tcp_index < 0 || headers.eh[tcp_index].protocol != IP_PROTOCOL_TCP)
	return NSIM_ACK_PARSE_NONE;
      for (u32 i = 0; i < tcp_index; i++)
	if (headers.eh[i].protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
	  return NSIM_ACK_PARSE_NONE;
      ip_hlen = headers.eh[tcp_index].offset;
      return nsim_ack_parse_tcp (b, info, ip, ip_len, ip_hlen, IP_PROTOCOL_TCP, 1, &src, &dst,
				 sw_if_index);
    }
  return NSIM_ACK_PARSE_NONE;
}

nsim_ack_state_t *
nsim_ack_state_alloc (u32 wheel_size)
{
  nsim_ack_state_t *state = clib_mem_alloc_aligned (sizeof (*state), CLIB_CACHE_LINE_BYTES);

  clib_memset (state, 0, sizeof (*state));
  clib_bihash_init_48_8 (&state->flows_by_key, "nsim ACK coalescing", 64, 1 << 20);
  vec_validate (state->flow_by_wheel, wheel_size - 1);
  state->initialized = 1;
  return state;
}

void
nsim_ack_state_free (nsim_ack_state_t *state)
{
  if (!state || !state->initialized)
    return;
  clib_bihash_free_48_8 (&state->flows_by_key);
  pool_free (state->flows);
  vec_free (state->flow_by_wheel);
  clib_mem_free (state);
}

void
nsim_ack_release (nsim_ack_state_t *state, u32 wheel_index)
{
  nsim_ack_flow_t *flow;
  u32 flow_index_plus_one;

  if (!state->initialized || (flow_index_plus_one = state->flow_by_wheel[wheel_index]) == 0)
    return;
  flow = pool_elt_at_index (state->flows, flow_index_plus_one - 1);
  clib_bihash_add_del_48_8 (&state->flows_by_key, &flow->kv, 0);
  pool_put (state->flows, flow);
  state->flow_by_wheel[wheel_index] = 0;
}

void
nsim_ack_barrier (nsim_ack_state_t *state, const nsim_ack_info_t *info)
{
  clib_bihash_kv_48_8_t result = info->kv;
  nsim_ack_flow_t *flow;

  if (clib_bihash_search_48_8 (&state->flows_by_key, &result, &result))
    return;
  flow = pool_elt_at_index (state->flows, result.value);
  nsim_ack_release (state, flow->wheel_index);
}

nsim_ack_action_t
nsim_ack_prepare (vlib_main_t *vm, nsim_ack_state_t *state, nsim_wheel_t *wheel,
		  const nsim_ack_info_t *info, u32 buffer_index, f64 release_time)
{
  clib_bihash_kv_48_8_t result = info->kv;
  nsim_ack_flow_t *flow;
  nsim_wheel_entry_t *entry;

  state->candidates++;
  if (clib_bihash_search_48_8 (&state->flows_by_key, &result, &result))
    return NSIM_ACK_EMIT_TRACKED;

  flow = pool_elt_at_index (state->flows, result.value);
  entry = wheel->entries + flow->wheel_index;
  if (release_time == entry->tx_time && seq_gt (info->ack_number, flow->ack_number))
    {
      if (!flow->replaceable)
	{
	  /* Without retaining per-connection history indefinitely, the first ACK
	   * in an opportunity might be a duplicate of the preceding opportunity.
	   * Keep it as an anchor and coalesce only the later advancing ACKs. */
	  nsim_ack_release (state, flow->wheel_index);
	  return NSIM_ACK_EMIT_REPLACEABLE;
	}

      u32 old_buffer_index = entry->buffer_index;

      entry->buffer_index = buffer_index;
      flow->ack_number = info->ack_number;
      vlib_buffer_free_one (vm, old_buffer_index);
      state->coalesced++;
      return NSIM_ACK_REPLACED;
    }

  if (seq_gt (info->ack_number, flow->ack_number))
    {
      /* Keep the older packet scheduled, but track the newest advancing ACK so
       * later ACKs in its release interval can supersede it. */
      nsim_ack_release (state, flow->wheel_index);
      return NSIM_ACK_EMIT_TRACKED;
    }
  nsim_ack_release (state, flow->wheel_index);
  return NSIM_ACK_EMIT_UNTRACKED;
}

void
nsim_ack_track (nsim_ack_state_t *state, const nsim_ack_info_t *info, u32 wheel_index,
		u8 replaceable)
{
  nsim_ack_flow_t *flow;
  u32 flow_index;

  pool_get_zero (state->flows, flow);
  flow_index = flow - state->flows;
  flow->kv = info->kv;
  flow->kv.value = flow_index;
  flow->wheel_index = wheel_index;
  flow->ack_number = info->ack_number;
  flow->replaceable = replaceable;
  if (clib_bihash_add_del_48_8 (&state->flows_by_key, &flow->kv, 1))
    {
      pool_put (state->flows, flow);
      return;
    }
  ASSERT (state->flow_by_wheel[wheel_index] == 0);
  state->flow_by_wheel[wheel_index] = flow_index + 1;
  state->tracked++;
  state->max_active = clib_max (state->max_active, pool_elts (state->flows));
}
