/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

/* decap.c : IPSec tunnel decapsulation */

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/feature/feature.h>
#include <vnet/ipsec/ipsec_spd_fp_lookup.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ah.h>
#include <vnet/ipsec/ipsec_io.h>

#define foreach_ipsec_input_error               	\
_(RX_PKTS, "IPSec pkts received")			\
_(RX_POLICY_MATCH, "IPSec policy match")		\
_(RX_POLICY_NO_MATCH, "IPSec policy not matched")	\
_(RX_POLICY_BYPASS, "IPSec policy bypass")		\
_(RX_POLICY_DISCARD, "IPSec policy discard")

typedef enum
{
#define _(sym,str) IPSEC_INPUT_ERROR_##sym,
  foreach_ipsec_input_error
#undef _
    IPSEC_INPUT_N_ERROR,
} ipsec_input_error_t;

static char *ipsec_input_error_strings[] = {
#define _(sym,string) string,
  foreach_ipsec_input_error
#undef _
};

typedef struct
{
  u64 by_policy_type[IPSEC_SPD_POLICY_N_TYPES];
  u64 unprocessed;
} ipsec_input_counters_t;

always_inline void
ipsec4_input_spd_add_flow_cache_entry (ipsec4_flow_cache_bucket_t *tbl, u32 sa, u32 da,
				       ipsec_spd_policy_type_t policy_type, u32 policy_index,
				       u64 flow_cache_mask)
{
  ipsec4_flow_cache_bucket_t *bucket;
  ipsec4_inbound_spd_tuple_t ip4_tuple = {
    .ip4_src_addr = (ip4_address_t) sa,
    .ip4_dest_addr = (ip4_address_t) da,
    .policy_type = policy_type,
    .value = policy_index,
  };

  bucket = tbl + (ipsec4_hash_16_8 (&ip4_tuple.kv_16_8) & flow_cache_mask);

  CLIB_SPINLOCK_LOCK (bucket->writer_lock);
  __atomic_fetch_add (&bucket->seq, 1, __ATOMIC_RELAXED);
  bucket->kv = ip4_tuple.kv_16_8;
  __atomic_fetch_add (&bucket->seq, 1, __ATOMIC_RELEASE);
  CLIB_SPINLOCK_UNLOCK (bucket->writer_lock);
}

always_inline ipsec_policy_t *
ipsec4_input_spd_find_flow_cache_entry (ipsec_main_t *im, ipsec4_flow_cache_bucket_t *tbl, u32 sa,
					u32 da, ipsec_spd_policy_type_t policy_type,
					u64 flow_cache_mask)
{
  ipsec4_hash_kv_16_8_t kv_result;
  ipsec4_flow_cache_bucket_t *bucket;
  ipsec4_inbound_spd_tuple_t ip4_tuple = {
    .ip4_src_addr = (ip4_address_t) sa,
    .ip4_dest_addr = (ip4_address_t) da,
    .policy_type = policy_type,
  };

  bucket = tbl + (ipsec4_hash_16_8 (&ip4_tuple.kv_16_8) & flow_cache_mask);

  while (1)
    {
      u32 seq = __atomic_load_n (&bucket->seq, __ATOMIC_ACQUIRE);
      if (PREDICT_FALSE (seq == 0))
	return 0;
      if (PREDICT_FALSE (seq & 1))
	goto again;

      kv_result = bucket->kv;
      if (PREDICT_FALSE (seq != __atomic_load_n (&bucket->seq, __ATOMIC_ACQUIRE)))
	goto again;
      break;
    again:
      CLIB_PAUSE ();
    }

  if (ipsec4_hash_key_compare_16_8 ((u64 *) &ip4_tuple.kv_16_8, (u64 *) &kv_result))
    return pool_elt_at_index (im->policies, kv_result.value);

  return 0;
}

always_inline void
ipsec_fp_in_5tuple_from_ip4_range (ipsec_fp_5tuple_t *tuple, u32 sa, u32 da,
				   u32 spi, u8 action)
{
  clib_memset (tuple->l3_zero_pad, 0, sizeof (tuple->l3_zero_pad));
  tuple->laddr.as_u32 = da;
  tuple->raddr.as_u32 = sa;
  tuple->spi = spi;
  tuple->action = action;
  tuple->is_ipv6 = 0;
}

always_inline void
ipsec_fp_in_5tuple_from_ip6_range (ipsec_fp_5tuple_t *tuple, ip6_address_t *sa,
				   ip6_address_t *da, u32 spi, u8 action)

{
  clib_memcpy (&tuple->ip6_laddr, da, sizeof (ip6_address_t));
  clib_memcpy (&tuple->ip6_raddr, sa, sizeof (ip6_address_t));

  tuple->spi = spi;
  tuple->action = action;
  tuple->is_ipv6 = 1;
}

always_inline ipsec_policy_t *
ipsec_input_policy_match (ipsec_spd_t *spd, u32 sa, u32 da, u32 spi, ipsec_spd_policy_type_t pt)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_sa_t *s;
  u32 *policy_indices = spd->policies[pt];
  u32 policy_index;
  u32 sah = clib_net_to_host_u32 (sa);
  u32 dah = clib_net_to_host_u32 (da);

  if (pt == IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT)
    {
      ipsec_tun_protect4_t *tp4 = spd->ip4_inbound_tun_protect_policies;
      u32 n_tp4 = vec_len (tp4);
      for (u32 i = 0; i < n_tp4; i++)
	{
	  if (spi != tp4[i].spi)
	    continue;

	  if (dah != tp4[i].da)
	    continue;

	  if (sah != tp4[i].sa)
	    continue;

	  return pool_elt_at_index (im->policies, tp4[i].policy_index);
	}
    }

  policy_index = ipsec_spd_ip4_find_range_match (spd, pt, da, sa);

  if (policy_index == ~0)
    return 0;

  for (; policy_index < vec_len (policy_indices); policy_index++)
    {
      p = pool_elt_at_index (im->policies, policy_indices[policy_index]);
      if (pt == IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT)
	{
	  s = ipsec_sa_get (p->sa_index);

	  if (ipsec_sa_is_set_IS_TUNNEL (s))
	    continue;

	  if (spi != s->spi)
	    continue;
	}

      if (dah < clib_net_to_host_u32 (p->laddr.start.ip4.as_u32))
	continue;

      if (dah > clib_net_to_host_u32 (p->laddr.stop.ip4.as_u32))
	continue;

      if (sah < clib_net_to_host_u32 (p->raddr.start.ip4.as_u32))
	continue;

      if (sah > clib_net_to_host_u32 (p->raddr.stop.ip4.as_u32))
	continue;

      return p;
    }

  return 0;
}

always_inline uword
ip6_addr_match_range (ip6_address_t *a, ip6_address_t *la, ip6_address_t *ua)
{
  if ((memcmp (a->as_u64, la->as_u64, 2 * sizeof (u64)) >= 0) &&
      (memcmp (a->as_u64, ua->as_u64, 2 * sizeof (u64)) <= 0))
    return 1;

  return 0;
}

always_inline ipsec_policy_t *
ipsec6_input_policy_match (ipsec_spd_t *spd, ip6_address_t *sa,
			   ip6_address_t *da,
			   ipsec_spd_policy_type_t policy_type)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  u32 *i;

  vec_foreach (i, spd->policies[policy_type])
  {
    p = pool_elt_at_index (im->policies, *i);

    if (!ip6_addr_match_range (sa, &p->raddr.start.ip6, &p->raddr.stop.ip6))
      continue;

    if (!ip6_addr_match_range (da, &p->laddr.start.ip6, &p->laddr.stop.ip6))
      continue;
    return p;
  }
  return 0;
}

always_inline void
ipsec_collect_ah_trace (vlib_buffer_t **b, vlib_node_runtime_t *node,
			vlib_main_t *vm, ip4_header_t *ip0, ah_header_t *ah0,
			u8 has_space0, ipsec_spd_t *spd0, ipsec_policy_t *p0,
			u32 pi0)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
      PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
    {
      ipsec_input_trace_t *tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));

      tr->proto = ip0->protocol;
      tr->sa_id = p0 ? p0->sa_id : ~0;
      tr->spi = has_space0 ? clib_net_to_host_u32 (ah0->spi) : ~0;
      tr->seq = has_space0 ? clib_net_to_host_u32 (ah0->seq_no) : ~0;
      tr->spd = spd0->id;
      tr->policy_index = pi0;
    }
}

always_inline void
ipsec_ah_packet_process (vlib_main_t *vm, ipsec_main_t *im, ip4_header_t *ip0, ah_header_t *ah0,
			 clib_thread_index_t thread_index, ipsec_spd_t *spd0,
			 ipsec4_flow_cache_bucket_t *flow_cache_tbl, u64 flow_cache_mask,
			 vlib_buffer_t **b, vlib_node_runtime_t *node,
			 ipsec_input_counters_t *counters, u16 *next)

{
  ipsec_policy_t *p0 = NULL;
  u32 da = ip0->dst_address.as_u32;
  u32 sa = ip0->src_address.as_u32;
  u32 spi = clib_net_to_host_u32 (ah0->spi);
  u8 has_space0;

  has_space0 = vlib_buffer_has_space (b[0], (clib_address_t) (ah0 + 1) - (clib_address_t) ip0);

  foreach_int (policy_type, IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT,
	       IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS, IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD)
    {
      bool is_protect = (policy_type == IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT);
      bool is_discard = (policy_type == IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD);
      u32 pi0;

      p0 = flow_cache_mask ? ipsec4_input_spd_find_flow_cache_entry (im, flow_cache_tbl, sa, da,
								     policy_type, flow_cache_mask) :
			     0;
      if (p0 == 0)
      {
	p0 = ipsec_input_policy_match (spd0, sa, da, spi, policy_type);

	if (flow_cache_mask && p0)
	  ipsec4_input_spd_add_flow_cache_entry (flow_cache_tbl, sa, da, policy_type,
						 p0 - im->policies, flow_cache_mask);
      }

      if (PREDICT_FALSE (p0 == NULL))
      continue;

      if (PREDICT_FALSE (is_protect && !has_space0))
      continue;

      pi0 = p0 - im->policies;
      vlib_increment_combined_counter (&ipsec_spd_policy_counters, thread_index, pi0, 1,
				       clib_net_to_host_u16 (ip0->length));
      counters->by_policy_type[policy_type] += 1;

      if (is_protect)
      {
	vnet_buffer (b[0])->ipsec.sad_index = p0->sa_index;
	next[0] = im->ah4_decrypt_next_index;
      }
      else if (is_discard)
      next[0] = IPSEC_INPUT_NEXT_DROP;

      ipsec_collect_ah_trace (b, node, vm, ip0, ah0, has_space0, spd0, p0, pi0);
      return;
    }

  /* Drop by default if no match on PROTECT, BYPASS or DISCARD */
  counters->unprocessed += 1;
  next[0] = IPSEC_INPUT_NEXT_DROP;
  return;
}

always_inline void
ipsec_esp_packet_process (vlib_main_t *vm, ipsec_main_t *im, ip4_header_t *ip0, udp_header_t *udp0,
			  esp_header_t *esp0, clib_thread_index_t thread_index, ipsec_spd_t *spd0,
			  ipsec4_flow_cache_bucket_t *flow_cache_tbl, u64 flow_cache_mask,
			  bool is_udp, vlib_buffer_t **b, vlib_node_runtime_t *node,
			  ipsec_input_counters_t *counters, u16 *next)

{
  ipsec_policy_t *p0 = NULL;
  u32 da = ip0->dst_address.as_u32;
  u32 sa = ip0->src_address.as_u32;
  u32 pi0 = ~0;
  u32 spi = clib_net_to_host_u32 (esp0->spi);
  u8 has_space0;
  ipsec_policy_t *policies[1];
  ipsec_fp_5tuple_t tuples[1];

  has_space0 = vlib_buffer_has_space (b[0], (clib_address_t) (esp0 + 1) - (clib_address_t) ip0);

  /* RFC5996 Section 2.23: "To tunnel IKE packets over UDP port 4500, the IKE
   * header has four octets of zero prepended and the result immediately
   * follows the UDP header. To tunnel ESP packets over UDP port 4500, the ESP
   * header immediately follows the UDP header. Since the first four octets of
   * the ESP header contain the SPI, and the SPI cannot validly be zero, it is
   * always possible to distinguish ESP and IKE messages."
   */

  /* RFC3948 Section 2.1 UDP-Encapsulated ESP Header Format:
   * "The UDP header is a standard [RFC0768] header, where
   * - the Source Port and Destination Port MUST be the same as that used
   *   by IKE traffic,
   * - the IPv4 UDP Checksum SHOULD be transmitted as a zero value, and
   * - receivers MUST NOT depend on the UDP checksum being a zero value.
   * The SPI field in the ESP header MUST NOT be a zero value."
   */

  /*
   * UDP-IKEv2: UDP protocol, checksum != 0, SPI == 0 and port 500/4500
   * UDP-ESP:   UDP protocol, checksum == 0, SPI != 0 and port 4500
   */
  if (((is_udp && (udp0->checksum == 0)) || !is_udp) && (spi == 0))
    {
      /* RFC4303 Section 2.1: "The SPI value of zero (0 is reserved for
       * local, implementation-specific use and MUST NOT be sent on the
       * wire."
       */
      counters->unprocessed += 1;
      next[0] = IPSEC_INPUT_NEXT_DROP;
      return;
    }

  foreach_int (policy_type, IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT,
	       IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS, IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD)
    {
      bool is_protect = (policy_type == IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT);
      bool is_discard = (policy_type == IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD);

      if (im->fp_spd_ipv4_in_is_enabled &&
	  PREDICT_TRUE (INDEX_INVALID != spd0->fp_spd.ip4_in_lookup_hash_idx))
      {
	if (is_protect)
	  ipsec_fp_in_5tuple_from_ip4_range (&tuples[0], sa, da, spi, policy_type);
	else
	  tuples->action = policy_type;

	ipsec_fp_in_policy_match_n (&spd0->fp_spd, 0, tuples, policies, 1);
	p0 = policies[0];
      }
      else
      {
	p0 = flow_cache_mask ? ipsec4_input_spd_find_flow_cache_entry (
				 im, flow_cache_tbl, sa, da, policy_type, flow_cache_mask) :
			       0;
	if (p0 == 0)
	  {
	    p0 = ipsec_input_policy_match (spd0, sa, da, spi, policy_type);

	    if (flow_cache_mask && p0)
	      ipsec4_input_spd_add_flow_cache_entry (flow_cache_tbl, sa, da, policy_type,
						     p0 - im->policies, flow_cache_mask);
	  }
      }

      if (PREDICT_FALSE (p0 == NULL))
      continue;

      if (PREDICT_FALSE (is_protect && !has_space0))
      continue;

      counters->by_policy_type[policy_type] += 1;
      pi0 = p0 - im->policies;
      vlib_increment_combined_counter (&ipsec_spd_policy_counters,
				       thread_index, pi0, 1,
				       clib_net_to_host_u16 (ip0->length));

      if (is_protect)
      {
	vnet_buffer (b[0])->ipsec.sad_index = p0->sa_index;
	next[0] = im->esp4_decrypt_next_index;
	vlib_buffer_advance (b[0], ((u8 *) esp0 - (u8 *) ip0));
      }
      else if (is_discard)
      next[0] = IPSEC_INPUT_NEXT_DROP;

      goto trace0;
    }

  /* Drop by default if no match on PROTECT, BYPASS or DISCARD */
  counters->unprocessed += 1;
  next[0] = IPSEC_INPUT_NEXT_DROP;

trace0:
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
      PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
    {
      ipsec_input_trace_t *tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));

      tr->proto = ip0->protocol;
      tr->sa_id = p0 ? p0->sa_id : ~0;
      tr->spi = has_space0 ? clib_net_to_host_u32 (esp0->spi) : ~0;
      tr->seq = has_space0 ? clib_net_to_host_u32 (esp0->seq) : ~0;
      tr->spd = spd0->id;
      tr->policy_index = pi0;
    }
}

always_inline ipsec_policy_t *
ipsec6_input_protect_policy_match (ipsec_spd_t * spd,
				   ip6_address_t * sa,
				   ip6_address_t * da, u32 spi)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_sa_t *s;
  u32 *i;

  vec_foreach (i, spd->policies[IPSEC_SPD_POLICY_IP6_INBOUND_PROTECT])
  {
    p = pool_elt_at_index (im->policies, *i);
    s = ipsec_sa_get (p->sa_index);

    if (spi != s->spi)
      continue;

    if (ipsec_sa_is_set_IS_TUNNEL (s))
      {
	if (!ip6_address_is_equal (sa, &s->tunnel.t_src.ip.ip6))
	  continue;

	if (!ip6_address_is_equal (da, &s->tunnel.t_dst.ip.ip6))
	  continue;

	return p;
      }

    if (!ip6_addr_match_range (sa, &p->raddr.start.ip6, &p->raddr.stop.ip6))
      continue;

    if (!ip6_addr_match_range (da, &p->laddr.start.ip6, &p->laddr.stop.ip6))
      continue;

    return p;
  }
  return 0;
}

extern vlib_node_registration_t ipsec4_input_node;

VLIB_NODE_FN (ipsec4_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_left_from, *from, thread_index;
  ipsec_main_t *im = &ipsec_main;
  ipsec_input_counters_t counters = {};
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  ipsec4_flow_cache_bucket_t *flow_cache_tbl = im->ipsec4_in_spd_hash_tbl;
  u64 flow_cache_mask = im->input_flow_cache_flag ? im->ipsec4_in_spd_hash_num_buckets - 1 : 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left_from);
  thread_index = vm->thread_index;


  while (n_left_from > 0)
    {
      u32 next32;
      ip4_header_t *ip0;
      esp_header_t *esp0 = NULL;
      ah_header_t *ah0;
      ip4_ipsec_config_t *c0;
      ipsec_spd_t *spd0;

      if (n_left_from > 2)
	{
	  vlib_prefetch_buffer_data (b[1], LOAD);
	}

      b[0]->flags |= VNET_BUFFER_F_IS_IP4;
      b[0]->flags &= ~VNET_BUFFER_F_IS_IP6;
      c0 = vnet_feature_next_with_data (&next32, b[0], sizeof (c0[0]));
      next[0] = (u16) next32;

      spd0 = pool_elt_at_index (im->spds, c0->spd_index);

      ip0 = vlib_buffer_get_current (b[0]);

      if (ip0->protocol == IP_PROTOCOL_UDP)
	{
	  udp_header_t *udp0 = NULL;
	  udp0 = (udp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));

	  /* RFC5996 Section 2.23: "Port 4500 is reserved for
	   * UDP-encapsulated ESP and IKE."
	   * RFC5996 Section 3.1: "IKE messages use UDP ports 500 and/or 4500"
	   */
	  if ((clib_host_to_net_u16 (500) == udp0->dst_port) ||
	      (clib_host_to_net_u16 (4500) == udp0->dst_port))
	  {
	    esp0 = (esp_header_t *) ((u8 *) udp0 + sizeof (udp_header_t));

	    ipsec_esp_packet_process (vm, im, ip0, udp0, esp0, thread_index, spd0, flow_cache_tbl,
				      flow_cache_mask, 1, b, node, &counters, next);
	  }
	}
      else if (PREDICT_TRUE (ip0->protocol == IP_PROTOCOL_IPSEC_ESP))
	{
	  esp0 = (esp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
	  ipsec_esp_packet_process (vm, im, ip0, NULL, esp0, thread_index, spd0, flow_cache_tbl,
				    flow_cache_mask, 0, b, node, &counters, next);
	}
      else if (ip0->protocol == IP_PROTOCOL_IPSEC_AH)
	{
	  ah0 = (ah_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));

	  ipsec_ah_packet_process (vm, im, ip0, ah0, thread_index, spd0, flow_cache_tbl,
				   flow_cache_mask, b, node, &counters, next);
	}
      else
	{
	  counters.unprocessed += 1;
	}
      n_left_from -= 1;
      b += 1;
      next += 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, ipsec4_input_node.index,
			       IPSEC_INPUT_ERROR_RX_PKTS, frame->n_vectors);

  vlib_node_increment_counter (vm, ipsec4_input_node.index, IPSEC_INPUT_ERROR_RX_POLICY_MATCH,
			       counters.by_policy_type[IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT]);

  vlib_node_increment_counter (vm, ipsec4_input_node.index, IPSEC_INPUT_ERROR_RX_POLICY_NO_MATCH,
			       counters.unprocessed);

  vlib_node_increment_counter (vm, ipsec4_input_node.index, IPSEC_INPUT_ERROR_RX_POLICY_DISCARD,
			       counters.by_policy_type[IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD]);

  vlib_node_increment_counter (vm, ipsec4_input_node.index, IPSEC_INPUT_ERROR_RX_POLICY_BYPASS,
			       counters.by_policy_type[IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS]);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ipsec4_input_node) = {
  .name = "ipsec4-input-feature",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_input_error_strings),
  .error_strings = ipsec_input_error_strings,
  .n_next_nodes = IPSEC_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [IPSEC_INPUT_NEXT_##s] = n,
    foreach_ipsec_input_next
#undef _
  },
};

extern vlib_node_registration_t ipsec6_input_node;

always_inline void
ipsec6_esp_packet_process (vlib_main_t *vm, ipsec_main_t *im, ip6_header_t *ip0, esp_header_t *esp0,
			   clib_thread_index_t thread_index, ipsec_spd_t *spd0, vlib_buffer_t **b,
			   vlib_node_runtime_t *node, ipsec_input_counters_t *counters, u32 *next)

{
  ipsec_policy_t *p0 = NULL;
  u8 has_space0 = 0;
  ipsec_policy_t *policies[1];
  ipsec_fp_5tuple_t tuples[1];
  bool ip_v6 = true;

  if (im->fp_spd_ipv6_in_is_enabled &&
      PREDICT_TRUE (INDEX_INVALID != spd0->fp_spd.ip6_in_lookup_hash_idx))
    ipsec_fp_in_5tuple_from_ip6_range (
      &tuples[0], &ip0->src_address, &ip0->dst_address,
      clib_net_to_host_u32 (esp0->spi), IPSEC_SPD_POLICY_IP6_INBOUND_PROTECT);

  if (esp0->spi != 0)
    {
      if (im->fp_spd_ipv6_in_is_enabled &&
	  PREDICT_TRUE (INDEX_INVALID != spd0->fp_spd.ip6_in_lookup_hash_idx))
	{
	  ipsec_fp_in_policy_match_n (&spd0->fp_spd, ip_v6, tuples, policies,
				      1);
	  p0 = policies[0];
	}
      else /* linear search if fast path is not enabled */
	{
	  p0 = ipsec6_input_protect_policy_match (
	    spd0, &ip0->src_address, &ip0->dst_address,
	    clib_net_to_host_u32 (esp0->spi));
	}
      has_space0 = vlib_buffer_has_space (b[0], (clib_address_t) (esp0 + 1) -
						  (clib_address_t) ip0);

      if (PREDICT_TRUE ((p0 != NULL) && (has_space0)))
	{
	  u32 pi0 = p0 - im->policies;
	  counters->by_policy_type[IPSEC_SPD_POLICY_IP6_INBOUND_PROTECT] += 1;

	  vlib_increment_combined_counter (
	    &ipsec_spd_policy_counters, thread_index, pi0, 1,
	    clib_net_to_host_u16 (ip0->payload_length));

	  vnet_buffer (b[0])->ipsec.sad_index = p0->sa_index;
	  next[0] = im->esp6_decrypt_next_index;
	  vlib_buffer_advance (b[0], ((u8 *) esp0 - (u8 *) ip0));
	  goto trace0;
	}
    }

  if (im->fp_spd_ipv6_in_is_enabled &&
      PREDICT_TRUE (INDEX_INVALID != spd0->fp_spd.ip6_in_lookup_hash_idx))
    {
      tuples->action = IPSEC_SPD_POLICY_IP6_INBOUND_BYPASS;
      ipsec_fp_in_policy_match_n (&spd0->fp_spd, ip_v6, tuples, policies, 1);
      p0 = policies[0];
    }
  else
    {
      p0 =
	ipsec6_input_policy_match (spd0, &ip0->src_address, &ip0->dst_address,
				   IPSEC_SPD_POLICY_IP6_INBOUND_BYPASS);
    }

  if (PREDICT_TRUE ((p0 != NULL)))
    {
      u32 pi0 = p0 - im->policies;
      counters->by_policy_type[IPSEC_SPD_POLICY_IP6_INBOUND_BYPASS] += 1;

      vlib_increment_combined_counter (
	&ipsec_spd_policy_counters, thread_index, pi0, 1,
	clib_net_to_host_u16 (ip0->payload_length));
      goto trace0;
    }
  else
    p0 = NULL;

  if (im->fp_spd_ipv6_in_is_enabled &&
      PREDICT_TRUE (INDEX_INVALID != spd0->fp_spd.ip6_in_lookup_hash_idx))
    {
      tuples->action = IPSEC_SPD_POLICY_IP6_INBOUND_DISCARD;
      ipsec_fp_in_policy_match_n (&spd0->fp_spd, ip_v6, tuples, policies, 1);
      p0 = policies[0];
    }
  else
    {
      p0 =
	ipsec6_input_policy_match (spd0, &ip0->src_address, &ip0->dst_address,
				   IPSEC_SPD_POLICY_IP6_INBOUND_DISCARD);
    }

  if (PREDICT_TRUE ((p0 != NULL)))
    {
      u32 pi0 = p0 - im->policies;
      counters->by_policy_type[IPSEC_SPD_POLICY_IP6_INBOUND_DISCARD] += 1;

      vlib_increment_combined_counter (
	&ipsec_spd_policy_counters, thread_index, pi0, 1,
	clib_net_to_host_u16 (ip0->payload_length));
      next[0] = IPSEC_INPUT_NEXT_DROP;
      goto trace0;
    }

  /* Drop by default if no match on PROTECT, BYPASS or DISCARD */
  counters->unprocessed += 1;
  next[0] = IPSEC_INPUT_NEXT_DROP;

trace0:
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
      PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
    {
      ipsec_input_trace_t *tr = vlib_add_trace (vm, node, b[0], sizeof (*tr));

      tr->proto = ip0->protocol;
      tr->sa_id = p0 ? p0->sa_id : ~0;
      tr->spi = has_space0 ? clib_net_to_host_u32 (esp0->spi) : ~0;
      tr->seq = has_space0 ? clib_net_to_host_u32 (esp0->seq) : ~0;
      tr->spd = spd0->id;
      tr->policy_index = p0 ? p0 - im->policies : ~0;
    }
}

VLIB_NODE_FN (ipsec6_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next, thread_index;
  ipsec_main_t *im = &ipsec_main;
  ipsec_input_counters_t counters = {};

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  thread_index = vm->thread_index;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0, pi0 = ~0;
	  vlib_buffer_t *b0;
	  ip6_header_t *ip0;
	  esp_header_t *esp0 = NULL;
	  ip4_ipsec_config_t *c0;
	  ipsec_spd_t *spd0;
	  ipsec_policy_t *p0 = 0;
	  u32 header_size = sizeof (ip0[0]);

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  b0->flags |= VNET_BUFFER_F_IS_IP6;
	  b0->flags &= ~VNET_BUFFER_F_IS_IP4;
	  c0 = vnet_feature_next_with_data (&next0, b0, sizeof (c0[0]));

	  spd0 = pool_elt_at_index (im->spds, c0->spd_index);

	  ip0 = vlib_buffer_get_current (b0);

	  if (ip0->protocol == IP_PROTOCOL_UDP)
	  {
	    udp_header_t *udp0 = (udp_header_t *) ((u8 *) ip0 + header_size);

	    /* RFC5996 Section 2.23: "Port 4500 is reserved for
	    * UDP-encapsulated ESP and IKE."
	    * RFC5996 Section 3.1: "IKE messages use UDP ports 500 and/or
	    4500"
	    */
	    if ((clib_host_to_net_u16 (500) == udp0->dst_port) ||
		(clib_host_to_net_u16 (4500) == udp0->dst_port))
	      esp0 = (esp_header_t *) ((u8 *) udp0 + sizeof (udp_header_t));
	  }
	  else if (ip0->protocol == IP_PROTOCOL_IPSEC_ESP)
	  esp0 = (esp_header_t *) ((u8 *) ip0 + header_size);

	  if (esp0 != NULL)
	  {
	    ipsec6_esp_packet_process (vm, im, ip0, esp0, thread_index, spd0, &b0, node, &counters,
				       &next0);
	  }
	  else if (ip0->protocol == IP_PROTOCOL_IPSEC_AH)
	    {
	    ah_header_t *ah0 = (ah_header_t *) ((u8 *) ip0 + header_size);

	    p0 = ipsec6_input_protect_policy_match (
	      spd0, &ip0->src_address, &ip0->dst_address,
	      clib_net_to_host_u32 (ah0->spi));

	    if (PREDICT_TRUE (p0 != 0))
	      {
		counters.by_policy_type[IPSEC_SPD_POLICY_IP6_INBOUND_PROTECT] += 1;
		pi0 = p0 - im->policies;
		vlib_increment_combined_counter (
		  &ipsec_spd_policy_counters, thread_index, pi0, 1,
		  clib_net_to_host_u16 (ip0->payload_length) + header_size);

		vnet_buffer (b0)->ipsec.sad_index = p0->sa_index;
		next0 = im->ah6_decrypt_next_index;
		if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
		    PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		  {
		    ipsec_input_trace_t *tr =
		      vlib_add_trace (vm, node, b0, sizeof (*tr));

		    if (p0)
		      {
			tr->sa_id = p0->sa_id;
			tr->policy_type = p0->type;
		      }

		    tr->proto = ip0->protocol;
		    tr->spi = clib_net_to_host_u32 (ah0->spi);
		    tr->spd = spd0->id;
		    tr->policy_index = pi0;
		  }
	      }
	    else
	      {
		pi0 = ~0;
		counters.unprocessed += 1;
		next0 = IPSEC_INPUT_NEXT_DROP;
	      }
	    }
	  else
	    {
	    counters.unprocessed += 1;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ipsec6_input_node.index, IPSEC_INPUT_ERROR_RX_PKTS,
			       from_frame->n_vectors - counters.unprocessed);

  vlib_node_increment_counter (vm, ipsec6_input_node.index, IPSEC_INPUT_ERROR_RX_POLICY_MATCH,
			       counters.by_policy_type[IPSEC_SPD_POLICY_IP6_INBOUND_PROTECT]);
  vlib_node_increment_counter (vm, ipsec6_input_node.index, IPSEC_INPUT_ERROR_RX_POLICY_DISCARD,
			       counters.by_policy_type[IPSEC_SPD_POLICY_IP6_INBOUND_DISCARD]);
  vlib_node_increment_counter (vm, ipsec6_input_node.index, IPSEC_INPUT_ERROR_RX_POLICY_BYPASS,
			       counters.by_policy_type[IPSEC_SPD_POLICY_IP6_INBOUND_BYPASS]);

  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (ipsec6_input_node) = {
  .name = "ipsec6-input-feature",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_input_error_strings),
  .error_strings = ipsec_input_error_strings,
  .n_next_nodes = IPSEC_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [IPSEC_INPUT_NEXT_##s] = n,
    foreach_ipsec_input_next
#undef _
  },
};
