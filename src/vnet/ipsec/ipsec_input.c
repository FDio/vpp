/*
 * decap.c : IPSec tunnel decapsulation
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
  ip_protocol_t proto;
  u32 spd;
  u32 policy_index;
  u32 policy_type;
  u32 sa_id;
  u32 spi;
  u32 seq;
} ipsec_input_trace_t;

/* packet trace format function */
static u8 *
format_ipsec_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_input_trace_t *t = va_arg (*args, ipsec_input_trace_t *);

  s =
    format (s, "%U: sa_id %u type: %u spd %u policy %d spi %u (0x%08x) seq %u",
	    format_ip_protocol, t->proto, t->sa_id, t->policy_type, t->spd,
	    t->policy_index, t->spi, t->spi, t->seq);

  return s;
}

always_inline void
ipsec4_input_spd_add_flow_cache_entry (ipsec_main_t *im, u32 sa, u32 da,
				       ipsec_spd_policy_type_t policy_type,
				       u32 pol_id)
{
  u64 hash;
  u8 is_overwrite = 0, is_stale_overwrite = 0;
  /* Store in network byte order to avoid conversion on lookup */
  ipsec4_inbound_spd_tuple_t ip4_tuple = {
    .ip4_src_addr = (ip4_address_t) clib_host_to_net_u32 (sa),
    .ip4_dest_addr = (ip4_address_t) clib_host_to_net_u32 (da),
    .policy_type = policy_type
  };

  ip4_tuple.kv_16_8.value =
    (((u64) pol_id) << 32) | ((u64) im->input_epoch_count);

  hash = ipsec4_hash_16_8 (&ip4_tuple.kv_16_8);
  hash &= (im->ipsec4_in_spd_hash_num_buckets - 1);

  ipsec_spinlock_lock (&im->ipsec4_in_spd_hash_tbl[hash].bucket_lock);
  /* Check if we are overwriting an existing entry so we know
    whether to increment the flow cache counter. Since flow
    cache counter is reset on any policy add/remove, but
    hash table values are not, we need to check if the entry
    we are overwriting is stale or not. If it's a stale entry
    overwrite, we still want to increment flow cache counter */
  is_overwrite = (im->ipsec4_in_spd_hash_tbl[hash].value != 0);
  /* Check if we are overwriting a stale entry by comparing
     with current epoch count */
  if (PREDICT_FALSE (is_overwrite))
    is_stale_overwrite =
      (im->input_epoch_count !=
       ((u32) (im->ipsec4_in_spd_hash_tbl[hash].value & 0xFFFFFFFF)));
  clib_memcpy_fast (&im->ipsec4_in_spd_hash_tbl[hash], &ip4_tuple.kv_16_8,
		    sizeof (ip4_tuple.kv_16_8));
  ipsec_spinlock_unlock (&im->ipsec4_in_spd_hash_tbl[hash].bucket_lock);

  /* Increment the counter to track active flow cache entries
    when entering a fresh entry or overwriting a stale one */
  if (!is_overwrite || is_stale_overwrite)
    clib_atomic_fetch_add_relax (&im->ipsec4_in_spd_flow_cache_entries, 1);

  return;
}

always_inline ipsec_policy_t *
ipsec4_input_spd_find_flow_cache_entry (ipsec_main_t *im, u32 sa, u32 da,
					ipsec_spd_policy_type_t policy_type)
{
  ipsec_policy_t *p = NULL;
  ipsec4_hash_kv_16_8_t kv_result;
  u64 hash;
  ipsec4_inbound_spd_tuple_t ip4_tuple = { .ip4_src_addr = (ip4_address_t) sa,
					   .ip4_dest_addr = (ip4_address_t) da,
					   .policy_type = policy_type };

  hash = ipsec4_hash_16_8 (&ip4_tuple.kv_16_8);
  hash &= (im->ipsec4_in_spd_hash_num_buckets - 1);

  ipsec_spinlock_lock (&im->ipsec4_in_spd_hash_tbl[hash].bucket_lock);
  kv_result = im->ipsec4_in_spd_hash_tbl[hash];
  ipsec_spinlock_unlock (&im->ipsec4_in_spd_hash_tbl[hash].bucket_lock);

  if (ipsec4_hash_key_compare_16_8 ((u64 *) &ip4_tuple.kv_16_8,
				    (u64 *) &kv_result))
    {
      if (im->input_epoch_count == ((u32) (kv_result.value & 0xFFFFFFFF)))
	{
	  /* Get the policy based on the index */
	  p =
	    pool_elt_at_index (im->policies, ((u32) (kv_result.value >> 32)));
	}
    }

  return p;
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
ipsec_input_policy_match (ipsec_spd_t *spd, u32 sa, u32 da,
			  ipsec_spd_policy_type_t policy_type)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  u32 *i;

  vec_foreach (i, spd->policies[policy_type])
  {
    p = pool_elt_at_index (im->policies, *i);

    if (da < clib_net_to_host_u32 (p->laddr.start.ip4.as_u32))
      continue;

    if (da > clib_net_to_host_u32 (p->laddr.stop.ip4.as_u32))
      continue;

    if (sa < clib_net_to_host_u32 (p->raddr.start.ip4.as_u32))
      continue;

    if (sa > clib_net_to_host_u32 (p->raddr.stop.ip4.as_u32))
      continue;

    if (im->input_flow_cache_flag)
      {
	/* Add an Entry in Flow cache */
	ipsec4_input_spd_add_flow_cache_entry (im, sa, da, policy_type, *i);
      }
    return p;
  }
  return 0;
}

always_inline ipsec_policy_t *
ipsec_input_protect_policy_match (ipsec_spd_t *spd, u32 sa, u32 da, u32 spi)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_sa_t *s;
  u32 *i;

  vec_foreach (i, spd->policies[IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT])
  {
    p = pool_elt_at_index (im->policies, *i);
    s = ipsec_sa_get (p->sa_index);

    if (spi != s->spi)
      continue;

    if (ipsec_sa_is_set_IS_TUNNEL (s))
      {
	if (da != clib_net_to_host_u32 (s->tunnel.t_dst.ip.ip4.as_u32))
	  continue;

	if (sa != clib_net_to_host_u32 (s->tunnel.t_src.ip.ip4.as_u32))
	  continue;

	goto return_policy;
      }

    if (da < clib_net_to_host_u32 (p->laddr.start.ip4.as_u32))
      continue;

    if (da > clib_net_to_host_u32 (p->laddr.stop.ip4.as_u32))
      continue;

    if (sa < clib_net_to_host_u32 (p->raddr.start.ip4.as_u32))
      continue;

    if (sa > clib_net_to_host_u32 (p->raddr.stop.ip4.as_u32))
      continue;

  return_policy:
    if (im->input_flow_cache_flag)
      {
	/* Add an Entry in Flow cache */
	ipsec4_input_spd_add_flow_cache_entry (
	  im, sa, da, IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT, *i);
      }

    return p;
  }
  return 0;
}

always_inline uword
ip6_addr_match_range (ip6_address_t * a, ip6_address_t * la,
		      ip6_address_t * ua)
{
  if ((memcmp (a->as_u64, la->as_u64, 2 * sizeof (u64)) >= 0) &&
      (memcmp (a->as_u64, ua->as_u64, 2 * sizeof (u64)) <= 0))
    return 1;
  return 0;
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
  u64 ipsec_unprocessed = 0, ipsec_matched = 0;
  u64 ipsec_dropped = 0, ipsec_bypassed = 0;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left_from);
  thread_index = vm->thread_index;


  while (n_left_from > 0)
    {
      u32 next32, pi0;
      ip4_header_t *ip0;
      esp_header_t *esp0 = NULL;
      ah_header_t *ah0;
      ip4_ipsec_config_t *c0;
      ipsec_spd_t *spd0;
      ipsec_policy_t *p0 = NULL;
      u8 has_space0;
      bool search_flow_cache = false;
      ipsec_policy_t *policies[1];
      ipsec_fp_5tuple_t tuples[1];
      bool ip_v6 = true;

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

      if (PREDICT_TRUE
	  (ip0->protocol == IP_PROTOCOL_IPSEC_ESP
	   || ip0->protocol == IP_PROTOCOL_UDP))
	{

	  esp0 = (esp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));
	  if (PREDICT_FALSE (ip0->protocol == IP_PROTOCOL_UDP))
	    {
	      /* FIXME Skip, if not a UDP encapsulated packet */
	      esp0 = (esp_header_t *) ((u8 *) esp0 + sizeof (udp_header_t));
	    }

	  // if flow cache is enabled, first search through flow cache for a
	  // policy match for either protect, bypass or discard rules, in that
	  // order. if no match is found search_flow_cache is set to false (1)
	  // and we revert back to linear search
	  search_flow_cache = im->input_flow_cache_flag;

	esp_or_udp:
	  if (im->fp_spd_ipv4_in_is_enabled &&
	      PREDICT_TRUE (INDEX_INVALID !=
			    spd0->fp_spd.ip4_in_lookup_hash_idx))
	    {
	      ipsec_fp_in_5tuple_from_ip4_range (
		&tuples[0], ip0->src_address.as_u32, ip0->dst_address.as_u32,
		clib_net_to_host_u32 (esp0->spi),
		IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT);
	      ipsec_fp_in_policy_match_n (&spd0->fp_spd, !ip_v6, tuples,
					  policies, 1);
	      p0 = policies[0];
	    }
	  else if (search_flow_cache) // attempt to match policy in flow cache
	    {
	      p0 = ipsec4_input_spd_find_flow_cache_entry (
		im, ip0->src_address.as_u32, ip0->dst_address.as_u32,
		IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT);
	    }

	  else // linear search if flow cache is not enabled,
	       // or flow cache search just failed
	    {
	      p0 = ipsec_input_protect_policy_match (
		spd0, clib_net_to_host_u32 (ip0->src_address.as_u32),
		clib_net_to_host_u32 (ip0->dst_address.as_u32),
		clib_net_to_host_u32 (esp0->spi));
	    }

	  has_space0 =
	    vlib_buffer_has_space (b[0],
				   (clib_address_t) (esp0 + 1) -
				   (clib_address_t) ip0);

	  if (PREDICT_TRUE ((p0 != NULL) & (has_space0)))
	    {
	      ipsec_matched += 1;

	      pi0 = p0 - im->policies;
	      vlib_increment_combined_counter
		(&ipsec_spd_policy_counters,
		 thread_index, pi0, 1, clib_net_to_host_u16 (ip0->length));

	      vnet_buffer (b[0])->ipsec.sad_index = p0->sa_index;
	      next[0] = im->esp4_decrypt_next_index;
	      vlib_buffer_advance (b[0], ((u8 *) esp0 - (u8 *) ip0));
	      goto trace0;
	    }
	  else
	    {
	      p0 = 0;
	      pi0 = ~0;
	    };

	  if (im->fp_spd_ipv4_in_is_enabled &&
	      PREDICT_TRUE (INDEX_INVALID !=
			    spd0->fp_spd.ip4_in_lookup_hash_idx))
	    {
	      tuples->action = IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS;
	      ipsec_fp_in_policy_match_n (&spd0->fp_spd, !ip_v6, tuples,
					  policies, 1);
	      p0 = policies[0];
	    }
	  else if (search_flow_cache)
	    {
	      p0 = ipsec4_input_spd_find_flow_cache_entry (
		im, ip0->src_address.as_u32, ip0->dst_address.as_u32,
		IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS);
	    }

	  else
	    {
	      p0 = ipsec_input_policy_match (
		spd0, clib_net_to_host_u32 (ip0->src_address.as_u32),
		clib_net_to_host_u32 (ip0->dst_address.as_u32),
		IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS);
	    }

	  if (PREDICT_TRUE ((p0 != NULL)))
	    {
	      ipsec_bypassed += 1;

	      pi0 = p0 - im->policies;
	      vlib_increment_combined_counter (
		&ipsec_spd_policy_counters, thread_index, pi0, 1,
		clib_net_to_host_u16 (ip0->length));

	      goto trace0;
	    }
	  else
	    {
	      p0 = 0;
	      pi0 = ~0;
	    };

	  if (im->fp_spd_ipv4_in_is_enabled &&
	      PREDICT_TRUE (INDEX_INVALID !=
			    spd0->fp_spd.ip4_in_lookup_hash_idx))
	    {
	      tuples->action = IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD;
	      ipsec_fp_in_policy_match_n (&spd0->fp_spd, !ip_v6, tuples,
					  policies, 1);
	      p0 = policies[0];
	    }
	  else

	    if (search_flow_cache)
	    {
	      p0 = ipsec4_input_spd_find_flow_cache_entry (
		im, ip0->src_address.as_u32, ip0->dst_address.as_u32,
		IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD);
	    }

	  else
	    {
	      p0 = ipsec_input_policy_match (
		spd0, clib_net_to_host_u32 (ip0->src_address.as_u32),
		clib_net_to_host_u32 (ip0->dst_address.as_u32),
		IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD);
	    }

	  if (PREDICT_TRUE ((p0 != NULL)))
	    {
	      ipsec_dropped += 1;

	      pi0 = p0 - im->policies;
	      vlib_increment_combined_counter (
		&ipsec_spd_policy_counters, thread_index, pi0, 1,
		clib_net_to_host_u16 (ip0->length));

	      next[0] = IPSEC_INPUT_NEXT_DROP;
	      goto trace0;
	    }
	  else
	    {
	      p0 = 0;
	      pi0 = ~0;
	    };

	  // flow cache search failed, try again with linear search
	  if (search_flow_cache && p0 == NULL)
	    {
	      search_flow_cache = false;
	      goto esp_or_udp;
	    }

	  /* Drop by default if no match on PROTECT, BYPASS or DISCARD */
	  ipsec_unprocessed += 1;
	  next[0] = IPSEC_INPUT_NEXT_DROP;

	trace0:
	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_input_trace_t *tr =
		vlib_add_trace (vm, node, b[0], sizeof (*tr));

	      tr->proto = ip0->protocol;
	      tr->sa_id = p0 ? p0->sa_id : ~0;
	      tr->spi = has_space0 ? clib_net_to_host_u32 (esp0->spi) : ~0;
	      tr->seq = has_space0 ? clib_net_to_host_u32 (esp0->seq) : ~0;
	      tr->spd = spd0->id;
	      tr->policy_index = pi0;
	    }
	}
      else if (ip0->protocol == IP_PROTOCOL_IPSEC_AH)
	{
	  ah0 = (ah_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));

	  // if flow cache is enabled, first search through flow cache for a
	  // policy match and revert back to linear search on failure
	  search_flow_cache = im->input_flow_cache_flag;

	ah:
	  if (search_flow_cache)
	    {
	      p0 = ipsec4_input_spd_find_flow_cache_entry (
		im, ip0->src_address.as_u32, ip0->dst_address.as_u32,
		IPSEC_SPD_POLICY_IP4_INBOUND_PROTECT);
	    }

	  else
	    {
	      p0 = ipsec_input_protect_policy_match (
		spd0, clib_net_to_host_u32 (ip0->src_address.as_u32),
		clib_net_to_host_u32 (ip0->dst_address.as_u32),
		clib_net_to_host_u32 (ah0->spi));
	    }

	  has_space0 =
	    vlib_buffer_has_space (b[0],
				   (clib_address_t) (ah0 + 1) -
				   (clib_address_t) ip0);

	  if (PREDICT_TRUE ((p0 != NULL) & (has_space0)))
	    {
	      ipsec_matched += 1;

	      pi0 = p0 - im->policies;
	      vlib_increment_combined_counter
		(&ipsec_spd_policy_counters,
		 thread_index, pi0, 1, clib_net_to_host_u16 (ip0->length));

	      vnet_buffer (b[0])->ipsec.sad_index = p0->sa_index;
	      next[0] = im->ah4_decrypt_next_index;
	      goto trace1;
	    }
	  else
	    {
	      p0 = 0;
	      pi0 = ~0;
	    }

	  if (search_flow_cache)
	    {
	      p0 = ipsec4_input_spd_find_flow_cache_entry (
		im, ip0->src_address.as_u32, ip0->dst_address.as_u32,
		IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS);
	    }

	  else
	    {
	      p0 = ipsec_input_policy_match (
		spd0, clib_net_to_host_u32 (ip0->src_address.as_u32),
		clib_net_to_host_u32 (ip0->dst_address.as_u32),
		IPSEC_SPD_POLICY_IP4_INBOUND_BYPASS);
	    }

	  if (PREDICT_TRUE ((p0 != NULL)))
	    {
	      ipsec_bypassed += 1;

	      pi0 = p0 - im->policies;
	      vlib_increment_combined_counter (
		&ipsec_spd_policy_counters, thread_index, pi0, 1,
		clib_net_to_host_u16 (ip0->length));

	      goto trace1;
	    }
	  else
	    {
	      p0 = 0;
	      pi0 = ~0;
	    };

	  if (search_flow_cache)
	    {
	      p0 = ipsec4_input_spd_find_flow_cache_entry (
		im, ip0->src_address.as_u32, ip0->dst_address.as_u32,
		IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD);
	    }

	  else
	    {
	      p0 = ipsec_input_policy_match (
		spd0, clib_net_to_host_u32 (ip0->src_address.as_u32),
		clib_net_to_host_u32 (ip0->dst_address.as_u32),
		IPSEC_SPD_POLICY_IP4_INBOUND_DISCARD);
	    }

	  if (PREDICT_TRUE ((p0 != NULL)))
	    {
	      ipsec_dropped += 1;

	      pi0 = p0 - im->policies;
	      vlib_increment_combined_counter (
		&ipsec_spd_policy_counters, thread_index, pi0, 1,
		clib_net_to_host_u16 (ip0->length));

	      next[0] = IPSEC_INPUT_NEXT_DROP;
	      goto trace1;
	    }
	  else
	    {
	      p0 = 0;
	      pi0 = ~0;
	    };

	  // flow cache search failed, retry with linear search
	  if (search_flow_cache && p0 == NULL)
	    {
	      search_flow_cache = false;
	      goto ah;
	    }

	  /* Drop by default if no match on PROTECT, BYPASS or DISCARD */
	  ipsec_unprocessed += 1;
	  next[0] = IPSEC_INPUT_NEXT_DROP;

	trace1:
	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_input_trace_t *tr =
		vlib_add_trace (vm, node, b[0], sizeof (*tr));

	      tr->proto = ip0->protocol;
	      tr->sa_id = p0 ? p0->sa_id : ~0;
	      tr->spi = has_space0 ? clib_net_to_host_u32 (ah0->spi) : ~0;
	      tr->seq = has_space0 ? clib_net_to_host_u32 (ah0->seq_no) : ~0;
	      tr->spd = spd0->id;
	      tr->policy_index = pi0;
	    }
	}
      else
	{
	  ipsec_unprocessed += 1;
	}
      n_left_from -= 1;
      b += 1;
      next += 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, ipsec4_input_node.index,
			       IPSEC_INPUT_ERROR_RX_PKTS, frame->n_vectors);

  vlib_node_increment_counter (vm, ipsec4_input_node.index,
			       IPSEC_INPUT_ERROR_RX_POLICY_MATCH,
			       ipsec_matched);

  vlib_node_increment_counter (vm, ipsec4_input_node.index,
			       IPSEC_INPUT_ERROR_RX_POLICY_NO_MATCH,
			       ipsec_unprocessed);

  vlib_node_increment_counter (vm, ipsec4_input_node.index,
			       IPSEC_INPUT_ERROR_RX_POLICY_DISCARD,
			       ipsec_dropped);

  vlib_node_increment_counter (vm, ipsec4_input_node.index,
			       IPSEC_INPUT_ERROR_RX_POLICY_BYPASS,
			       ipsec_bypassed);

  return frame->n_vectors;
}


/* *INDENT-OFF* */
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
/* *INDENT-ON* */

extern vlib_node_registration_t ipsec6_input_node;


VLIB_NODE_FN (ipsec6_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next, thread_index;
  ipsec_main_t *im = &ipsec_main;
  u32 ipsec_unprocessed = 0;
  u32 ipsec_matched = 0;
  ipsec_policy_t *policies[1];
  ipsec_fp_5tuple_t tuples[1];
  bool ip_v6 = true;

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
	  esp_header_t *esp0;
	  ip4_ipsec_config_t *c0;
	  ipsec_spd_t *spd0;
	  ipsec_policy_t *p0 = 0;
	  ah_header_t *ah0;
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
	  esp0 = (esp_header_t *) ((u8 *) ip0 + header_size);
	  ah0 = (ah_header_t *) ((u8 *) ip0 + header_size);

	  if (PREDICT_TRUE (ip0->protocol == IP_PROTOCOL_IPSEC_ESP))
	    {
#if 0
	      clib_warning
		("packet received from %U to %U spi %u size %u spd_id %u",
		 format_ip6_address, &ip0->src_address, format_ip6_address,
		 &ip0->dst_address, clib_net_to_host_u32 (esp0->spi),
		 clib_net_to_host_u16 (ip0->payload_length) + header_size,
		 spd0->id);
#endif
	      if (im->fp_spd_ipv6_in_is_enabled &&
		  PREDICT_TRUE (INDEX_INVALID !=
				spd0->fp_spd.ip6_in_lookup_hash_idx))
		{
		  ipsec_fp_in_5tuple_from_ip6_range (
		    &tuples[0], &ip0->src_address, &ip0->dst_address,
		    clib_net_to_host_u32 (esp0->spi),
		    IPSEC_SPD_POLICY_IP6_INBOUND_PROTECT);
		  ipsec_fp_in_policy_match_n (&spd0->fp_spd, ip_v6, tuples,
					      policies, 1);
		  p0 = policies[0];
		}
	      else
		p0 = ipsec6_input_protect_policy_match (
		  spd0, &ip0->src_address, &ip0->dst_address,
		  clib_net_to_host_u32 (esp0->spi));

	      if (PREDICT_TRUE (p0 != 0))
		{
		  ipsec_matched += 1;

		  pi0 = p0 - im->policies;
		  vlib_increment_combined_counter
		    (&ipsec_spd_policy_counters,
		     thread_index, pi0, 1,
		     clib_net_to_host_u16 (ip0->payload_length) +
		     header_size);

		  vnet_buffer (b0)->ipsec.sad_index = p0->sa_index;
		  next0 = im->esp6_decrypt_next_index;
		  vlib_buffer_advance (b0, header_size);
		  /* TODO Add policy matching for bypass and discard policy
		   * type */
		  goto trace0;
		}
	      else
		{
		  pi0 = ~0;
		  ipsec_unprocessed += 1;
		  next0 = IPSEC_INPUT_NEXT_DROP;
		}
	    }
	  else if (ip0->protocol == IP_PROTOCOL_IPSEC_AH)
	    {
	      p0 = ipsec6_input_protect_policy_match (spd0,
						      &ip0->src_address,
						      &ip0->dst_address,
						      clib_net_to_host_u32
						      (ah0->spi));

	      if (PREDICT_TRUE (p0 != 0))
		{
		  ipsec_matched += 1;
		  pi0 = p0 - im->policies;
		  vlib_increment_combined_counter
		    (&ipsec_spd_policy_counters,
		     thread_index, pi0, 1,
		     clib_net_to_host_u16 (ip0->payload_length) +
		     header_size);

		  vnet_buffer (b0)->ipsec.sad_index = p0->sa_index;
		  next0 = im->ah6_decrypt_next_index;
		  goto trace0;
		}
	      else
		{
		  pi0 = ~0;
		  ipsec_unprocessed += 1;
		  next0 = IPSEC_INPUT_NEXT_DROP;
		}
	    }
	  else
	    {
	      ipsec_unprocessed += 1;
	    }

	trace0:
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
	      tr->spi = clib_net_to_host_u32 (esp0->spi);
	      tr->seq = clib_net_to_host_u32 (esp0->seq);
	      tr->spd = spd0->id;
	      tr->policy_index = pi0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ipsec6_input_node.index,
			       IPSEC_INPUT_ERROR_RX_PKTS,
			       from_frame->n_vectors - ipsec_unprocessed);

  vlib_node_increment_counter (vm, ipsec6_input_node.index,
			       IPSEC_INPUT_ERROR_RX_POLICY_MATCH,
			       ipsec_matched);

  return from_frame->n_vectors;
}


/* *INDENT-OFF* */
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
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
