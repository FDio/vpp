/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Intel and/or its affiliates.
 */

#ifndef IPSEC_OUTPUT_H
#define IPSEC_OUTPUT_H

#include <vppinfra/types.h>
#include <vnet/ipsec/ipsec_spd.h>
#include <vnet/ipsec/ipsec_spd_fp_lookup.h>

always_inline int
ipsec4_out_proto_is_tcp_udp_or_sctp (u8 proto)
{
  return (proto == IP_PROTOCOL_TCP || proto == IP_PROTOCOL_UDP || proto == IP_PROTOCOL_SCTP);
}

always_inline void
ipsec4_out_spd_add_flow_cache_entry (ipsec4_flow_cache_bucket_t *tbl, u8 pr, u32 la, u32 ra, u16 lp,
				     u16 rp, u32 policy_index, u64 flow_cache_mask)
{
  ipsec4_flow_cache_bucket_t *bucket;
  ipsec4_spd_5tuple_t ip4_5tuple = { .ip4_addr = { (ip4_address_t) la,
						   (ip4_address_t) ra },
				     .port = { lp, rp },
				     .proto = pr };

  ip4_5tuple.kv_16_8.value = policy_index;

  bucket = tbl + (ipsec4_hash_16_8 (&ip4_5tuple.kv_16_8) & flow_cache_mask);

  CLIB_SPINLOCK_LOCK (bucket->writer_lock);
  __atomic_fetch_add (&bucket->seq, 1, __ATOMIC_RELAXED);
  bucket->kv = ip4_5tuple.kv_16_8;
  __atomic_fetch_add (&bucket->seq, 1, __ATOMIC_RELEASE);
  CLIB_SPINLOCK_UNLOCK (bucket->writer_lock);
}

always_inline void
ipsec4_out_spd_add_flow_cache_entry_n (ipsec4_flow_cache_bucket_t *tbl,
				       ipsec4_spd_5tuple_t *ip4_5tuple, u32 policy_index,
				       u64 flow_cache_mask)
{
  ipsec4_flow_cache_bucket_t *bucket;

  ip4_5tuple->kv_16_8.value = policy_index;

  bucket = tbl + (ipsec4_hash_16_8 (&ip4_5tuple->kv_16_8) & flow_cache_mask);

  CLIB_SPINLOCK_LOCK (bucket->writer_lock);
  __atomic_fetch_add (&bucket->seq, 1, __ATOMIC_RELAXED);
  bucket->kv = ip4_5tuple->kv_16_8;
  __atomic_fetch_add (&bucket->seq, 1, __ATOMIC_RELEASE);
  CLIB_SPINLOCK_UNLOCK (bucket->writer_lock);
}

always_inline void
ipsec_fp_5tuple_from_ip4_range (ipsec_fp_5tuple_t *tuple, u32 la, u32 ra,
				u16 lp, u16 rp, u8 pr)
{
  clib_memset (tuple->l3_zero_pad, 0, sizeof (tuple->l3_zero_pad));
  tuple->laddr.as_u32 = la;
  tuple->raddr.as_u32 = ra;

  if (PREDICT_FALSE (!ipsec4_out_proto_is_tcp_udp_or_sctp (pr)))
    {
      tuple->lport = 0;
      tuple->rport = 0;
    }
  else
    {
      tuple->lport = clib_net_to_host_u16 (lp);
      tuple->rport = clib_net_to_host_u16 (rp);
    }

  tuple->protocol = pr;
  tuple->is_ipv6 = 0;
}

always_inline void
ipsec_fp_5tuple_from_ip4_range_n (ipsec_fp_5tuple_t *tuples,
				  ipsec4_spd_5tuple_t *ip4_5tuple, u32 n)
{
  u32 n_left = n;
  ipsec_fp_5tuple_t *tuple = tuples;

  while (n_left)
    {
      clib_memset (tuple->l3_zero_pad, 0, sizeof (tuple->l3_zero_pad));
      tuple->laddr.as_u32 = ip4_5tuple->ip4_addr[0].as_u32;
      tuple->raddr.as_u32 = ip4_5tuple->ip4_addr[1].as_u32;
      if (PREDICT_FALSE (!ipsec4_out_proto_is_tcp_udp_or_sctp (ip4_5tuple->proto)))
	{
	  tuple->lport = 0;
	  tuple->rport = 0;
	}
      else
	{
	  tuple->lport = clib_net_to_host_u16 (ip4_5tuple->port[0]);
	  tuple->rport = clib_net_to_host_u16 (ip4_5tuple->port[1]);
	}
      tuple->protocol = ip4_5tuple->proto;
      tuple->is_ipv6 = 0;
      n_left--;
      tuple++;
    }
}

always_inline int
ipsec_output_policy_match_n (ipsec_spd_t *spd, ipsec4_spd_5tuple_t *ip4_5tuples,
			     ipsec_policy_t **policies, u32 n, u64 flow_cache_mask)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_policy_t **pp = policies;
  u32 n_left = n;
  ipsec4_spd_5tuple_t *ip4_5tuple = ip4_5tuples;
  u32 policy_ids[n], *policy_id = policy_ids;
  ipsec_fp_5tuple_t tuples[n];
  u32 *policy_indices;
  u32 chunk;
  u32 lane;
  u32 policy_index;
  u32 counter = 0;

  if (!spd)
    return 0;

  clib_memset (policies, 0, n * sizeof (ipsec_policy_t *));

  if (im->fp_spd_ipv4_out_is_enabled &&
      PREDICT_TRUE (INDEX_INVALID != spd->fp_spd.ip4_out_lookup_hash_idx))
    {
      ipsec_fp_5tuple_from_ip4_range_n (tuples, ip4_5tuples, n);
      counter += ipsec_fp_out_policy_match_n (&spd->fp_spd, 0, tuples,
					      policies, policy_ids, n);
    }

  while (n_left)
    {
      u16 lph = clib_net_to_host_u16 (ip4_5tuple->port[0]);
      u16 rph = clib_net_to_host_u16 (ip4_5tuple->port[1]);

      if (*pp != 0)
	goto next;

      policy_indices = spd->policies[IPSEC_SPD_POLICY_IP4_OUTBOUND];
      vec_foreach_index (chunk, spd->ip4_policies[IPSEC_SPD_POLICY_IP4_OUTBOUND])
	{
	  u32 slot;

	  slot = ipsec_spd_ip4_range_match_slot (
	    &spd->ip4_policies[IPSEC_SPD_POLICY_IP4_OUTBOUND][chunk],
	    ip4_5tuple->ip4_addr[0].as_u32, ip4_5tuple->ip4_addr[1].as_u32);
	  policy_index = chunk << 2;
	  lane = slot;

	  if (slot != ~0 && policy_index + lane < vec_len (policy_indices))
	    {
	      p = pool_elt_at_index (im->policies, policy_indices[policy_index + lane]);
	      if (PREDICT_FALSE (p->protocol && (p->protocol != ip4_5tuple->proto)))
		continue;

	      if (PREDICT_FALSE (!ipsec4_out_proto_is_tcp_udp_or_sctp (ip4_5tuple->proto)))
		{
		  ip4_5tuple->port[0] = 0;
		  ip4_5tuple->port[1] = 0;
		  goto add_policy;
		}

	      if (lph < p->lport.start)
		continue;

	      if (lph > p->lport.stop)
		continue;

	      if (rph < p->rport.start)
		continue;

	      if (rph > p->rport.stop)
		continue;

	    add_policy:
	      *pp = p;
	      *policy_id = policy_indices[policy_index + lane];
	      counter++;
	      goto next;
	    }
	}

    next:
      n_left--;
      pp++;
      ip4_5tuple++;
      policy_id++;
    }

  if (flow_cache_mask)
    {
      n_left = n;
      policy_id = policy_ids;
      ip4_5tuple = ip4_5tuples;
      pp = policies;

      while (n_left)
	{
	  if (*pp != NULL)
	    {
	      /* Add an Entry in Flow cache */
	      ipsec4_out_spd_add_flow_cache_entry_n (im->ipsec4_out_spd_hash_tbl, ip4_5tuple,
						     *policy_id, flow_cache_mask);
	    }

	  n_left--;
	  policy_id++;
	  ip4_5tuple++;
	  pp++;
	}
    }

  return counter;
}

always_inline ipsec_policy_t *
ipsec4_out_spd_find_flow_cache_entry (ipsec4_flow_cache_bucket_t *tbl, ipsec_main_t *im, u8 pr,
				      u32 la, u32 ra, u16 lp, u16 rp, u64 flow_cache_mask)
{
  ipsec_policy_t *p = NULL;
  ipsec4_flow_cache_bucket_t *bucket;
  ipsec4_hash_kv_16_8_t kv_result;

  if (PREDICT_FALSE (!ipsec4_out_proto_is_tcp_udp_or_sctp (pr)))
    {
      lp = 0;
      rp = 0;
    }
  ipsec4_spd_5tuple_t ip4_5tuple = {
    .ip4_addr = { (ip4_address_t) la, (ip4_address_t) ra },
    .port = { lp, rp },
    .proto = pr,
  };

  bucket = tbl + (ipsec4_hash_16_8 (&ip4_5tuple.kv_16_8) & flow_cache_mask);

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

  if (ipsec4_hash_key_compare_16_8 ((u64 *) &ip4_5tuple.kv_16_8, (u64 *) &kv_result))
    p = pool_elt_at_index (im->policies, kv_result.value);

  return p;
}

always_inline ipsec_policy_t *
ipsec_output_policy_match (ipsec_spd_t *spd, u8 pr, u32 la, u32 ra, u16 lp, u16 rp,
			   u64 flow_cache_mask)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_policy_t *policies[1];
  ipsec_fp_5tuple_t tuples[1];
  u32 fp_policy_ids[1];
  u32 matched_policy_index;
  u32 *policy_indices;
  u32 policy_index;
  u32 lah, rah;
  u16 lph, rph;

  if (!spd)
    return 0;

  if (im->fp_spd_ipv4_out_is_enabled &&
      PREDICT_TRUE (INDEX_INVALID != spd->fp_spd.ip4_out_lookup_hash_idx))
    {
      ipsec_fp_5tuple_from_ip4_range (&tuples[0], la, ra, lp, rp, pr);
      ipsec_fp_out_policy_match_n (&spd->fp_spd, 0, tuples, policies,
				   fp_policy_ids, 1);
      p = policies[0];
      if (!p)
	return 0;
      matched_policy_index = fp_policy_ids[0];
      if (PREDICT_FALSE (!ipsec4_out_proto_is_tcp_udp_or_sctp (pr)))
	{
	  lp = 0;
	  rp = 0;
	}
      goto add_flow_cache;
    }

  policy_indices = spd->policies[IPSEC_SPD_POLICY_IP4_OUTBOUND];
  policy_index = ipsec_spd_ip4_find_range_match (spd, IPSEC_SPD_POLICY_IP4_OUTBOUND, la, ra);

  if (policy_index == ~0)
    return 0;

  lph = clib_net_to_host_u16 (lp);
  rph = clib_net_to_host_u16 (rp);
  lah = clib_net_to_host_u32 (la);
  rah = clib_net_to_host_u32 (ra);

  for (; policy_index < vec_len (policy_indices); policy_index++)
    {
      p = pool_elt_at_index (im->policies, policy_indices[policy_index]);

      if (lah < clib_net_to_host_u32 (p->laddr.start.ip4.as_u32))
	continue;

      if (lah > clib_net_to_host_u32 (p->laddr.stop.ip4.as_u32))
	continue;

      if (rah < clib_net_to_host_u32 (p->raddr.start.ip4.as_u32))
	continue;

      if (rah > clib_net_to_host_u32 (p->raddr.stop.ip4.as_u32))
	continue;

      if (PREDICT_FALSE ((p->protocol != IPSEC_POLICY_PROTOCOL_ANY) && (p->protocol != pr)))
	continue;

      matched_policy_index = policy_indices[policy_index];

      if (PREDICT_FALSE (!ipsec4_out_proto_is_tcp_udp_or_sctp (pr)))
	{
	  lp = 0;
	  rp = 0;
	  goto add_flow_cache;
	}

      if (lph < p->lport.start || lph > p->lport.stop || rph < p->rport.start ||
	  rph > p->rport.stop)
	continue;

      goto add_flow_cache;
    }

  return 0;

add_flow_cache:
  if (flow_cache_mask)
    {
      /* Add an Entry in Flow cache */
      ipsec4_out_spd_add_flow_cache_entry (im->ipsec4_out_spd_hash_tbl, pr, la, ra, lp, rp,
					   matched_policy_index, flow_cache_mask);
    }

  return p;
}

always_inline uword
ip6_addr_match_range (ip6_address_t *a, ip6_address_t *la, ip6_address_t *ua)
{
  if ((memcmp (a->as_u64, la->as_u64, 2 * sizeof (u64)) >= 0) &&
      (memcmp (a->as_u64, ua->as_u64, 2 * sizeof (u64)) <= 0))
    return 1;
  return 0;
}

always_inline void
ipsec_fp_5tuple_from_ip6_range (ipsec_fp_5tuple_t *tuple, ip6_address_t *la,
				ip6_address_t *ra, u16 lp, u16 rp, u8 pr)

{
  clib_memcpy (&tuple->ip6_laddr, la, sizeof (ip6_address_t));
  clib_memcpy (&tuple->ip6_raddr, ra, sizeof (ip6_address_t));

  tuple->lport = lp;
  tuple->rport = rp;
  tuple->protocol = pr;
  tuple->is_ipv6 = 1;
}

always_inline ipsec_policy_t *
ipsec6_output_policy_match (ipsec_spd_t *spd, ip6_address_t *la,
			    ip6_address_t *ra, u16 lp, u16 rp, u8 pr)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_policy_t *p;
  ipsec_policy_t *policies[1];
  ipsec_fp_5tuple_t tuples[1];
  u32 fp_policy_ids[1];

  u32 *i;

  if (!spd)
    return 0;

  lp = clib_net_to_host_u16 (lp);
  rp = clib_net_to_host_u16 (rp);

  if (im->fp_spd_ipv6_out_is_enabled &&
      PREDICT_TRUE (INDEX_INVALID != spd->fp_spd.ip6_out_lookup_hash_idx))
    {

      ipsec_fp_5tuple_from_ip6_range (&tuples[0], la, ra, lp, rp, pr);
      ipsec_fp_out_policy_match_n (&spd->fp_spd, 1, tuples, policies,
				   fp_policy_ids, 1);
      p = policies[0];
      i = fp_policy_ids;
      return p;
    }

  vec_foreach (i, spd->policies[IPSEC_SPD_POLICY_IP6_OUTBOUND])
    {
      p = pool_elt_at_index (im->policies, *i);
      if (PREDICT_FALSE ((p->protocol != IPSEC_POLICY_PROTOCOL_ANY) &&
			 (p->protocol != pr)))
	continue;

      if (!ip6_addr_match_range (ra, &p->raddr.start.ip6, &p->raddr.stop.ip6))
	continue;

      if (!ip6_addr_match_range (la, &p->laddr.start.ip6, &p->laddr.stop.ip6))
	continue;

      if (PREDICT_FALSE ((pr != IP_PROTOCOL_TCP) && (pr != IP_PROTOCOL_UDP) &&
			 (pr != IP_PROTOCOL_SCTP)))
	return p;

      if (lp < p->lport.start)
	continue;

      if (lp > p->lport.stop)
	continue;

      if (rp < p->rport.start)
	continue;

      if (rp > p->rport.stop)
	continue;

      return p;
    }

  return 0;
}

#endif /* !IPSEC_OUTPUT_H */
