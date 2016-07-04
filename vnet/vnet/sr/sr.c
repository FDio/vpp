/*
 * sr.c: ipv6 segment routing
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
#include <vnet/sr/sr.h>

#include <openssl/hmac.h>

ip6_sr_main_t sr_main;
static vlib_node_registration_t sr_local_node;

void sr_fix_hmac (ip6_sr_main_t * sm, ip6_header_t * ip,
                         ip6_sr_header_t * sr)
{
  u32 key_index;
  static u8 * keybuf;
  u8 * copy_target;
  int first_segment;
  ip6_address_t *addrp;
  int i;
  ip6_sr_hmac_key_t * hmac_key;
  u32 sig_len;

  key_index = sr->hmac_key;

  /* No signature? Pass... */
  if (key_index == 0)
    return;

  /* We don't know about this key? Fail... */
  if (key_index >= vec_len (sm->hmac_keys))
    return;

  hmac_key = sm->hmac_keys + key_index;

  vec_reset_length (keybuf);

  /* pkt ip6 src address */
  vec_add2 (keybuf, copy_target, sizeof (ip6_address_t));
  clib_memcpy (copy_target, ip->src_address.as_u8, sizeof (ip6_address_t));

  /* first segment */
  vec_add2 (keybuf, copy_target, 1);
  copy_target[0] = sr->first_segment;

  /* octet w/ bit 0 = "clean" flag */
  vec_add2 (keybuf, copy_target, 1);
  copy_target[0]
    = (sr->flags & clib_host_to_net_u16 (IP6_SR_HEADER_FLAG_CLEANUP))
    ? 0x80 : 0;

  /* hmac key id */
  vec_add2 (keybuf, copy_target, 1);
  copy_target[0] = sr->hmac_key;

  first_segment = sr->first_segment;

  addrp = sr->segments;

  /* segments */
  for (i = 0; i <= first_segment; i++)
    {
      vec_add2 (keybuf, copy_target, sizeof (ip6_address_t));
      clib_memcpy (copy_target, addrp->as_u8, sizeof (ip6_address_t));
      addrp++;
    }

  addrp++;

  HMAC_CTX_init(sm->hmac_ctx);
  if (!HMAC_Init(sm->hmac_ctx, hmac_key->shared_secret,
                 vec_len(hmac_key->shared_secret),sm->md))
      clib_warning ("barf1");
  if (!HMAC_Update(sm->hmac_ctx,keybuf,vec_len(keybuf)))
      clib_warning ("barf2");
  if (!HMAC_Final(sm->hmac_ctx, (unsigned char *) addrp, &sig_len))
      clib_warning ("barf3");
  HMAC_CTX_cleanup(sm->hmac_ctx);
}

u8 * format_ip6_sr_header_flags (u8 * s, va_list * args)
{
  u16 flags = (u16) va_arg (*args, int);
  u8 pl_flag;
  int bswap_needed = va_arg (*args, int);
  int i;

  if (bswap_needed)
      flags = clib_host_to_net_u16 (flags);

  if (flags & IP6_SR_HEADER_FLAG_CLEANUP)
      s = format (s, "cleanup ");

  if (flags & IP6_SR_HEADER_FLAG_PROTECTED)
      s = format (s, "reroute ");

  s = format (s, "pl: ");
  for (i = 1; i <= 4; i++)
    {
      pl_flag = ip6_sr_policy_list_flags (flags, i);
      s = format (s, "[%d] ", i);

      switch (pl_flag)
        {
        case IP6_SR_HEADER_FLAG_PL_ELT_NOT_PRESENT:
          s = format (s, "NotPr ");
          break;
        case IP6_SR_HEADER_FLAG_PL_ELT_INGRESS_PE:
          s = format (s, "InPE ");
          break;
        case IP6_SR_HEADER_FLAG_PL_ELT_EGRESS_PE:
          s = format (s, "EgPE ");
          break;

        case IP6_SR_HEADER_FLAG_PL_ELT_ORIG_SRC_ADDR:
          s = format (s, "OrgSrc ");
          break;
        }
    }
  return s;
}

u8 * format_ip6_sr_header (u8 * s, va_list * args)
{
  ip6_sr_header_t * h = va_arg (*args, ip6_sr_header_t *);
  int print_hmac = va_arg (*args, int);
  int i, pl_index, max_segs;
  int flags_host_byte_order = clib_net_to_host_u16(h->flags);

  s = format (s, "next proto %d, len %d, type %d",
              h->protocol, (h->length<<3)+8, h->type);
  s = format (s, "\n      segs left %d, first_segment %d, hmac key %d",
              h->segments_left, h->first_segment, h->hmac_key);
  s = format (s, "\n      flags %U", format_ip6_sr_header_flags,
              flags_host_byte_order, 0 /* bswap needed */ );

  /*
   * Header length is in 8-byte units (minus one), so
   * divide by 2 to ascertain the number of ip6 addresses in the
   * segment list
   */
  max_segs = (h->length>>1);

  if (!print_hmac && h->hmac_key)
    max_segs -= 2;

  s = format (s, "\n  Segments (in processing order):");

  for (i = h->first_segment; i >= 1; i--)
    s = format (s, "\n  %U", format_ip6_address, h->segments + i);

  s = format (s, "\n  Policy List:");

  pl_index = 1;                 /* to match the RFC text */
  for (i = (h->first_segment+1); i < max_segs; i++, pl_index++)
    {
      char * tag;
      char * tags[] = {" ", "InPE: ", "EgPE: ", "OrgSrc: "};

      tag = tags[0];
      if (pl_index >=1 && pl_index <= 4)
        {
          int this_pl_flag = ip6_sr_policy_list_flags
            (flags_host_byte_order, pl_index);
          tag = tags[this_pl_flag];
        }

      s = format (s, "\n  %s%U", tag, format_ip6_address, h->segments + i);
    }

  return s;
}

u8 * format_ip6_sr_header_with_length (u8 * s, va_list * args)
{
  ip6_header_t * h = va_arg (*args, ip6_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  uword header_bytes;

  header_bytes = sizeof (h[0]) + sizeof (ip6_sr_header_t);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "ip6_sr header truncated");

  s = format (s, "IP6: %U\n", format_ip6_header, h, max_header_bytes);
  s = format (s, "SR: %U\n", format_ip6_sr_header, (ip6_sr_header_t *)(h+1),
              0 /* print_hmac */, max_header_bytes);
  return s;
}

#if DPDK > 0 /* Cannot call replicate yet without DPDK */
#define foreach_sr_rewrite_next                 \
_(ERROR, "error-drop")                          \
_(IP6_LOOKUP, "ip6-lookup")                     \
_(SR_LOCAL, "sr-local")                         \
_(SR_REPLICATE,"sr-replicate")
#else
#define foreach_sr_rewrite_next                 \
_(ERROR, "error-drop")                          \
_(IP6_LOOKUP, "ip6-lookup")                     \
_(SR_LOCAL, "sr-local")
#endif /* DPDK */

typedef enum {
#define _(s,n) SR_REWRITE_NEXT_##s,
  foreach_sr_rewrite_next
#undef _
  SR_REWRITE_N_NEXT,
} sr_rewrite_next_t;

typedef struct {
  ip6_address_t src, dst;
  u16 length;
  u32 next_index;
  u32 tunnel_index;
  u8 sr[256];
} sr_rewrite_trace_t;

static char * sr_rewrite_error_strings[] = {
#define sr_error(n,s) s,
#include "sr_error.def"
#undef sr_error
};

typedef enum {
#define sr_error(n,s) SR_REWRITE_ERROR_##n,
#include "sr_error.def"
#undef sr_error
  SR_REWRITE_N_ERROR,
} sr_rewrite_error_t;


u8 * format_sr_rewrite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sr_rewrite_trace_t * t = va_arg (*args, sr_rewrite_trace_t *);
  ip6_main_t * im = &ip6_main;
  ip6_sr_main_t * sm = &sr_main;
  ip6_sr_tunnel_t *tun = pool_elt_at_index (sm->tunnels, t->tunnel_index);
  ip6_fib_t * rx_fib, * tx_fib;

  rx_fib = find_ip6_fib_by_table_index_or_id (im, tun->rx_fib_index,
                                              IP6_ROUTE_FLAG_FIB_INDEX);

  tx_fib = find_ip6_fib_by_table_index_or_id (im, tun->tx_fib_index,
                                              IP6_ROUTE_FLAG_FIB_INDEX);

  s = format
    (s, "SR-REWRITE: next %s ip6 src %U dst %U len %u\n"
     "           rx-fib-id %d tx-fib-id %d\n%U",
     (t->next_index == SR_REWRITE_NEXT_SR_LOCAL)
     ? "sr-local" : "ip6-lookup",
     format_ip6_address, &t->src,
     format_ip6_address, &t->dst, t->length,
     rx_fib->table_id, tx_fib->table_id,
     format_ip6_sr_header, t->sr, 0 /* print_hmac */);
  return s;
}

static uword
sr_rewrite (vlib_main_t * vm,
                   vlib_node_runtime_t * node,
                   vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip6_sr_main_t * sm = &sr_main;
  u32 (*sr_local_cb) (vlib_main_t *, vlib_node_runtime_t *,
                      vlib_buffer_t *, ip6_header_t *,
                      ip6_sr_header_t *);
  sr_local_cb = sm->sr_local_cb;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      /* Note 2x loop disabled */
      while (0 && n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          ip6_header_t * ip0, * ip1;
          ip_adjacency_t * adj0, * adj1;
          ip6_sr_header_t * sr0, * sr1;
          ip6_sr_tunnel_t * t0, *t1;
	  u32 next0 = SR_REWRITE_NEXT_IP6_LOOKUP;
	  u32 next1 = SR_REWRITE_NEXT_IP6_LOOKUP;
          u16 new_l0 = 0;
	  u16 new_l1 = 0;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

          /*
           * $$$ parse through header(s) to pick the point
           * where we punch in the SR extention header
           */

          adj0 = ip_get_adjacency (lm, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);
          adj1 = ip_get_adjacency (lm, vnet_buffer(b1)->ip.adj_index[VLIB_TX]);
          t0 = pool_elt_at_index (sm->tunnels,
                                  adj0->rewrite_header.sw_if_index);
          t1 = pool_elt_at_index (sm->tunnels,
                                  adj1->rewrite_header.sw_if_index);

          ASSERT (VLIB_BUFFER_PRE_DATA_SIZE
                  >= ((word) vec_len (t0->rewrite)) + b0->current_data);
          ASSERT (VLIB_BUFFER_PRE_DATA_SIZE
                  >= ((word) vec_len (t1->rewrite)) + b1->current_data);

          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->tx_fib_index;
          vnet_buffer(b1)->sw_if_index[VLIB_TX] = t1->tx_fib_index;

          ip0 = vlib_buffer_get_current (b0);
          ip1 = vlib_buffer_get_current (b1);

          /*
           * SR-unaware service chaining case: pkt coming back from
           * service has the original dst address, and will already
           * have an SR header. If so, send it to sr-local
           */
          if (PREDICT_FALSE(ip0->protocol == IPPROTO_IPV6_ROUTE))
            {
              vlib_buffer_advance (b0, sizeof(ip0));
              sr0 = (ip6_sr_header_t *) (ip0+1);
              new_l0 = clib_net_to_host_u16(ip0->payload_length);
              next0 = SR_REWRITE_NEXT_SR_LOCAL;
            }
          else
            {
              /*
               * Copy data before the punch-in point left by the
               * required amount. Assume (for the moment) that only
               * the main packet header needs to be copied.
               */
              clib_memcpy (((u8 *)ip0) - vec_len (t0->rewrite),
                           ip0, sizeof (ip6_header_t));
              vlib_buffer_advance (b0, - (word) vec_len(t0->rewrite));
              ip0 = vlib_buffer_get_current (b0);
              sr0 = (ip6_sr_header_t *) (ip0+1);
              /* $$$ tune */
              clib_memcpy (sr0, t0->rewrite, vec_len (t0->rewrite));

              /* Fix the next header chain */
              sr0->protocol = ip0->protocol;
              ip0->protocol = IPPROTO_IPV6_ROUTE; /* routing extension header */
              new_l0 = clib_net_to_host_u16(ip0->payload_length) +
                vec_len (t0->rewrite);
              ip0->payload_length = clib_host_to_net_u16(new_l0);

              /* Copy dst address into the DA slot in the segment list */
              clib_memcpy (sr0->segments, ip0->dst_address.as_u64,
                           sizeof (ip6_address_t));
              /* Rewrite the ip6 dst address with the first hop */
              clib_memcpy (ip0->dst_address.as_u64, t0->first_hop.as_u64,
                           sizeof (ip6_address_t));

              sr_fix_hmac (sm, ip0, sr0);

              next0 = sr_local_cb ? sr_local_cb (vm, node, b0, ip0, sr0) :
                  next0;

              /*
               * Ignore "do not rewrite" shtik in this path
               */
              if (PREDICT_FALSE (next0 & 0x80000000))
              {
                  next0 ^= 0xFFFFFFFF;
                  if (PREDICT_FALSE(next0 == SR_REWRITE_NEXT_ERROR))
                      b0->error =
                          node->errors[SR_REWRITE_ERROR_APP_CALLBACK];
              }
            }

          if (PREDICT_FALSE(ip1->protocol == IPPROTO_IPV6_ROUTE))
            {
              vlib_buffer_advance (b1, sizeof(ip1));
              sr1 = (ip6_sr_header_t *) (ip1+1);
              new_l1 = clib_net_to_host_u16(ip1->payload_length);
              next1 = SR_REWRITE_NEXT_SR_LOCAL;
            }
          else
            {
              clib_memcpy (((u8 *)ip0) - vec_len (t0->rewrite),
                           ip0, sizeof (ip6_header_t));
              vlib_buffer_advance (b1, - (word) vec_len(t1->rewrite));
              ip1 = vlib_buffer_get_current (b1);
              sr1 = (ip6_sr_header_t *) (ip1+1);
              clib_memcpy (sr1, t1->rewrite, vec_len (t1->rewrite));

              sr1->protocol = ip1->protocol;
              ip1->protocol = IPPROTO_IPV6_ROUTE;
              new_l1 = clib_net_to_host_u16(ip1->payload_length) +
                vec_len (t1->rewrite);
              ip1->payload_length = clib_host_to_net_u16(new_l1);

              /* Copy dst address into the DA slot in the segment list */
              clib_memcpy (sr1->segments, ip1->dst_address.as_u64,
                           sizeof (ip6_address_t));
              /* Rewrite the ip6 dst address with the first hop */
              clib_memcpy (ip1->dst_address.as_u64, t1->first_hop.as_u64,
                           sizeof (ip6_address_t));

              sr_fix_hmac (sm, ip1, sr1);

              next1 = sr_local_cb ? sr_local_cb (vm, node, b1, ip1, sr1) :
                  next1;

              /*
               * Ignore "do not rewrite" shtik in this path
               */
              if (PREDICT_FALSE (next1 & 0x80000000))
              {
                  next1 ^= 0xFFFFFFFF;
                  if (PREDICT_FALSE(next1 == SR_REWRITE_NEXT_ERROR))
                      b1->error =
                          node->errors[SR_REWRITE_ERROR_APP_CALLBACK];
              }
            }

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              sr_rewrite_trace_t *tr = vlib_add_trace (vm, node,
                                                       b0, sizeof (*tr));
              tr->tunnel_index = t0 - sm->tunnels;
              clib_memcpy (tr->src.as_u8, ip0->src_address.as_u8,
                      sizeof (tr->src.as_u8));
              clib_memcpy (tr->dst.as_u8, ip0->dst_address.as_u8,
                      sizeof (tr->dst.as_u8));
              tr->length = new_l0;
              tr->next_index = next0;
              clib_memcpy (tr->sr, sr0, sizeof (tr->sr));
            }
          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
              sr_rewrite_trace_t *tr = vlib_add_trace (vm, node,
                                                       b1, sizeof (*tr));
              tr->tunnel_index = t1 - sm->tunnels;
              clib_memcpy (tr->src.as_u8, ip1->src_address.as_u8,
                      sizeof (tr->src.as_u8));
              clib_memcpy (tr->dst.as_u8, ip1->dst_address.as_u8,
                      sizeof (tr->dst.as_u8));
              tr->length = new_l1;
              tr->next_index = next1;
              clib_memcpy (tr->sr, sr1, sizeof (tr->sr));
            }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
          ip6_header_t * ip0 = 0;
          ip_adjacency_t * adj0;
          ip6_sr_header_t * sr0 = 0;
          ip6_sr_tunnel_t * t0;
	  u32 next0 = SR_REWRITE_NEXT_IP6_LOOKUP;
          u16 new_l0 = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          /*
           * $$$ parse through header(s) to pick the point
           * where we punch in the SR extention header
           */

          adj0 = ip_get_adjacency (lm, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);
          t0 = pool_elt_at_index (sm->tunnels,
                                  adj0->rewrite_header.sw_if_index);

#if DPDK > 0 /* Cannot call replication node yet without DPDK */
	  /* add a replication node */
	  if(PREDICT_FALSE(t0->policy_index != ~0))
	    {
	      vnet_buffer(b0)->ip.save_protocol = t0->policy_index;
	      next0=SR_REWRITE_NEXT_SR_REPLICATE;
	      goto trace0;
	    }
#endif /* DPDK */

          ASSERT (VLIB_BUFFER_PRE_DATA_SIZE
                  >= ((word) vec_len (t0->rewrite)) + b0->current_data);

          vnet_buffer(b0)->sw_if_index[VLIB_TX] = t0->tx_fib_index;

          ip0 = vlib_buffer_get_current (b0);

          /*
           * SR-unaware service chaining case: pkt coming back from
           * service has the original dst address, and will already
           * have an SR header. If so, send it to sr-local
           */
          if (PREDICT_FALSE(ip0->protocol == IPPROTO_IPV6_ROUTE))
            {
              vlib_buffer_advance (b0, sizeof(ip0));
              sr0 = (ip6_sr_header_t *) (ip0+1);
              new_l0 = clib_net_to_host_u16(ip0->payload_length);
              next0 = SR_REWRITE_NEXT_SR_LOCAL;
            }
          else
            {
              /*
               * Copy data before the punch-in point left by the
               * required amount. Assume (for the moment) that only
               * the main packet header needs to be copied.
               */
              clib_memcpy (((u8 *)ip0) - vec_len (t0->rewrite),
                           ip0, sizeof (ip6_header_t));
              vlib_buffer_advance (b0, - (word) vec_len(t0->rewrite));
              ip0 = vlib_buffer_get_current (b0);
              sr0 = (ip6_sr_header_t *) (ip0+1);
              /* $$$ tune */
              clib_memcpy (sr0, t0->rewrite, vec_len (t0->rewrite));

              /* Fix the next header chain */
              sr0->protocol = ip0->protocol;
              ip0->protocol = IPPROTO_IPV6_ROUTE; /* routing extension header */
              new_l0 = clib_net_to_host_u16(ip0->payload_length) +
                vec_len (t0->rewrite);
              ip0->payload_length = clib_host_to_net_u16(new_l0);

              /* Copy dst address into the DA slot in the segment list */
              clib_memcpy (sr0->segments, ip0->dst_address.as_u64,
                           sizeof (ip6_address_t));
              /* Rewrite the ip6 dst address with the first hop */
              clib_memcpy (ip0->dst_address.as_u64, t0->first_hop.as_u64,
                           sizeof (ip6_address_t));

              sr_fix_hmac (sm, ip0, sr0);

              next0 = sr_local_cb ? sr_local_cb (vm, node, b0, ip0, sr0) :
                  next0;

              /*
               * Ignore "do not rewrite" shtik in this path
               */
              if (PREDICT_FALSE (next0 & 0x80000000))
              {
                  next0 ^= 0xFFFFFFFF;
                  if (PREDICT_FALSE(next0 == SR_REWRITE_NEXT_ERROR))
                      b0->error =
                          node->errors[SR_REWRITE_ERROR_APP_CALLBACK];
              }
            }

#if DPDK > 0 /* Cannot run replicate without DPDK and only replicate uses this label */
	trace0:
#endif /* DPDK */
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              sr_rewrite_trace_t *tr = vlib_add_trace (vm, node,
                                                       b0, sizeof (*tr));
              tr->tunnel_index = t0 - sm->tunnels;
	      if (ip0)
		{
		  memcpy (tr->src.as_u8, ip0->src_address.as_u8,
                      sizeof (tr->src.as_u8));
		  memcpy (tr->dst.as_u8, ip0->dst_address.as_u8,
                      sizeof (tr->dst.as_u8));
		}
              tr->length = new_l0;
              tr->next_index = next0;
              clib_memcpy (tr->sr, sr0, sizeof (tr->sr));
            }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (sr_rewrite_node) = {
  .function = sr_rewrite,
  .name = "sr-rewrite",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .format_trace = format_sr_rewrite_trace,
  .format_buffer = format_ip6_sr_header_with_length,

  .n_errors = SR_REWRITE_N_ERROR,
  .error_strings = sr_rewrite_error_strings,

  .runtime_data_bytes = 0,

  .n_next_nodes = SR_REWRITE_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_REWRITE_NEXT_##s] = n,
    foreach_sr_rewrite_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (sr_rewrite_node, sr_rewrite)

static int ip6_delete_route_no_next_hop (ip6_address_t *dst_address_arg,
                                         u32 dst_address_length,
                                         u32 rx_table_id)
{
  ip6_add_del_route_args_t a;
  ip6_address_t dst_address;
  ip6_fib_t * fib;
  ip6_main_t * im6 = &ip6_main;
  BVT(clib_bihash_kv) kv, value;

  fib = find_ip6_fib_by_table_index_or_id (im6, rx_table_id,
                                           IP6_ROUTE_FLAG_TABLE_ID);
  memset (&a, 0, sizeof (a));
  a.flags |= IP4_ROUTE_FLAG_DEL;
  a.dst_address_length = dst_address_length;

  dst_address = *dst_address_arg;

  ip6_address_mask (&dst_address,
                    &im6->fib_masks[dst_address_length]);

  kv.key[0] = dst_address.as_u64[0];
  kv.key[1] = dst_address.as_u64[1];
  kv.key[2] = ((u64)((fib - im6->fibs))<<32) | dst_address_length;

  if (BV(clib_bihash_search)(&im6->ip6_lookup_table, &kv, &value) < 0)
    {
      clib_warning ("%U/%d not in FIB",
                    format_ip6_address, &a.dst_address,
                    a.dst_address_length);
      return -10;
    }

  a.adj_index = value.value;
  a.dst_address = dst_address;

  ip6_add_del_route (im6, &a);
  ip6_maybe_remap_adjacencies (im6, rx_table_id, IP6_ROUTE_FLAG_TABLE_ID);
  return 0;
}

static ip6_sr_hmac_key_t *
find_or_add_shared_secret (ip6_sr_main_t * sm, u8 * secret, u32 * indexp)
{
  uword * p;
  ip6_sr_hmac_key_t * key = 0;
  int i;

  p = hash_get_mem (sm->hmac_key_by_shared_secret, secret);

  if (p)
    {
      key = vec_elt_at_index (sm->hmac_keys, p[0]);
      if (indexp)
        *indexp = p[0];
      return (key);
    }

  /* Specific key ID? */
  if (indexp && *indexp)
    {
      vec_validate (sm->hmac_keys, *indexp);
      key = sm->hmac_keys + *indexp;
    }
  else
    {
      for (i = 0; i < vec_len (sm->hmac_keys); i++)
        {
          if (sm->hmac_keys[i].shared_secret == 0)
            key = sm->hmac_keys + i;
          goto found;
        }
      vec_validate (sm->hmac_keys, i);
      key = sm->hmac_keys + i;
    found:
      ;
    }

  key->shared_secret = vec_dup (secret);

  hash_set_mem (sm->hmac_key_by_shared_secret, key->shared_secret,
                key - sm->hmac_keys);

  if (indexp)
    *indexp = key - sm->hmac_keys;
  return (key);
}


int ip6_sr_add_del_tunnel (ip6_sr_add_del_tunnel_args_t * a)
{
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip6_sr_tunnel_key_t key;
  ip6_sr_tunnel_t * t;
  uword * p, * n;
  ip6_sr_header_t * h = 0;
  u32 header_length;
  ip6_address_t * addrp, *this_address;
  ip_adjacency_t adj, * ap, * add_adj = 0;
  u32 adj_index;
  ip6_sr_main_t * sm = &sr_main;
  u8 * key_copy;
  u32 rx_fib_index, tx_fib_index;
  ip6_add_del_route_args_t aa;
  u32 hmac_key_index_u32;
  u8 hmac_key_index = 0;
  ip6_sr_policy_t * pt;
  int i;

  /* Make sure that the rx FIB exists */
  p = hash_get (im->fib_index_by_table_id, a->rx_table_id);

  if (p == 0)
    return -3;

  /* remember the FIB index */
  rx_fib_index = p[0];

  /* Make sure that the supplied FIB exists */
  p = hash_get (im->fib_index_by_table_id, a->tx_table_id);

  if (p == 0)
    return -4;

  /* remember the FIB index */
  tx_fib_index = p[0];

  clib_memcpy (key.src.as_u8, a->src_address->as_u8, sizeof (key.src));
  clib_memcpy (key.dst.as_u8, a->dst_address->as_u8, sizeof (key.dst));

  /* When adding a tunnel:
   * - If a "name" is given, it must not exist.
   * - The "key" is always checked, and must not exist.
   * When deleting a tunnel:
   * - If the "name" is given, and it exists, then use it.
   * - If the "name" is not given, use the "key".
   * - If the "name" and the "key" are given, then both must point to the same
   *   thing.
   */

  /* Lookup the key */
  p = hash_get_mem (sm->tunnel_index_by_key, &key);

  /* If the name is given, look it up */
  if (a->name)
    n = hash_get_mem(sm->tunnel_index_by_name, a->name);
  else
    n = 0;

  /* validate key/name parameters */
  if (!a->is_del) /* adding a tunnel */
    {
      if (a->name && n) /* name given & exists already */
        return -1;
      if (p) /* key exists already */
        return -1;
    }
  else /* deleting a tunnel */
    {
      if (!p) /* key doesn't exist */
        return -2;
      if (a->name && !n) /* name given & it doesn't exist */
        return -2;

      if (n) /* name given & found */
        {
          if (n[0] != p[0]) /* name and key do not point to the same thing */
            return -2;
        }
    }


  if (a->is_del) /* delete the tunnel */
    {
      hash_pair_t *hp;

      /* Delete existing tunnel */
      t = pool_elt_at_index (sm->tunnels, p[0]);

      ip6_delete_route_no_next_hop (&t->key.dst, t->dst_mask_width,
                                    a->rx_table_id);
      vec_free (t->rewrite);
      /* Remove tunnel from any policy if associated */
      if (t->policy_index != ~0)
        {
          pt=pool_elt_at_index (sm->policies, t->policy_index);
          for (i=0; i< vec_len (pt->tunnel_indices); i++)
            {
              if (pt->tunnel_indices[i] == t - sm->tunnels)
                {
                  vec_delete (pt->tunnel_indices, 1, i);
                  goto found;
                }
            }
          clib_warning ("Tunnel index %d not found in policy_index %d",
                         t - sm->tunnels, pt - sm->policies);
        found:
           /* If this is last tunnel in the  policy, clean up the policy too */
          if (vec_len (pt->tunnel_indices) == 0)
            {
              hash_unset_mem (sm->policy_index_by_policy_name, pt->name);
              vec_free (pt->name);
              pool_put (sm->policies, pt);
            }
        }

      /* Clean up the tunnel by name */
      if (t->name)
        {
          hash_unset_mem (sm->tunnel_index_by_name, t->name);
          vec_free (t->name);
        }
      pool_put (sm->tunnels, t);
      hp = hash_get_pair (sm->tunnel_index_by_key, &key);
      key_copy = (void *)(hp->key);
      hash_unset_mem (sm->tunnel_index_by_key, &key);
      vec_free (key_copy);
      return 0;
    }

  /* create a new tunnel */
  pool_get (sm->tunnels, t);
  memset (t, 0, sizeof (*t));
  t->policy_index = ~0;

  clib_memcpy (&t->key, &key, sizeof (t->key));
  t->dst_mask_width = a->dst_mask_width;
  t->rx_fib_index = rx_fib_index;
  t->tx_fib_index = tx_fib_index;

  if (!vec_len (a->segments))
      /* there must be at least one segment... */
      return -4;

  /* The first specified hop goes right into the dst address */
  clib_memcpy(&t->first_hop, &a->segments[0], sizeof (ip6_address_t));

  /*
   * Create the sr header rewrite string
   * The list of segments needs an extra slot for the ultimate destination
   * which is taken from the packet we add the SRH to.
   */
  header_length = sizeof (*h) +
    sizeof (ip6_address_t) * (vec_len (a->segments) + 1 + vec_len (a->tags));

  if (a->shared_secret)
    {
      /* Allocate a new key slot if we don't find the secret key */
      hmac_key_index_u32 = 0;
      (void) find_or_add_shared_secret (sm, a->shared_secret,
                                        &hmac_key_index_u32);

      /* Hey Vinz Clortho: Gozzer is pissed.. you're out of keys! */
      if (hmac_key_index_u32 >= 256)
        return -5;
      hmac_key_index = hmac_key_index_u32;
      header_length += SHA256_DIGEST_LENGTH;
    }

  vec_validate (t->rewrite, header_length-1);

  h = (ip6_sr_header_t *) t->rewrite;

  h->protocol = 0xFF; /* we don't know yet */

  h->length = (header_length/8) - 1;
  h->type = ROUTING_HEADER_TYPE_SR;

  /* first_segment and segments_left need to have the index of the last
   * element in the list; a->segments has one element less than ends up
   * in the header (it does not have the DA in it), so vec_len(a->segments)
   * is the value we want.
   */
  h->first_segment = h->segments_left = vec_len (a->segments);

  if (a->shared_secret)
    h->hmac_key = hmac_key_index & 0xFF;

  h->flags = a->flags_net_byte_order;

  /* Paint on the segment list, in reverse.
   * This is offset by one to leave room at the start for the ultimate
   * destination.
   */
  addrp = h->segments + vec_len (a->segments);

  vec_foreach (this_address, a->segments)
    {
      clib_memcpy (addrp->as_u8, this_address->as_u8, sizeof (ip6_address_t));
      addrp--;
    }

  /*
   * Since the ultimate destination address is not yet known, set that slot
   * to a value we will instantly recognize as bogus.
   */
  memset (h->segments, 0xfe, sizeof (ip6_address_t));

  /* Paint on the tag list, not reversed */
  addrp = h->segments + vec_len(a->segments);

  vec_foreach (this_address, a->tags)
    {
      clib_memcpy (addrp->as_u8, this_address->as_u8, sizeof (ip6_address_t));
      addrp++;
    }

  key_copy = vec_new (ip6_sr_tunnel_key_t, 1);
  clib_memcpy (key_copy, &key, sizeof (ip6_sr_tunnel_key_t));
  hash_set_mem (sm->tunnel_index_by_key, key_copy, t - sm->tunnels);

  memset(&adj, 0, sizeof (adj));

  /* Create an adjacency and add to v6 fib */
  adj.lookup_next_index = IP_LOOKUP_NEXT_REWRITE;
  adj.lookup_next_index = sm->ip6_lookup_sr_next_index;
  adj.explicit_fib_index = ~0;

  ap = ip_add_adjacency (lm, &adj, 1 /* one adj */,
                         &adj_index);

  /*
   * Stick the tunnel index into the rewrite header.
   *
   * Unfortunately, inserting an SR header according to the various
   * RFC's requires parsing through the ip6 header, perhaps consing a
   * buffer onto the head of the vlib_buffer_t, etc. We don't use the
   * normal reverse bcopy rewrite code.
   *
   * We don't handle ugly RFC-related cases yet, but I'm sure PL will complain
   * at some point...
   */
  ap->rewrite_header.sw_if_index = t - sm->tunnels;

  vec_add1 (add_adj, ap[0]);

  clib_memcpy (aa.dst_address.as_u8, a->dst_address, sizeof (aa.dst_address.as_u8));
  aa.dst_address_length = a->dst_mask_width;

  aa.flags = (a->is_del ? IP6_ROUTE_FLAG_DEL : IP6_ROUTE_FLAG_ADD);
  aa.flags |= IP6_ROUTE_FLAG_FIB_INDEX;
  aa.table_index_or_table_id = rx_fib_index;
  aa.add_adj = add_adj;
  aa.adj_index = adj_index;
  aa.n_add_adj = 1;
  ip6_add_del_route (im, &aa);
  vec_free (add_adj);

  if (a->policy_name)
    {
      p=hash_get_mem (sm->policy_index_by_policy_name, a->policy_name);
      if (p)
	{
	  pt = pool_elt_at_index (sm->policies, p[0]);
	}
      else /* no policy, lets create one */
	{
	  pool_get (sm->policies, pt);
	  memset (pt, 0, sizeof(*pt));
	  pt->name = format (0, "%s%c", a->policy_name, 0);
	  hash_set_mem (sm->policy_index_by_policy_name, pt->name, pt - sm->policies);
	  p=hash_get_mem (sm->policy_index_by_policy_name, a->policy_name);
	}
      vec_add1 (pt->tunnel_indices, t - sm->tunnels);
      t->policy_index = p[0]; /* equiv. to (pt - sm->policies) */
    }

  if (a->name)
    {
      t->name = format (0, "%s%c", a->name, 0);
      hash_set_mem(sm->tunnel_index_by_name, t->name, t - sm->tunnels);
    }

  return 0;
}

static clib_error_t *
sr_add_del_tunnel_command_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  int is_del = 0;
  ip6_address_t src_address;
  int src_address_set = 0;
  ip6_address_t dst_address;
  u32 dst_mask_width;
  int dst_address_set = 0;
  u16 flags = 0;
  u8 *shared_secret = 0;
  u8 *name = 0;
  u8 *policy_name = 0;
  u32 rx_table_id = 0;
  u32 tx_table_id = 0;
  ip6_address_t * segments = 0;
  ip6_address_t * this_seg;
  ip6_address_t * tags = 0;
  ip6_address_t * this_tag;
  ip6_sr_add_del_tunnel_args_t _a, *a=&_a;
  ip6_address_t next_address, tag;
  int pl_index;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
        is_del = 1;
      else if (unformat (input, "rx-fib-id %d", &rx_table_id))
        ;
      else if (unformat (input, "tx-fib-id %d", &tx_table_id))
        ;
      else if (unformat (input, "src %U", unformat_ip6_address, &src_address))
        src_address_set = 1;
      else if (unformat (input, "name %s", &name))
        ;
      else if (unformat (input, "policy %s", &policy_name))
        ;
      else if (unformat (input, "dst %U/%d",
                         unformat_ip6_address, &dst_address,
                         &dst_mask_width))
        dst_address_set = 1;
      else if (unformat (input, "next %U", unformat_ip6_address,
                         &next_address))
        {
          vec_add2 (segments, this_seg, 1);
          clib_memcpy (this_seg->as_u8, next_address.as_u8, sizeof (*this_seg));
        }
      else if (unformat (input, "tag %U", unformat_ip6_address,
                         &tag))
        {
          vec_add2 (tags, this_tag, 1);
          clib_memcpy (this_tag->as_u8, tag.as_u8, sizeof (*this_tag));
        }
      else if (unformat (input, "clean"))
        flags |= IP6_SR_HEADER_FLAG_CLEANUP;
      else if (unformat (input, "protected"))
        flags |= IP6_SR_HEADER_FLAG_PROTECTED;
      else if (unformat (input, "key %s", &shared_secret))
          /* Do not include the trailing NULL byte. Guaranteed interop issue */
          _vec_len (shared_secret) -= 1;
      else if (unformat (input, "InPE %d", &pl_index))
        {
          if (pl_index <= 0 || pl_index > 4)
            {
            pl_index_range_error:
              return clib_error_return
                (0, "Policy List Element Index %d out of range (1-4)", pl_index);

            }
          flags |= IP6_SR_HEADER_FLAG_PL_ELT_INGRESS_PE
            << ip6_sr_policy_list_shift_from_index (pl_index);
        }
      else if (unformat (input, "EgPE %d", &pl_index))
        {
          if (pl_index <= 0 || pl_index > 4)
            goto pl_index_range_error;
          flags |= IP6_SR_HEADER_FLAG_PL_ELT_EGRESS_PE
            << ip6_sr_policy_list_shift_from_index (pl_index);
        }
      else if (unformat (input, "OrgSrc %d", &pl_index))
        {
          if (pl_index <= 0 || pl_index > 4)
            goto pl_index_range_error;
          flags |= IP6_SR_HEADER_FLAG_PL_ELT_ORIG_SRC_ADDR
            << ip6_sr_policy_list_shift_from_index (pl_index);
        }
      else
        break;
    }

  if (!src_address_set)
    return clib_error_return (0, "src address required");

  if (!dst_address_set)
    return clib_error_return (0, "dst address required");

  if (!segments)
    return clib_error_return (0, "at least one sr segment required");

  memset (a, 0, sizeof (*a));
  a->src_address = &src_address;
  a->dst_address = &dst_address;
  a->dst_mask_width = dst_mask_width;
  a->segments = segments;
  a->tags = tags;
  a->flags_net_byte_order = clib_host_to_net_u16(flags);
  a->is_del = is_del;
  a->rx_table_id = rx_table_id;
  a->tx_table_id = tx_table_id;
  a->shared_secret = shared_secret;

  if (vec_len(name))
    a->name = name;
  else
    a->name = 0;

  if (vec_len(policy_name))
    a->policy_name = policy_name;
  else
    a->policy_name = 0;

  rv = ip6_sr_add_del_tunnel (a);

  vec_free (segments);
  vec_free (tags);
  vec_free (shared_secret);

  switch (rv)
    {
    case 0:
      break;

    case -1:
      return clib_error_return (0, "SR tunnel src %U dst %U already exists",
                                format_ip6_address, &src_address,
                                format_ip6_address, &dst_address);

    case -2:
      return clib_error_return (0, "SR tunnel src %U dst %U does not exist",
                                format_ip6_address, &src_address,
                                format_ip6_address, &dst_address);

    case -3:
      return clib_error_return (0, "FIB table %d does not exist", rx_table_id);

    case -4:
      return clib_error_return (0, "At least one segment is required");

    default:
      return clib_error_return (0, "BUG: ip6_sr_add_del_tunnel returns %d",
                                rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (sr_tunnel_command, static) = {
    .path = "sr tunnel",
    .short_help =
      "sr tunnel [del] [name <name>] src <addr> dst <addr> [next <addr>] "
      "[clean] [reroute] [key <secret>] [policy <policy_name>]"
      "[rx-fib-id <fib_id>] [tx-fib-id <fib_id>]",
    .function = sr_add_del_tunnel_command_fn,
};

void
ip6_sr_tunnel_display (vlib_main_t * vm,
		       ip6_sr_tunnel_t * t)
{
  ip6_main_t * im = &ip6_main;
  ip6_sr_main_t * sm = &sr_main;
  ip6_fib_t * rx_fib, * tx_fib;
  ip6_sr_policy_t * pt;

  rx_fib = find_ip6_fib_by_table_index_or_id (im, t->rx_fib_index,
                                                  IP6_ROUTE_FLAG_FIB_INDEX);

  tx_fib = find_ip6_fib_by_table_index_or_id (im, t->tx_fib_index,
                                                  IP6_ROUTE_FLAG_FIB_INDEX);

  if (t->name)
    vlib_cli_output (vm,"sr tunnel name: %s", (char *)t->name);

  vlib_cli_output (vm, "src %U dst %U first hop %U",
		   format_ip6_address, &t->key.src,
		   format_ip6_address, &t->key.dst,
		   format_ip6_address, &t->first_hop);
  vlib_cli_output (vm, "    rx-fib-id %d tx-fib-id %d",
		   rx_fib->table_id, tx_fib->table_id);
  vlib_cli_output (vm, "  sr: %U", format_ip6_sr_header, t->rewrite,
		   0 /* print_hmac */);

  if (t->policy_index != ~0)
    {
      pt=pool_elt_at_index(sm->policies, t->policy_index);
      vlib_cli_output (vm,"sr policy: %s", (char *)pt->name);
    }
  vlib_cli_output (vm, "-------");

  return;
}

static clib_error_t *
show_sr_tunnel_fn (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd)
{
  static ip6_sr_tunnel_t ** tunnels;
  ip6_sr_tunnel_t * t;
  ip6_sr_main_t * sm = &sr_main;
  int i;
  uword * p = 0;
  u8 *name = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &name))
	{
	  p=hash_get_mem (sm->tunnel_index_by_name, name);
	  if(!p)
	    vlib_cli_output (vm, "No SR tunnel with name: %s. Showing all.", name);
	 }
      else
        break;
    }

  vec_reset_length (tunnels);

  if(!p) /* Either name parm not passed or no tunnel with that name found, show all */
    {
  pool_foreach (t, sm->tunnels,
  ({
    vec_add1 (tunnels, t);
  }));
    }
  else /* Just show the one tunnel by name */
    vec_add1 (tunnels, &sm->tunnels[p[0]]);

  if (vec_len (tunnels) == 0)
    vlib_cli_output (vm, "No SR tunnels configured");

  for (i = 0; i < vec_len (tunnels); i++)
    {
      t = tunnels[i];
      ip6_sr_tunnel_display (vm, t);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_sr_tunnel_command, static) = {
    .path = "show sr tunnel",
    .short_help = "show sr tunnel [name <sr-tunnel-name>]",
    .function = show_sr_tunnel_fn,
};

int ip6_sr_add_del_policy (ip6_sr_add_del_policy_args_t * a)
{
  ip6_sr_main_t * sm = &sr_main;
  uword * p;
  ip6_sr_tunnel_t * t = 0;
  ip6_sr_policy_t * policy;
  u32 * tunnel_indices = 0;
  int i;



      if (a->is_del)
	{
	  p=hash_get_mem (sm->policy_index_by_policy_name, a->name);
	  if (!p)
	    return -6; /* policy name not found */

	  policy = pool_elt_at_index(sm->policies, p[0]);

	  vec_foreach_index (i, policy->tunnel_indices)
	    {
	      t = pool_elt_at_index (sm->tunnels, policy->tunnel_indices[i]);
	      t->policy_index = ~0;
	    }
	  hash_unset_mem (sm->policy_index_by_policy_name, a->name);
	  pool_put (sm->policies, policy);
	  return 0;
	}


      if (!vec_len(a->tunnel_names))
	return -3; /*tunnel name is required case */

      vec_reset_length (tunnel_indices);
      /* Check tunnel names, add tunnel_index to policy */
      for (i=0; i < vec_len (a->tunnel_names); i++)
	{
	  p = hash_get_mem (sm->tunnel_index_by_name, a->tunnel_names[i]);
	  if (!p)
	    return -4; /* tunnel name not found case */

	  t = pool_elt_at_index (sm->tunnels, p[0]);
	  /*
	    No need to check t==0. -3 condition above ensures name
	  */
	  if (t->policy_index != ~0)
	    return -5; /* tunnel name already associated with a policy */

	  /* Add to tunnel indicies */
	  vec_add1 (tunnel_indices, p[0]);
	}

      /* Add policy to ip6_sr_main_t */
      pool_get (sm->policies, policy);
      policy->name = a->name;
      policy->tunnel_indices = tunnel_indices;
      hash_set_mem (sm->policy_index_by_policy_name, policy->name, policy - sm->policies);

      /* Yes, this could be construed as overkill but the last thing you should do is set
	 the policy_index on the tunnel after everything is set in ip6_sr_main_t.
	 If this is deemed overly cautious, could set this in the vec_len(tunnel_names) loop.
      */
      for (i=0; i < vec_len(policy->tunnel_indices); i++)
	{
	  t = pool_elt_at_index (sm->tunnels, policy->tunnel_indices[i]);
	  t->policy_index = policy - sm->policies;
	}

      return 0;
}


static clib_error_t *
sr_add_del_policy_command_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  int is_del = 0;
  u8 ** tunnel_names = 0;
  u8 * tunnel_name = 0;
  u8 * name = 0;
  ip6_sr_add_del_policy_args_t _a, *a=&_a;
  int rv;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
        is_del = 1;
      else if (unformat (input, "name %s", &name))
	;
      else if (unformat (input, "tunnel %s", &tunnel_name))
	{
	  if (tunnel_name)
	    {
	      vec_add1 (tunnel_names, tunnel_name);
	      tunnel_name = 0;
	    }
	}
      else
        break;
    }

  if (!name)
    return clib_error_return (0, "name of SR policy required");


  memset(a, 0, sizeof(*a));

  a->is_del = is_del;
  a->name = name;
  a->tunnel_names = tunnel_names;

  rv = ip6_sr_add_del_policy (a);

  vec_free(tunnel_names);

  switch (rv)
    {
    case 0:
      break;

    case -3:
      return clib_error_return (0, "tunnel name to associate to SR policy is required");

    case -4:
      return clib_error_return (0, "tunnel name not found");

    case -5:
      return clib_error_return (0, "tunnel already associated with policy");

    case -6:
      return clib_error_return (0, "policy name %s not found", name);

    case -7:
      return clib_error_return (0, "TODO: deleting policy name %s", name);

    default:
      return clib_error_return (0, "BUG: ip6_sr_add_del_policy returns %d", rv);

    }
  return 0;
}

VLIB_CLI_COMMAND (sr_policy_command, static) = {
    .path = "sr policy",
    .short_help =
    "sr policy [del] name <policy-name> tunnel <sr-tunnel-name> [tunnel <sr-tunnel-name>]*",
    .function = sr_add_del_policy_command_fn,
};

static clib_error_t *
show_sr_policy_fn (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd)
{
  static ip6_sr_policy_t ** policies;
  ip6_sr_policy_t * policy;
  ip6_sr_tunnel_t * t;
  ip6_sr_main_t * sm = &sr_main;
  int i, j;
  uword * p = 0;
  u8 * name = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &name))
	{
	  p=hash_get_mem (sm->policy_index_by_policy_name, name);
	  if(!p)
	    vlib_cli_output (vm, "policy with name %s not found. Showing all.", name);
	 }
      else
        break;
    }

  vec_reset_length (policies);

  if(!p) /* Either name parm not passed or no policy with that name found, show all */
    {
  pool_foreach (policy, sm->policies,
  ({
    vec_add1 (policies, policy);
  }));
    }
  else /* Just show the one policy by name and a summary of tunnel names */
    {
      policy = pool_elt_at_index(sm->policies, p[0]);
      vec_add1 (policies, policy);
    }

  if (vec_len (policies) == 0)
    vlib_cli_output (vm, "No SR policies configured");

  for (i = 0; i < vec_len (policies); i++)
    {
      policy = policies [i];

      if(policy->name)
	vlib_cli_output (vm,"SR policy name: %s", (char *)policy->name);
      for(j = 0; j < vec_len (policy->tunnel_indices); j++)
	{
	  t = pool_elt_at_index (sm->tunnels, policy->tunnel_indices[j]);
	  ip6_sr_tunnel_display (vm, t);
	}
    }

  return 0;

}

VLIB_CLI_COMMAND (show_sr_policy_command, static) = {
    .path = "show sr policy",
    .short_help = "show sr policy [name <sr-policy-name>]",
    .function = show_sr_policy_fn,
};

int ip6_sr_add_del_multicastmap (ip6_sr_add_del_multicastmap_args_t * a)
{
  uword * p;
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip6_sr_tunnel_t * t;
  ip_adjacency_t adj, * ap, * add_adj = 0;
  u32 adj_index;
  ip6_sr_main_t * sm = &sr_main;
  ip6_add_del_route_args_t aa;
  ip6_sr_policy_t * pt;

  if (a->is_del)
    {
      /* clean up the adjacency */
      p = hash_get_mem (sm->policy_index_by_multicast_address, a->multicast_address);
    }
  else
    {
      /* Get our policy by policy_name */
      p = hash_get_mem (sm->policy_index_by_policy_name, a->policy_name);

    }
  if (!p)
    return -1;

  pt=pool_elt_at_index (sm->policies, p[0]);

  /*
     Get the first tunnel associated with policy populate the fib adjacency.
     From there, since this tunnel will have it's policy_index != ~0 it will
     be the trigger in the dual_loop to pull up the policy and make a copy-rewrite
     for each tunnel in the policy
  */

  t = pool_elt_at_index (sm->tunnels, pt->tunnel_indices[0]);

  /* Construct a FIB entry for multicast using the rx/tx fib from the first tunnel */
  memset(&adj, 0, sizeof (adj));

  /* Create an adjacency and add to v6 fib */
  adj.lookup_next_index = sm->ip6_lookup_sr_replicate_index;
  adj.explicit_fib_index = ~0;

  ap = ip_add_adjacency (lm, &adj, 1 /* one adj */,
			 &adj_index);

  /*
   * Stick the tunnel index into the rewrite header.
   *
   * Unfortunately, inserting an SR header according to the various
   * RFC's requires parsing through the ip6 header, perhaps consing a
   * buffer onto the head of the vlib_buffer_t, etc. We don't use the
   * normal reverse bcopy rewrite code.
   *
   * We don't handle ugly RFC-related cases yet, but I'm sure PL will complain
   * at some point...
   */
  ap->rewrite_header.sw_if_index = t - sm->tunnels;

  vec_add1 (add_adj, ap[0]);

  memcpy (aa.dst_address.as_u8, a->multicast_address, sizeof (aa.dst_address.as_u8));
  aa.dst_address_length = 128;

  aa.flags = (a->is_del ? IP6_ROUTE_FLAG_DEL : IP6_ROUTE_FLAG_ADD);
  aa.flags |= IP6_ROUTE_FLAG_FIB_INDEX;
  aa.table_index_or_table_id = t->rx_fib_index;
  aa.add_adj = add_adj;
  aa.adj_index = adj_index;
  aa.n_add_adj = 1;
  ip6_add_del_route (im, &aa);
  vec_free (add_adj);

  u8 * mcast_copy = 0;
  mcast_copy = vec_new (ip6_address_t, 1);
  memcpy (mcast_copy, a->multicast_address, sizeof (ip6_address_t));

  if (a->is_del)
    {
      hash_unset_mem (sm->policy_index_by_multicast_address, mcast_copy);
      vec_free (mcast_copy);
      return 0;
    }
  /* else */

  hash_set_mem (sm->policy_index_by_multicast_address, mcast_copy, pt - sm->policies);


  return 0;
}

static clib_error_t *
sr_add_del_multicast_map_command_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  int is_del = 0;
  ip6_address_t multicast_address;
  u8 * policy_name = 0;
  int multicast_address_set = 0;
  ip6_sr_add_del_multicastmap_args_t _a, *a=&_a;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
        is_del = 1;
      else if (unformat (input, "address %U", unformat_ip6_address, &multicast_address))
	multicast_address_set = 1;
      else if (unformat (input, "sr-policy %s", &policy_name))
        ;
      else
        break;
    }

  if (!is_del && !policy_name)
    return clib_error_return (0, "name of sr policy required");

  if (!multicast_address_set)
    return clib_error_return (0, "multicast address required");

  memset(a, 0, sizeof(*a));

  a->is_del = is_del;
  a->multicast_address = &multicast_address;
  a->policy_name = policy_name;

#if DPDK > 0 /*Cannot call replicate or configure multicast map yet without DPDK */
  rv = ip6_sr_add_del_multicastmap (a);
#else
  return clib_error_return (0, "cannot use multicast replicate spray case without DPDK installed");
#endif /* DPDK */

  switch (rv)
    {
    case 0:
      break;
    case -1:
      return clib_error_return (0, "no policy with name: %s", policy_name);

    case -2:
      return clib_error_return (0, "multicast map someting ");

    case -3:
      return clib_error_return (0, "tunnel name to associate to SR policy is required");

    case -7:
      return clib_error_return (0, "TODO: deleting policy name %s", policy_name);

    default:
      return clib_error_return (0, "BUG: ip6_sr_add_del_policy returns %d", rv);

    }
  return 0;

}


VLIB_CLI_COMMAND (sr_multicast_map_command, static) = {
    .path = "sr multicast-map",
    .short_help =
    "sr multicast-map address <multicast-ip6-address> sr-policy <sr-policy-name> [del]",
    .function = sr_add_del_multicast_map_command_fn,
};

static clib_error_t *
show_sr_multicast_map_fn (vlib_main_t * vm,
                   unformat_input_t * input,
                   vlib_cli_command_t * cmd)
{
  ip6_sr_main_t * sm = &sr_main;
  u8 * key = 0;
  u32 value;
  ip6_address_t multicast_address;
  ip6_sr_policy_t * pt ;

  /* pull all entries from the hash table into vector for display */

  hash_foreach_mem (key, value, sm->policy_index_by_multicast_address,
  ({
    if (!key)
	vlib_cli_output (vm, "no multicast maps configured");
    else
      {
	multicast_address = *((ip6_address_t *)key);
	pt = pool_elt_at_index (sm->policies, value);
	if (pt)
	  {
	    vlib_cli_output (vm, "address: %U policy: %s",
			     format_ip6_address, &multicast_address,
			     pt->name);
	  }
	else
	  vlib_cli_output (vm, "BUG: policy not found for address: %U with policy index %d",
			     format_ip6_address, &multicast_address,
			     value);

      }

  }));

  return 0;
}

VLIB_CLI_COMMAND (show_sr_multicast_map_command, static) = {
    .path = "show sr multicast-map",
    .short_help = "show sr multicast-map",
    .function = show_sr_multicast_map_fn,
};


#define foreach_sr_fix_dst_addr_next            \
_(DROP, "error-drop")

typedef enum {
#define _(s,n) SR_FIX_DST_ADDR_NEXT_##s,
foreach_sr_fix_dst_addr_next
#undef _
  SR_FIX_DST_ADDR_N_NEXT,
} sr_fix_dst_addr_next_t;

static char * sr_fix_dst_error_strings[] = {
#define sr_fix_dst_error(n,s) s,
#include "sr_fix_dst_error.def"
#undef sr_fix_dst_error
};

typedef enum {
#define sr_fix_dst_error(n,s) SR_FIX_DST_ERROR_##n,
#include "sr_fix_dst_error.def"
#undef sr_fix_dst_error
  SR_FIX_DST_N_ERROR,
} sr_fix_dst_error_t;

typedef struct {
  ip6_address_t src, dst;
  u32 next_index;
  u32 adj_index;
  u8 sr[256];
} sr_fix_addr_trace_t;

u8 * format_sr_fix_addr_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sr_fix_addr_trace_t * t = va_arg (*args, sr_fix_addr_trace_t *);
  vnet_hw_interface_t * hi = 0;
  ip_adjacency_t * adj;
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  vnet_main_t * vnm = vnet_get_main();

  if (t->adj_index != ~0)
    {
      adj = ip_get_adjacency (lm, t->adj_index);
      hi = vnet_get_sup_hw_interface (vnm, adj->rewrite_header.sw_if_index);
    }

  s = format (s, "SR-FIX_ADDR: next %s ip6 src %U dst %U\n",
              (t->next_index == SR_FIX_DST_ADDR_NEXT_DROP)
              ? "drop" : "output",
              format_ip6_address, &t->src,
              format_ip6_address, &t->dst);
  if (t->next_index != SR_FIX_DST_ADDR_NEXT_DROP)
    {
      s = format (s, "%U\n", format_ip6_sr_header, t->sr, 1 /* print_hmac */);
      s = format (s, "   output via %s", hi ? (char *)(hi->name)
                  : "Invalid adj");
    }
  return s;
}

static uword
sr_fix_dst_addr (vlib_main_t * vm,
                   vlib_node_runtime_t * node,
                   vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

#if 0
      while (0 && n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  __attribute__((unused)) vlib_buffer_t * b0, * b1;
	  u32 next0 = SR_FIX_DST_ADDR_NEXT_DROP;
	  u32 next1 = SR_FIX_DST_ADDR_NEXT_DROP;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);


	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
        }
#endif

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
          ip6_header_t * ip0;
          ip_adjacency_t * adj0;
          ip6_sr_header_t * sr0;
	  u32 next0 = SR_FIX_DST_ADDR_NEXT_DROP;
          ip6_address_t *new_dst0;
          ethernet_header_t * eh0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          adj0 = ip_get_adjacency (lm, vnet_buffer(b0)->ip.adj_index[VLIB_TX]);
          next0 = adj0->mcast_group_index;

          /* We should be pointing at an Ethernet header... */
          eh0 = vlib_buffer_get_current (b0);
          ip0 = (ip6_header_t *)(eh0+1);
          sr0 = (ip6_sr_header_t *) (ip0+1);

          /* We'd better find an SR header... */
          if (PREDICT_FALSE(ip0->protocol != IPPROTO_IPV6_ROUTE))
            {
              b0->error = node->errors[SR_FIX_DST_ERROR_NO_SR_HEADER];
              goto do_trace0;
            }
          else
            {
              /*
               * We get here from sr_rewrite or sr_local, with
               * sr->segments_left pointing at the (copy of the original) dst
               * address. Use it, then increment sr0->segments_left.
               */

              /* Out of segments? Turf the packet */
              if (PREDICT_FALSE (sr0->segments_left == 0))
                {
                  b0->error = node->errors[SR_FIX_DST_ERROR_NO_MORE_SEGMENTS];
                  goto do_trace0;
                }

              /*
               * Rewrite the packet with the original dst address
               * We assume that the last segment (in processing order) contains
               * the original dst address. The list is reversed, so sr0->segments
               * contains the original dst address.
               */
              new_dst0 = sr0->segments;
              ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
              ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];
            }

        do_trace0:

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              sr_fix_addr_trace_t *t = vlib_add_trace (vm, node,
                                                       b0, sizeof (*t));
              t->next_index = next0;
              t->adj_index = ~0;

              if (next0 != SR_FIX_DST_ADDR_NEXT_DROP)
                {
                  t->adj_index = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
                  clib_memcpy (t->src.as_u8, ip0->src_address.as_u8,
                          sizeof (t->src.as_u8));
                  clib_memcpy (t->dst.as_u8, ip0->dst_address.as_u8,
                          sizeof (t->dst.as_u8));
                  clib_memcpy (t->sr, sr0, sizeof (t->sr));
                }
            }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return from_frame->n_vectors;
}


VLIB_REGISTER_NODE (sr_fix_dst_addr_node) = {
  .function = sr_fix_dst_addr,
  .name = "sr-fix-dst-addr",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .format_trace = format_sr_fix_addr_trace,
  .format_buffer = format_ip6_sr_header_with_length,

  .runtime_data_bytes = 0,

  .n_errors = SR_FIX_DST_N_ERROR,
  .error_strings = sr_fix_dst_error_strings,

  .n_next_nodes = SR_FIX_DST_ADDR_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_FIX_DST_ADDR_NEXT_##s] = n,
    foreach_sr_fix_dst_addr_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (sr_fix_dst_addr_node, sr_fix_dst_addr)

static clib_error_t * sr_init (vlib_main_t * vm)
{
  ip6_sr_main_t * sm = &sr_main;
  clib_error_t * error = 0;
  vlib_node_t * ip6_lookup_node, * ip6_rewrite_node;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip6_lookup_init)))
    return error;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main();

  vec_validate (sm->hmac_keys, 0);
  sm->hmac_keys[0].shared_secret = (u8 *) 0xdeadbeef;

  sm->tunnel_index_by_key =
    hash_create_mem (0, sizeof (ip6_sr_tunnel_key_t), sizeof (uword));

  sm->tunnel_index_by_name =
    hash_create_string (0, sizeof (uword));

  sm->policy_index_by_policy_name =
    hash_create_string(0, sizeof (uword));

  sm->policy_index_by_multicast_address =
    hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));

  sm->hmac_key_by_shared_secret = hash_create_string (0, sizeof(uword));

  ip6_register_protocol (IPPROTO_IPV6_ROUTE, sr_local_node.index);

  ip6_lookup_node = vlib_get_node_by_name (vm, (u8 *)"ip6-lookup");
  ASSERT(ip6_lookup_node);

  ip6_rewrite_node = vlib_get_node_by_name (vm, (u8 *)"ip6-rewrite");
  ASSERT(ip6_rewrite_node);

  /* Add a disposition to ip6_lookup for the sr rewrite node */
  sm->ip6_lookup_sr_next_index =
    vlib_node_add_next (vm, ip6_lookup_node->index, sr_rewrite_node.index);

#if DPDK > 0 /* Cannot run replicate without DPDK */
  /* Add a disposition to sr_replicate for the sr multicast replicate node */
  sm->ip6_lookup_sr_replicate_index =
    vlib_node_add_next (vm, ip6_lookup_node->index, sr_replicate_node.index);
#endif /* DPDK */

  /* Add a disposition to ip6_rewrite for the sr dst address hack node */
  sm->ip6_rewrite_sr_next_index =
    vlib_node_add_next (vm, ip6_rewrite_node->index,
                        sr_fix_dst_addr_node.index);

  OpenSSL_add_all_digests();

  sm->md = (void *) EVP_get_digestbyname ("sha1");
  sm->hmac_ctx = clib_mem_alloc (sizeof (HMAC_CTX));

  return error;
}

VLIB_INIT_FUNCTION (sr_init);

#define foreach_sr_local_next                   \
  _ (ERROR, "error-drop")                       \
  _ (IP6_LOOKUP, "ip6-lookup")

typedef enum {
#define _(s,n) SR_LOCAL_NEXT_##s,
  foreach_sr_local_next
#undef _
  SR_LOCAL_N_NEXT,
} sr_local_next_t;

typedef struct {
  u8 next_index;
  u8 sr_valid;
  ip6_address_t src, dst;
  u16 length;
  u8 sr[256];
} sr_local_trace_t;

static char * sr_local_error_strings[] = {
#define sr_error(n,s) s,
#include "sr_error.def"
#undef sr_error
};

typedef enum {
#define sr_error(n,s) SR_LOCAL_ERROR_##n,
#include "sr_error.def"
#undef sr_error
  SR_LOCAL_N_ERROR,
} sr_local_error_t;

u8 * format_sr_local_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  sr_local_trace_t * t = va_arg (*args, sr_local_trace_t *);

  s = format (s, "SR-LOCAL: src %U dst %U len %u next_index %d",
              format_ip6_address, &t->src,
              format_ip6_address, &t->dst, t->length, t->next_index);
  if (t->sr_valid)
    s = format (s, "\n  %U", format_ip6_sr_header, t->sr, 1 /* print_hmac */);
  else
    s = format (s, "\n  popped SR header");

  return s;
}


/* $$$$ fixme: smp, don't copy data, cache input, output (maybe) */

static int sr_validate_hmac (ip6_sr_main_t * sm, ip6_header_t * ip,
                             ip6_sr_header_t * sr)
{
  u32 key_index;
  static u8 * keybuf;
  u8 * copy_target;
  int first_segment;
  ip6_address_t *addrp;
  int i;
  ip6_sr_hmac_key_t * hmac_key;
  static u8 * signature;
  u32 sig_len;

  key_index = sr->hmac_key;

  /* No signature? Pass... */
  if (key_index == 0)
    return 0;

  /* We don't know about this key? Fail... */
  if (key_index >= vec_len (sm->hmac_keys))
    return 1;

  vec_validate (signature, SHA256_DIGEST_LENGTH-1);

  hmac_key = sm->hmac_keys + key_index;

  vec_reset_length (keybuf);

  /* pkt ip6 src address */
  vec_add2 (keybuf, copy_target, sizeof (ip6_address_t));
  clib_memcpy (copy_target, ip->src_address.as_u8, sizeof (ip6_address_t));

  /* last segment */
  vec_add2 (keybuf, copy_target, 1);
  copy_target[0] = sr->first_segment;

  /* octet w/ bit 0 = "clean" flag */
  vec_add2 (keybuf, copy_target, 1);
  copy_target[0]
    = (sr->flags & clib_host_to_net_u16 (IP6_SR_HEADER_FLAG_CLEANUP))
    ? 0x80 : 0;

  /* hmac key id */
  vec_add2 (keybuf, copy_target, 1);
  copy_target[0] = sr->hmac_key;

  first_segment = sr->first_segment;

  addrp = sr->segments;

  /* segments */
  for (i = 0; i <= first_segment; i++)
    {
      vec_add2 (keybuf, copy_target, sizeof (ip6_address_t));
      clib_memcpy (copy_target, addrp->as_u8, sizeof (ip6_address_t));
      addrp++;
    }

  if (sm->is_debug)
      clib_warning ("verify key index %d keybuf: %U", key_index,
                    format_hex_bytes, keybuf, vec_len(keybuf));

  /* shared secret */

  /* SHA1 is shorter than SHA-256 */
  memset (signature, 0, vec_len(signature));

  HMAC_CTX_init(sm->hmac_ctx);
  if (!HMAC_Init(sm->hmac_ctx, hmac_key->shared_secret,
                 vec_len(hmac_key->shared_secret),sm->md))
      clib_warning ("barf1");
  if (!HMAC_Update(sm->hmac_ctx,keybuf,vec_len(keybuf)))
      clib_warning ("barf2");
  if (!HMAC_Final(sm->hmac_ctx,signature,&sig_len))
      clib_warning ("barf3");
  HMAC_CTX_cleanup(sm->hmac_ctx);

  if (sm->is_debug)
      clib_warning ("computed signature len %d, value %U", sig_len,
                    format_hex_bytes, signature, vec_len(signature));

  /* Point at the SHA signature in the packet */
  addrp++;
  if (sm->is_debug)
      clib_warning ("read signature %U", format_hex_bytes, addrp,
                    SHA256_DIGEST_LENGTH);

  return memcmp (signature, addrp, SHA256_DIGEST_LENGTH);
}

static uword
sr_local (vlib_main_t * vm,
          vlib_node_runtime_t * node,
          vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  ip6_sr_main_t * sm = &sr_main;
  u32 (*sr_local_cb) (vlib_main_t *, vlib_node_runtime_t *,
                      vlib_buffer_t *, ip6_header_t *,
                      ip6_sr_header_t *);
  sr_local_cb = sm->sr_local_cb;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t * b0, * b1;
          ip6_header_t * ip0, *ip1;
          ip6_sr_header_t * sr0, *sr1;
          ip6_address_t * new_dst0, * new_dst1;
	  u32 next0 = SR_LOCAL_NEXT_IP6_LOOKUP;
	  u32 next1 = SR_LOCAL_NEXT_IP6_LOOKUP;
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;


	  b0 = vlib_get_buffer (vm, bi0);
          ip0 = vlib_buffer_get_current (b0);
          sr0 = (ip6_sr_header_t *)(ip0+1);

          if (PREDICT_FALSE(sr0->type != ROUTING_HEADER_TYPE_SR))
            {
              next0 = SR_LOCAL_NEXT_ERROR;
              b0->error = node->errors[SR_LOCAL_ERROR_BAD_ROUTING_HEADER_TYPE];
              goto do_trace0;
            }

          /* Out of segments? Turf the packet */
          if (PREDICT_FALSE (sr0->segments_left == 0))
            {
              next0 = SR_LOCAL_NEXT_ERROR;
              b0->error = node->errors[SR_LOCAL_ERROR_NO_MORE_SEGMENTS];
              goto do_trace0;
            }

          if (PREDICT_FALSE(sm->validate_hmac))
            {
              if (sr_validate_hmac (sm, ip0, sr0))
                {
                  next0 = SR_LOCAL_NEXT_ERROR;
                  b0->error = node->errors[SR_LOCAL_ERROR_HMAC_INVALID];
                  goto do_trace0;
                }
            }

          next0 = sr_local_cb ? sr_local_cb (vm, node, b0, ip0, sr0) :
              next0;

          /*
           * To suppress rewrite, return ~SR_LOCAL_NEXT_xxx
           */
          if (PREDICT_FALSE (next0 & 0x80000000))
          {
              next0 ^= 0xFFFFFFFF;
              if (PREDICT_FALSE(next0 == SR_LOCAL_NEXT_ERROR))
                  b0->error =
                  node->errors[SR_LOCAL_ERROR_APP_CALLBACK];
            }
          else
            {
              u32 segment_index0;

              segment_index0 = sr0->segments_left - 1;

              /* Rewrite the packet */
              new_dst0 = (ip6_address_t *)(sr0->segments + segment_index0);
              ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
              ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];

              if (PREDICT_TRUE (sr0->segments_left > 0))
                  sr0->segments_left -= 1;
            }

          /* End of the path. Clean up the SR header, or not */
          if (PREDICT_FALSE
              (sr0->segments_left == 0 &&
               (sr0->flags & clib_host_to_net_u16(IP6_SR_HEADER_FLAG_CLEANUP))))
          {
              u64 *copy_dst0, *copy_src0;
              u16 new_l0;
              /*
               * Copy the ip6 header right by the (real) length of the
               * sr header. Here's another place which assumes that
               * the sr header is the only extention header.
               */

              ip0->protocol = sr0->protocol;
              vlib_buffer_advance (b0, (sr0->length+1)*8);

              new_l0 = clib_net_to_host_u16(ip0->payload_length) -
                  (sr0->length+1)*8;
              ip0->payload_length = clib_host_to_net_u16(new_l0);

              copy_src0 = (u64 *)ip0;
              copy_dst0 = copy_src0 + (sr0->length + 1);

              copy_dst0 [4] = copy_src0[4];
              copy_dst0 [3] = copy_src0[3];
              copy_dst0 [2] = copy_src0[2];
              copy_dst0 [1] = copy_src0[1];
              copy_dst0 [0] = copy_src0[0];

              sr0 = 0;
            }

        do_trace0:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              sr_local_trace_t *tr = vlib_add_trace (vm, node,
                                                     b0, sizeof (*tr));
              clib_memcpy (tr->src.as_u8, ip0->src_address.as_u8,
                      sizeof (tr->src.as_u8));
              clib_memcpy (tr->dst.as_u8, ip0->dst_address.as_u8,
                      sizeof (tr->dst.as_u8));
              tr->length = vlib_buffer_length_in_chain (vm, b0);
              tr->next_index = next0;
              tr->sr_valid = sr0 != 0;
              if (tr->sr_valid)
                clib_memcpy (tr->sr, sr0, sizeof (tr->sr));
            }

	  b1 = vlib_get_buffer (vm, bi1);
          ip1 = vlib_buffer_get_current (b1);
          sr1 = (ip6_sr_header_t *)(ip1+1);

          if (PREDICT_FALSE(sr1->type != ROUTING_HEADER_TYPE_SR))
            {
              next1 = SR_LOCAL_NEXT_ERROR;
              b1->error = node->errors[SR_LOCAL_ERROR_BAD_ROUTING_HEADER_TYPE];
              goto do_trace1;
            }

          /* Out of segments? Turf the packet */
          if (PREDICT_FALSE (sr1->segments_left == 0))
            {
              next1 = SR_LOCAL_NEXT_ERROR;
              b1->error = node->errors[SR_LOCAL_ERROR_NO_MORE_SEGMENTS];
              goto do_trace1;
            }

          if (PREDICT_FALSE(sm->validate_hmac))
            {
              if (sr_validate_hmac (sm, ip1, sr1))
                {
                  next1 = SR_LOCAL_NEXT_ERROR;
                  b1->error = node->errors[SR_LOCAL_ERROR_HMAC_INVALID];
                  goto do_trace1;
                }
            }

          next1 = sr_local_cb ? sr_local_cb (vm, node, b1, ip1, sr1) :
              next1;

          /*
           * To suppress rewrite, return ~SR_LOCAL_NEXT_xxx
           */
          if (PREDICT_FALSE (next1 & 0x80000000))
          {
              next1 ^= 0xFFFFFFFF;
              if (PREDICT_FALSE(next1 == SR_LOCAL_NEXT_ERROR))
                  b1->error =
                  node->errors[SR_LOCAL_ERROR_APP_CALLBACK];
            }
          else
            {
              u32 segment_index1;

              segment_index1 = sr1->segments_left - 1;

              /* Rewrite the packet */
              new_dst1 = (ip6_address_t *)(sr1->segments + segment_index1);
              ip1->dst_address.as_u64[0] = new_dst1->as_u64[0];
              ip1->dst_address.as_u64[1] = new_dst1->as_u64[1];

              if (PREDICT_TRUE (sr1->segments_left > 0))
                  sr1->segments_left -= 1;
            }

          /* End of the path. Clean up the SR header, or not */
          if (PREDICT_FALSE
              (sr1->segments_left == 0 &&
               (sr1->flags & clib_host_to_net_u16(IP6_SR_HEADER_FLAG_CLEANUP))))
            {
              u64 *copy_dst1, *copy_src1;
              u16 new_l1;
              /*
               * Copy the ip6 header right by the (real) length of the
               * sr header. Here's another place which assumes that
               * the sr header is the only extention header.
               */

              ip1->protocol = sr1->protocol;
              vlib_buffer_advance (b1, (sr1->length+1)*8);

              new_l1 = clib_net_to_host_u16(ip1->payload_length) -
                  (sr1->length+1)*8;
              ip1->payload_length = clib_host_to_net_u16(new_l1);

              copy_src1 = (u64 *)ip1;
              copy_dst1 = copy_src1 + (sr1->length + 1);

              copy_dst1 [4] = copy_src1[4];
              copy_dst1 [3] = copy_src1[3];
              copy_dst1 [2] = copy_src1[2];
              copy_dst1 [1] = copy_src1[1];
              copy_dst1 [0] = copy_src1[0];

              sr1 = 0;
            }

        do_trace1:
          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
              sr_local_trace_t *tr = vlib_add_trace (vm, node,
                                                     b1, sizeof (*tr));
              clib_memcpy (tr->src.as_u8, ip1->src_address.as_u8,
                      sizeof (tr->src.as_u8));
              clib_memcpy (tr->dst.as_u8, ip1->dst_address.as_u8,
                      sizeof (tr->dst.as_u8));
              tr->length = vlib_buffer_length_in_chain (vm, b1);
              tr->next_index = next1;
              tr->sr_valid = sr1 != 0;
              if (tr->sr_valid)
                clib_memcpy (tr->sr, sr1, sizeof (tr->sr));
            }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
          ip6_header_t * ip0 = 0;
          ip6_sr_header_t * sr0;
          ip6_address_t * new_dst0;
	  u32 next0 = SR_LOCAL_NEXT_IP6_LOOKUP;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
          ip0 = vlib_buffer_get_current (b0);
          sr0 = (ip6_sr_header_t *)(ip0+1);

          if (PREDICT_FALSE(sr0->type != ROUTING_HEADER_TYPE_SR))
            {
              next0 = SR_LOCAL_NEXT_ERROR;
              b0->error = node->errors[SR_LOCAL_ERROR_BAD_ROUTING_HEADER_TYPE];
              goto do_trace;
            }

          /* Out of segments? Turf the packet */
          if (PREDICT_FALSE (sr0->segments_left == 0))
            {
              next0 = SR_LOCAL_NEXT_ERROR;
              b0->error = node->errors[SR_LOCAL_ERROR_NO_MORE_SEGMENTS];
              goto do_trace;
            }

          if (PREDICT_FALSE(sm->validate_hmac))
            {
              if (sr_validate_hmac (sm, ip0, sr0))
                {
                  next0 = SR_LOCAL_NEXT_ERROR;
                  b0->error = node->errors[SR_LOCAL_ERROR_HMAC_INVALID];
                  goto do_trace;
                }
            }

          next0 = sr_local_cb ? sr_local_cb (vm, node, b0, ip0, sr0) :
            next0;

          /*
           * To suppress rewrite, return ~SR_LOCAL_NEXT_xxx
           */
          if (PREDICT_FALSE (next0 & 0x80000000))
            {
              next0 ^= 0xFFFFFFFF;
              if (PREDICT_FALSE(next0 == SR_LOCAL_NEXT_ERROR))
                b0->error =
                  node->errors[SR_LOCAL_ERROR_APP_CALLBACK];
            }
          else
            {
              u32 segment_index0;

              segment_index0 = sr0->segments_left - 1;

              /* Rewrite the packet */
              new_dst0 = (ip6_address_t *)(sr0->segments + segment_index0);
              ip0->dst_address.as_u64[0] = new_dst0->as_u64[0];
              ip0->dst_address.as_u64[1] = new_dst0->as_u64[1];

              if (PREDICT_TRUE (sr0->segments_left > 0))
                  sr0->segments_left -= 1;
            }

          /* End of the path. Clean up the SR header, or not */
          if (PREDICT_FALSE
              (sr0->segments_left == 0 &&
               (sr0->flags & clib_host_to_net_u16(IP6_SR_HEADER_FLAG_CLEANUP))))
            {
              u64 *copy_dst0, *copy_src0;
              u16 new_l0;
              /*
               * Copy the ip6 header right by the (real) length of the
               * sr header. Here's another place which assumes that
               * the sr header is the only extention header.
               */

              ip0->protocol = sr0->protocol;
              vlib_buffer_advance (b0, (sr0->length+1)*8);

              new_l0 = clib_net_to_host_u16(ip0->payload_length) -
                  (sr0->length+1)*8;
              ip0->payload_length = clib_host_to_net_u16(new_l0);

              copy_src0 = (u64 *)ip0;
              copy_dst0 = copy_src0 + (sr0->length + 1);

              copy_dst0 [4] = copy_src0[4];
              copy_dst0 [3] = copy_src0[3];
              copy_dst0 [2] = copy_src0[2];
              copy_dst0 [1] = copy_src0[1];
              copy_dst0 [0] = copy_src0[0];

              sr0 = 0;
            }

        do_trace:
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              sr_local_trace_t *tr = vlib_add_trace (vm, node,
                                                     b0, sizeof (*tr));
              clib_memcpy (tr->src.as_u8, ip0->src_address.as_u8,
                      sizeof (tr->src.as_u8));
              clib_memcpy (tr->dst.as_u8, ip0->dst_address.as_u8,
                      sizeof (tr->dst.as_u8));
              tr->length = vlib_buffer_length_in_chain (vm, b0);
              tr->next_index = next0;
              tr->sr_valid = sr0 != 0;
              if (tr->sr_valid)
                clib_memcpy (tr->sr, sr0, sizeof (tr->sr));
            }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, sr_local_node.index,
                               SR_LOCAL_ERROR_PKTS_PROCESSED,
                               from_frame->n_vectors);
  return from_frame->n_vectors;
}

VLIB_REGISTER_NODE (sr_local_node, static) = {
  .function = sr_local,
  .name = "sr-local",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .format_trace = format_sr_local_trace,

  .runtime_data_bytes = 0,

  .n_errors = SR_LOCAL_N_ERROR,
  .error_strings = sr_local_error_strings,

  .n_next_nodes = SR_LOCAL_N_NEXT,
  .next_nodes = {
#define _(s,n) [SR_LOCAL_NEXT_##s] = n,
    foreach_sr_local_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (sr_local_node, sr_local)

ip6_sr_main_t * sr_get_main (vlib_main_t * vm)
{
  vlib_call_init_function (vm, sr_init);
  ASSERT(sr_local_node.index);
  return &sr_main;
}


static clib_error_t *
set_ip6_sr_rewrite_fn (vlib_main_t * vm,
                       unformat_input_t * input,
                       vlib_cli_command_t * cmd)
{
  ip6_address_t a;
  ip6_main_t * im = &ip6_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  u32 fib_index = 0;
  u32 fib_id = 0;
  u32 adj_index;
  uword * p;
  ip_adjacency_t * adj;
  vnet_hw_interface_t * hi;
  u32 sw_if_index;
  ip6_sr_main_t * sm = &sr_main;
  vnet_main_t * vnm = vnet_get_main();

  if (!unformat (input, "%U", unformat_ip6_address, &a))
    return clib_error_return (0, "ip6 address missing in '%U'",
                              format_unformat_error, input);

  if (unformat (input, "rx-table-id %d", &fib_id))
    {
      p = hash_get (im->fib_index_by_table_id, fib_id);
      if (p == 0)
        return clib_error_return (0, "fib-id %d not found");
      fib_index = p[0];
    }

  adj_index = ip6_fib_lookup_with_table (im, fib_index, &a);

  if (adj_index == lm->miss_adj_index)
    return clib_error_return (0, "no match for %U",
                              format_ip6_address, &a);

  adj = ip_get_adjacency (lm, adj_index);

  if (adj->lookup_next_index != IP_LOOKUP_NEXT_REWRITE)
    return clib_error_return (0, "%U unresolved (not a rewrite adj)",
                              format_ip6_address, &a);

  adj->rewrite_header.next_index = sm->ip6_rewrite_sr_next_index;

  sw_if_index = adj->rewrite_header.sw_if_index;
  hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  adj->rewrite_header.node_index = sr_fix_dst_addr_node.index;

  /* $$$$$ hack... steal the mcast group index */
  adj->mcast_group_index =
    vlib_node_add_next (vm, sr_fix_dst_addr_node.index, hi->output_node_index);

  return 0;
}

VLIB_CLI_COMMAND (set_ip6_sr_rewrite, static) = {
    .path = "set ip6 sr rewrite",
    .short_help = "set ip6 sr rewrite <ip6-address> [fib-id <id>]",
    .function = set_ip6_sr_rewrite_fn,
};

void vnet_register_sr_app_callback (void *cb)
{
  ip6_sr_main_t * sm = &sr_main;

  sm->sr_local_cb = cb;
}

static clib_error_t *
test_sr_hmac_validate_fn (vlib_main_t * vm,
                    unformat_input_t * input,
                    vlib_cli_command_t * cmd)
{
  ip6_sr_main_t * sm = &sr_main;

  if (unformat (input, "validate on"))
    sm->validate_hmac = 1;
  else if (unformat (input, "chunk-offset off"))
    sm->validate_hmac = 0;
  else
    return clib_error_return (0, "expected validate on|off in '%U'",
                              format_unformat_error, input);

  vlib_cli_output (vm, "hmac signature validation %s",
                   sm->validate_hmac ?
                   "on" : "off");
  return 0;
}

VLIB_CLI_COMMAND (test_sr_hmac_validate, static) = {
    .path = "test sr hmac",
    .short_help = "test sr hmac validate [on|off]",
    .function = test_sr_hmac_validate_fn,
};

i32 sr_hmac_add_del_key (ip6_sr_main_t * sm, u32 key_id, u8 * shared_secret,
                         u8 is_del)
{
  u32 index;
  ip6_sr_hmac_key_t * key;

  if (is_del == 0)
    {
      /* Specific key in use? Fail. */
      if (key_id && vec_len (sm->hmac_keys) > key_id
          && sm->hmac_keys[key_id].shared_secret)
        return -2;

      index = key_id;
      key = find_or_add_shared_secret (sm, shared_secret, &index);
      ASSERT(index == key_id);
      return 0;
    }

  /* delete */

  if (key_id)                   /* delete by key ID */
    {
      if (vec_len (sm->hmac_keys) <= key_id)
        return -3;

      key = sm->hmac_keys + key_id;

      hash_unset_mem (sm->hmac_key_by_shared_secret, key->shared_secret);
      vec_free (key->shared_secret);
      return 0;
    }

  index = 0;
  key = find_or_add_shared_secret (sm, shared_secret, &index);
  hash_unset_mem (sm->hmac_key_by_shared_secret, key->shared_secret);
  vec_free (key->shared_secret);
  return 0;
}


static clib_error_t *
sr_hmac_add_del_key_fn (vlib_main_t * vm,
                        unformat_input_t * input,
                        vlib_cli_command_t * cmd)
{
  ip6_sr_main_t * sm = &sr_main;
  u8 is_del = 0;
  u32 key_id = 0;
  u8 key_id_set = 0;
  u8 * shared_secret = 0;
  i32 rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
        is_del = 1;
      else if (unformat (input, "id %d", &key_id))
          key_id_set = 1;
      else if (unformat (input, "key %s", &shared_secret))
        {
          /* Do not include the trailing NULL byte. Guaranteed interop issue */
          _vec_len (shared_secret) -= 1;
        }
      else
        break;
    }

  if (is_del == 0 && shared_secret == 0)
    return clib_error_return (0, "shared secret must be set to add a key");

  if (shared_secret == 0 && key_id_set == 0)
    return clib_error_return (0, "shared secret and key id both unset");

  rv = sr_hmac_add_del_key (sm, key_id, shared_secret, is_del);

  vec_free (shared_secret);

  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "sr_hmac_add_del_key returned %d",
                                rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (sr_hmac, static) = {
    .path = "sr hmac",
    .short_help = "sr hmac [del] id <nn> key <str>",
    .function = sr_hmac_add_del_key_fn,
};


static clib_error_t *
show_sr_hmac_fn (vlib_main_t * vm,
                 unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  ip6_sr_main_t * sm = &sr_main;
  int i;

  for (i = 1; i < vec_len (sm->hmac_keys); i++)
    {
      if (sm->hmac_keys[i].shared_secret)
          vlib_cli_output (vm, "[%d]: %v", i, sm->hmac_keys[i].shared_secret);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_sr_hmac, static) = {
    .path = "show sr hmac",
    .short_help = "show sr hmac",
    .function = show_sr_hmac_fn,
};

static clib_error_t *
test_sr_debug_fn (vlib_main_t * vm,
                    unformat_input_t * input,
                    vlib_cli_command_t * cmd)
{
  ip6_sr_main_t * sm = &sr_main;

  if (unformat (input, "on"))
    sm->is_debug = 1;
  else if (unformat (input, "off"))
    sm->is_debug = 0;
  else
    return clib_error_return (0, "expected on|off in '%U'",
                              format_unformat_error, input);

  vlib_cli_output (vm, "debug trace now %s", sm->is_debug ? "on" : "off");

  return 0;
}

VLIB_CLI_COMMAND (test_sr_debug, static) = {
    .path = "test sr debug",
    .short_help = "test sr debug on|off",
    .function = test_sr_debug_fn,
};
