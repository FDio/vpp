/*
 * mpls_lookup.c: MPLS lookup
 *
 * Copyright (c) 2012-2014 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/mpls/mpls_lookup.h>
#include <vnet/fib/mpls_fib.h>
#include <vnet/dpo/load_balance_map.h>
#include <vnet/dpo/replicate_dpo.h>

/**
 * The arc/edge from the MPLS lookup node to the MPLS replicate node
 */
#ifndef CLIB_MARCH_VARIANT
u32 mpls_lookup_to_replicate_edge;
#endif /* CLIB_MARCH_VARIANT */

typedef struct {
  u32 next_index;
  u32 lb_index;
  u32 lfib_index;
  u32 label_net_byte_order;
  u32 hash;
} mpls_lookup_trace_t;

static u8 *
format_mpls_lookup_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mpls_lookup_trace_t * t = va_arg (*args, mpls_lookup_trace_t *);

  s = format (s, "MPLS: next [%d], lookup fib index %d, LB index %d hash %x "
              "label %d eos %d", 
              t->next_index, t->lfib_index, t->lb_index, t->hash,
              vnet_mpls_uc_get_label(
                  clib_net_to_host_u32(t->label_net_byte_order)),
              vnet_mpls_uc_get_s(
                  clib_net_to_host_u32(t->label_net_byte_order)));
  return s;
}

VLIB_NODE_FN (mpls_lookup_node) (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
  vlib_combined_counter_main_t * cm = &load_balance_main.lbm_to_counters;
  u32 n_left_from, next_index, * from, * to_next;
  mpls_main_t * mm = &mpls_main;
  u32 thread_index = vlib_get_thread_index();

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

      while (n_left_from >= 8 && n_left_to_next >= 4)
        {
          u32 lbi0, next0, lfib_index0, bi0, hash_c0;
          const mpls_unicast_header_t * h0;
          const load_balance_t *lb0;
          const dpo_id_t *dpo0;
          vlib_buffer_t * b0;
          u32 lbi1, next1, lfib_index1, bi1, hash_c1;
          const mpls_unicast_header_t * h1;
          const load_balance_t *lb1;
          const dpo_id_t *dpo1;
          vlib_buffer_t * b1;
          u32 lbi2, next2, lfib_index2, bi2, hash_c2;
          const mpls_unicast_header_t * h2;
          const load_balance_t *lb2;
          const dpo_id_t *dpo2;
          vlib_buffer_t * b2;
          u32 lbi3, next3, lfib_index3, bi3, hash_c3;
          const mpls_unicast_header_t * h3;
          const load_balance_t *lb3;
          const dpo_id_t *dpo3;
          vlib_buffer_t * b3;

           /* Prefetch next iteration. */
          {
              vlib_buffer_t *p4, *p5, *p6, *p7;

            p4 = vlib_get_buffer (vm, from[4]);
            p5 = vlib_get_buffer (vm, from[5]);
            p6 = vlib_get_buffer (vm, from[6]);
            p7 = vlib_get_buffer (vm, from[7]);

            vlib_prefetch_buffer_header (p4, STORE);
            vlib_prefetch_buffer_header (p5, STORE);
            vlib_prefetch_buffer_header (p6, STORE);
            vlib_prefetch_buffer_header (p7, STORE);

            CLIB_PREFETCH (p4->data, sizeof (h0[0]), LOAD);
            CLIB_PREFETCH (p5->data, sizeof (h0[0]), LOAD);
            CLIB_PREFETCH (p6->data, sizeof (h0[0]), LOAD);
            CLIB_PREFETCH (p7->data, sizeof (h0[0]), LOAD);
          }

          bi0 = to_next[0] = from[0];
          bi1 = to_next[1] = from[1];
          bi2 = to_next[2] = from[2];
          bi3 = to_next[3] = from[3];

          from += 4;
          n_left_from -= 4;
          to_next += 4;
          n_left_to_next -= 4;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);
          b2 = vlib_get_buffer (vm, bi2);
          b3 = vlib_get_buffer (vm, bi3);
          h0 = vlib_buffer_get_current (b0);
          h1 = vlib_buffer_get_current (b1);
          h2 = vlib_buffer_get_current (b2);
          h3 = vlib_buffer_get_current (b3);

          lfib_index0 = vec_elt(mm->fib_index_by_sw_if_index,
                                vnet_buffer(b0)->sw_if_index[VLIB_RX]);
          lfib_index1 = vec_elt(mm->fib_index_by_sw_if_index,
                                vnet_buffer(b1)->sw_if_index[VLIB_RX]);
          lfib_index2 = vec_elt(mm->fib_index_by_sw_if_index,
                                vnet_buffer(b2)->sw_if_index[VLIB_RX]);
          lfib_index3 = vec_elt(mm->fib_index_by_sw_if_index,
                                vnet_buffer(b3)->sw_if_index[VLIB_RX]);

          lbi0 = mpls_fib_table_forwarding_lookup (lfib_index0, h0);
          lbi1 = mpls_fib_table_forwarding_lookup (lfib_index1, h1);
          lbi2 = mpls_fib_table_forwarding_lookup (lfib_index2, h2);
          lbi3 = mpls_fib_table_forwarding_lookup (lfib_index3, h3);

          hash_c0 = vnet_buffer(b0)->ip.flow_hash = 0;
          hash_c1 = vnet_buffer(b1)->ip.flow_hash = 0;
          hash_c2 = vnet_buffer(b2)->ip.flow_hash = 0;
          hash_c3 = vnet_buffer(b3)->ip.flow_hash = 0;

          if (MPLS_IS_REPLICATE & lbi0)
          {
              next0 = mpls_lookup_to_replicate_edge;
              vnet_buffer (b0)->ip.adj_index =
                  (lbi0 & ~MPLS_IS_REPLICATE);
          }
          else
          {
              lb0 = load_balance_get(lbi0);
              ASSERT (lb0->lb_n_buckets > 0);
              ASSERT (is_pow2 (lb0->lb_n_buckets));

              if (PREDICT_FALSE(lb0->lb_n_buckets > 1))
              {
                  hash_c0 = vnet_buffer (b0)->ip.flow_hash =
                      mpls_compute_flow_hash(h0, lb0->lb_hash_config);
                  dpo0 = load_balance_get_fwd_bucket
                      (lb0,
                       (hash_c0 & (lb0->lb_n_buckets_minus_1)));
              }
              else
              {
                  dpo0 = load_balance_get_bucket_i (lb0, 0);
              }
              next0 = dpo0->dpoi_next_node;

              vnet_buffer (b0)->ip.adj_index = dpo0->dpoi_index;

              vlib_increment_combined_counter
                  (cm, thread_index, lbi0, 1,
                   vlib_buffer_length_in_chain (vm, b0));
          }
          if (MPLS_IS_REPLICATE & lbi1)
          {
              next1 = mpls_lookup_to_replicate_edge;
              vnet_buffer (b1)->ip.adj_index =
                  (lbi1 & ~MPLS_IS_REPLICATE);
          }
          else
          {
              lb1 = load_balance_get(lbi1);
              ASSERT (lb1->lb_n_buckets > 0);
              ASSERT (is_pow2 (lb1->lb_n_buckets));

              if (PREDICT_FALSE(lb1->lb_n_buckets > 1))
              {
                  hash_c1 = vnet_buffer (b1)->ip.flow_hash =
                      mpls_compute_flow_hash(h1, lb1->lb_hash_config);
                  dpo1 = load_balance_get_fwd_bucket
                      (lb1,
                       (hash_c1 & (lb1->lb_n_buckets_minus_1)));
              }
              else
              {
                  dpo1 = load_balance_get_bucket_i (lb1, 0);
              }
              next1 = dpo1->dpoi_next_node;

              vnet_buffer (b1)->ip.adj_index = dpo1->dpoi_index;

              vlib_increment_combined_counter
                  (cm, thread_index, lbi1, 1,
                   vlib_buffer_length_in_chain (vm, b1));
          }
          if (MPLS_IS_REPLICATE & lbi2)
          {
              next2 = mpls_lookup_to_replicate_edge;
              vnet_buffer (b2)->ip.adj_index =
                  (lbi2 & ~MPLS_IS_REPLICATE);
          }
          else
          {
              lb2 = load_balance_get(lbi2);
              ASSERT (lb2->lb_n_buckets > 0);
              ASSERT (is_pow2 (lb2->lb_n_buckets));

              if (PREDICT_FALSE(lb2->lb_n_buckets > 1))
              {
                  hash_c2 = vnet_buffer (b2)->ip.flow_hash =
                      mpls_compute_flow_hash(h2, lb2->lb_hash_config);
                  dpo2 = load_balance_get_fwd_bucket
                      (lb2,
                       (hash_c2 & (lb2->lb_n_buckets_minus_1)));
              }
              else
              {
                  dpo2 = load_balance_get_bucket_i (lb2, 0);
              }
              next2 = dpo2->dpoi_next_node;

              vnet_buffer (b2)->ip.adj_index = dpo2->dpoi_index;

              vlib_increment_combined_counter
                  (cm, thread_index, lbi2, 1,
                   vlib_buffer_length_in_chain (vm, b2));
          }
          if (MPLS_IS_REPLICATE & lbi3)
          {
              next3 = mpls_lookup_to_replicate_edge;
              vnet_buffer (b3)->ip.adj_index =
                  (lbi3 & ~MPLS_IS_REPLICATE);
          }
          else
          {
              lb3 = load_balance_get(lbi3);
              ASSERT (lb3->lb_n_buckets > 0);
              ASSERT (is_pow2 (lb3->lb_n_buckets));

              if (PREDICT_FALSE(lb3->lb_n_buckets > 1))
              {
                  hash_c3 = vnet_buffer (b3)->ip.flow_hash =
                      mpls_compute_flow_hash(h3, lb3->lb_hash_config);
                  dpo3 = load_balance_get_fwd_bucket
                      (lb3,
                       (hash_c3 & (lb3->lb_n_buckets_minus_1)));
              }
              else
              {
                  dpo3 = load_balance_get_bucket_i (lb3, 0);
              }
              next3 = dpo3->dpoi_next_node;

              vnet_buffer (b3)->ip.adj_index = dpo3->dpoi_index;

              vlib_increment_combined_counter
                  (cm, thread_index, lbi3, 1,
                   vlib_buffer_length_in_chain (vm, b3));
          }

          /*
           * before we pop the label copy th values we need to maintain.
           * The label header is in network byte order.
           *  last byte is the TTL.
           *  bits 2 to 4 inclusive are the EXP bits
           */
          vnet_buffer (b0)->mpls.ttl = ((char*)h0)[3];
          vnet_buffer (b0)->mpls.exp = (((char*)h0)[2] & 0xe) >> 1;
          vnet_buffer (b0)->mpls.first = 1;
          vnet_buffer (b1)->mpls.ttl = ((char*)h1)[3];
          vnet_buffer (b1)->mpls.exp = (((char*)h1)[2] & 0xe) >> 1;
          vnet_buffer (b1)->mpls.first = 1;
          vnet_buffer (b2)->mpls.ttl = ((char*)h2)[3];
          vnet_buffer (b2)->mpls.exp = (((char*)h2)[2] & 0xe) >> 1;
          vnet_buffer (b2)->mpls.first = 1;
          vnet_buffer (b3)->mpls.ttl = ((char*)h3)[3];
          vnet_buffer (b3)->mpls.exp = (((char*)h3)[2] & 0xe) >> 1;
          vnet_buffer (b3)->mpls.first = 1;

          /*
           * pop the label that was just used in the lookup
           */
          vlib_buffer_advance(b0, sizeof(*h0));
          vlib_buffer_advance(b1, sizeof(*h1));
          vlib_buffer_advance(b2, sizeof(*h2));
          vlib_buffer_advance(b3, sizeof(*h3));

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_lookup_trace_t *tr = vlib_add_trace (vm, node,
                                                        b0, sizeof (*tr));
              tr->next_index = next0;
              tr->lb_index = lbi0;
              tr->lfib_index = lfib_index0;
              tr->hash = hash_c0;
              tr->label_net_byte_order = h0->label_exp_s_ttl;
          }

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_lookup_trace_t *tr = vlib_add_trace (vm, node,
                                                        b1, sizeof (*tr));
              tr->next_index = next1;
              tr->lb_index = lbi1;
              tr->lfib_index = lfib_index1;
              tr->hash = hash_c1;
              tr->label_net_byte_order = h1->label_exp_s_ttl;
          }

          if (PREDICT_FALSE(b2->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_lookup_trace_t *tr = vlib_add_trace (vm, node,
                                                        b2, sizeof (*tr));
              tr->next_index = next2;
              tr->lb_index = lbi2;
              tr->lfib_index = lfib_index2;
              tr->hash = hash_c2;
              tr->label_net_byte_order = h2->label_exp_s_ttl;
          }

          if (PREDICT_FALSE(b3->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_lookup_trace_t *tr = vlib_add_trace (vm, node,
                                                        b3, sizeof (*tr));
              tr->next_index = next3;
              tr->lb_index = lbi3;
              tr->lfib_index = lfib_index3;
              tr->hash = hash_c3;
              tr->label_net_byte_order = h3->label_exp_s_ttl;
          }

          vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1, bi2, bi3,
                                           next0, next1, next2, next3);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
      {
          u32 lbi0, next0, lfib_index0, bi0, hash_c0;
          const mpls_unicast_header_t * h0;
          const load_balance_t *lb0;
          const dpo_id_t *dpo0;
          vlib_buffer_t * b0;

          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          h0 = vlib_buffer_get_current (b0);

          lfib_index0 = vec_elt(mm->fib_index_by_sw_if_index,
                                vnet_buffer(b0)->sw_if_index[VLIB_RX]);

          lbi0 = mpls_fib_table_forwarding_lookup(lfib_index0, h0);
          hash_c0 = vnet_buffer(b0)->ip.flow_hash = 0;

          if (MPLS_IS_REPLICATE & lbi0)
          {
              next0 = mpls_lookup_to_replicate_edge;
              vnet_buffer (b0)->ip.adj_index =
                  (lbi0 & ~MPLS_IS_REPLICATE);
          }
          else
          {
              lb0 = load_balance_get(lbi0);
              ASSERT (lb0->lb_n_buckets > 0);
              ASSERT (is_pow2 (lb0->lb_n_buckets));

              if (PREDICT_FALSE(lb0->lb_n_buckets > 1))
              {
                  hash_c0 = vnet_buffer (b0)->ip.flow_hash =
                      mpls_compute_flow_hash(h0, lb0->lb_hash_config);
                  dpo0 = load_balance_get_fwd_bucket
                      (lb0,
                       (hash_c0 & (lb0->lb_n_buckets_minus_1)));
              }
              else
              {
                  dpo0 = load_balance_get_bucket_i (lb0, 0);
              }
              next0 = dpo0->dpoi_next_node;
              vnet_buffer (b0)->ip.adj_index = dpo0->dpoi_index;

              vlib_increment_combined_counter
                  (cm, thread_index, lbi0, 1,
                   vlib_buffer_length_in_chain (vm, b0));
          }

          /*
           * before we pop the label copy, values we need to maintain.
           * The label header is in network byte order.
           *  last byte is the TTL.
           *  bits 2 to 4 inclusive are the EXP bits
           */
          vnet_buffer (b0)->mpls.ttl = ((char*)h0)[3];
          vnet_buffer (b0)->mpls.exp = (((char*)h0)[2] & 0xe) >> 1;
          vnet_buffer (b0)->mpls.first = 1;

          /*
           * pop the label that was just used in the lookup
           */
          vlib_buffer_advance(b0, sizeof(*h0));

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_lookup_trace_t *tr = vlib_add_trace (vm, node,
                                                        b0, sizeof (*tr));
              tr->next_index = next0;
              tr->lb_index = lbi0;
              tr->lfib_index = lfib_index0;
              tr->hash = hash_c0;
              tr->label_net_byte_order = h0->label_exp_s_ttl;
          }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, mm->mpls_lookup_node_index,
                               MPLS_ERROR_PKTS_DECAP, from_frame->n_vectors);
  return from_frame->n_vectors;
}

static char * mpls_error_strings[] = {
#define mpls_error(n,s) s,
#include "error.def"
#undef mpls_error
};

VLIB_REGISTER_NODE (mpls_lookup_node) = {
  .name = "mpls-lookup",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_errors = MPLS_N_ERROR,
  .error_strings = mpls_error_strings,

  .sibling_of = "mpls-load-balance",

  .format_buffer = format_mpls_header,
  .format_trace = format_mpls_lookup_trace,
  .unformat_buffer = unformat_mpls_header,
};

typedef struct {
  u32 next_index;
  u32 lb_index;
  u32 hash;
} mpls_load_balance_trace_t;

static u8 *
format_mpls_load_balance_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  mpls_load_balance_trace_t * t = va_arg (*args, mpls_load_balance_trace_t *);

  s = format (s, "MPLS: next [%d], LB index %d hash %d",
              t->next_index, t->lb_index, t->hash);
  return s;
}

VLIB_NODE_FN (mpls_load_balance_node) (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  vlib_combined_counter_main_t * cm = &load_balance_main.lbm_via_counters;
  u32 n_left_from, n_left_to_next, * from, * to_next;
  u32 thread_index = vlib_get_thread_index();
  u32 next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next,
                           to_next, n_left_to_next);


      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          const load_balance_t *lb0, *lb1;
          vlib_buffer_t * p0, *p1;
          u32 pi0, lbi0, hc0, pi1, lbi1, hc1, next0, next1;
          const mpls_unicast_header_t *mpls0, *mpls1;
          const dpo_id_t *dpo0, *dpo1;

          /* Prefetch next iteration. */
          {
            vlib_buffer_t * p2, * p3;

            p2 = vlib_get_buffer (vm, from[2]);
            p3 = vlib_get_buffer (vm, from[3]);

            vlib_prefetch_buffer_header (p2, STORE);
            vlib_prefetch_buffer_header (p3, STORE);

            CLIB_PREFETCH (p2->data, sizeof (mpls0[0]), LOAD);
            CLIB_PREFETCH (p3->data, sizeof (mpls0[0]), LOAD);
          }

          pi0 = to_next[0] = from[0];
          pi1 = to_next[1] = from[1];

          from += 2;
          n_left_from -= 2;
          to_next += 2;
          n_left_to_next -= 2;

          p0 = vlib_get_buffer (vm, pi0);
          p1 = vlib_get_buffer (vm, pi1);

          mpls0 = vlib_buffer_get_current (p0);
          mpls1 = vlib_buffer_get_current (p1);
          lbi0 = vnet_buffer (p0)->ip.adj_index;
          lbi1 = vnet_buffer (p1)->ip.adj_index;

          lb0 = load_balance_get(lbi0);
          lb1 = load_balance_get(lbi1);

          /*
           * this node is for via FIBs we can re-use the hash value from the
           * to node if present.
           * We don't want to use the same hash value at each level in the recursion
           * graph as that would lead to polarisation
           */
          hc0 = vnet_buffer (p0)->ip.flow_hash = 0;
          hc1 = vnet_buffer (p1)->ip.flow_hash = 0;

          if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
          {
              if (PREDICT_TRUE (vnet_buffer(p0)->ip.flow_hash))
              {
                  hc0 = vnet_buffer(p0)->ip.flow_hash = vnet_buffer(p0)->ip.flow_hash >> 1;
              }
              else
              {
                  hc0 = vnet_buffer(p0)->ip.flow_hash = mpls_compute_flow_hash(mpls0, hc0);
              }
              dpo0 = load_balance_get_fwd_bucket(lb0, (hc0 & lb0->lb_n_buckets_minus_1));
          }
          else
          {
              dpo0 = load_balance_get_bucket_i (lb0, 0);
          }
          if (PREDICT_FALSE (lb1->lb_n_buckets > 1))
          {
              if (PREDICT_TRUE (vnet_buffer(p1)->ip.flow_hash))
              {
                  hc1 = vnet_buffer(p1)->ip.flow_hash = vnet_buffer(p1)->ip.flow_hash >> 1;
              }
              else
              {
                  hc1 = vnet_buffer(p1)->ip.flow_hash = mpls_compute_flow_hash(mpls1, hc1);
              }
              dpo1 = load_balance_get_fwd_bucket(lb1, (hc1 & lb1->lb_n_buckets_minus_1));
          }
          else
          {
              dpo1 = load_balance_get_bucket_i (lb1, 0);
          }

          next0 = dpo0->dpoi_next_node;
          next1 = dpo1->dpoi_next_node;

          vnet_buffer (p0)->ip.adj_index = dpo0->dpoi_index;
          vnet_buffer (p1)->ip.adj_index = dpo1->dpoi_index;

          vlib_increment_combined_counter
              (cm, thread_index, lbi0, 1,
               vlib_buffer_length_in_chain (vm, p0));
          vlib_increment_combined_counter
              (cm, thread_index, lbi1, 1,
               vlib_buffer_length_in_chain (vm, p1));

          if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_load_balance_trace_t *tr = vlib_add_trace (vm, node,
                                                              p0, sizeof (*tr));
              tr->next_index = next0;
              tr->lb_index = lbi0;
              tr->hash = hc0;
          }
          if (PREDICT_FALSE(p1->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_load_balance_trace_t *tr = vlib_add_trace (vm, node,
                                                              p1, sizeof (*tr));
              tr->next_index = next1;
              tr->lb_index = lbi1;
              tr->hash = hc1;
          }

          vlib_validate_buffer_enqueue_x2 (vm, node, next,
                                           to_next, n_left_to_next,
                                           pi0, pi1, next0, next1);
       }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          const load_balance_t *lb0;
          vlib_buffer_t * p0;
          u32 pi0, lbi0, hc0, next0;
          const mpls_unicast_header_t *mpls0;
          const dpo_id_t *dpo0;

          pi0 = from[0];
          to_next[0] = pi0;
          from += 1;
          to_next += 1;
          n_left_to_next -= 1;
          n_left_from -= 1;

          p0 = vlib_get_buffer (vm, pi0);

          mpls0 = vlib_buffer_get_current (p0);
          lbi0 = vnet_buffer (p0)->ip.adj_index;

          lb0 = load_balance_get(lbi0);

          hc0 = vnet_buffer (p0)->ip.flow_hash = 0;
          if (PREDICT_FALSE (lb0->lb_n_buckets > 1))
          {
              if (PREDICT_TRUE (vnet_buffer(p0)->ip.flow_hash))
              {
                  hc0 = vnet_buffer(p0)->ip.flow_hash = vnet_buffer(p0)->ip.flow_hash >> 1;
              }
              else
              {
                  hc0 = vnet_buffer(p0)->ip.flow_hash = mpls_compute_flow_hash(mpls0, hc0);
              }
               dpo0 = load_balance_get_fwd_bucket(lb0, (hc0 & lb0->lb_n_buckets_minus_1));
          }
          else
          {
              dpo0 = load_balance_get_bucket_i (lb0, 0);
          }

          next0 = dpo0->dpoi_next_node;
          vnet_buffer (p0)->ip.adj_index = dpo0->dpoi_index;

          if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
          {
              mpls_load_balance_trace_t *tr = vlib_add_trace (vm, node,
                                                              p0, sizeof (*tr));
              tr->next_index = next0;
              tr->lb_index = lbi0;
              tr->hash = hc0;
          }

          vlib_increment_combined_counter
              (cm, thread_index, lbi0, 1,
               vlib_buffer_length_in_chain (vm, p0));

          vlib_validate_buffer_enqueue_x1 (vm, node, next,
                                           to_next, n_left_to_next,
                                           pi0, next0);
        }

      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (mpls_load_balance_node) = {
  .name = "mpls-load-balance",
  .vector_size = sizeof (u32),
  .format_trace = format_mpls_load_balance_trace,
  .n_next_nodes = 1,
  .next_nodes =
  {
      [MPLS_LOOKUP_NEXT_DROP] = "mpls-drop",
  },

};


#ifndef CLIB_MARCH_VARIANT
static clib_error_t *
mpls_lookup_init (vlib_main_t * vm)
{
  mpls_main_t *mm = &mpls_main;
  clib_error_t * error;
  vlib_node_t *node = vlib_get_node_by_name (vm, (u8*)"mpls-lookup" );

  mm->mpls_lookup_node_index = node->index;

  if ((error = vlib_call_init_function (vm, mpls_init)))
    return error;

  mpls_lookup_to_replicate_edge =
      vlib_node_add_named_next(vm,
                               mm->mpls_lookup_node_index,
                               "mpls-replicate");

  return (NULL);
}

VLIB_INIT_FUNCTION (mpls_lookup_init);
#endif /* CLIB_MARCH_VARIANT */
