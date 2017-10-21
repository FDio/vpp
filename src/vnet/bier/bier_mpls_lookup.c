/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/buffer.h>
#include <vnet/vnet.h>

#include <vnet/bier/bier_fmask.h>
#include <vnet/bier/bier_hdr_inlines.h>
#include <vnet/bier/bier_table.h>
#include <vnet/bier/bier_fmask.h>

static char * bier_mpls_lookup_error_strings[] = {
#define bier_error(n,s) s,
#include <vnet/bier/bier_lookup_error.def>
#undef bier_error
};

/*
 * Keep these values sematically the same as BIER lookup
 */
#define foreach_bier_mpls_lookup_next           \
_(DROP, "bier-drop")                            \
_(OUTPUT, "bier-output")

typedef enum {
#define _(s,n) BIER_MPLS_LOOKUP_NEXT_##s,
  foreach_bier_mpls_lookup_next
#undef _
  BIER_MPLS_LOOKUP_N_NEXT,
} bier_mpls_lookup_next_t;

typedef enum {
#define bier_error(n,s) BIER_MPLS_LOOKUP_ERROR_##n,
#include <vnet/bier/bier_lookup_error.def>
#undef bier_error
  BIER_MPLS_LOOKUP_N_ERROR,
} bier_mpls_lookup_error_t;

vlib_node_registration_t bier_mpls_lookup_node;

/**
 * @brief Packet trace recoed for a BIER lookup
 */
typedef struct bier_mpls_lookup_trace_t_
{
    u32 next_index;
    index_t bt_index;
    index_t bfm_index;
    bier_bp_t bp;
} bier_mpls_lookup_trace_t;

static uword
bier_mpls_lookup (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * from_frame)
{
    u32 n_left_from, next_index, * from, * to_next;

    from = vlib_frame_vector_args (from_frame);
    n_left_from = from_frame->n_vectors;
    next_index = BIER_MPLS_LOOKUP_NEXT_DROP;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame (vm, node, next_index,
                             to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            bier_bit_mask_bucket_t buckets_copy[BIER_HDR_BUCKETS_256];
            u32 next0, bi0, last0, n_bytes, bti0, bfmi0;
            const bier_fmask_t *bfm0;
            const bier_table_t *bt0;
            u16 index, num_buckets;
            const bier_hdr_t *bh0;
            bier_bit_string_t bbs;
            vlib_buffer_t *b0;
            int bucket, n_tx;
            bier_bp_t fbs;

            bi0 = from[0];
            from += 1;
            n_left_from -= 1;
            n_tx = 0;

            b0 = vlib_get_buffer (vm, bi0);
            bh0 = vlib_buffer_get_current (b0);
            bti0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];

            /*
             * default to drop so that if no bits are matched then
             * that is where we go - DROP.
             */
            next0 = BIER_MPLS_LOOKUP_NEXT_DROP;

            /*
             * At the imposition or input node,
             * we stored the BIER Table index in the TX adjacency
             */
            bt0 = bier_table_get(vnet_buffer(b0)->ip.adj_index[VLIB_TX]);

            /*
             * we should only forward via one for the ECMP tables
             */
            ASSERT(!bier_table_is_main(bt0));

            /*
             * number of integer sized buckets
             */
            n_bytes = bier_hdr_len_id_to_num_buckets(bt0->bt_id.bti_hdr_len);
            vnet_buffer(b0)->sw_if_index[VLIB_TX] = ~0;
            num_buckets = n_bytes / sizeof(int);
            bier_bit_string_init(&bbs,
                                 bt0->bt_id.bti_hdr_len,
                                 buckets_copy);
            memcpy(bbs.bbs_buckets, bh0->bh_bit_string, bbs.bbs_len);

            /*
             * Loop through the buckets in the header
             */
            for (index = 0; index < num_buckets; index++) {
                /*
                 * loop through each bit in the bucket
                 */
                bucket = ((int*)bbs.bbs_buckets)[index];

                while (bucket) {
                    fbs  = bier_find_first_bit_string_set(bucket);
                    fbs += (((num_buckets - 1) - index) *
                            BIER_BIT_MASK_BITS_PER_INT);

                    bfmi0 = bier_table_fwd_lookup(bt0, fbs);

                    /*
                     * whatever happens, the bit we just looked for
                     * MUST be clear from the packet
                     * otherwise we could be in this loop a while ...
                     */
                    bier_bit_string_clear_bit(&bbs, fbs);

                    if (PREDICT_TRUE(INDEX_INVALID != bfmi0))
                    {
                        bfm0 = bier_fmask_get(bfmi0);
                        vnet_buffer (b0)->ip.adj_index[VLIB_TX] = bfmi0;

                        /*
                         * use the bit-string on the fmask to reset
                         * the bits in the header we are walking
                         */
                        bier_bit_string_clear_string(
                            &bfm0->bfm_bits.bfmb_input_reset_string,
                            &bbs);
                        bucket = ((int*)bbs.bbs_buckets)[index];

                        /*
                         * the fmask is resolved so replicate a
                         * packet its way
                         */
                        next0 = BIER_MPLS_LOOKUP_NEXT_OUTPUT;
                    } else {
                        /*
                         * go to the next bit-position set
                         */
                        bucket = ((int*)bbs.bbs_buckets)[index];
                        continue;
                    }

                    /*
                     * save whether this is the last replication we need
                     * to make. If it is, then we can use this original
                     */
                    // TODO must be able to do better
                    last0 = bier_bit_string_is_zero(&bbs);

                    if (PREDICT_FALSE(last0)) {
                        /*
                         * no more bits set in the packet,
                         * we can send the original
                         */
                        if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
                        {
                            bier_mpls_lookup_trace_t *tr;

                            tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
                            tr->next_index = next0;
                            tr->bt_index = bti0;
                            tr->bfm_index = bfmi0;
                            tr->bp = fbs;
                        }

                        to_next[0] = bi0;
                        to_next += 1;
                        n_left_to_next -= 1;
                        n_tx++;

                        vlib_validate_buffer_enqueue_x1 (
                            vm, node, next_index,
                            to_next, n_left_to_next,
                            bi0, next0);
                    } else {
                        /*
                         * Make a copy
                         */
                        vlib_buffer_t *c0;
                        u32 ci0;

                        c0 = vlib_buffer_copy(vm, b0);
                        ci0 = vlib_get_buffer_index (vm, c0);

                        to_next[0] = ci0;
                        to_next += 1;
                        n_left_to_next -= 1;
                        n_tx++;

                        VLIB_BUFFER_TRACE_TRAJECTORY_INIT (c0);
                        if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
                        {
                            bier_mpls_lookup_trace_t *tr;

                            tr = vlib_add_trace (vm, node, c0, sizeof (*tr));
                            tr->next_index = next0;
                            tr->bt_index = bti0;
                            tr->bfm_index = bfmi0;
                            tr->bp = fbs;

                            c0->flags |= VLIB_BUFFER_IS_TRACED;
                        }

                        vlib_validate_buffer_enqueue_x1 (
                            vm, node, next_index,
                            to_next, n_left_to_next,
                            ci0, next0);
                    }

                    /*
                     * After the enqueue it is possible that we over-flow the
                     * frame of the to-next node. When this happens we need to
                     * 'put' that full frame to the node and get a fresh empty
                     * one. Note that these are macros with side effects that
                     * change to_next & n_left_to_next
                     */
                    if (PREDICT_FALSE(0 == n_left_to_next))
                    {
                        vlib_put_next_frame (vm, node, next_index,
                                             n_left_to_next);
                        vlib_get_next_frame (vm, node, next_index,
                                             to_next, n_left_to_next);
                    }
                }
            }
            if (0 == n_tx)
            {
                /*
                 * No replications, bin it.
                 */
                to_next[0] = bi0;
                to_next += 1;
                n_left_to_next -= 1;

                if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
                {
                    bier_mpls_lookup_trace_t *tr;

                    tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
                    tr->next_index = next0;
                    tr->bt_index = bti0;
                    tr->bfm_index = ~0;
                    tr->bp = 0;
                }
               vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                                                to_next, n_left_to_next,
                                                bi0,
                                                BIER_MPLS_LOOKUP_NEXT_DROP);

            }
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    vlib_node_increment_counter (vm, bier_mpls_lookup_node.index,
                                 BIER_MPLS_LOOKUP_ERROR_NONE,
                                 from_frame->n_vectors);
    return (from_frame->n_vectors);
}

static u8 *
format_bier_mpls_lookup_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  bier_mpls_lookup_trace_t * t = va_arg (*args, bier_mpls_lookup_trace_t *);

  s = format (s, "BIER-MPLS: next [%d], BP:%d tbl:%d BFM:%d",
              t->next_index,
              t->bp,
              t->bt_index,
              t->bfm_index);
  return s;
}

VLIB_REGISTER_NODE (bier_mpls_lookup_node) = {
  .function = bier_mpls_lookup,
  .name = "bier-mpls-lookup",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = BIER_MPLS_LOOKUP_N_ERROR,
  .error_strings = bier_mpls_lookup_error_strings,

  .format_trace = format_bier_mpls_lookup_trace,
  .n_next_nodes = BIER_MPLS_LOOKUP_N_NEXT,
  .next_nodes = {
        [BIER_MPLS_LOOKUP_NEXT_DROP] = "bier-drop",
        [BIER_MPLS_LOOKUP_NEXT_OUTPUT] = "bier-mpls-output",
  },
};
