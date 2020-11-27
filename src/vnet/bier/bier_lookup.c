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

/**
 * Struct maintaining the per-worker thread data for BIER lookups
 */
typedef struct bier_lookup_main_t_
{
    /* per-cpu vector of cloned packets */
    u32 **blm_clones;
    /* per-cpu vector of BIER fmasks */
    u32 **blm_fmasks;
} bier_lookup_main_t;

/**
 * Single instance of the lookup main
 */
static bier_lookup_main_t bier_lookup_main;

static char * bier_lookup_error_strings[] = {
#define bier_error(n,s) s,
#include <vnet/bier/bier_lookup_error.def>
#undef bier_error
};

/*
 * Keep these values semantically the same as BIER lookup
 */
#define foreach_bier_lookup_next                \
    _(DROP, "bier-drop")                        \
    _(OUTPUT, "bier-output")

typedef enum {
#define _(s,n) BIER_LOOKUP_NEXT_##s,
    foreach_bier_lookup_next
#undef _
    BIER_LOOKUP_N_NEXT,
} bier_lookup_next_t;

typedef enum {
#define bier_error(n,s) BIER_LOOKUP_ERROR_##n,
#include <vnet/bier/bier_lookup_error.def>
#undef bier_error
    BIER_LOOKUP_N_ERROR,
} bier_lookup_error_t;

vlib_node_registration_t bier_lookup_node;

/**
 * @brief Packet trace record for a BIER lookup
 */
typedef struct bier_lookup_trace_t_
{
    u32 next_index;
    index_t bt_index;
    index_t bfm_index;
} bier_lookup_trace_t;

static uword
bier_lookup (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
    u32 n_left_from, next_index, * from, * to_next;
    bier_lookup_main_t *blm = &bier_lookup_main;
    u32 thread_index = vlib_get_thread_index();
    bier_bit_mask_bucket_t buckets_copy[BIER_HDR_BUCKETS_4096];

    from = vlib_frame_vector_args (from_frame);
    n_left_from = from_frame->n_vectors;
    next_index = BIER_LOOKUP_NEXT_DROP;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame (vm, node, next_index,
                             to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 next0, bi0, n_bytes, bti0, bfmi0;
            const bier_fmask_t *bfm0;
            const bier_table_t *bt0;
            u16 index, num_buckets;
            const bier_hdr_t *bh0;
            bier_bit_string_t bbs;
            vlib_buffer_t *b0;
            bier_bp_t fbs;
            int bucket;

            bi0 = from[0];
            from += 1;
            n_left_from -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            bh0 = vlib_buffer_get_current (b0);
            bti0 = vnet_buffer(b0)->ip.adj_index;

            /*
             * default to drop so that if no bits are matched then
             * that is where we go - DROP.
             */
            next0 = BIER_LOOKUP_NEXT_DROP;

            /*
             * At the imposition or input node,
             * we stored the BIER Table index in the TX adjacency
             */
            bt0 = bier_table_get(vnet_buffer(b0)->ip.adj_index);

            /*
             * we should only forward via one for the ECMP tables
             */
            ASSERT(!bier_table_is_main(bt0));

            /*
             * number of integer sized buckets
             */
            n_bytes = bier_hdr_len_id_to_num_buckets(bt0->bt_id.bti_hdr_len);
            vnet_buffer(b0)->mpls.bier.n_bytes = n_bytes;
            vnet_buffer(b0)->sw_if_index[VLIB_TX] = ~0;
            num_buckets = n_bytes / sizeof(int);
            bier_bit_string_init(&bbs,
                                 bt0->bt_id.bti_hdr_len,
                                 buckets_copy);
            memcpy(bbs.bbs_buckets, bh0->bh_bit_string, bbs.bbs_len);

            /*
             * reset the fmask storage vector
             */
            vec_reset_length (blm->blm_fmasks[thread_index]);

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
                     * MUST be cleared from the packet
                     * otherwise we could be in this loop a while ...
                     */
                    bier_bit_string_clear_bit(&bbs, fbs);

                    if (PREDICT_TRUE(INDEX_INVALID != bfmi0))
                    {
                        bfm0 = bier_fmask_get(bfmi0);

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
                        next0 = BIER_LOOKUP_NEXT_OUTPUT;

                        vec_add1 (blm->blm_fmasks[thread_index], bfmi0);
                    } else {
                        /*
                         * go to the next bit-position set
                         */
                        vlib_node_increment_counter(
                            vm, node->node_index,
                            BIER_LOOKUP_ERROR_FMASK_UNRES, 1);
                        bucket = ((int*)bbs.bbs_buckets)[index];
                        continue;
                    }
                }
            }

            /*
             * Full mask now processed.
             * Create the number of clones we need based on the number
             * of fmasks we are sending to.
             */
            u16 num_cloned, clone;
            u32 n_clones;

            n_clones = vec_len(blm->blm_fmasks[thread_index]);

            if (PREDICT_TRUE(0 != n_clones))
            {
                vec_set_len(blm->blm_clones[thread_index], n_clones);
                num_cloned = vlib_buffer_clone(vm, bi0,
                                               blm->blm_clones[thread_index],
                                               n_clones,
					       VLIB_BUFFER_CLONE_HEAD_SIZE);


                if (num_cloned != n_clones)
                {
                    vec_set_len(blm->blm_clones[thread_index], num_cloned);
                    vlib_node_increment_counter
                        (vm, node->node_index,
                         BIER_LOOKUP_ERROR_BUFFER_ALLOCATION_FAILURE, 1);
                }

                for (clone = 0; clone < num_cloned; clone++)
                {
                    vlib_buffer_t *c0;
                    u32 ci0;

                    ci0 = blm->blm_clones[thread_index][clone];
                    c0 = vlib_get_buffer(vm, ci0);
                    vnet_buffer(c0)->ip.adj_index =
                        blm->blm_fmasks[thread_index][clone];

                    to_next[0] = ci0;
                    to_next += 1;
                    n_left_to_next -= 1;

                    if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
                    {
                        bier_lookup_trace_t *tr;

                        tr = vlib_add_trace (vm, node, c0, sizeof (*tr));
                        tr->bt_index = bti0;
                        tr->bfm_index = blm->blm_fmasks[thread_index][clone];
                    }

                    vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                                                    to_next, n_left_to_next,
                                                    ci0, next0);

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
            else
            {
                /*
                 * no clones/replications required. drop this packet
                 */
                next0 = BIER_LOOKUP_NEXT_DROP;
                to_next[0] = bi0;
                to_next += 1;
                n_left_to_next -= 1;

                if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
                {
                    bier_lookup_trace_t *tr;

                    tr = vlib_add_trace (vm, node, b0, sizeof (*tr));

                    tr->bt_index = bti0;
                    tr->bfm_index = ~0;
                }

                vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                                                to_next, n_left_to_next,
                                                bi0, next0);
            }
        }

        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }

    vlib_node_increment_counter(vm, bier_lookup_node.index,
                                BIER_LOOKUP_ERROR_NONE,
                                from_frame->n_vectors);
    return (from_frame->n_vectors);
}

static u8 *
format_bier_lookup_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    bier_lookup_trace_t * t = va_arg (*args, bier_lookup_trace_t *);

    s = format (s, "BIER: next [%d], tbl:%d BFM:%d",
                t->next_index,
                t->bt_index,
                t->bfm_index);
    return s;
}

VLIB_REGISTER_NODE (bier_lookup_node) = {
    .function = bier_lookup,
    .name = "bier-lookup",
    /* Takes a vector of packets. */
    .vector_size = sizeof (u32),

    .n_errors = BIER_LOOKUP_N_ERROR,
    .error_strings = bier_lookup_error_strings,

    .format_trace = format_bier_lookup_trace,
    .n_next_nodes = BIER_LOOKUP_N_NEXT,
    .next_nodes = {
        [BIER_LOOKUP_NEXT_DROP] = "bier-drop",
        [BIER_LOOKUP_NEXT_OUTPUT] = "bier-output",
    },
};

clib_error_t *
bier_lookup_module_init (vlib_main_t * vm)
{
    bier_lookup_main_t *blm = &bier_lookup_main;
    u32 thread_index;

    vec_validate (blm->blm_clones, vlib_num_workers());
    vec_validate (blm->blm_fmasks, vlib_num_workers());

    for (thread_index = 0;
         thread_index <= vlib_num_workers();
         thread_index++)
    {
        /*
         *  1024 is the most we will ever need to support
         * a Bit-Mask length of 1024
         */
        vec_validate(blm->blm_fmasks[thread_index], 1023);
        vec_validate(blm->blm_clones[thread_index], 1023);
    }

    return 0;
}

VLIB_INIT_FUNCTION (bier_lookup_module_init);
