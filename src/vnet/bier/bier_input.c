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

#include <vnet/bier/bier_table.h>
#include <vnet/bier/bier_hdr_inlines.h>

typedef enum {
#define bier_error(n,s) BIER_INPUT_ERROR_##n,
#include <vnet/bier/bier_input_error.def>
#undef bier_error
    BIER_INPUT_N_ERROR,
} bier_input_error_t;

static char * bier_error_strings[] = {
#define bier_error(n,s) s,
#include <vnet/bier/bier_input_error.def>
#undef bier_error
};

typedef enum bier_input_next_t_ {
    BIER_INPUT_NEXT_BIER_LOOKUP,
    BIER_INPUT_NEXT_DROP,
    BIER_INPUT_N_NEXT,
} bier_input_next_t;

vlib_node_registration_t bier_input_node;

/**
 * @brief Packet trace record for BIER input
 */
typedef struct bier_input_trace_t_
{
    u32 next_index;
    u32 bt_index;
} bier_input_trace_t;

static int
bier_hdr_validate (bier_hdr_t *bier_hdr,
                   bier_hdr_len_id_t expected_length)
{
    /*
     * checks:
     *  - the version field must be 1
     *  - the header length matches the length expected
     */
    if (PREDICT_FALSE((BIER_HDR_VERSION_1 != bier_hdr_get_version(bier_hdr)) ||
                      (expected_length != bier_hdr_get_len_id(bier_hdr)))) {
        return (0);
    }

    return (1);
}

static uword
bier_input (vlib_main_t * vm,
            vlib_node_runtime_t * node,
            vlib_frame_t * from_frame)
{
    u32 n_left_from, next_index, * from, * to_next;

    from = vlib_frame_vector_args (from_frame);
    n_left_from = from_frame->n_vectors;

    /*
     * objection your honour! speculation!
     */
    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame (vm, node, next_index,
                             to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            const bier_table_t *bt0;
            vlib_buffer_t * b0;
            bier_hdr_t * bh0;
            u32 bi0, next0;
            u32 bt_index0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            bh0 = vlib_buffer_get_current (b0);
            bier_hdr_ntoh(bh0);

            /*
             * In the MPLS decap node we squirrelled away the
             * index for the BIER table as the tx adjacency
             */
            bt_index0 = vnet_buffer(b0)->ip.adj_index;
            bt0 = bier_table_get(bt_index0);

            if (PREDICT_TRUE(bier_hdr_validate(bh0, bt0->bt_id.bti_hdr_len)))
            {
                next0 = BIER_INPUT_NEXT_BIER_LOOKUP;
            } else {
                next0 = BIER_INPUT_NEXT_DROP;
                b0->error = node->errors[BIER_INPUT_ERROR_INVALID_HEADER];
            }

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                bier_input_trace_t *tr;

                tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->next_index = next0;
                tr->bt_index = bt_index0;
            }

            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    vlib_node_increment_counter (vm, bier_input_node.index,
                                 BIER_INPUT_ERROR_PKTS_VALID,
                                 from_frame->n_vectors);
    return (from_frame->n_vectors);
}

static u8 *
format_bier_input_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    bier_input_trace_t * t = va_arg (*args, bier_input_trace_t *);

    s = format (s, " next [%d], BIER Table index %d",
                t->next_index, t->bt_index);
    return s;
}

VLIB_REGISTER_NODE (bier_input_node) = {
    .function = bier_input,
    .name = "bier-input",
    /* Takes a vector of packets. */
    .vector_size = sizeof (u32),

    .n_errors = BIER_INPUT_N_ERROR,
    .error_strings = bier_error_strings,

    .n_next_nodes = BIER_INPUT_N_NEXT,
    .next_nodes = {
        [BIER_INPUT_NEXT_BIER_LOOKUP] = "bier-lookup",
        [BIER_INPUT_NEXT_DROP] = "bier-drop",
    },

    .format_trace = format_bier_input_trace,
};
