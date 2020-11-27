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

#include <vnet/bier/bier_fmask.h>
#include <vnet/bier/bier_hdr_inlines.h>
#include <vlib/vlib.h>

static char * bier_output_error_strings[] = {
#define bier_error(n,s) s,
#include <vnet/bier/bier_output_error.def>
#undef bier_error
};

/*
 * Keep these values semantically the same as BIER output
 */
#define foreach_bier_output_next                \
    _(DROP, "bier-drop")

typedef enum {
#define _(s,n) BIER_OUTPUT_NEXT_##s,
    foreach_bier_output_next
#undef _
    BIER_OUTPUT_N_NEXT,
} bier_output_next_t;

typedef enum {
#define bier_error(n,s) BIER_OUTPUT_ERROR_##n,
#include <vnet/bier/bier_output_error.def>
#undef bier_error
    BIER_OUTPUT_N_ERROR,
} bier_output_error_t;

/**
 * Forward declaration
 */
vlib_node_registration_t bier_output_node;
extern vlib_combined_counter_main_t bier_fmask_counters;

/**
 * @brief Packet trace record for a BIER output
 */
typedef struct bier_output_trace_t_
{
    u32 next_index;
    index_t bfm_index;
    mpls_label_t bfm_label;
} bier_output_trace_t;

static uword
bier_output (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
  vlib_combined_counter_main_t *cm = &bier_fmask_counters;
    u32 n_left_from, next_index, * from, * to_next;
    u32 thread_index;

    thread_index = vm->thread_index;
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
            bier_output_next_t next0;
            bier_bit_string_t bbs;
            vlib_buffer_t * b0;
            bier_fmask_t *bfm0;
            mpls_label_t *h0;
            bier_hdr_t *bh0;
            u32 bfmi0;
            u32 bi0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            bh0 = vlib_buffer_get_current (b0);
            bier_bit_string_init_from_hdr(bh0, &bbs);

            /*
             * In the BIER Lookup node we squirrelled away the
             * BIER fmask index as the adj index
             */
            bfmi0 = vnet_buffer (b0)->ip.adj_index;
            bfm0 = bier_fmask_get(bfmi0);

            vlib_increment_combined_counter(
                cm, thread_index, bfmi0, 1,
                vlib_buffer_length_in_chain (vm, b0));

            /*
             * perform the logical AND of the packet's mask with
             * that of the fmask objects, to reset the bits that
             * are only on the shortest path the the fmask NH.
             */
            bier_bit_string_logical_and_string(
                &bfm0->bfm_bits.bfmb_input_reset_string,
                &bbs);

            /*
             * this is the last time we touch the BIER header
             * so flip to network order
             */
            bier_hdr_hton(bh0);

            /*
             * paint the BIER peer's label
             */
            if (!(bfm0->bfm_flags & BIER_FMASK_FLAG_DISP))
            {
                /*
                 * since a BIFT value and a MPLS label are formated the
                 * same, this painting works OK.
                 */
                vlib_buffer_advance(b0, -(word)sizeof(mpls_label_t));
                h0 = vlib_buffer_get_current(b0);
                
                h0[0] = bfm0->bfm_label;

                ((char*)h0)[3]= vnet_buffer(b0)->mpls.ttl - 1;
            }

            /*
             * setup next graph node
             */
            next0 = bfm0->bfm_dpo.dpoi_next_node;
            vnet_buffer(b0)->ip.adj_index = bfm0->bfm_dpo.dpoi_index;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                bier_output_trace_t *tr;

                tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->next_index = next0;
                tr->bfm_index = bfmi0;
                tr->bfm_label = bfm0->bfm_label;
            }

            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    vlib_node_increment_counter (vm, bier_output_node.index,
                                 BIER_OUTPUT_ERROR_NONE,
                                 from_frame->n_vectors);
    return (from_frame->n_vectors);
}

static u8 *
format_bier_output_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    bier_output_trace_t * t = va_arg (*args, bier_output_trace_t *);

    s = format (s, " next [%d], BFM index %d label:%x",
                t->next_index, t->bfm_index, t->bfm_label);
    return s;
}

VLIB_REGISTER_NODE (bier_output_node) = {
    .function = bier_output,
    .name = "bier-output",
    /* Takes a vector of packets. */
    .vector_size = sizeof (u32),

    .n_errors = BIER_OUTPUT_N_ERROR,
    .error_strings = bier_output_error_strings,

    .n_next_nodes = BIER_OUTPUT_N_NEXT,
    .next_nodes = {
        [BIER_OUTPUT_NEXT_DROP] = "bier-drop",
    },

    .format_trace = format_bier_output_trace,
};
