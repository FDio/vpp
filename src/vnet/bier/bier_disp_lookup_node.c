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

#include <vnet/bier/bier_disp_table.h>
#include <vnet/bier/bier_hdr_inlines.h>

/**
 * @brief A struct to hold tracing information for the MPLS label imposition
 * node.
 */
typedef struct bier_disp_lookup_trace_t_
{
    /**
     * BIER source BP used in the lookup - host order
     */
    bier_bp_t bp;
    /**
     * BIER disp table
     */
    index_t bdti;
} bier_disp_lookup_trace_t;

/**
 * Next nodes from BIER disposition lookup
 */
typedef enum bier_disp_lookup_next_t_
{
    BIER_DISP_LOOKUP_NEXT_DROP,
    BIER_DISP_LOOKUP_NEXT_DISPATCH,
} bier_disp_lookup_next_t;
#define BIER_DISP_LOOKUP_N_NEXT (BIER_DISP_LOOKUP_NEXT_DISPATCH+1)

always_inline uword
bier_disp_lookup_inline (vlib_main_t * vm,
                         vlib_node_runtime_t * node,
                         vlib_frame_t * from_frame)
{
    u32 n_left_from, next_index, * from, * to_next;

    from = vlib_frame_vector_args (from_frame);
    n_left_from = from_frame->n_vectors;

    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            const bier_hdr_t *hdr0;
            bier_hdr_src_id_t src0;
            vlib_buffer_t * b0;
            u32 bdei0, bdti0;
            u32 next0, bi0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);

            bdti0 = vnet_buffer(b0)->ip.adj_index;
            hdr0 = vlib_buffer_get_current(b0);

            /*
             * lookup - source is in network order.
             */
            src0 = bier_hdr_get_src_id(hdr0);
            next0 = BIER_DISP_LOOKUP_NEXT_DISPATCH;

            bdei0 = bier_disp_table_lookup(bdti0, src0);

            if (PREDICT_FALSE(INDEX_INVALID == bdei0))
            {
                /*
                 * if a specific match misses, try the default
                 */
                bdei0 = bier_disp_table_lookup(bdti0, 0);

                if (PREDICT_FALSE(INDEX_INVALID == bdei0))
                {
                    next0 = BIER_DISP_LOOKUP_NEXT_DROP;
                }
            }

            vnet_buffer(b0)->ip.adj_index = bdei0;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                bier_disp_lookup_trace_t *tr =
                    vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->bp = clib_net_to_host_u16(bier_hdr_get_src_id(hdr0));
                tr->bdti = bdti0;
            }

            vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

static u8 *
format_bier_disp_lookup_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    bier_disp_lookup_trace_t * t;

    t = va_arg (*args, bier_disp_lookup_trace_t *);
    s = format (s, "tbl:%d src:%d", t->bdti, t->bp);

    return (s);
}

VLIB_NODE_FN (bier_disp_lookup_node) (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
    return (bier_disp_lookup_inline(vm, node, frame));
}

VLIB_REGISTER_NODE (bier_disp_lookup_node) = {
    .name = "bier-disp-lookup",
    .vector_size = sizeof (u32),

    .format_trace = format_bier_disp_lookup_trace,
    .n_next_nodes = BIER_DISP_LOOKUP_N_NEXT,
    .next_nodes = {
        [BIER_DISP_LOOKUP_NEXT_DROP] = "bier-drop",
        [BIER_DISP_LOOKUP_NEXT_DISPATCH] = "bier-disp-dispatch",
    }
};
