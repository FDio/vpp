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

#include <vnet/bier/bier_disp_entry.h>
#include <vnet/bier/bier_hdr_inlines.h>

/**
 * @brief A struct to hold tracing information for the MPLS label imposition
 * node.
 */
typedef struct bier_disp_dispatch_trace_t_
{
    /**
     * BIER payload protocol used to dispatch
     */
    bier_hdr_proto_id_t pproto;

    /**
     * RPF-ID packet is tagged with
     */
    u32 rpf_id;
} bier_disp_dispatch_trace_t;

always_inline uword
bier_disp_dispatch_inline (vlib_main_t * vm,
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
            bier_hdr_proto_id_t pproto0;
            bier_disp_entry_t *bde0;
            u32 next0, bi0, bdei0;
            const dpo_id_t *dpo0;
            vlib_buffer_t * b0;
            bier_hdr_t *hdr0;
            u32 entropy0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            bdei0 = vnet_buffer(b0)->ip.adj_index;
            hdr0 = vlib_buffer_get_current(b0);
            bde0 = bier_disp_entry_get(bdei0);
            vnet_buffer(b0)->mpls.rpf = BIER_RX_ITF;

            /*
             * header is in network order - flip it, we are about to
             * consume it anyway
             */
            bier_hdr_ntoh(hdr0);
            pproto0 = bier_hdr_get_proto_id(hdr0);
            entropy0 = bier_hdr_get_entropy(hdr0);

            /*
             * strip the header and copy the entropy value into
             * the packets flow-hash field
             * DSCP mumble mumble...
             */
            vlib_buffer_advance(b0, (vnet_buffer(b0)->mpls.bier.n_bytes +
                                     sizeof(*hdr0)));
            vnet_buffer(b0)->ip.flow_hash = entropy0;

            /*
             * use the payload proto to dispatch to the
             * correct stacked DPO.
             */
            dpo0 = &bde0->bde_fwd[pproto0].bde_dpo;
            next0 = dpo0->dpoi_next_node;
            vnet_buffer(b0)->ip.adj_index = dpo0->dpoi_index;
            vnet_buffer(b0)->ip.rpf_id = bde0->bde_fwd[pproto0].bde_rpf_id;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                bier_disp_dispatch_trace_t *tr =
                    vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->pproto = pproto0;
                tr->rpf_id = vnet_buffer(b0)->ip.rpf_id;
            }

            vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

static u8 *
format_bier_disp_dispatch_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    bier_disp_dispatch_trace_t * t;

    t = va_arg (*args, bier_disp_dispatch_trace_t *);
    s = format (s, "%U", format_bier_hdr_proto, t->pproto);

    return (s);
}

VLIB_NODE_FN (bier_disp_dispatch_node) (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
    return (bier_disp_dispatch_inline(vm, node, frame));
}

VLIB_REGISTER_NODE (bier_disp_dispatch_node) = {
    .name = "bier-disp-dispatch",
    .vector_size = sizeof (u32),

    .format_trace = format_bier_disp_dispatch_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "bier-drop",
    }
};
