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

#include <vnet/bier/bier_imp.h>
#include <vnet/bier/bier_hdr_inlines.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

/**
 * @brief A struct to hold tracing information for the BIER imposition
 * node.
 */
typedef struct bier_imp_trace_t_
{
    /**
     * BIER imposition object hit
     */
    index_t imp;

    /**
     * BIER hdr applied
     */
    bier_hdr_t hdr;
} bier_imp_trace_t;

always_inline uword
bier_imp_dpo_inline (vlib_main_t * vm,
                     vlib_node_runtime_t * node,
                     vlib_frame_t * from_frame,
                     fib_protocol_t fproto,
                     bier_hdr_proto_id_t bproto)
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
            vlib_buffer_t * b0;
            bier_imp_t *bimp0;
            bier_hdr_t *hdr0;
            u32 bi0, bii0;
            u32 next0;

            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);

            bii0 = vnet_buffer(b0)->ip.adj_index;
            bimp0 = bier_imp_get(bii0);

            if (FIB_PROTOCOL_IP4 == fproto)
            {
                /*
                 * decrement the TTL on ingress to the BIER domain
                 */
                ip4_header_t * ip0 = vlib_buffer_get_current(b0);
                u32 checksum0;

                checksum0 = ip0->checksum + clib_host_to_net_u16 (0x0100);
                checksum0 += checksum0 >= 0xffff;

                ip0->checksum = checksum0;
                ip0->ttl -= 1;

                /*
                 * calculate an entropy
                 */
                if (0 == vnet_buffer(b0)->ip.flow_hash)
                {
                    vnet_buffer(b0)->ip.flow_hash =
                        ip4_compute_flow_hash (ip0, IP_FLOW_HASH_DEFAULT);
                }
            }
            if (FIB_PROTOCOL_IP6 == fproto)
            {
                /*
                 * decrement the TTL on ingress to the BIER domain
                 */
                ip6_header_t * ip0 = vlib_buffer_get_current(b0);

                ip0->hop_limit -= 1;

                /*
                 * calculate an entropy
                 */
                if (0 == vnet_buffer(b0)->ip.flow_hash)
                {
                    vnet_buffer(b0)->ip.flow_hash =
                        ip6_compute_flow_hash (ip0, IP_FLOW_HASH_DEFAULT);
                }
            }

            /* Paint the BIER header */
            vlib_buffer_advance(b0, -(sizeof(bier_hdr_t) +
                                      bier_hdr_len_id_to_num_bytes(bimp0->bi_tbl.bti_hdr_len)));
            hdr0 = vlib_buffer_get_current(b0);

            /* RPF check */
            if (PREDICT_FALSE(BIER_RX_ITF == vnet_buffer(b0)->mpls.rpf))
            {
                next0 = 0;
            }
            else
            {
                clib_memcpy_fast(hdr0, &bimp0->bi_hdr,
                            (sizeof(bier_hdr_t) +
                             bier_hdr_len_id_to_num_bytes(bimp0->bi_tbl.bti_hdr_len)));
                /*
                 * Fixup the entropy and protocol, both of which have a
                 * zero value post the paint job
                 */
                hdr0->bh_oam_dscp_proto |=
                    clib_host_to_net_u16(bproto << BIER_HDR_PROTO_FIELD_SHIFT);
                hdr0->bh_first_word |=
                    clib_host_to_net_u32((vnet_buffer(b0)->ip.flow_hash &
                                          BIER_HDR_ENTROPY_FIELD_MASK) <<
                                         BIER_HDR_ENTROPY_FIELD_SHIFT);

                /*
                 * use TTL 64 for the post encap MPLS label/BIFT-ID
                 * this we be decremented in bier_output node.
                 */
                vnet_buffer(b0)->mpls.ttl = 65;

                /* next node */
                next0 = bimp0->bi_dpo[fproto].dpoi_next_node;
                vnet_buffer(b0)->ip.adj_index =
                    bimp0->bi_dpo[fproto].dpoi_index;
            }

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
                bier_imp_trace_t *tr =
                    vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->imp = bii0;
                tr->hdr = *hdr0;
            }

            vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                            n_left_to_next, bi0, next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return from_frame->n_vectors;
}

static u8 *
format_bier_imp_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    bier_imp_trace_t * t;
    u32 indent;

    t = va_arg (*args, bier_imp_trace_t *);
    indent = format_get_indent (s);

    s = format (s, "%U", format_bier_imp, t->imp, indent, BIER_SHOW_BRIEF);
    return (s);
}

VLIB_NODE_FN (bier_imp_ip4_node) (vlib_main_t * vm,
              vlib_node_runtime_t * node,
              vlib_frame_t * frame)
{
    return (bier_imp_dpo_inline(vm, node, frame,
                                FIB_PROTOCOL_IP4,
                                BIER_HDR_PROTO_IPV4));
}

VLIB_REGISTER_NODE (bier_imp_ip4_node) = {
    .name = "bier-imp-ip4",
    .vector_size = sizeof (u32),

    .format_trace = format_bier_imp_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "bier-drop",
    }
};

VLIB_NODE_FN (bier_imp_ip6_node) (vlib_main_t * vm,
              vlib_node_runtime_t * node,
              vlib_frame_t * frame)
{
    return (bier_imp_dpo_inline(vm, node, frame,
                                FIB_PROTOCOL_IP6,
                                BIER_HDR_PROTO_IPV6));
}

VLIB_REGISTER_NODE (bier_imp_ip6_node) = {
    .name = "bier-imp-ip6",
    .vector_size = sizeof (u32),

    .format_trace = format_bier_imp_trace,
    .n_next_nodes = 1,
    .next_nodes = {
        [0] = "error-drop",
    }
};
