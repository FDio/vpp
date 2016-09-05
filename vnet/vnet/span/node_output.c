/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>
#include <vppinfra/error.h>

#if DPDK==1
#include <vnet/span/span.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

vlib_node_registration_t span_out_node;

/* packet trace format function */
static u8 * format_span_out_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    span_trace_t * t = va_arg (*args, span_trace_t *);

    s = format (s, "SPAN-out: mirrored sw_if_index %d -> %d",
            t->src_sw_if_index, t->mirror_sw_if_index);

    return s;
}

#define foreach_span_out_error                      \
_(HITS, "SPAN outgoing packets processed")

typedef enum {
#define _(sym,str) SPAN_ERROR_OUT_##sym,
    foreach_span_out_error
#undef _
    SPAN_N_ERROR,
} span_out_error_t;

static char * span_out_error_strings[] = {
#define _(sym,string) string,
    foreach_span_out_error
#undef _
};

typedef enum {
    SPAN_OUT_NEXT_ORIGINAL_INTERFACE_TX,
    SPAN_OUT_NEXT_MIRROR_INTERFACE_TX,
    SPAN_OUT_N_NEXT,
} span_out_next_t;

static uword
span_out_node_fn (vlib_main_t * vm,
        vlib_node_runtime_t * node,
        vlib_frame_t * frame)
{
    span_main_t *sm = &span_main;
    u32 n_left_from, * from, * to_next;
    span_out_next_t next_index;
    u32 n_span_packets = 0;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    while (n_left_from > 0) {
        u32 n_left_to_next;

        vlib_get_next_frame (vm, node, next_index,
                to_next, n_left_to_next);

        while (n_left_from >= 4 && n_left_to_next >= 4) {
            u32 bi0, bi1;
            u32 ci0, ci1;
            vlib_buffer_t * b0, * b1;
            vlib_buffer_t * c0, * c1;
            u32 next0 = SPAN_OUT_NEXT_ORIGINAL_INTERFACE_TX;
            u32 next1 = SPAN_OUT_NEXT_ORIGINAL_INTERFACE_TX;
            u32 cnext0 = SPAN_OUT_NEXT_MIRROR_INTERFACE_TX;
            u32 cnext1 = SPAN_OUT_NEXT_MIRROR_INTERFACE_TX;

            /* Prefetch next iteration. */
            {
                vlib_buffer_t * p2, * p3;

                p2 = vlib_get_buffer (vm, from[2]);
                p3 = vlib_get_buffer (vm, from[3]);

                vlib_prefetch_buffer_header (p2, LOAD);
                vlib_prefetch_buffer_header (p3, LOAD);

                CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
                CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
            }

            /* speculatively enqueue b0 to the current next frame */
            to_next[0] = bi0 = from[0];
            to_next[1] = bi1 = from[1];
            to_next += 2;
            n_left_to_next -= 2;

            b0 = vlib_get_buffer (vm, bi0);
            b1 = vlib_get_buffer (vm, bi1);
            u32 src_if0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
            u32 src_if1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
            uword *p0 = hash_get(sm->dst_sw_if_index_by_src, src_if0);
            uword *p1 = hash_get(sm->dst_sw_if_index_by_src, src_if1);

            // first packet
            if (PREDICT_TRUE(p0 != 0)) {
                c0 = span_duplicate_buffer (vm, b0, p0[0], 0);
                ci0 = vlib_get_buffer_index (vm, c0);

                to_next[0] = ci0;
                to_next += 2;
                n_left_to_next -= 2;

                if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                                  && (c0->flags & VLIB_BUFFER_IS_TRACED))) {
                    span_trace_t *t = vlib_add_trace (vm, node, c0, sizeof (*t));
                    t->src_sw_if_index = src_if0;
                    t->mirror_sw_if_index = p0[0];
                }

                /* verify speculative enqueue, maybe switch current next frame */
                vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                        to_next, n_left_to_next,
                        bi0, ci0, next0, cnext0);

                ++n_span_packets;
            } else {
                clib_warning("SPAN entry not found for this interface!");

                if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                                  && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
                    span_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->src_sw_if_index = src_if0;
                    t->mirror_sw_if_index = ~0;
                }

                /* verify speculative enqueue, maybe switch current next frame */
                vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                        to_next, n_left_to_next, bi0, next0);
            }

            // second packet
            if (PREDICT_TRUE(p1 != 0)) {
                c1 = span_duplicate_buffer (vm, b1, p1[0], 0);
                ASSERT(c1 != 0);
                ci1 = vlib_get_buffer_index (vm, c1);

                if (n_left_to_next == 0) {
                    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
                    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
                }

                to_next[1] = ci1;
                to_next += 2;
                n_left_to_next -= 2;

                if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                                  && (c1->flags & VLIB_BUFFER_IS_TRACED))) {
                    span_trace_t *t = vlib_add_trace (vm, node, c1, sizeof (*t));
                    t->src_sw_if_index = src_if1;
                    t->mirror_sw_if_index = p1[0];
                }

                /* verify speculative enqueue, maybe switch current next frame */
                vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                        to_next, n_left_to_next,
                        bi1, ci1, next1, cnext1);

                ++n_span_packets;
            } else {
                clib_warning("SPAN entry not found for this interface!");

                if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                                  && (b1->flags & VLIB_BUFFER_IS_TRACED))) {
                    span_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
                    t->src_sw_if_index = src_if1;
                    t->mirror_sw_if_index = ~0;
                }

                /* verify speculative enqueue, maybe switch current next frame */
                vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                        to_next, n_left_to_next, bi1, next1);
            }

            from += 2;
            n_left_from -= 2;
        }

        while (n_left_from > 0 && n_left_to_next > 0) {
            u32 bi0;
            u32 ci0;
            vlib_buffer_t * b0;
            vlib_buffer_t * c0;
            u32 next0 = SPAN_OUT_NEXT_ORIGINAL_INTERFACE_TX;
            u32 cnext0 = SPAN_OUT_NEXT_MIRROR_INTERFACE_TX;

            /* speculatively enqueue b0 to the current next frame */
            bi0 = from[0];
            to_next[0] = bi0;
            to_next += 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            u32 dst_if = vnet_buffer(b0)->sw_if_index[VLIB_TX];
            uword *p = hash_get(sm->dst_sw_if_index_by_src, dst_if);

            if (PREDICT_TRUE(p[0] != 0)) {
                if (PREDICT_FALSE(b0->flags & VLIB_NODE_FLAG_IS_SPAN)) {
                    clib_warning("Ignoring SPAN packet %u", b0);

                    /* verify speculative enqueue, maybe switch current next frame */
                    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                            to_next, n_left_to_next, bi0, next0);
                } else {
                    c0 = span_duplicate_buffer (vm, b0, p[0], 0);
                    ASSERT(c0 != 0);
                    ci0 = vlib_get_buffer_index (vm, c0);

                    if (n_left_to_next == 0) {
                        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
                        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
                    }

                    to_next[0] = ci0;
                    to_next++;
                    n_left_to_next--;

                    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                                      && (c0->flags & VLIB_BUFFER_IS_TRACED))) {
                        span_trace_t *t = vlib_add_trace (vm, node, c0, sizeof (*t));
                        t->src_sw_if_index = dst_if;
                        t->mirror_sw_if_index = p[0];
                    }

                    /* verify speculative enqueue, maybe switch current next frame */
                    vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                            to_next, n_left_to_next,
                            bi0, ci0, next0, cnext0);

                    ++n_span_packets;
                }
            } else {
                if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                                  && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
                    span_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->src_sw_if_index = dst_if;
                    t->mirror_sw_if_index = ~0;
                }

                /* verify speculative enqueue, maybe switch current next frame */
                vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                        to_next, n_left_to_next, bi0, next0);
            }

            from += 1;
            n_left_from -= 1;
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    vlib_node_increment_counter (vm, node->node_index, SPAN_ERROR_OUT_HITS,
            n_span_packets);

    return frame->n_vectors;
}

uword
span_out_register_node (vlib_main_t * vm,
        u32 src_sw_if_index,
        u32 dst_sw_if_index,
        u8 disable)
{
    span_main_t * sm = &span_main;
    vnet_sw_interface_t * sw = vnet_get_sw_interface (sm->vnet_main, src_sw_if_index);
    vnet_hw_interface_t * hw = vnet_get_hw_interface (sm->vnet_main, sw->hw_if_index);

    u32 span_node_index;
    char * node_name = (char *) format (0, "%v-span", hw->name);
    vlib_node_t *node_span = vlib_get_node_by_name (vm, (u8 *) node_name);

    if (!disable) {
        ASSERT (node_span == 0);

        clib_warning("span_node %s about to setup", node_name);

        // get/create IF-span-output node
        if (vec_len (sm->free_span_out_nodes) > 0) {
            u32 * index = vec_end (sm->free_span_out_nodes) - 1;
            span_node_index = index[0];
            _vec_len (sm->free_span_out_nodes) -= 1;

            vlib_node_rename (vm, span_node_index, "%v", node_name);
            clib_warning("free span node index %u renamed to %s", span_node_index, node_name);
        } else {
            vlib_node_registration_t r;

            memset (&r, 0, sizeof (r));

            r.type = VLIB_NODE_TYPE_INTERNAL;
            r.scalar_size = 0;
            r.vector_size = sizeof (u32);
            r.flags = VLIB_NODE_FLAG_IS_OUTPUT;
            r.name = node_name;
            r.n_errors = ARRAY_LEN (span_out_error_strings);
            r.error_strings = span_out_error_strings;
            r.function = span_out_node_fn;
            r.format_trace = format_span_out_trace;

            span_node_index = vlib_register_node (vm, &r);

            clib_warning("span node %s index %u created", node_name, span_node_index);
        }
        node_span = vlib_get_node (vm, span_node_index);
        ASSERT (node_span != 0);

        // connect IF-span-output node
        vnet_sw_interface_t * dst_sw = vnet_get_sw_interface (sm->vnet_main, dst_sw_if_index);
        vnet_hw_interface_t * dst_hw = vnet_get_hw_interface (sm->vnet_main, dst_sw->hw_if_index);

        // make SPAN node point IF-tx for original packets
        vlib_node_add_next_with_slot (vm, span_node_index,
                    hw->tx_node_index,
                    SPAN_OUT_NEXT_ORIGINAL_INTERFACE_TX);

        // make SPAN node point DEST-IF-tx for cloned packets
        vlib_node_add_next_with_slot (vm, span_node_index,
                    dst_hw->tx_node_index,
                    SPAN_OUT_NEXT_MIRROR_INTERFACE_TX);

        // make IF-output node to point to SPAN in stead of IF-tx
        vlib_node_add_next_with_slot (vm, hw->output_node_index,
                    node_span->index,
                    VNET_INTERFACE_OUTPUT_NEXT_TX);
    } else {
        ASSERT (node_span != 0);

        // point back IF-output to IF-tx
        vlib_node_add_next_with_slot (vm, hw->output_node_index,
                        hw->tx_node_index,
                        VNET_INTERFACE_OUTPUT_NEXT_TX);

        // point SPAN original & mirror to something "useless"
        vlib_node_add_named_next_with_slot (vm, node_span->index,
                  "ip4-drop",
                  SPAN_OUT_NEXT_ORIGINAL_INTERFACE_TX);

        vlib_node_add_named_next_with_slot (vm, node_span->index,
                  "error-drop",
                  SPAN_OUT_NEXT_MIRROR_INTERFACE_TX);

        u32 * index;
        vec_add2 (sm->free_span_out_nodes, index, 1);
        *index = node_span->index;

        vlib_node_rename (vm, node_span->index, "%v-free", node_name);
        clib_warning("node %u renamed to %s", node_span->index, node_span->name);
    }

    return 0;
}

#else
#include <vlib/vlib.h>

uword
span_out_register_node (vlib_main_t * vm,
        u32 src_sw_if_index,
        u32 dst_sw_if_index,
        u8 disable)
{
    clib_warning ("SPAN (out) not implemented (no DPDK)");
    return 0;
}

static clib_error_t *
span_out_init (vlib_main_t * vm)
{
    return 0;
}

VLIB_INIT_FUNCTION(span_out_init);

#endif /* DPDK */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
