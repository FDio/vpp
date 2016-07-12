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

vlib_node_registration_t span_node;

typedef struct {
    u32 next_index;
    u32 mirror_sw_if_index;
} span_trace_t;

/* packet trace format function */
static u8 * format_span_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    span_trace_t * t = va_arg (*args, span_trace_t *);

    s = format (s, "SPAN: mirrored to sw_if_index %d (next_index: %d)",
            t->mirror_sw_if_index, t->next_index);

    return s;
}

#define foreach_span_error                      \
_(HITS, "SPAN packets processed")

typedef enum {
#define _(sym,str) SPAN_ERROR_##sym,
    foreach_span_error
#undef _
    SPAN_N_ERROR,
} span_error_t;

static char * span_error_strings[] = {
#define _(sym,string) string,
    foreach_span_error
#undef _
};

typedef enum {
    SPAN_NEXT_ETHERNET,
    SPAN_NEXT_INTERFACE_OUTPUT,
    SPAN_N_NEXT,
} span_next_t;

static uword
span_node_fn (vlib_main_t * vm,
        vlib_node_runtime_t * node,
        vlib_frame_t * frame)
{
    span_main_t *sm = &span_main;
    u32 n_left_from, * from, * to_next;
    span_next_t next_index;
    //vlib_node_t *output_node = vlib_get_node_by_name(vm, (u8 *)"interface-output");
    unsigned socket_id = rte_socket_id();
    vlib_buffer_main_t * bm = vm->buffer_main;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    // vlib_buffer_free_list_t * fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
    // TODO: dual loop

    while (n_left_from > 0) {
        u32 n_left_to_next;

        vlib_get_next_frame (vm, node, next_index,
                to_next, n_left_to_next);

        clib_warning("n_left_from: %d", n_left_from);

        while (n_left_from > 0 && n_left_to_next > 0) {
            u32 bi0;
            u32 ci0;
            vlib_buffer_t * b0;
            vlib_buffer_t * c0;
            struct rte_mbuf * mb0 = 0, * clone0 = 0;
            u32 next0 = SPAN_NEXT_ETHERNET;
            u32 cnext0 = SPAN_NEXT_INTERFACE_OUTPUT;
            clib_warning("n_left_to_next: %d", n_left_to_next);

            /* speculatively enqueue b0 to the current next frame */
            bi0 = from[0];
            to_next[0] = bi0;
            to_next += 1;
            n_left_to_next -= 1;

            clib_warning("bi0: %d", bi0);
            b0 = vlib_get_buffer (vm, bi0);
            uword *p = hash_get(sm->dst_sw_if_index_by_src,
                    vnet_buffer(b0)->sw_if_index[VLIB_RX]);
            //orig_mb0 = rte_mbuf_from_vlib_buffer(b0);
            //clib_warning("orig pkt_len: %d, data_len: %d, data_off: %d", 
            //        orig_mb0->pkt_len, orig_mb0->data_len, orig_mb0->data_off);

            if (PREDICT_TRUE(p != 0)) {
                mb0 = rte_mbuf_from_vlib_buffer (b0);

                /*i16 delta0 = vlib_buffer_length_in_chain (vm, orig_b0)
                      - (i16) mb0->pkt_len;

                u16 new_data_len0 = (u16)((i16) mb0->data_len + delta0);
                u16 new_pkt_len0  = (u16)((i16) mb0->pkt_len + delta0);

                mb0->data_len = new_data_len0;
                mb0->pkt_len = new_pkt_len0;
                mb0->data_off = (u16)(RTE_PKTMBUF_HEADROOM + b0->current_data);*/
                clib_warning("mb0 pkt_len: %d, data_len: %d, data_off: %d", 
                        mb0->pkt_len, mb0->data_len, mb0->data_off);

                clone0 = rte_pktmbuf_clone
                    (mb0, bm->pktmbuf_pools[socket_id]);

                c0 = vlib_buffer_from_rte_mbuf (clone0);
                //clib_memcpy(c0->data + b0->current_data, b0->data + b0->current_data, b0->current_length);

                c0->current_data = b0->current_data;
                c0->current_length = b0->current_length;
                c0->flags = b0->flags;

                vnet_buffer(c0)->sw_if_index[VLIB_TX] = p[0];
                vnet_buffer(c0)->sw_if_index[VLIB_RX] = vnet_buffer(b0)->sw_if_index[VLIB_RX];
                vnet_buffer(c0)->l2 = vnet_buffer(b0)->l2;
                clib_warning("clone len: %d, current: %d", vlib_buffer_length_in_chain(vm, c0), c0->current_length);


                //vlib_buffer_init_for_free_list (c0, fl);

                ci0 = vlib_get_buffer_index (vm, c0);

                if (n_left_to_next == 0) {
                    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
                    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
                }

                to_next[0] = ci0;
                to_next++;
                n_left_to_next--;

                if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                                  && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
                    span_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->mirror_sw_if_index = p[0];
                    t->next_index = next0;
                }

                /* verify speculative enqueue, maybe switch current next frame */
                vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                        to_next, n_left_to_next,
                        bi0, ci0, next0, cnext0);
            } else {
                if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                                  && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
                    span_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->mirror_sw_if_index = ~0;
                    t->next_index = next0;
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

    vlib_node_increment_counter (vm, span_node.index, SPAN_ERROR_HITS,
            frame->n_vectors);

    return frame->n_vectors;
}

VLIB_REGISTER_NODE (span_node) = {
    .function = span_node_fn,
    .name = "span",
    .vector_size = sizeof (u32),
    .format_trace = format_span_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN(span_error_strings),
    .error_strings = span_error_strings,

    .n_next_nodes = SPAN_N_NEXT,

    /* edit / add dispositions here */
    .next_nodes = {
          [SPAN_NEXT_ETHERNET] = "ethernet-input",
          [SPAN_NEXT_INTERFACE_OUTPUT] = "interface-output",
    },
};

VLIB_NODE_FUNCTION_MULTIARCH (span_node, span_node_fn)

#else
#include <vlib/vlib.h>

static uword
span_node_fn (vlib_main_t * vm,
        vlib_node_runtime_t * node,
        vlib_frame_t * frame)
{
    clib_warning ("SPAN not implemented (no DPDK)");
    return 0;
}

VLIB_REGISTER_NODE (span_node) = {
    .vector_size = sizeof (u32),
    .function = span_node_fn,
    .name = "span",
};

static clib_error_t *
span_init (vlib_main_t * vm)
{
    return 0;
}

VLIB_INIT_FUNCTION(span_init);

#endif /* DPDK */
