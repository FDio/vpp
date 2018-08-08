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

#define _GNU_SOURCE
#define __USE_GNU
#include <dlfcn.h>

#include "portmirroring.h"

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

/* for vlib_get_plugin_symbol() */
#include <vlib/unix/plugin.h>

#include <flowtable/flowtable.h>
#include <flowtable/flowdata.h>
#include "portmirroring.h"

vlib_node_registration_t pm_hit_node;

typedef struct {
    u32 next_index;
} pm_in_hit_trace_t;

/* packet trace format function */
static u8 *
format_pm_in_hit_trace(u8 * s, va_list * args)
{
    CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
    pm_in_hit_trace_t * t = va_arg(*args, pm_in_hit_trace_t *);

    s = format(s, "PM_IN_HIT: next index %d", t->next_index);

    return s;
}

vlib_node_registration_t pm_hit_node;

#define foreach_pm_in_hit_error                     \
    _(HITS, "PM in packets processed")              \
    _(NO_INTF_OUT, "No out interface configured")   \
    _(OFFLOADED, "offloaded packets")               \
    _(TIMEOUT_MSG_SENT, "Timeout messages sent")

typedef enum {
#define _(sym, str) PM_IN_HIT_ERROR_ ## sym,
    foreach_pm_in_hit_error
#undef _
    PM_IN_HIT_N_ERROR,
} pm_in_hit_error_t;

static char * pm_in_hit_error_strings[] = {
#define _(sym, string) string,
    foreach_pm_in_hit_error
#undef _
};

static inline int
flowtable_expiration_get(flowtable_main_t * fm, u8 * buffer, u32 buffer_len)
{
    int n_msg;
    timeout_msg_t * msg;

    if (PREDICT_FALSE(fm->first_msg_index == ~0))
        return 0;

    n_msg = 0;
    while (buffer_len > sizeof(*msg))
    {
        msg = &fm->msg_pool[fm->first_msg_index];
        if (msg->flags == 0)
            break;

        fm->first_msg_index = (fm->first_msg_index + 1) & TIMEOUT_MSG_MASK;
        n_msg++;

        clib_memcpy(buffer, msg, sizeof(*msg));
        buffer += sizeof(*msg);
        buffer_len -= sizeof(*msg);
    }

    return n_msg;
}

static uword
pm_hit_node_fn(vlib_main_t * vm,
    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    u32 n_left_from, * from, * to_next;
    u32 next_index;
    vlib_frame_t * dup_frame = 0;
    u32 * to_int_next = 0;
    u32 n_left_to_next = 0;
    pm_main_t * pm = &pm_main;
    int offloaded_pkts = 0;

    from = vlib_frame_vector_args(frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    if (pm->sw_if_index == ~0)
    {
        vlib_node_increment_counter(vm, pm_hit_node.index,
            PM_IN_HIT_ERROR_NO_INTF_OUT,
            n_left_from);
    } else {
        /* The intercept frame... */
        dup_frame = vlib_get_frame_to_node(vm, pm->interface_output_node_index);
        to_int_next = vlib_frame_vector_args(dup_frame);
    }

    while (n_left_from > 0)
    {
        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        /* dual loop */
        while (n_left_from >= 4 && n_left_to_next >= 2)
        {
            u32 bi0, bi1;
            vlib_buffer_t * b0, * b1;
            vlib_buffer_t * c0, * c1;
            flow_data_t flow_data0 = {.data.offloaded = 0};
            flow_data_t flow_data1 = {.data.offloaded = 0};
            u32 next0 = pm->next_node_index;
            u32 next1 = pm->next_node_index;

            /* prefetch next frames */
            {
                vlib_buffer_t * p2, * p3;

                p2 = vlib_get_buffer(vm, from[2]);
                p3 = vlib_get_buffer(vm, from[3]);

                vlib_prefetch_buffer_header(p2, LOAD);
                vlib_prefetch_buffer_header(p3, LOAD);
            }

            /* speculatively enqueue b0 to the current next frame */
            bi0 = from[0];
            bi1 = from[1];
            to_next[0] = bi0;
            to_next[1] = bi1;
            from += 2;
            to_next += 2;
            n_left_from -= 2;
            n_left_to_next -= 2;

            b0 = vlib_get_buffer(vm, bi0);
            b1 = vlib_get_buffer(vm, bi1);

            clib_memcpy(&flow_data0, vnet_plugin_buffer(b0), sizeof(flow_data0));
            clib_memcpy(&flow_data1, vnet_plugin_buffer(b1), sizeof(flow_data1));

            /* Make copies */
            if (PREDICT_TRUE(to_int_next != 0) && flow_data1.data.offloaded == 0)
            {
                c0 = vlib_buffer_copy(vm, b0);
                dup_frame->n_vectors++;

                if (pm->sw_if_index != ~0)
                    vnet_buffer(c0)->sw_if_index[VLIB_TX] = pm->sw_if_index;

                to_int_next[0] = vlib_get_buffer_index(vm, c0);
                to_int_next += 1;
            }
            if (PREDICT_TRUE(to_int_next != 0) && flow_data0.data.offloaded == 0)
            {
                c1 = vlib_buffer_copy(vm, b0);
                dup_frame->n_vectors++;

                if (pm->sw_if_index != ~0)
                    vnet_buffer(c1)->sw_if_index[VLIB_TX] = pm->sw_if_index;

                to_int_next[0] = vlib_get_buffer_index(vm, c1);
                to_int_next += 1;
            }
            offloaded_pkts += flow_data0.data.offloaded + flow_data1.data.offloaded;

            if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
                pm_in_hit_trace_t * t = vlib_add_trace(vm, node, b0, sizeof(*t));
                t->next_index = next0;
            }
            if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                && (b1->flags & VLIB_BUFFER_IS_TRACED)))
            {
                pm_in_hit_trace_t * t = vlib_add_trace(vm, node, b1, sizeof(*t));
                t->next_index = next1;
            }

            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x2(vm, node, next_index, to_next,
                n_left_to_next, bi0, bi1, next0, next1);
        }

        /* single loop */
        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 bi0;
            vlib_buffer_t * b0;
            vlib_buffer_t * c0;
            flow_data_t flow_data = {.data.offloaded = 0};
            u32 next0 = pm->next_node_index;

            /* speculatively enqueue b0 to the current next frame */
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer(vm, bi0);
            clib_memcpy(&flow_data, vnet_plugin_buffer(b0), sizeof(flow_data));

            /* Make a copy */
            if (PREDICT_TRUE(to_int_next != 0) && flow_data.data.offloaded == 0)
            {
                c0 = vlib_buffer_copy(vm, b0);
                dup_frame->n_vectors++;

                if (pm->sw_if_index != ~0)
                    vnet_buffer(c0)->sw_if_index[VLIB_TX] = pm->sw_if_index;

                to_int_next[0] = vlib_get_buffer_index(vm, c0);
                to_int_next++;
            }
            offloaded_pkts += flow_data.data.offloaded;

            if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
                pm_in_hit_trace_t * t = vlib_add_trace(vm, node, b0, sizeof(*t));
                t->next_index = next0;
            }

            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                to_next, n_left_to_next, bi0, next0);
        }

        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }


    if (n_left_to_next > 0)
    {
        int i;
        vlib_buffer_t * eb;
        u32 ebi;

        if (vlib_buffer_alloc(vm, &ebi, 1) == 1)
        {
            eb = vlib_get_buffer(vm, ebi);
            eb->current_length = sizeof(expiration_msg_hdr_t) + 1280;
            expiration_msg_hdr_t * hdr = (expiration_msg_hdr_t *) (eb->data + eb->current_data);
            memset(hdr, 0, sizeof(*hdr));
            hdr->eth_hdr.type = clib_host_to_net_u16(0x0101);

            flowtable_main_t * ftm = vlib_get_plugin_symbol("flowtable_plugin.so", "flowtable_main");
            ASSERT(ftm != NULL);

            i = flowtable_expiration_get(ftm,
                    eb->data + eb->current_data + sizeof(expiration_msg_hdr_t),
                    eb->current_length - sizeof(expiration_msg_hdr_t));
            if (i > 0)
            {
                hdr->number = i;
                vlib_node_increment_counter(vm, pm_hit_node.index,
                    PM_IN_HIT_ERROR_TIMEOUT_MSG_SENT, i);
                vnet_buffer(eb)->sw_if_index[VLIB_TX] = pm->sw_if_index;
                to_int_next[0] = vlib_get_buffer_index(vm, eb);
                to_int_next++;
                dup_frame->n_vectors++;
            } else {
                vlib_buffer_free(vm, &ebi, 1);
            }
        }
    }

    if (dup_frame)
    {
        if (dup_frame->n_vectors)
            vlib_put_frame_to_node(vm, pm->interface_output_node_index, dup_frame);
        else /* all the packets were offloaded */
            vlib_frame_free(vm, node, dup_frame);
    }

    vlib_node_increment_counter(vm, pm_hit_node.index,
        PM_IN_HIT_ERROR_HITS, frame->n_vectors);

    vlib_node_increment_counter(vm, pm_hit_node.index,
            PM_IN_HIT_ERROR_OFFLOADED, offloaded_pkts);
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(pm_hit_node) = {
    .function = pm_hit_node_fn,
    .name = "pm-hit",
    .vector_size = sizeof(u32),
    .format_trace = format_pm_in_hit_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN(pm_in_hit_error_strings),
    .error_strings = pm_in_hit_error_strings,

    .n_next_nodes = PM_IN_HIT_N_NEXT,
    .next_nodes = {
        [PM_IN_HIT_NEXT_ERROR] = "error-drop",
        [PM_IN_HIT_NEXT_ETHERNET_INPUT] = "ethernet-input",
        [PM_IN_HIT_NEXT_L2_LEARN] = "l2-learn",
    }
};
