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

#include <portmirroring/portmirroring.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

vlib_node_registration_t pm_out_hit_node;

typedef struct {
    u32 next_index;
} pm_out_hit_trace_t;

/* packet trace format function */
static u8 *
format_pm_out_hit_trace(u8 * s, va_list * args)
{
    CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
    pm_out_hit_trace_t * t = va_arg(*args, pm_out_hit_trace_t *);

    s = format(s, "PM_OUT_HIT: next index %d", t->next_index);

    return s;
}

#define foreach_pm_out_hit_error                    \
    _(HITS, "PM out packets processed")                 \
    _(NO_COLLECTOR, "No collector configured")

typedef enum {
#define _(sym, str) PM_OUT_HIT_ERROR_ ## sym,
    foreach_pm_out_hit_error
#undef _
    PM_OUT_HIT_N_ERROR,
} pm_out_hit_error_t;

static char * pm_out_hit_error_strings[] = {
#define _(sym, string) string,
    foreach_pm_out_hit_error
#undef _
};

typedef enum {
    PM_OUT_HIT_NEXT_IF_OUT,
    PM_OUT_HIT_N_NEXT,
} pm_out_hit_next_t;

static uword
pm_out_hit_node_fn(vlib_main_t * vm,
    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    u32 n_left_from, * from, * to_next;
    pm_out_hit_next_t next_index;
    vlib_frame_t * dup_frame = 0;
    u32 * to_int_next = 0;
    pm_main_t * pm = &pm_main;

    from = vlib_frame_vector_args(frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    if (pm->sw_if_index == ~0) {
        vlib_node_increment_counter (vm, pm_out_hit_node.index,
                PM_OUT_HIT_ERROR_NO_COLLECTOR,
                n_left_from);
    } else {
        /* The intercept frame... */
        dup_frame = vlib_get_frame_to_node(vm, pm->interface_output_node_index);
        to_int_next = vlib_frame_vector_args(dup_frame);
    }

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 bi0;
            vlib_buffer_t * b0;
            vlib_buffer_t * c0;
            u32 next0 = PM_OUT_HIT_NEXT_IF_OUT;

            /* speculatively enqueue b0 to the current next frame */
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer(vm, bi0);
            if (PREDICT_TRUE(to_int_next != 0))
            {
                /* Make an intercept copy */
                c0 = vlib_buffer_copy(vm, b0);

                vnet_buffer (c0)->sw_if_index[VLIB_TX] = pm->sw_if_index;

                to_int_next[0] = vlib_get_buffer_index(vm, c0);
                to_int_next++;
            }

            if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
                pm_out_hit_trace_t * t = vlib_add_trace(vm, node, b0, sizeof(*t));
                t->next_index = next0;
            }
            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x1(vm, node, next_index,
                to_next, n_left_to_next, bi0, next0);
        }

        vlib_put_next_frame(vm, node, next_index, n_left_to_next);
    }

    if (dup_frame)
    {
        dup_frame->n_vectors = frame->n_vectors;
        vlib_put_frame_to_node(vm, pm->interface_output_node_index, dup_frame);
    }

    vlib_node_increment_counter(vm, pm_out_hit_node.index,
        PM_OUT_HIT_ERROR_HITS, frame->n_vectors);
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(pm_out_hit_node) = {
    .function = pm_out_hit_node_fn,
    .name = "pm-out-hit",
    .vector_size = sizeof(u32),
    .format_trace = format_pm_out_hit_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN(pm_out_hit_error_strings),
    .error_strings = pm_out_hit_error_strings,

    .n_next_nodes = PM_OUT_HIT_N_NEXT,

    .next_nodes = {
        [PM_OUT_HIT_NEXT_IF_OUT] = "interface-output",
    }
};
