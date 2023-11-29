/* Copyright (c) 2023 Cisco and/or its affiliates.
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
 * limitations under the License. */
#include "sch_rr.h"

static u8* format_sch_rr_enqueue_trace (u8 *s, va_list *args) {
    CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t*);
    CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t*);
    trace_en_t *tr = va_arg (*args, trace_en_t*);
    s = format (s, "packet enqueued, queue: %d, queue position: %d", tr->queue_i, tr->pos);
    return s;
}

static u8* format_sch_rr_dequeue_trace (u8 *s, va_list *args) {
    CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t*);
    CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t*);
    trace_de_t *tr = va_arg (*args, trace_de_t*);
    s = format (s, "packet dequeued, queue: %d, frame position: %d, packets left in this queue: %d", tr->queue_i, tr->pos, tr->rem_pkt);
    return s;
}

/*
add the buffer index of each packet contained in the frame at the end of the queue corresponding to the packet class
set as 1 the bit corresponding to the class in the class bitmap
*/

static void enqueue_frame(vlib_main_t *vm, vlib_node_runtime_t *node, sch_rr_buffer_t *rr_b, vlib_buffer_t **b, u32 *from, int n_pkt) {
    for (u32 i = 0; i < n_pkt; i++) {
        u8 class = vnet_buffer2(b[0])->qos.bits;
        ring_buffer_push(&(rr_b->queue_map[class]), from[i]);
        rr_b->class_bitmap = clib_bitmap_set(rr_b->class_bitmap, class, 1);
        if (PREDICT_FALSE(b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
            trace_en_t *tr;
            tr = vlib_add_trace(vm, node, b[0], sizeof(*tr));
            tr->queue_i = class;
            tr->pos = rr_b->queue_map[class].count-1;
        }
        b++;
    }
}

/*
loop until the frame is full or all queues are empty
if a qeuue is empty, set at 0 its corresponding bit in the class bitmap
*/
static int select_next_frame(vlib_main_t *vm, vlib_node_runtime_t *node, sch_rr_buffer_t *rr_b, u32* i_arr, u32 n_pkt) {
    int i = 0;
    static int j = -1;
    while (i < n_pkt && !clib_bitmap_is_zero(rr_b->class_bitmap)) {
        j = clib_bitmap_next_set(rr_b->class_bitmap, j+1);
        if (j == ~0)
            j = clib_bitmap_next_set(rr_b->class_bitmap, 0);
        if (rr_b->queue_map[j].count) {
            i_arr[i++] = ring_buffer_pop(&rr_b->queue_map[j]);
            if (PREDICT_FALSE(vlib_get_buffer(vm, i_arr[i-1])->flags & VLIB_BUFFER_IS_TRACED)) {
                trace_de_t *tr;
                tr = vlib_add_trace(vm, node, vlib_get_buffer(vm, i_arr[i-1]), sizeof(*tr));
                tr->queue_i = j;
                tr->pos = i-1;
                tr->rem_pkt = rr_b->queue_map[j].count;
            }
        }
        else
            rr_b->class_bitmap = clib_bitmap_set(rr_b->class_bitmap, j, 0);
    }
    return i;
}

static uword sch_rr_enqueue_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {

    sch_rr_buffer_t *rr_b = vec_elt_at_index (rr_buffer, vm->thread_index);
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
    u32 n_pkt, *from;

    from = vlib_frame_vector_args(frame);
    n_pkt = frame->n_vectors;
    b = bufs;

    vlib_get_buffers(vm, from, bufs, n_pkt);
    enqueue_frame(vm, node, rr_b, b, from, n_pkt);
    return n_pkt;
}

static uword sch_rr_dequeue_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {

    sch_rr_buffer_t *rr_b = vec_elt_at_index (rr_buffer, vm->thread_index);
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
    u32 i_arr[VLIB_FRAME_SIZE];
    u16 next[VLIB_FRAME_SIZE];

    int n_pkt = select_next_frame(vm, node, rr_b, i_arr, VLIB_FRAME_SIZE);
    vlib_get_buffers(vm, i_arr, bufs, n_pkt);

    for (int i = 0; i < n_pkt; i++)
       vnet_feature_next_u16 (&next[i], bufs[i]);

    vlib_buffer_enqueue_to_next (vm, node, i_arr, next, n_pkt);
    return n_pkt;
}

VLIB_REGISTER_NODE(sch_rr_enqueue_node) = {
    .function = sch_rr_enqueue_node_fn,
    .name = "sch_rr_enqueue_node",
    .vector_size = sizeof(32),
    .type = VLIB_NODE_TYPE_INTERNAL,
    .sibling_of = "sch_rr_dequeue_node",
    .format_trace = format_sch_rr_enqueue_trace,
};

VLIB_REGISTER_NODE(sch_rr_dequeue_node) = {
    .function = sch_rr_dequeue_node_fn,
    .name = "sch_rr_dequeue_node",
    .vector_size = sizeof(32),
    .type = VLIB_NODE_TYPE_INPUT,
    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
    .format_trace = format_sch_rr_dequeue_trace,
};

VNET_FEATURE_INIT(sch_rr_enqueue_feat, static) = {
    .arc_name = "interface-output",
    .node_name = "sch_rr_enqueue_node",
};