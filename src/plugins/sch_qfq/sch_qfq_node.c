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
 * limitations under the License.*/

#include "sch_qfq.h"

static u8* format_sch_qfq_enqueue_trace (u8 *s, va_list *args) {
    CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t*);
    CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t*);
    trace_en_t *tr = va_arg (*args, trace_en_t*);
    s = format (s, "packet enqueued, queue: %d, queue position: %d, start time: %d, finish time: %d",
                tr->queue_i, tr->pos, tr->start_time, tr->finish_time);
    return s;
}

static u8* format_sch_qfq_dequeue_trace (u8 *s, va_list *args) {
    CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t*);
    CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t*);
    trace_de_t *tr = va_arg (*args, trace_de_t*);
    s = format (s, "packet dequeued, queue: %d, frame position: %d, packets left in this queue: %d, real finish time: %d",
                tr->queue_i, tr->pos, tr->rem_pkt, tr->virtual_time);
    return s;
}

int compute_group_state(vlib_main_t* vm, sch_qfq_buffer_t *qfq_b, int g) {
    int s = (qfq_b->group_map[g].approx_start_time <= qfq_b->virtual_time) ? ER : IR ;
    int n = clib_bitmap_next_set(qfq_b->state_bitmaps[ER], g+1);
    s += (n != ~0 && qfq_b->group_map[n].approx_finish_time < qfq_b->group_map[g].approx_finish_time) ? 1 : 0;
    return s;
}

void insert_bucket(vlib_main_t* vm, sch_qfq_buffer_t *qfq_b, int g, int class) {

    if (qfq_b->flow_map[class].next_flow == NULL || qfq_b->flow_map[class].next_flow == &qfq_b->flow_map[class])
        clib_bitmap_set(qfq_b->group_map[g].bucket_bitmap, qfq_b->flow_map[class].bucket, 0);

    int s = ((qfq_b->flow_map[class].start_time & ~(qfq_b->group_map[g].slot_size - 1)) - qfq_b->group_map[g].approx_start_time) >> g;
    s = s%MAX_BUCKET;
    qfq_b->flow_map[class].bucket = s;

    if (qfq_b->group_map[g].bucket_list[s] != NULL) {
        flow_t* head = qfq_b->group_map[g].bucket_list[s];
        while (head->next_flow != NULL) {
            head = head->next_flow;
        }
        head->next_flow = &qfq_b->flow_map[class];
        head->next_flow->prev_flow = head;
    }
    else {
        qfq_b->group_map[g].bucket_list[s] = &qfq_b->flow_map[class];
        qfq_b->flow_map[class].prev_flow = NULL;
    }
    clib_bitmap_set(qfq_b->group_map[g].bucket_bitmap, s, 1);
    qfq_b->flow_map[class].next_flow = NULL;
}

void move_groups(clib_bitmap_t* mask, clib_bitmap_t* src, clib_bitmap_t* dest) {
    clib_bitmap_and(mask, src);
    clib_bitmap_or(dest, mask);
    clib_bitmap_andnot(src, mask);
}

void make_eligible(vlib_main_t* vm, sch_qfq_buffer_t* qfq_b, unsigned long long old_time) {
    unsigned long long v = qfq_b->virtual_time ^ old_time;
    int i = log2(v & -v) + 1;
    clib_bitmap_zero(qfq_b->tool_bitmap);
    qfq_b->tool_bitmap = clib_bitmap_set(qfq_b->tool_bitmap, i+1, 1);
    *qfq_b->tool_bitmap -= 1;
    move_groups(qfq_b->tool_bitmap, qfq_b->state_bitmaps[IR], qfq_b->state_bitmaps[ER]);
    move_groups(qfq_b->tool_bitmap, qfq_b->state_bitmaps[IB], qfq_b->state_bitmaps[EB]);
}

void unblock_groups(vlib_main_t* vm, sch_qfq_buffer_t* qfq_b, int group_i, unsigned long long old_finish_time) {
    int x = clib_bitmap_first_set(qfq_b->state_bitmaps[ER]);
    if (x == ~0 || qfq_b->group_map[x].approx_finish_time > old_finish_time) {
        clib_bitmap_zero(qfq_b->tool_bitmap);
        qfq_b->tool_bitmap = clib_bitmap_set(qfq_b->tool_bitmap, group_i, 1);
        *qfq_b->tool_bitmap -= 1;
        move_groups(qfq_b->tool_bitmap, qfq_b->state_bitmaps[EB], qfq_b->state_bitmaps[ER]);
        move_groups(qfq_b->tool_bitmap, qfq_b->state_bitmaps[IB], qfq_b->state_bitmaps[IR]);
    }
}

static void enqueue_pkt(vlib_main_t *vm, sch_qfq_buffer_t *qfq_b, vlib_buffer_t *b, u32 *from, u8 class, u32 pkt_index, bool force_insert) {
    // append the pkt to its flow buffer, if the flow is already active, the work is done
    ring_buffer_push(&qfq_b->flow_map[class].pkt_queue, pkt_index);
    if (qfq_b->flow_map[class].pkt_queue.count > 1 && !force_insert)
        return;

    u8 g = qfq_b->flow_map[class].group_index;
    qfq_b->flow_map[class].id = class;
    // the flow was idle so we need to compute its state and update its group
    qfq_b->flow_map[class].start_time = max(qfq_b->flow_map[class].finish_time, qfq_b->virtual_time);
    qfq_b->flow_map[class].finish_time = qfq_b->flow_map[class].start_time + b->current_length;

    if (clib_bitmap_first_set(qfq_b->group_map[g].bucket_bitmap) == ~0 || qfq_b->flow_map[class].start_time < qfq_b->group_map[g].approx_start_time) {
        qfq_b->state_bitmaps[IR] = clib_bitmap_set(qfq_b->state_bitmaps[IR], g, 0);
        qfq_b->state_bitmaps[IB] = clib_bitmap_set(qfq_b->state_bitmaps[IB], g, 0);
        qfq_b->group_map[g].approx_start_time = qfq_b->flow_map[class].start_time & ~(qfq_b->group_map[g].slot_size - 1);
        qfq_b->group_map[g].approx_finish_time = qfq_b->group_map[g].approx_start_time + 2*qfq_b->group_map[g].slot_size;
    }

    insert_bucket(vm, qfq_b, g, class);

    if (clib_bitmap_is_zero(qfq_b->state_bitmaps[ER]) && qfq_b->virtual_time < qfq_b->group_map[g].approx_start_time)
        qfq_b->virtual_time = qfq_b->group_map[g].approx_start_time;
    int state = compute_group_state(vm, qfq_b, g);

    qfq_b->state_bitmaps[state] = clib_bitmap_set(qfq_b->state_bitmaps[state], g, 1);
}

static void update_groups_flows(vlib_main_t *vm, sch_qfq_buffer_t *qfq_b, int group_i, group_t* group ,flow_t* flow, int pkt_i) {
    flow->start_time = flow->finish_time;
    int pkt_wait = ring_buffer_front(&flow->pkt_queue);

    if (pkt_wait != ~0) {
        vlib_buffer_t* b = vlib_get_buffer(vm, pkt_wait);
        flow->finish_time = flow->start_time + b->current_length;
        insert_bucket(vm, qfq_b, group_i, vnet_buffer2(b)->qos.bits);
    }
    else
        flow->next_flow = NULL;

    unsigned long long old_time = qfq_b->virtual_time;
    qfq_b->virtual_time += vlib_get_buffer(vm, pkt_i)->current_length;

    unsigned long long old_finish_time = group->approx_finish_time;
    int state;
    if (clib_bitmap_is_zero(group->bucket_bitmap))
        state = IDLE;
    else {
        flow_t* next_flow = group->bucket_list[clib_bitmap_first_set(group->bucket_bitmap)];
        group->approx_start_time = next_flow->start_time & ~(group->slot_size - 1);
        group->approx_finish_time = group->approx_start_time + 2 * group->slot_size;
        state = compute_group_state(vm, qfq_b, group_i);
    }
    if (state == IDLE || group->approx_finish_time > old_finish_time) {
        qfq_b->state_bitmaps[ER] = clib_bitmap_set(qfq_b->state_bitmaps[ER], group_i, 0);
        qfq_b->state_bitmaps[state] = clib_bitmap_set(qfq_b->state_bitmaps[state], group_i, 1);
        unblock_groups(vm, qfq_b, group_i, old_finish_time);
    }

    clib_bitmap_zero(qfq_b->tool_bitmap);
    clib_bitmap_and(qfq_b->tool_bitmap, qfq_b->state_bitmaps[IB]);
    clib_bitmap_and(qfq_b->tool_bitmap, qfq_b->state_bitmaps[IR]);

    if (!clib_bitmap_is_zero(qfq_b->tool_bitmap)) {
        if (clib_bitmap_is_zero(qfq_b->state_bitmaps[ER]))
            qfq_b->virtual_time = max(qfq_b->virtual_time, qfq_b->group_map[clib_bitmap_first_set(qfq_b->tool_bitmap)].approx_start_time);
        make_eligible(vm, qfq_b, old_time);
    }
}

static void enqueue_frame(vlib_main_t *vm, vlib_node_runtime_t *node, sch_qfq_buffer_t *qfq_b, vlib_buffer_t **b, u32 *from, int n_pkt) {
    // loop trough the vector to update individually each packet
    // need to take care of tracking Lmax and updating the flow and groups state
    for (u32 i = 0; i < n_pkt; i++) {
        u8 class = vnet_buffer2(b[0])->qos.bits;
        bool force_insert = false;
        if (b[0]->current_length > qfq_b->flow_map[class].lmax) {
            u16 group_i = max_log2(b[0]->current_length);
            flow_t* flow = &qfq_b->flow_map[class];
            if (flow->pkt_queue.count > 0 && group_i != flow->group_index) {
                if (flow->prev_flow != NULL) {
                    flow->prev_flow->next_flow = flow->next_flow;
                    if (flow->next_flow != NULL) {
                        flow->next_flow->prev_flow = flow->prev_flow;
                    }
                    force_insert = true;
                    flow->next_flow = NULL;
                    flow->prev_flow = NULL;
                }
                else {
                    group_t* group = &qfq_b->group_map[flow->group_index];
                    group->bucket_list[flow->bucket] = flow->next_flow;
                    if (group->bucket_list[flow->bucket] == NULL) {
                        group->bucket_bitmap = clib_bitmap_set(group->bucket_bitmap, flow->bucket, 0);
                        unsigned long long old_finish_time = group->approx_finish_time;
                        int state;
                        if (clib_bitmap_is_zero(group->bucket_bitmap))
                            state = IDLE;
                        else {
                            flow_t* next_flow = group->bucket_list[clib_bitmap_first_set(group->bucket_bitmap)];
                            group->approx_start_time = next_flow->start_time & ~(group->slot_size - 1);
                            group->approx_finish_time = group->approx_start_time + 2 * group->slot_size;
                            state = compute_group_state(vm, qfq_b, group_i);
                        }
                        if (state == IDLE || group->approx_finish_time > old_finish_time) {
                            qfq_b->state_bitmaps[ER] = clib_bitmap_set(qfq_b->state_bitmaps[ER], group_i, 0);
                            qfq_b->state_bitmaps[state] = clib_bitmap_set(qfq_b->state_bitmaps[state], group_i, 1);
                            unblock_groups(vm, qfq_b, group_i, old_finish_time);
                        }
                    }
                    else
                        group->bucket_list[flow->bucket]->prev_flow = NULL;

                    force_insert = true;
                    flow->next_flow = NULL;
                    flow->prev_flow = NULL;
                }
            }
            flow->group_index = group_i;
            flow->lmax = b[0]->current_length;
        }
        enqueue_pkt(vm, qfq_b, b[0], from, class, from[i], force_insert);

        b++;
    }
}


static int qfq_select_next_frame(vlib_main_t *vm, vlib_node_runtime_t *node, sch_qfq_buffer_t *qfq_b, u32* i_arr, u32 n_pkt) {
    int i = 0;
    while (!clib_bitmap_is_zero(qfq_b->state_bitmaps[ER]) && i < n_pkt) {
        int group_i = clib_bitmap_first_set(qfq_b->state_bitmaps[ER]);
        group_t* group = &qfq_b->group_map[group_i];
        int bucket_i = clib_bitmap_first_set(group->bucket_bitmap);
        if (bucket_i == ~0) {
            clib_bitmap_set(qfq_b->state_bitmaps[ER], group_i, 0);
            continue;
        }
        flow_t* flow = group->bucket_list[bucket_i];
        if (flow->next_flow == NULL || flow->next_flow == flow) {
            if (flow->next_flow == NULL || flow->pkt_queue.count <= 1) {
                group->bucket_bitmap = clib_bitmap_set(group->bucket_bitmap, flow->bucket, 0);
                group->bucket_list[flow->bucket] = NULL;
            }
        }
        else
            group->bucket_list[flow->bucket] = flow->next_flow;

        u32 pkt_i = ring_buffer_pop(&flow->pkt_queue);
        update_groups_flows(vm, qfq_b, group_i, group, flow, pkt_i);
        i_arr[i++] = pkt_i;
    }
    return i;
}

static uword sch_qfq_enqueue_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {

    sch_qfq_buffer_t *qfq_b = vec_elt_at_index (qfq_buffer, vm->thread_index);
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
    u32 n_pkt, *from;

    from = vlib_frame_vector_args(frame);
    n_pkt = frame->n_vectors;
    b = bufs;

    vlib_get_buffers(vm, from, bufs, n_pkt);
    enqueue_frame(vm, node, qfq_b, b, from, n_pkt);

    return n_pkt;
}

static uword sch_qfq_dequeue_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {

    sch_qfq_buffer_t *qfq_b = vec_elt_at_index (qfq_buffer, vm->thread_index);
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
    u32 i_arr[VLIB_FRAME_SIZE];
    u16 next[VLIB_FRAME_SIZE];

    int n_pkt = qfq_select_next_frame(vm, node, qfq_b, i_arr, VLIB_FRAME_SIZE);
    vlib_get_buffers(vm, i_arr, bufs, n_pkt);

    for (int i = 0; i < n_pkt; i++)
        vnet_feature_next_u16 (&next[i], bufs[i]);

    vlib_buffer_enqueue_to_next (vm, node, i_arr, next, n_pkt);
    return n_pkt;
}

VLIB_REGISTER_NODE(sch_qfq_enqueue_node) = {
    .function = sch_qfq_enqueue_node_fn,
    .name = "sch_qfq_enqueue_node",
    .vector_size = sizeof(32),
    .type = VLIB_NODE_TYPE_INTERNAL,
    .sibling_of = "sch_qfq_dequeue_node",
    .format_trace = format_sch_qfq_enqueue_trace,
};

VLIB_REGISTER_NODE(sch_qfq_dequeue_node) = {
    .function = sch_qfq_dequeue_node_fn,
    .name = "sch_qfq_dequeue_node",
    .vector_size = sizeof(32),
    .type = VLIB_NODE_TYPE_INPUT,
    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
    .format_trace = format_sch_qfq_dequeue_trace,
};

VNET_FEATURE_INIT(sch_qfq_enqueue_feat, static) = {
    .arc_name = "interface-output",
    .node_name = "sch_qfq_enqueue_node",
};