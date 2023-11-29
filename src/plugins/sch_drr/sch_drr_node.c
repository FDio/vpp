#include "sch_drr.h"

static u8* format_sch_drr_enqueue_trace (u8 *s, va_list *args) {
    CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t*);
    CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t*);
    trace_en_t *tr = va_arg (*args, trace_en_t*);
    s = format (s, "packet enqueued, queue: %d, queue position: %d", tr->queue_i, tr->pos);
    return s;
}

static u8* format_sch_drr_dequeue_trace (u8 *s, va_list *args) {
    CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t*);
    CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t*);
    trace_de_t *tr = va_arg (*args, trace_de_t*);
    s = format (s, "packet dequeued, queue: %d, frame position: %d, packets left in this queue: %d", tr->queue_i, tr->pos, tr->rem_pkt);
    return s;
}

static void enqueue_frame(vlib_main_t *vm, vlib_node_runtime_t *node, sch_drr_buffer_t *drr_b, vlib_buffer_t **b, u32 *from, int n_pkt) {
    for (u32 i = 0; i < n_pkt; i++) {
        u8 class = vnet_buffer2(b[0])->qos.bits;
        ring_buffer_push(&(drr_b->queue_map[class]), from[i]);
        drr_b->class_bitmap = clib_bitmap_set(drr_b->class_bitmap, class, 1);
        if (PREDICT_FALSE(b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
            trace_en_t *tr;
            tr = vlib_add_trace(vm, node, b[0], sizeof(*tr));
            tr->queue_i = class;
            tr->pos = drr_b->queue_map[class].count-1;
        }
        b++;
    }
}

static int select_next_frame(vlib_main_t *vm, vlib_node_runtime_t *node, sch_drr_buffer_t *drr_b, u32* i_arr, vlib_buffer_t* bufs[VLIB_FRAME_SIZE] , u32 n_pkt) {
    int i = 0;
    static int j = -1;
    bool first_call = true;
    if (!clib_bitmap_is_zero(drr_b->class_bitmap)) {
        j = clib_bitmap_next_set(drr_b->class_bitmap, j+1);
        if (j == ~0)
            j = clib_bitmap_next_set(drr_b->class_bitmap, 0);
    }
    while (i < n_pkt && !clib_bitmap_is_zero(drr_b->class_bitmap)) {
        if (drr_b->queue_map[j].count) {
            if (first_call) {
                drr_b->deficit_counter[j] += drr_b->quantum_size;
                first_call = false;
            }
            vlib_buffer_t* temp_bufs = vlib_get_buffer(vm, ring_buffer_front(&drr_b->queue_map[j]));
            if (temp_bufs->current_length <= drr_b->deficit_counter[j]) {
                i_arr[i++] = ring_buffer_pop(&drr_b->queue_map[j]);
                drr_b->deficit_counter[j] -= temp_bufs->current_length;
                if (PREDICT_FALSE(vlib_get_buffer(vm, i_arr[i-1])->flags & VLIB_BUFFER_IS_TRACED)) {
                    trace_de_t *tr;
                    tr = vlib_add_trace(vm, node, vlib_get_buffer(vm, i_arr[i-1]), sizeof(*tr));
                    tr->queue_i = j;
                    tr->pos = i-1;
                    tr->rem_pkt = drr_b->queue_map[j].count;
                }
            }
            else {
                j = clib_bitmap_next_set(drr_b->class_bitmap, j+1);
                if (j == ~0)
                    j = clib_bitmap_next_set(drr_b->class_bitmap, 0);
                first_call = true;
            }
        }
        else {
            drr_b->class_bitmap = clib_bitmap_set(drr_b->class_bitmap, j, 0);
            j = clib_bitmap_next_set(drr_b->class_bitmap, j+1);
            if (j == ~0)
                j = clib_bitmap_next_set(drr_b->class_bitmap, 0);
            first_call = true;
        }
    }
    return i;
}

static uword sch_drr_enqueue_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {

    sch_drr_buffer_t *drr_b = vec_elt_at_index (drr_buffer, vm->thread_index);
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
    u32 n_pkt, *from;

    from = vlib_frame_vector_args(frame);
    n_pkt = frame->n_vectors;
    b = bufs;

    vlib_get_buffers(vm, from, bufs, n_pkt);
    enqueue_frame(vm, node, drr_b, b, from, n_pkt);

    return n_pkt;
}

static uword sch_drr_dequeue_node_fn(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {

    sch_drr_buffer_t *drr_b = vec_elt_at_index (drr_buffer, vm->thread_index);
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
    u32 i_arr[VLIB_FRAME_SIZE];
    u16 next[VLIB_FRAME_SIZE];

    int n_pkt = select_next_frame(vm, node, drr_b, i_arr, bufs, VLIB_FRAME_SIZE);
    vlib_get_buffers(vm, i_arr, bufs, n_pkt);

    for (int i = 0; i < n_pkt; i++)
        vnet_feature_next_u16 (&next[i], bufs[i]);

    vlib_buffer_enqueue_to_next (vm, node, i_arr, next, n_pkt);

    return n_pkt;
}

VLIB_REGISTER_NODE(sch_drr_enqueue_node) = {
    .function = sch_drr_enqueue_node_fn,
    .name = "sch_drr_enqueue_node",
    .vector_size = sizeof(32),
    .type = VLIB_NODE_TYPE_INTERNAL,
    .sibling_of = "sch_drr_dequeue_node",
    .format_trace = format_sch_drr_enqueue_trace,
};

VLIB_REGISTER_NODE(sch_drr_dequeue_node) = {
    .function = sch_drr_dequeue_node_fn,
    .name = "sch_drr_dequeue_node",
    .vector_size = sizeof(32),
    .type = VLIB_NODE_TYPE_INPUT,
    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
    .format_trace = format_sch_drr_dequeue_trace
};

VNET_FEATURE_INIT(sch_drr_enqueue_feat, static) = {
    .arc_name = "interface-output",
    .node_name = "sch_drr_enqueue_node",
};