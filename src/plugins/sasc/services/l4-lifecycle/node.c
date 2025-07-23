// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <sasc/sasc.h>
#include <sasc/service.h>
#include <sasc/sasc_funcs.h>

typedef struct {
    u32 flow_id;
    u8 new_state;
} sasc_l4_lifecycle_trace_t;

static u8 *
format_sasc_l4_lifecycle_trace(u8 *s, va_list *args) {
    vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
    vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
    sasc_l4_lifecycle_trace_t *t = va_arg(*args, sasc_l4_lifecycle_trace_t *);

    s = format(s, "sasc-l4-lifecycle: flow-id %u (session %u, %s) new_state: %U", t->flow_id, t->flow_id >> 1,
               t->flow_id & 0x1 ? "reverse" : "forward", format_sasc_session_state, t->new_state);
    return s;
}

VLIB_NODE_FN(sasc_l4_lifecycle_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
    sasc_main_t *sasc = &sasc_main;

    u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
    u32 *from = vlib_frame_vector_args(frame);
    u32 n_left = frame->n_vectors;

    vlib_get_buffers(vm, from, bufs, n_left);

    while (n_left) {
        u32 session_idx = sasc_session_from_flow_index(b[0]->flow_id);
        sasc_session_t *session = sasc_session_at_index(sasc, session_idx);
        sasc_session_slow_path_t *sp = vec_elt_at_index(sasc->sp_sessions, session_idx);
        u8 direction = sasc_direction_from_flow_index(b[0]->flow_id);
        if (session->state == SASC_SESSION_STATE_FSOL && direction == SASC_FLOW_REVERSE) {
            /*Establish the session*/
            sasc_log_debug("Establishing session [%u] %U", session_idx, format_sasc_session_key, &sp->forward_key);
            session->state = SASC_SESSION_STATE_ESTABLISHED;
        }
        sasc_next(b[0], to_next);

        b++;
        to_next++;
        n_left--;
    }

    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
        n_left = frame->n_vectors;
        b = bufs;
        for (int i = 0; i < n_left; i++) {
            if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
                sasc_l4_lifecycle_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
                u32 session_idx = sasc_session_from_flow_index(b[0]->flow_id);
                sasc_session_t *session = sasc_session_at_index(sasc, session_idx);
                u16 state = session->state;
                t->flow_id = b[0]->flow_id;
                t->new_state = state;
                b++;
            } else
                break;
        }
    }
    vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(sasc_l4_lifecycle_node) = {
    .name = "sasc-l4-lifecycle",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_l4_lifecycle_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
};

SASC_SERVICE_DEFINE(l4_lifecycle) = {
    .node_name = "sasc-l4-lifecycle",
};