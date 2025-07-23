// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

// Get packets from the IP unicast input feature arc set tenant and pass them to
// VCDP.

#include <vlib/vlib.h>
#include <vnet/fib/fib_table.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/feature/feature.h>
#include <sasc/sasc.h>
#include <sasc/service.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <sasc/sasc_funcs.h>
#include "ingress.h"

uword icmp_error_next_node_index;

enum sasc_input_next_e { SASC_INTERFACE_NEXT_LOOKUP, SASC_INTERFACE_NEXT_DROP, SASC_INTERFACE_N_NEXT };

typedef struct {
    u16 tenant_index;
} sasc_input_trace_t;

static inline u8 *
format_sasc_input_trace(u8 *s, va_list *args) {
    CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
    sasc_input_trace_t *t = va_arg(*args, sasc_input_trace_t *);

    s = format(s, "sasc-input: tenant idx %d", t->tenant_index);
    return s;
}

static inline u8 *
format_sasc_feature_arc_return_trace(u8 *s, va_list *args) {
    CLIB_UNUSED(vlib_main_t * vm) = va_arg(*args, vlib_main_t *);
    CLIB_UNUSED(vlib_node_t * node) = va_arg(*args, vlib_node_t *);
    s = format(s, "sasc-feature-arc-return: terminating SASC chain");
    return s;
}

// This node assumes that the tenant has been configured for the given FIB table
// before being enabled.
static inline uword
sasc_input_node_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, bool is_dpo, bool is_output) {

    // use VRF ID as tenant ID
    sasc_main_t *sasc = &sasc_main;
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
    u16 tenant_indicies[VLIB_FRAME_SIZE] = {0},
        *tenant_idx = tenant_indicies; // Used only for tracing
    u32 *from = vlib_frame_vector_args(frame);
    u32 n_left = frame->n_vectors;
    u16 next_indices[VLIB_FRAME_SIZE], *current_next;
    vlib_get_buffers(vm, from, bufs, n_left);
    b = bufs;
    current_next = next_indices;
    while (n_left) {
        int dir = is_output ? VLIB_TX : VLIB_RX;
        u32 sw_if_index = vnet_buffer(b[0])->sw_if_index[dir];
        tenant_idx[0] = sasc_tenant_idx_from_sw_if_index(sw_if_index, dir);
        if (tenant_idx[0] == UINT16_MAX) {
            vnet_feature_next_u16(current_next, b[0]);
            goto next;
        }
        sasc_tenant_t *tenant = sasc_tenant_at_index(sasc, tenant_idx[0]);
        sasc_buffer(b[0])->context_id = tenant->context_id;
        sasc_buffer(b[0])->tenant_index = tenant_idx[0];
        current_next[0] = SASC_INTERFACE_NEXT_LOOKUP;
    next:
        b += 1;
        current_next += 1;
        n_left -= 1;
        tenant_idx += 1;
    }
    vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);

    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
        int i;
        b = bufs;
        tenant_idx = tenant_indicies;
        for (i = 0; i < frame->n_vectors; i++) {
            if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
                sasc_input_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
                t->tenant_index = tenant_idx[0];
                b++;
                tenant_idx++;
            } else
                break;
        }
    }
    return frame->n_vectors;
}

VLIB_NODE_FN(sasc_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    return sasc_input_node_inline(vm, node, frame, false, false);
}
VLIB_NODE_FN(sasc_input_out_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    return sasc_input_node_inline(vm, node, frame, false, true);
}

VLIB_REGISTER_NODE(sasc_input_node) = {
    .name = "sasc-input",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_input_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_next_nodes = SASC_INTERFACE_N_NEXT,
    .next_nodes =
        {
            [SASC_INTERFACE_NEXT_LOOKUP] = "sasc-lookup-ip4",
            [SASC_INTERFACE_NEXT_DROP] = "error-drop",
        },
    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
};

VLIB_REGISTER_NODE(sasc_input_out_node) = {
    .name = "sasc-input-out",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_input_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .sibling_of = "sasc-input",
};

VNET_FEATURE_INIT(sasc_input_feat, static) = {
    .arc_name = "ip4-unicast",
    .node_name = "sasc-input",
    .runs_after = VNET_FEATURES("ip4-sv-reassembly-feature"),
};

VNET_FEATURE_INIT(sasc_input_out_feat, static) = {
    .arc_name = "ip4-output",
    .node_name = "sasc-input-out",
    .runs_before = VNET_FEATURES("interface-output"),
};

VNET_FEATURE_INIT(sasc_feature_arc_return_feat, static) = {
    .arc_name = "ip4-output",
    .node_name = "sasc-feature-arc-return",
};

static inline uword
sasc_feature_arc_return_node_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    u32 *from = vlib_frame_vector_args(frame);
    u32 n_left = frame->n_vectors;
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
    u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

    vlib_get_buffers(vm, from, bufs, n_left);
    b = bufs;

    while (n_left > 0) {
        ip4_header_t *ip = sasc_get_ip4_header(b[0]);
        vnet_feature_next_u16(next, b[0]);
        if (next[0] > node->n_next_nodes) {
            sasc_log_err("next index %d invalid %U", next[0], format_ip4_header, ip, sizeof(ip4_header_t));
            next[0] = SASC_INTERFACE_NEXT_DROP;
        }
        /* Reset error in case it's been set elsewhere in the chain. */
        b[0]->error = 0;

        b++;
        next++;
        n_left--;
    }

    vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
        int i;
        b = bufs;
        for (i = 0; i < frame->n_vectors; i++) {
            if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
                vlib_add_trace(vm, node, b[0], 0);
                b++;
            } else
                break;
        }
    }
    return frame->n_vectors;
}

VLIB_NODE_FN(sasc_feature_arc_return_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    return sasc_feature_arc_return_node_inline(vm, node, frame);
}

VLIB_REGISTER_NODE(sasc_feature_arc_return_node) = {
    .name = "sasc-feature-arc-return",
    .vector_size = sizeof(u32),
    .type = VLIB_NODE_TYPE_INTERNAL,
    .format_trace = format_sasc_feature_arc_return_trace,
    .sibling_of = "sasc-input",

};

SASC_SERVICE_DEFINE(output) = {
    .node_name = "sasc-feature-arc-return",
};
