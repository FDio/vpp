// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <sasc/sasc.h>
#include <sasc/service.h>
#include <sasc/sasc_funcs.h>
#include <sasc/lookup/lookup_inlines.h>
#include <sasc/sasc.api_enum.h>
#include "format.h"
#include "session.h"
#include "counter.h"

typedef struct {
    u32 next_index;
} sasc_create_trace_t;

static u8 *
format_sasc_create_trace(u8 *s, va_list *args) {
    vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
    vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
    sasc_create_trace_t *t = va_arg(*args, sasc_create_trace_t *);

    s = format(s, "sasc-create: next-index %u", t->next_index);
    return s;
}

void
sasc_set_session_service_chain(sasc_tenant_t *tenant, sasc_session_t *session, u8 proto) {
    sasc_main_t *sasc = &sasc_main;
    session->service_chain[SASC_FLOW_FORWARD] = sasc_get_effective_service_chain_index(
        sasc, tenant->service_chains[SASC_SERVICE_CHAIN_FORWARD], sasc_proto_to_group(proto));
    session->service_chain[SASC_FLOW_REVERSE] = sasc_get_effective_service_chain_index(
        sasc, tenant->service_chains[SASC_SERVICE_CHAIN_REVERSE], sasc_proto_to_group(proto));
}

//
// Terminal service.
// Recycle back to fast-path lookup
//
static_always_inline uword
sasc_create_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, bool is_ip6) {
    sasc_main_t *sasc = &sasc_main;
    u32 thread_index = vlib_get_thread_index();
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
    u32 *from;
    u32 n_left = frame->n_vectors;
    u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
    sasc_session_key_t keys[VLIB_FRAME_SIZE], *k = keys;
    u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
    int rv;
    sasc_session_t *session;
    u16 error_next = 0;

    // Session created successfully: pass packet back to sasc-lookup
    // Session already exists / collision: pass packet back to sasc-lookup
    // Cannot create key, or table is full: pass packet to drop
    from = vlib_frame_vector_args(frame);
    vlib_get_buffers(vm, from, b, n_left);

    while (n_left) {
        u64 value = 0;
        u32 error = 0;
        u32 flow_index = ~0;

        u16 tenant_idx = sasc_buffer(b[0])->tenant_index;
        bool is_icmp_error = false;
        rv = sasc_calc_key(b[0], sasc_buffer(b[0])->context_id, k, h, is_ip6, SASC_LOOKUP_MODE_DEFAULT, &is_icmp_error);

        if (rv != 0) {
            error = SASC_CREATE_ERROR_NO_KEY;
            goto next;
        }

        // Lookup first; do not assume existence for ICMP errors
        int lookup_rv = sasc_lookup_with_hash(h[0], k, &value);
        if (lookup_rv == 0) {
            flow_index = value & (~(u32)0);
            u32 session_index = sasc_session_from_flow_index(flow_index);
            session = sasc_session_at_index(sasc, session_index);
        } else if (!is_icmp_error) {
            sasc_log_debug("Creating session for: %U", format_sasc_session_key, k);
            sasc_session_key_t reverse_key;
            sasc_session_generate_reverse_key(k, &reverse_key);
            session = sasc_create_session(tenant_idx, k, &reverse_key, false, &flow_index);
        } else {
            session = 0;
        }

        // If non-ICMP and no session, fail fast
        if (!session) {
            error = SASC_CREATE_ERROR_NO_KEY;
            error_next = SASC_LOOKUP_NEXT_BYPASS;
            clib_warning("Failed to create or find session");
            goto next;
        }

        // Compute service chain id (guaranteed set by one of the branches)
        u32 direction = sasc_direction_from_flow_index(flow_index);
        u32 chain_id = session->service_chain[direction];
        sasc_buffer_init_chain(SASC_INGRESS_NODE_LOOKUP_IP4, k->proto, b[0], chain_id);

        if (is_icmp_error) {
            error = SASC_CREATE_ERROR_ICMP_ERROR;
            error_next = SASC_LOOKUP_NEXT_ICMP_ERROR;
        }

        session->pkts[direction]++;
        session->bytes[direction] += sasc_get_l3_length(vm, b[0]);

        vlib_increment_simple_counter(&sasc->counters[SASC_COUNTER_CREATED], thread_index, tenant_idx, 1);
        b[0]->flow_id = flow_index;

    next:
        if (error == 0) {
            sasc_next(b[0], next);
        } else {
            b[0]->error = node->errors[error];
            next[0] = error_next;
        }

        next += 1;
        h += 1;
        k += 1;
        b += 1;
        n_left -= 1;
    }
    vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

    // vlib_node_increment_counter(vm, node->node_index, SASC_BYPASS_ERROR_BYPASS, n_left);
    n_left = frame->n_vectors;
    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
        int i;
        vlib_get_buffers(vm, from, bufs, n_left);
        b = bufs;
        for (i = 0; i < n_left; i++) {
            if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
                sasc_create_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
                t->next_index = nexts[i];
                b++;
            } else
                break;
        }
    }
    return frame->n_vectors;
}

VLIB_NODE_FN(sasc_create_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) { return sasc_create_inline(vm, node, frame, false); }

VLIB_NODE_FN(sasc_create_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) { return sasc_create_inline(vm, node, frame, true); }

VLIB_REGISTER_NODE(sasc_create_ip4_node) = {
    .name = "sasc-create",
    .sibling_of = "sasc-lookup-ip4",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_create_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = SASC_CREATE_N_ERROR,
    .error_counters = sasc_create_error_counters,
};
VLIB_REGISTER_NODE(sasc_create_ip6_node) = {
    .name = "sasc-create-ip6",
    .sibling_of = "sasc-create",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_create_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = SASC_CREATE_N_ERROR,
    .error_counters = sasc_create_error_counters,
};

SASC_SERVICE_DEFINE(sasc_create) = {
    .node_name = "sasc-create",
};
