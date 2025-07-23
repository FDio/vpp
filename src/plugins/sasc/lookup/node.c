// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <sasc/sasc_funcs.h>
#include <sasc/session.h>
#include "lookup_inlines.h"
#include <sasc/sasc.api_enum.h>
#include <stdbool.h>
#include <sasc/service.h>

typedef struct {
    u32 next_index;
    u32 sw_if_index;
    u64 hash;
    u32 flow_id;
    u32 error;
    u32 remote_worker;
    bool hit;
    u32 session_idx;
    u32 service_bitmap;
    sasc_session_key_t k4;
} sasc_lookup_trace_t;

typedef struct {
    u32 next_index;
    u32 flow_id;
} sasc_handoff_trace_t;

int
sasc_lookup(sasc_session_key_t *k, u64 *v) {
    u64 h = clib_bihash_hash_40_8((clib_bihash_kv_40_8_t *)(k));
    return sasc_lookup_with_hash(h, k, v);
}

static_always_inline uword
sasc_lookup_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, bool is_ip6,
                   enum sasc_lookup_mode_e lookup_mode) {
    sasc_main_t *sasc = &sasc_main;
    u32 thread_index = vm->thread_index;
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
    sasc_session_t *session;
    u32 session_index;
    u32 *bi, *from = vlib_frame_vector_args(frame);
    u32 n_left = frame->n_vectors;
    u32 to_local[VLIB_FRAME_SIZE], n_local = 0;
    u32 to_remote[VLIB_FRAME_SIZE], n_remote = 0;
    u16 thread_indices[VLIB_FRAME_SIZE];
    u16 local_next_indices[VLIB_FRAME_SIZE];
    sasc_session_key_t keys[VLIB_FRAME_SIZE], *k = keys;
    u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
    f64 now = vlib_time_now(vm);
    bool hits[VLIB_FRAME_SIZE], *hit = hits;
    u32 session_indices[VLIB_FRAME_SIZE], *si = session_indices;
    u32 service_bitmaps[VLIB_FRAME_SIZE], *sb = service_bitmaps;
    bool is_icmp_error[VLIB_FRAME_SIZE], *is_icmp_error_p = is_icmp_error;
    vlib_get_buffers(vm, from, bufs, n_left);
    b = bufs;

    // Calculate key and hash
    while (n_left) {
        sasc_calc_key(b[0], sasc_buffer(b[0])->context_id, k, h, is_ip6, lookup_mode, is_icmp_error_p);
        is_icmp_error_p += 1;
        h += 1;
        k += 1;
        b += 1;
        n_left -= 1;
    }

    h = hashes;
    k = keys;
    b = bufs;
    u16 *current_next = local_next_indices;
    bi = from;
    n_left = frame->n_vectors;
    is_icmp_error_p = is_icmp_error;

    while (n_left) {
    again:
        b[0]->error = 0;
        u64 value;
        // clib_warning("Looking up: %U", format_sasc_session_key, k);
        if (sasc_lookup_with_hash(h[0], k, &value)) {
            // clib_warning("Missed lookup: %U", format_sasc_session_key, k);
            b[0]->error = node->errors[SASC_LOOKUP_ERROR_MISS];
            sasc_tenant_t *tenant = sasc_tenant_at_index(sasc, sasc_buffer(b[0])->tenant_index);
            if (!tenant) {
                sasc_log_err("Tenant not found for buffer %p", b[0]);
                goto next;
            }
            sasc_service_chain_type_t chain_type = SASC_SERVICE_CHAIN_MISS;

            // Miss-chain. Continue down the existing miss-chain or start a new one.
            if (lookup_mode == SASC_LOOKUP_MODE_DEFAULT) {
                u32 effective_index = sasc_get_effective_service_chain_index(sasc, tenant->service_chains[chain_type],
                                                                             sasc_proto_to_group(k->proto));
                sasc_buffer_init_chain(SASC_INGRESS_NODE_LOOKUP_IP4, k->proto, b[0], effective_index);
            }

            sasc_next(b[0], current_next);
            // clib_warning("Setting next-node %d", *current_next);
            to_local[n_local] = bi[0];
            n_local++;
            current_next++;
            b[0]->flow_id = ~0; // No session
            hit[0] = false;
            // sasc_log_debug("Miss lookup: %U", format_sasc_session_key, k);
            goto next;
        }

        hit[0] = true;
        // Figure out if this is local or remote thread
        u32 flow_thread_index = sasc_thread_index_from_lookup(value);
        if (flow_thread_index == thread_index) {
            /* known flow which belongs to this thread */
            u32 flow_index = value & (~(u32)0);
            to_local[n_local] = bi[0];

            session_index = sasc_session_from_flow_index(flow_index);
            si[0] = session_index;
            b[0]->flow_id = flow_index;

            session = sasc_session_at_index(sasc, session_index);

            if (sasc_session_is_expired(session, now)) {
                sasc_log_warn("Expired session: %u %U (%.02f)", session_index, format_sasc_session_key, k,
                              sasc_session_remaining_time(session, now));
                sasc_session_remove(sasc, session, thread_index, session_index);
                goto again;
            }
            u32 chain_id = session->service_chain[sasc_direction_from_flow_index(flow_index)];
            sasc_buffer_init_chain(SASC_INGRESS_NODE_LOOKUP_IP4, k->proto, b[0], chain_id);
            /* Propagate PCAP sampling from session to per-plugin buffer flags */
            if (session->flags & SASC_SESSION_F_PCAP_SAMPLE)
                sasc_buffer(b[0])->flags |= SASC_BUFFER_F_PCAP_TRACE;
            /* The tenant of the buffer is the tenant of the session */
            sasc_buffer(b[0])->tenant_index = session->tenant_idx;
            if (is_icmp_error_p[0]) {
                current_next[0] = SASC_LOOKUP_NEXT_ICMP_ERROR;
            } else {
                sasc_next(b[0], current_next);
            }

            current_next += 1;
            n_local++;
            session->pkts[sasc_direction_from_flow_index(flow_index)]++;
            session->bytes[sasc_direction_from_flow_index(flow_index)] += sasc_get_l3_length(vm, b[0]);
            session->last_heard = now;

        } else {
            /* known flow which belongs to remote thread */
            to_remote[n_remote] = bi[0];
            thread_indices[n_remote] = flow_thread_index;
            n_remote++;
        }

        b[0]->flow_id = value & (~(u32)0);

    next:
        b += 1;
        n_left -= 1;
        h += 1;
        k += 1;
        bi += 1;
        hit += 1;
        si += 1;
        sb += 1;
        is_icmp_error_p += 1;
    }

    /* handover buffers to remote node */
#if 0
  if (n_remote) {
    u32 n_remote_enq;
    n_remote_enq =
      vlib_buffer_enqueue_to_thread(vm, node, sasc->frame_queue_index, to_remote, thread_indices, n_remote, 1);
    // vlib_node_increment_counter(vm, node->node_index, SASC_LOOKUP_ERROR_REMOTE, n_remote_enq);
    // vlib_node_increment_counter(vm, node->node_index, SASC_LOOKUP_ERROR_CON_DROP, n_remote - n_remote_enq);
  }
#endif

    /* enqueue local */
    if (n_local) {
        vlib_buffer_enqueue_to_next(vm, node, to_local, local_next_indices, n_local);
    }

    // clib_warning("Tracing %d buffers", frame->n_vectors);
    int i;
    b = bufs;
    bi = from;
    h = hashes;
    si = session_indices;
    hit = hits;
    sb = service_bitmaps;
    u32 *in_local = to_local;
    u32 *in_remote = to_remote;

    for (i = 0; i < frame->n_vectors; i++) {
        if (!(b[0]->flags & VLIB_BUFFER_IS_TRACED)) {
            if (PREDICT_FALSE(vlib_trace_buffer(vm, node, local_next_indices[i], b[0], 0))) {
                b[0]->flags |= VLIB_BUFFER_IS_TRACED;
            }
        }

        if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
            clib_warning("Adding trace for buffer %p", b[0]);
            sasc_lookup_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
            t->sw_if_index = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
            t->flow_id = b[0]->flow_id;
            t->hash = h[0];
            t->hit = hit[0];
            t->session_idx = si[0];
            t->service_bitmap = sb[0];
            if (bi[0] == in_local[0]) {
                t->next_index = local_next_indices[(in_local++) - to_local];
            } else {
                t->next_index = ~0;
                t->remote_worker = thread_indices[(in_remote++) - to_remote];
            }
            if (b[0]->error) {
                t->error = b[0]->error;
            } else {
                t->error = 0;
            }
            clib_memcpy(&t->k4, &keys[i], sizeof(t->k4));
            bi++;
            b++;
            h++;
            hit++;
            si++;
            sb++;
        } else
            break;
    }
    return frame->n_vectors;
}

VLIB_NODE_FN(sasc_lookup_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    return sasc_lookup_inline(vm, node, frame, false, SASC_LOOKUP_MODE_DEFAULT);
}

VLIB_NODE_FN(sasc_lookup_ip4_4tuple_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    return sasc_lookup_inline(vm, node, frame, false, SASC_LOOKUP_MODE_4TUPLE);
}

VLIB_NODE_FN(sasc_lookup_ip4_3tuple_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    return sasc_lookup_inline(vm, node, frame, false, SASC_LOOKUP_MODE_3TUPLE);
}

VLIB_NODE_FN(sasc_lookup_ip4_1tuple_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    return sasc_lookup_inline(vm, node, frame, false, SASC_LOOKUP_MODE_1TUPLE);
}

VLIB_NODE_FN(sasc_lookup_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    return sasc_lookup_inline(vm, node, frame, true, false);
}

/*
 * This node is used to handoff packets to the correct thread.
 */
#if 0
VLIB_NODE_FN(sasc_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  sasc_main_t *sasc = &sasc_main;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from = vlib_frame_vector_args(frame);
  u32 n_left = frame->n_vectors;
  u16 next_indices[VLIB_FRAME_SIZE], *current_next;
  f64 now = vlib_time_now(vm);


  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;
  current_next = next_indices;

  while (n_left) {
    u32 flow_index = b[0]->flow_id;
    u32 session_index = sasc_session_from_flow_index(flow_index);
    sasc_session_t *session = sasc_session_at_index_check(sasc, session_index);
    if (!session) {
      // Session has been deleted underneath us
      sasc_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      b[0]->error = node->errors[VCDP_HANDOFF_ERROR_NO_SESSION];
      goto next;
    }

    // Check if session has expired. If so send it back to the lookup node to be created.
    if (sasc_session_is_expired(session, now)) {
      sasc_log_debug("Forwarding against expired handoff session, deleting and recreating %d", session_index);
      sasc_session_remove(sasc, session, thread_index, session_index);

      // TODO: NOT YET IMPLEMENTED. DROP FOR NOW
      sasc_buffer(b[0])->service_bitmap = VCDP_SERVICE_MASK(drop);
      b[0]->error = node->errors[VCDP_HANDOFF_ERROR_NO_SESSION];
      goto next;
    }

    session->last_heard = now;
    u32 pbmp = sasc_service_next(session->service_chain[sasc_direction_from_flow_index(flow_index)], 0);
    sasc_buffer(b[0])->service_bitmap = pbmp;
  next:
    sasc_next(b[0], current_next);
    current_next += 1;
    b += 1;
    n_left -= 1;
  }
  vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    current_next = next_indices;
    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        sasc_handoff_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        t->flow_id = b[0]->flow_id;
        t->next_index = current_next[0];
        b++;
        current_next++;
      } else
        break;
    }
  }
  return frame->n_vectors;
}
#endif

/*
 * next_index is ~0 if the packet was enqueued to the remote node
 */
static u8 *
format_sasc_lookup_trace(u8 *s, va_list *args) {
    vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
    vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
    sasc_lookup_trace_t *t = va_arg(*args, sasc_lookup_trace_t *);
    u32 indent = format_get_indent(s);

    if (t->next_index == ~0)
        s = format(s, "handoff: %u", t->remote_worker);
    else {
        if (t->hit)
            s = format(s, "found session, index: %d", t->session_idx);
        else
            s = format(s, "missed session:");
    }
    s = format(s, "\n%Urx ifindex %d, hash 0x%x flow-id %u", format_white_space, indent, t->sw_if_index, t->hash,
               t->flow_id);
    //  s = format(s, "\n%Ukey: %U", format_white_space, indent, format_sasc_session_key, &t->k4);
    // s = format(s, "\n%Uservice chain: %U", format_white_space, indent, format_sasc_bitmap,
    // t->service_bitmap);
    s = format(s, "\n%Uerror: %u", format_white_space, indent, t->error);
    return s;
}

#if 0
static u8 *
format_sasc_handoff_trace(u8 *s, va_list *args)
{
  vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
  vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
  sasc_handoff_trace_t *t = va_arg(*args, sasc_handoff_trace_t *);

  s = format(s,
             "sasc-handoff: next index %d "
             "flow-id %u (session %u, %s)",
             t->next_index, t->flow_id, t->flow_id >> 1, t->flow_id & 0x1 ? "reverse" : "forward");
  return s;
}
#endif

VLIB_REGISTER_NODE(sasc_lookup_ip4_node) = {
    .name = "sasc-lookup-ip4",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_lookup_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = SASC_LOOKUP_N_ERROR,
    .error_counters = sasc_lookup_error_counters,
    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
    .n_next_nodes = SASC_LOOKUP_N_NEXT,
    .next_nodes =
        {
            [SASC_LOOKUP_NEXT_BYPASS] = "error-drop",
            [SASC_LOOKUP_NEXT_ICMP_ERROR] = "sasc-icmp-error",
        },

};

VLIB_REGISTER_NODE(sasc_lookup_ip4_4tuple_node) = {
    .name = "sasc-lookup-ip4-4tuple",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_lookup_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = SASC_LOOKUP_N_ERROR,
    .error_counters = sasc_lookup_error_counters,
};
SASC_SERVICE_DEFINE(lookup_ip4_4tuple) = {
    .node_name = "sasc-lookup-ip4-4tuple",
};

VLIB_REGISTER_NODE(sasc_lookup_ip4_3tuple_node) = {
    .name = "sasc-lookup-ip4-3tuple",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_lookup_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = SASC_LOOKUP_N_ERROR,
    .error_counters = sasc_lookup_error_counters,
};
SASC_SERVICE_DEFINE(lookup_ip4_3tuple) = {
    .node_name = "sasc-lookup-ip4-3tuple",
};

VLIB_REGISTER_NODE(sasc_lookup_ip4_1tuple_node) = {
    .name = "sasc-lookup-ip4-1tuple",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_lookup_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = SASC_LOOKUP_N_ERROR,
    .error_counters = sasc_lookup_error_counters,
};
SASC_SERVICE_DEFINE(lookup_ip4_1tuple) = {
    .node_name = "sasc-lookup-ip4-1tuple",
};

VLIB_REGISTER_NODE(sasc_lookup_ip6_node) = {
    .name = "sasc-lookup-ip6",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_lookup_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = SASC_LOOKUP_N_ERROR,
    .error_counters = sasc_lookup_error_counters,
};
#if 0
VLIB_REGISTER_NODE(sasc_handoff_node) = {
  .name = "sasc-handoff",
  .vector_size = sizeof(u32),
  .format_trace = format_sasc_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = SASC_HANDOFF_N_ERROR,
  .error_counters = sasc_handoff_error_counters,
  .sibling_of = "sasc-lookup-ip4",
};
#endif
