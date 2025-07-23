// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

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

enum sasc_icmp_error_next_e {
    // SASC_ICMP_ERROR_NEXT_BYPASS,
    SASC_ICMP_ERROR_NEXT_DROP,
    SASC_ICMP_ERROR_N_NEXT
};

typedef struct {
    u32 next_index;
} sasc_icmp_error_trace_t;

static u8 *
format_sasc_icmp_error_trace(u8 *s, va_list *args) {
    vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
    vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
    sasc_icmp_error_trace_t *t = va_arg(*args, sasc_icmp_error_trace_t *);

    s = format(s, "sasc-icmp-error: next-index %u", t->next_index);
    return s;
}

//
// ICMP error service.
// Handle ICMP errors.
//
static_always_inline uword
sasc_icmp_error_inline(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, bool is_ip6) {
    sasc_main_t *sasc = &sasc_main;
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
    u32 *from;
    u32 n_left = frame->n_vectors;
    u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
    sasc_session_t *session;

    // Session created successfully: pass packet back to sasc-lookup
    // Session already exists / collision: pass packet back to sasc-lookup
    // Cannot create key, or table is full: pass packet to drop
    from = vlib_frame_vector_args(frame);
    vlib_get_buffers(vm, from, b, n_left);

    while (n_left) {
        /* Default: advance along the configured service chain */
        // sasc_next(b[0], next);
        next[0] = SASC_ICMP_ERROR_NEXT_DROP;

        /* Derive session from flow_id (set by lookup) */
        u32 flow_index = b[0]->flow_id;
        u32 session_index = sasc_session_from_flow_index(flow_index);
        session = sasc_session_at_index_check(sasc, session_index);

        if (PREDICT_TRUE(session != 0)) {
            /* Parse IPv4 ICMP error fields */
            u8 icmp_type = 0;
            u8 icmp_code = 0;
            u32 mtu = 0;

            if (!is_ip6) {
                ip4_header_t *ip4 = sasc_get_ip4_header(b[0]);
                icmp46_header_t *icmp = (icmp46_header_t *)ip4_next_header(ip4);
                icmp_type = icmp->type;
                icmp_code = icmp->code;

                /* For IPv4 Frag Needed (type 3, code 4), next-hop MTU is in low 16 bits
                 * of the 32-bit field immediately following the ICMP header */
                if (icmp_type == ICMP4_destination_unreachable &&
                    icmp_code == ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set) {
                    u8 *p = (u8 *)(icmp + 1);
                    mtu = clib_net_to_host_u16(*(u16 *)(p + 2));
                }
            } else {
                ip6_header_t *ip6 = sasc_get_ip6_header(b[0]);
                icmp46_header_t *icmp = (icmp46_header_t *)ip6_next_header(ip6);
                icmp_type = icmp->type;
                icmp_code = icmp->code;
                if (icmp_type == ICMP6_packet_too_big) {
                    u32 *mtu_p = (u32 *)(icmp + 1);
                    mtu = clib_net_to_host_u32(*mtu_p);
                }
            }

            /* Directly update session counters for efficiency */
            sasc_icmp_error_type_t error_type = sasc_icmp_type_to_error_type(icmp_type, icmp_code);
            switch (error_type) {
            case SASC_ICMP_ERROR_DEST_UNREACH:
                session->icmp_unreach++;
                break;
            case SASC_ICMP_ERROR_FRAG_NEEDED:
                session->icmp_frag_needed++;
                break;
            case SASC_ICMP_ERROR_TTL_EXPIRED:
                session->icmp_ttl_expired++;
                break;
            case SASC_ICMP_ERROR_PACKET_TOO_BIG:
                session->icmp_packet_too_big++;
                break;
            default:
                session->icmp_other++;
                break;
            }

            /* Store MTU if available */
            if (mtu > 0) {
                session->icmp_mtu = (u16)clib_min(mtu, 65535);
            }

            sasc_icmp_error_info_t info = {0};
            info.session_index = session_index;
            info.icmp_type = icmp_type;
            info.icmp_code = icmp_code;
            info.error_type = error_type;
            info.data = mtu; /* carry MTU if available */

            /* Notify registered listeners (same worker) */
            sasc_icmp_error_notify(&info);
        }

        next += 1;
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
                sasc_icmp_error_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
                t->next_index = nexts[i];
                b++;
            } else
                break;
        }
    }
    return frame->n_vectors;
}

VLIB_NODE_FN(sasc_icmp_error_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    return sasc_icmp_error_inline(vm, node, frame, false);
}
VLIB_REGISTER_NODE(sasc_icmp_error_node) = {
    .name = "sasc-icmp-error",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_icmp_error_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_next_nodes = SASC_ICMP_ERROR_N_NEXT,
    .next_nodes =
        {
            [SASC_ICMP_ERROR_NEXT_DROP] = "error-drop",
        },
    //     .n_errors = SASC_ICMP_ERROR_N_ERROR,
    //     .error_counters = sasc_icmp_error_error_counters,
};
