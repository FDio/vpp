// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.

#include <vlib/vlib.h>
#include <vnet/buffer.h>
#include <sasc/service.h>
#include <sasc/sasc.h>
#include <sasc/sasc_funcs.h>
#include <vnet/ip/ip.h>
#include <vnet/interface_funcs.h>
#include "pcap.h"
#include <vnet/ethernet/ethernet.h>

// Easy to adjust sampling parameters
#define SASC_SAMPLING_RATE_PERCENT 1    // 1% of sessions
#define SASC_MAX_PACKETS_PER_SESSION 1000  // Max packets per session

typedef struct {
    u32 flow_id;
    u32 packet_length;
    u32 captured_bytes;
} sasc_pcap_trace_t;

static u8 *
format_sasc_pcap_trace(u8 *s, va_list *args) {
    vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
    vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
    sasc_pcap_trace_t *t = va_arg(*args, sasc_pcap_trace_t *);

    s = format(s, "sasc-pcap: flow-id %u, packet-length %u, captured-bytes %u", t->flow_id, t->packet_length,
               t->captured_bytes);
    return s;
}

// In session creation (sasc_create_session)
static inline bool
sample_session(sasc_pcap_main_t *pcm, u32 session_index) {
    // Simple random sampling - 1% of sessions
    u32 hash = clib_crc32c((u8 *)&session_index, sizeof(session_index));

    if ((hash % 100) < SASC_SAMPLING_RATE_PERCENT) { // 1% sampling rate
        return true;
    }
    return false;
}

#if 0
// In PCAP service node
if (pcm->enabled && (sasc_buffer(b[0])->flags & SASC_BUFFER_F_PCAP_TRACE)) {
    // Add session metadata to PCAP
    u32 session_idx = sasc_session_from_flow_index(b[0]->flow_id);
    sasc_session_t *session = sasc_session_at_index(sasc, session_idx);

    // Write session metadata before packet data
    sasc_pcap_session_metadata_t metadata = {
        .session_index = session_idx,
        .flow_id = b[0]->flow_id,
        .quality_score = psm->session_data[session_idx].quality_score,
        .retransmissions = psm->session_data[session_idx].tcp_session_data.retransmissions,
        .ack_stalls = psm->session_data[session_idx].tcp_session_data.ack_stall_count_0,
        .timestamp_us = (u64)(vlib_time_now(vm) * 1e6)
    };

    // Write metadata to PCAP
    pcap_add_buffer(&pcm->pcap_main, vm, &metadata, sizeof(metadata));
}

// Enhanced session export with PCAP correlation
typedef struct {
    char *pcap_filename;
    u32 session_index;
    u64 pcap_start_time;
    u64 pcap_end_time;
    u32 packets_in_pcap;
} sasc_session_pcap_correlation_t;

// Add to session export
static cbor_item_t *format_sasc_session_cbor_with_pcap(sasc_session_t *session) {
    cbor_item_t *session_obj = format_sasc_session_cbor(session);

    // Add PCAP correlation if available
    if (session->flags & SASC_SESSION_F_PCAP_SAMPLE) {
        sasc_session_pcap_correlation_t *pcap_info = get_pcap_correlation(session);
        if (pcap_info) {
            cbor_item_t *pcap_map = cbor_new_indefinite_map();
            cbor_map_add(pcap_map,
                (struct cbor_pair){.key = cbor_move(cbor_build_string("pcap_file")),
                                   .value = cbor_move(cbor_build_string(pcap_info->pcap_filename))});
            cbor_map_add(pcap_map,
                (struct cbor_pair){.key = cbor_move(cbor_build_string("packets_captured")),
                                   .value = cbor_move(cbor_build_uint32(pcap_info->packets_in_pcap))});
            cbor_array_push(session_obj, cbor_move(pcap_map));
        }
    }

    return session_obj;
}
#endif

VLIB_NODE_FN(sasc_pcap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    sasc_pcap_main_t *pcm = &sasc_pcap_main;
    sasc_main_t *sasc = &sasc_main;
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
    u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
    u32 *bi, *from = vlib_frame_vector_args(frame);
    u32 n_left = frame->n_vectors;

    vlib_get_buffers(vm, from, bufs, n_left);
    bi = from;
    while (n_left) {
        u32 session_idx = sasc_session_from_flow_index(b[0]->flow_id);
        sasc_session_t *session = sasc_session_at_index(sasc, session_idx);
        sasc_pcap_session_data_t *session_data = vec_elt_at_index(pcm->session_data, session_idx);

        // New session
        if (session_data->version != session->session_version) {
            session_data->version = session->session_version;
            if (sample_session(pcm, session_idx)) {
                sasc_buffer(b[0])->flags |= SASC_BUFFER_F_PCAP_TRACE;
                session_data->sampled_packets = 0;
                sasc_log_debug("Started sampling session %u", session_idx);
                session->flags |= SASC_SESSION_F_PCAP_SAMPLE;
            } else {
                goto next;
            }
        }

        u32 packet_length = vlib_buffer_length_in_chain(vm, b[0]);
        /* Update statistics */
        pcm->packets_processed++;

        /* Capture packet if service is enabled and buffer marked for PCAP tracing */
        if (pcm->enabled && (sasc_buffer(b[0])->flags & SASC_BUFFER_F_PCAP_TRACE) &&
            pcm->pcap_main.n_packets_captured < pcm->pcap_main.n_packets_to_capture &&
            session_data->sampled_packets < SASC_MAX_PACKETS_PER_SESSION) {
            /* Trace all drops, or drops received on a specific interface */

            /*
             * Typically, we'll need to rewind the buffer
             * if l2_hdr_offset is valid, make sure to rewind to the start of
             * the L2 header. This may not be the buffer start in case we pop-ed
             * vlan tags.
             * Otherwise, rewind to buffer start and hope for the best.
             */
            i16 rewind_bytes = 0;
            if (b[0]->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID) {
                if (b[0]->current_data > vnet_buffer(b[0])->l2_hdr_offset)
                    rewind_bytes = vnet_buffer(b[0])->l2_hdr_offset - b[0]->current_data;
            } else if (b[0]->current_data > 0) {
                rewind_bytes = -b[0]->current_data;
            }
            vlib_buffer_advance(b[0], rewind_bytes);
            pcap_add_buffer(&pcm->pcap_main, vm, bi[0], ETHERNET_MAX_PACKET_BYTES);
            vlib_buffer_advance(b[0], -rewind_bytes);

            /* Update statistics */
            pcm->packets_captured++;
            pcm->packets_captured_total++;
            pcm->bytes_captured_total += packet_length;
            session_data->sampled_packets++;

            /* Write to file if we've reached the limit */
            if (pcm->pcap_main.n_packets_captured >= pcm->pcap_main.n_packets_to_capture) {
                clib_warning("PCAP capture limit reached (%u packets), writing to file",
                             pcm->pcap_main.n_packets_to_capture);
                pcap_write(&pcm->pcap_main);
            }
        }

    /* Continue to next service in chain */
    next:
        sasc_next(b[0], to_next);

        b++;
        bi++;
        to_next++;
        n_left--;
    }

    /* Add traces if enabled */
    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
        n_left = frame->n_vectors;
        b = bufs;
        for (int i = 0; i < n_left; i++) {
            if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
                sasc_pcap_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
                t->flow_id = b[0]->flow_id;
                t->packet_length = vlib_buffer_length_in_chain(vm, b[0]);
                t->captured_bytes = pcm->enabled ? clib_min(t->packet_length, ETHERNET_MAX_PACKET_BYTES) : 0;
                b++;
            } else
                break;
        }
    }

    vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(sasc_pcap_node) = {
    .name = "sasc-pcap",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_pcap_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = 0,
    .error_counters = 0,
};

SASC_SERVICE_DEFINE(pcap) = {
    .node_name = "sasc-pcap",
};