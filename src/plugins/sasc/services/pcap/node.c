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

    s = format(s, "sasc-pcap: flow-id %u, packet-length %u, captured-bytes %u", t->flow_id,
               t->packet_length, t->captured_bytes);
    return s;
}

VLIB_NODE_FN(sasc_pcap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    sasc_pcap_main_t *pcm = &sasc_pcap_main;
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
    u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
    u32 *bi, *from = vlib_frame_vector_args(frame);
    u32 n_left = frame->n_vectors;

    vlib_get_buffers(vm, from, bufs, n_left);
    bi = from;
    while (n_left) {
        u32 packet_length = vlib_buffer_length_in_chain(vm, b[0]);
        /* Update statistics */
        pcm->packets_processed++;

        /* Capture packet if service is enabled */
        if (pcm->enabled &&
            pcm->pcap_main.n_packets_captured < pcm->pcap_main.n_packets_to_capture) {
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

            /* Write to file if we've reached the limit */
            if (pcm->pcap_main.n_packets_captured >= pcm->pcap_main.n_packets_to_capture) {
                clib_warning("PCAP capture limit reached (%u packets), writing to file",
                             pcm->pcap_main.n_packets_to_capture);
                pcap_write(&pcm->pcap_main);
            }
        }

        /* Continue to next service in chain */
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
                t->captured_bytes =
                    pcm->enabled ? clib_min(t->packet_length, ETHERNET_MAX_PACKET_BYTES) : 0;
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