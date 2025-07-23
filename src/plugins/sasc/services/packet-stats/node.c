// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <sasc/sasc.h>
#include <sasc/service.h>
#include <sasc/sasc_funcs.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>
#include <vppinfra/sparse_vec.h>
#include "packet_stats.h"
#include "counter.h"
#include <cbor.h>
#include "format.h"

typedef struct {
    u32 flow_id;
    u32 packet_size;
    f64 timestamp;
} sasc_packet_stats_trace_t;

static u8 *
format_sasc_packet_stats_trace(u8 *s, va_list *args) {
    vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
    vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
    sasc_packet_stats_trace_t *t = va_arg(*args, sasc_packet_stats_trace_t *);

    s = format(s, "sasc-packet-stats: flow-id %u packet-size %u timestamp %.6f", t->flow_id,
               t->packet_size, t->timestamp);
    return s;
}

static void
same_session_in_vector(u32 *session_indices, u32 n_vectors, u32 thread_index) {
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    // After processing all packets, count session coalescing using sparse vector
    u32 *session_counts = sparse_vec_new(sizeof(u32), 16);

    // Count sessions in this vector
    for (int i = 0; i < n_vectors; i++) {
        u32 session_idx = session_indices[i];
        u32 *count_ptr = sparse_vec_elt_at_index(session_counts, session_idx);

        if (count_ptr) {
            (*count_ptr)++; // Session already exists, increment count
        } else {
            // Session doesn't exist, create new entry with count 1
            u32 new_count = 1;
            sparse_vec_validate(session_counts, session_idx);
            *sparse_vec_elt_at_index(session_counts, session_idx) = new_count;
        }
    }

    // Now bin the session counts into coalescing histogram
    for (int i = 1; i < vec_len(session_counts); i++) { // Skip index 0 (invalid)
        if (session_counts[i] > 0) {
            u32 count = session_counts[i];
            u8 coalescing_bucket =
                vlib_log2_histogram_bin_index(&psm->session_coalescing_histogram, count);
            vlib_increment_log2_histogram_bin(&psm->session_coalescing_histogram, thread_index,
                                              coalescing_bucket, 1);
        }
    }

    // Clean up sparse vector for next use
    sparse_vec_free(session_counts);
}

VLIB_NODE_FN(sasc_packet_stats_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
    u32 session_indices[VLIB_FRAME_SIZE], *sip = session_indices;
    sasc_main_t *sasc = &sasc_main;
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;

    u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
    u32 *from = vlib_frame_vector_args(frame);
    u32 n_left = frame->n_vectors;
    f64 current_time = vlib_time_now(vm);
    u32 thread_index = vlib_get_thread_index();

    /* Update vector size histogram using log2 bins */
    u8 vector_bucket = vlib_log2_histogram_bin_index(&psm->vector_size_histogram, n_left);
    vlib_increment_log2_histogram_bin(&psm->vector_size_histogram, thread_index, vector_bucket, 1);

    vlib_get_buffers(vm, from, bufs, n_left);

    while (n_left) {
        u32 session_idx = sasc_session_from_flow_index(b[0]->flow_id);
        sasc_session_t *session = sasc_session_at_index(sasc, session_idx);
        u16 tenant_idx = sasc_buffer(b[0])->tenant_index;
        sip[0] = session_idx;
        /* Get or create session data */
        sasc_packet_stats_session_data_t *session_data;
        session_data = &psm->session_data[session_idx];

        /* Handle session version mismatch */
        if (PREDICT_FALSE(session_data->version != session->session_version)) {
            clib_memset(session_data, 0, sizeof(*session_data));
            session_data->version = session->session_version;
        }

        u32 packet_size = b[0]->current_length;
        u8 protocol = session->forward_key.proto;

        /* Update packet size histogram using fast lookup table */
        u8 bucket = vlib_log2_histogram_bin_index(&psm->packet_size_histogram, packet_size);
        vlib_increment_log2_histogram_bin(&psm->packet_size_histogram, thread_index, bucket, 1);
        session_data->size_buckets[bucket]++;

        session_data->vector_size_buckets[vector_bucket]++;

        /* Update flow statistics */
        session_data->total_packets++;
        session_data->total_bytes += packet_size;
        vlib_increment_simple_counter(&psm->counters[SASC_PACKET_STATS_COUNTER_PACKETS],
                                      thread_index, tenant_idx, 1);
        vlib_increment_simple_counter(&psm->counters[SASC_PACKET_STATS_COUNTER_BYTES], thread_index,
                                      tenant_idx, packet_size);

        /* Update protocol statistics */
        switch (protocol) {
        case IP_PROTOCOL_TCP:
            session_data->tcp_packets++;
            vlib_increment_simple_counter(&psm->counters[SASC_PACKET_STATS_COUNTER_TCP_PACKETS],
                                          thread_index, tenant_idx, 1);
            break;
        case IP_PROTOCOL_UDP:
            session_data->udp_packets++;
            vlib_increment_simple_counter(&psm->counters[SASC_PACKET_STATS_COUNTER_UDP_PACKETS],
                                          thread_index, tenant_idx, 1);
            break;
        case IP_PROTOCOL_ICMP:
            session_data->icmp_packets++;
            vlib_increment_simple_counter(&psm->counters[SASC_PACKET_STATS_COUNTER_ICMP_PACKETS],
                                          thread_index, tenant_idx, 1);
            break;
        default:
            session_data->other_packets++;
            vlib_increment_simple_counter(&psm->counters[SASC_PACKET_STATS_COUNTER_OTHER_PACKETS],
                                          thread_index, tenant_idx, 1);
            break;
        }

        /* Update inter-packet timing and gap histogram */
        if (session_data->last_packet_time > 0) {
            f64 inter_packet_time = current_time - session_data->last_packet_time;

            /* Update gap histogram using log2 bins (convert to microseconds) */
            u32 gap_us = (u32)(inter_packet_time * 1000000.0);
            u8 gap_bucket =
                vlib_log2_histogram_bin_index(&psm->session_coalescing_histogram, gap_us);
            vlib_increment_log2_histogram_bin(&psm->session_coalescing_histogram, thread_index,
                                              gap_bucket, 1);
            session_data->gap_buckets[gap_bucket]++;

            /* Update timing statistics */
            if (session_data->inter_packet_samples == 0) {
                session_data->min_inter_packet_time = inter_packet_time;
                session_data->max_inter_packet_time = inter_packet_time;
            } else {
                if (inter_packet_time < session_data->min_inter_packet_time)
                    session_data->min_inter_packet_time = inter_packet_time;
                if (inter_packet_time > session_data->max_inter_packet_time)
                    session_data->max_inter_packet_time = inter_packet_time;
            }
            session_data->avg_inter_packet_time =
                (session_data->avg_inter_packet_time * session_data->inter_packet_samples +
                 inter_packet_time) /
                (session_data->inter_packet_samples + 1);
            session_data->inter_packet_samples++;

            /* Detect bursts and idle periods */
            if (inter_packet_time < 0.001) { /* Less than 1ms gap = burst */
                session_data->burst_count++;
            } else if (inter_packet_time > 1.0) { /* More than 1 second gap = idle */
                session_data->idle_periods++;
            }

            /* Update flow duration */
            if (session_data->flow_duration_ns == 0) {
                session_data->flow_duration_ns = (u64)(current_time * 1e9);
            } else {
                session_data->flow_duration_ns =
                    (u64)(current_time * 1e9) - session_data->flow_duration_ns;
            }

            /* Update rate calculations every second */
            session_data->packets_since_rate_update++;
            session_data->bytes_since_rate_update += packet_size;

            if (current_time - session_data->last_rate_update_time >= 1.0) {
                /* Calculate current rates */
                session_data->packets_per_second = session_data->packets_since_rate_update;
                session_data->bytes_per_second = session_data->bytes_since_rate_update;

                /* Update peak rates */
                if (session_data->packets_per_second > session_data->peak_packets_per_second) {
                    session_data->peak_packets_per_second = session_data->packets_per_second;
                }
                if (session_data->bytes_per_second > session_data->peak_bytes_per_second) {
                    session_data->peak_bytes_per_second = session_data->bytes_per_second;
                }

                /* Reset counters */
                session_data->packets_since_rate_update = 0;
                session_data->bytes_since_rate_update = 0;
                session_data->last_rate_update_time = current_time;
            }
        }
        // Always set last_packet_time to current_time
        session_data->last_packet_time = current_time;

        sasc_next(b[0], to_next);

        b++;
        to_next++;
        n_left--;
        sip++;
    }

    // Count packets in same session in this vector
    same_session_in_vector(session_indices, frame->n_vectors, thread_index);

    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
        n_left = frame->n_vectors;
        b = bufs;
        for (int i = 0; i < n_left; i++) {
            if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
                sasc_packet_stats_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
                t->flow_id = b[0]->flow_id;
                t->packet_size = b[0]->current_length;
                t->timestamp = current_time;
                b++;
            } else
                break;
        }
    }
    vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(sasc_packet_stats_node) = {
    .name = "sasc-packet-stats",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_packet_stats_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
};

static u8 *
format_sasc_packet_stats_service(u8 *s, u32 thread_index, u32 session_index) {
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    sasc_packet_stats_session_data_t *session_data = &psm->session_data[session_index];

    s = format(s, "sasc-packet-stats: session %u\n", session_index);
    s = format(s, "  Total Packets: %lu\n", session_data->total_packets);
    s = format(s, "  Total Bytes: %lu\n", session_data->total_bytes);
    s = format(s, "  Flow Duration: %lu ns\n", session_data->flow_duration_ns);

    s = format_protocol_stats(s, session_data);
    s = format_packet_size_histogram(s, session_data->size_buckets);
    s = format_gap_histogram(s, session_data->gap_buckets);
    s = format_vector_size_histogram(s, session_data->vector_size_buckets);

    // Inter-packet timing
    if (session_data->inter_packet_samples > 0) {
        s = format_timing_stats(s, session_data);
    }

    // Rate statistics
    s = format_rate_stats(s, session_data);
    return s;
}

static cbor_item_t *
format_sasc_packet_stats_service_cbor(u32 thread_index, u32 session_index) {
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    sasc_packet_stats_session_data_t *session_data = &psm->session_data[session_index];
    cbor_item_t *obj = cbor_new_indefinite_map();
    bool success = true;

    // Basic info
    success &=
        cbor_map_add(obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("session")),
                                             .value = cbor_move(cbor_build_uint32(session_index))});
    success &= cbor_map_add(
        obj,
        (struct cbor_pair){.key = cbor_move(cbor_build_string("total_packets")),
                           .value = cbor_move(cbor_build_uint64(session_data->total_packets))});
    success &= cbor_map_add(
        obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("total_bytes")),
                                .value = cbor_move(cbor_build_uint64(session_data->total_bytes))});
    success &= cbor_map_add(
        obj,
        (struct cbor_pair){.key = cbor_move(cbor_build_string("flow_duration_ns")),
                           .value = cbor_move(cbor_build_uint64(session_data->flow_duration_ns))});

    // Protocol stats
    success &= cbor_map_add(
        obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("tcp_packets")),
                                .value = cbor_move(cbor_build_uint64(session_data->tcp_packets))});
    success &= cbor_map_add(
        obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("udp_packets")),
                                .value = cbor_move(cbor_build_uint64(session_data->udp_packets))});
    success &= cbor_map_add(
        obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("icmp_packets")),
                                .value = cbor_move(cbor_build_uint64(session_data->icmp_packets))});
    success &= cbor_map_add(
        obj,
        (struct cbor_pair){.key = cbor_move(cbor_build_string("other_packets")),
                           .value = cbor_move(cbor_build_uint64(session_data->other_packets))});

    // Rate stats
    success &= cbor_map_add(
        obj, (struct cbor_pair){
                 .key = cbor_move(cbor_build_string("packets_per_second")),
                 .value = cbor_move(cbor_build_uint64(session_data->packets_per_second))});
    success &= cbor_map_add(
        obj,
        (struct cbor_pair){.key = cbor_move(cbor_build_string("bytes_per_second")),
                           .value = cbor_move(cbor_build_uint64(session_data->bytes_per_second))});
    success &= cbor_map_add(
        obj, (struct cbor_pair){
                 .key = cbor_move(cbor_build_string("peak_packets_per_second")),
                 .value = cbor_move(cbor_build_uint32(session_data->peak_packets_per_second))});
    success &= cbor_map_add(
        obj, (struct cbor_pair){
                 .key = cbor_move(cbor_build_string("peak_bytes_per_second")),
                 .value = cbor_move(cbor_build_uint32(session_data->peak_bytes_per_second))});
    success &= cbor_map_add(
        obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("burst_count")),
                                .value = cbor_move(cbor_build_uint64(session_data->burst_count))});
    success &= cbor_map_add(
        obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("idle_periods")),
                                .value = cbor_move(cbor_build_uint64(session_data->idle_periods))});

    // Inter-packet timing
    success &= cbor_map_add(
        obj, (struct cbor_pair){
                 .key = cbor_move(cbor_build_string("min_inter_packet_time")),
                 .value = cbor_move(cbor_build_uint64(session_data->min_inter_packet_time))});
    success &= cbor_map_add(
        obj, (struct cbor_pair){
                 .key = cbor_move(cbor_build_string("max_inter_packet_time")),
                 .value = cbor_move(cbor_build_uint64(session_data->max_inter_packet_time))});
    success &= cbor_map_add(
        obj, (struct cbor_pair){
                 .key = cbor_move(cbor_build_string("avg_inter_packet_time")),
                 .value = cbor_move(cbor_build_uint64(session_data->avg_inter_packet_time))});
    success &= cbor_map_add(
        obj, (struct cbor_pair){
                 .key = cbor_move(cbor_build_string("inter_packet_samples")),
                 .value = cbor_move(cbor_build_uint64(session_data->inter_packet_samples))});

    // Histograms as arrays
    cbor_item_t *size_buckets = cbor_new_definite_array(8);
    for (int i = 0; i < 8; i++)
        success &= cbor_array_push(size_buckets,
                                   cbor_move(cbor_build_uint64(session_data->size_buckets[i])));
    success &=
        cbor_map_add(obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("size_buckets")),
                                             .value = cbor_move(size_buckets)});

    cbor_item_t *gap_buckets = cbor_new_definite_array(16);
    for (int i = 0; i < 16; i++)
        success &= cbor_array_push(gap_buckets,
                                   cbor_move(cbor_build_uint64(session_data->gap_buckets[i])));
    success &=
        cbor_map_add(obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("gap_buckets")),
                                             .value = cbor_move(gap_buckets)});

    cbor_item_t *vector_size_buckets = cbor_new_definite_array(8);
    for (int i = 0; i < 8; i++)
        success &=
            cbor_array_push(vector_size_buckets,
                            cbor_move(cbor_build_uint64(session_data->vector_size_buckets[i])));
    success &= cbor_map_add(
        obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("vector_size_buckets")),
                                .value = cbor_move(vector_size_buckets)});

    return success ? obj : 0;
}

SASC_SERVICE_DEFINE(packet_stats) = {
    .node_name = "sasc-packet-stats",
    .format_service = format_sasc_packet_stats_service,
    .format_service_cbor = format_sasc_packet_stats_service_cbor,
};