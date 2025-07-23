// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

/*
 * TCP Anomaly Detection Service
 *
 * This module provides comprehensive TCP anomaly detection including:
 *
 * 1. 3-Way Handshake Validation:
 *    - Validates proper SYN -> SYN-ACK -> ACK sequence
 *    - Detects unexpected SYN packets
 *    - Handles session version mismatches
 *
 * 2. Session State Tracking:
 *    - Tracks connection establishment, data transfer, and teardown phases
 *    - Validates FIN/ACK sequences during graceful closure
 *    - Handles RST packets for immediate termination
 *
 * 3. Anomaly Detection:
 *    - Retransmission detection with configurable thresholds
 *    - Packet reordering detection with configurable tolerance
 *    - Fast retransmit detection (3 duplicate ACKs)
 *    - TCP flag malformation detection
 *    - Invalid header length detection
 *
 * 4. Error Counters:
 *    - Session-specific anomaly counters for granular tracking
 *    - Per-session anomaly monitoring and debugging
 *    - Direct counter increments for minimal overhead
 *    - Real-time monitoring capabilities for network health
 *    - Total anomalies calculated on-demand when reporting
 *
 * 5. Modular Design:
 *    - Separated flag processing logic for better maintainability
 *    - Helper functions for session initialization and cleanup
 *    - Clear separation of concerns between anomaly detection and state management
 *    - Direct session-specific counter updates for maximum performance
 *
 * Configuration:
 *    - retransmit_threshold: Time threshold for retransmission detection (default: 100ms)
 *    - reorder_tolerance: Sequence number tolerance for reorder detection (default: 100000)
 *
 * Session Flags:
 *    - WAIT_FOR_RESP_SYN: Waiting for SYN-ACK response
 *    - WAIT_FOR_INIT_ACK_TO_SYN: Waiting for ACK to SYN-ACK
 *    - WAIT_FOR_RESP_ACK_TO_SYN: Waiting for ACK to SYN
 *    - SEEN_FIN_INIT: FIN seen from initiator
 *    - SEEN_FIN_RESP: FIN seen from responder
 *    - SEEN_ACK_TO_FIN_INIT: ACK to initiator FIN seen
 *    - SEEN_ACK_TO_FIN_RESP: ACK to responder FIN seen
 *    - ESTABLISHED: Connection fully established
 *    - REMOVING: Session being removed
 *    - BLOCKED: Session blocked due to protocol violation
 *    - RETRANSMIT_DETECTED: Retransmission anomaly detected
 *    - REORDER_DETECTED: Packet reordering anomaly detected
 *
 * Key Functions:
 *    - update_state_one_pkt: Main entry point for packet processing
 *    - process_tcp_flags: Handles TCP flag processing and state transitions
 *    - check_tcp_anomalies: Detects various TCP anomalies
 *    - init_tcp_session: Handles session initialization and reset
 *    - finalize_session_state: Handles final state updates and cleanup
 */

#include <vlib/vlib.h>
#include <sasc/service.h>
#include <sasc/sasc.h>
#include <sasc/sasc_funcs.h>
#include <vnet/ip/ip.h>
#include "tcp_check.h"
#include <sasc/services/tcp-check/tcp_check.api_enum.h>
#include "counter.h"

typedef struct {
    u32 flow_id;
    u32 old_state_flags;
    u32 new_state_flags;
} sasc_tcp_check_trace_t;

static u8 *
format_sasc_tcp_check_trace(u8 *s, va_list *args) {
    vlib_main_t __clib_unused *vm = va_arg(*args, vlib_main_t *);
    vlib_node_t __clib_unused *node = va_arg(*args, vlib_node_t *);
    sasc_tcp_check_trace_t *t = va_arg(*args, sasc_tcp_check_trace_t *);
    u32 indent = format_get_indent(s);
    indent += 2;
    s = format(s, "sasc-tcp-check: flow-id %u (session %u, %s)\n", t->flow_id, t->flow_id >> 1,
               t->flow_id & 0x1 ? "reverse" : "forward");
    s = format(s, "%Uold session flags: %U\n", format_white_space, indent,
               format_sasc_tcp_check_session_flags, t->old_state_flags);
    s = format(s, "%Unew session flags: %U\n", format_white_space, indent,
               format_sasc_tcp_check_session_flags, t->new_state_flags);
    return s;
}

// Add function to calculate retransmission rate
static_always_inline f64
calculate_retransmission_rate(sasc_tcp_check_session_state_t *tcp_session, u8 dir) {
    u32 total_packets = tcp_session->packet_count[dir];
    u32 retransmits = tcp_session->retransmit_count[dir];

    if (total_packets == 0)
        return 0.0;
    return (f64)retransmits / (f64)total_packets;
}

// Add function to calculate average retransmission delay
static_always_inline f64
calculate_avg_retransmit_delay(sasc_tcp_check_session_state_t *tcp_session, u8 dir) {
    if (tcp_session->retransmit_delay_count[dir] == 0)
        return 0.0;

    f64 total_delay = 0.0;
    for (u32 i = 0; i < tcp_session->retransmit_delay_count[dir]; i++) {
        total_delay += tcp_session->retransmit_delays[dir][i];
    }
    return total_delay / (f64)tcp_session->retransmit_delay_count[dir];
}

static u8 *
format_sasc_tcp_check_service(u8 *s, u32 thread_index, u32 session_index) {
    sasc_tcp_check_main_t *tcm = &sasc_tcp_check_main;
    sasc_tcp_check_session_state_t *tcp_session = &tcm->state[session_index];

    s = format(s, "sasc-tcp-check: session %u, flags: %U", session_index,
               format_sasc_tcp_check_session_flags, tcp_session->flags);

    if (tcp_session->retransmit_count[SASC_FLOW_FORWARD] > 0 ||
        tcp_session->retransmit_count[SASC_FLOW_REVERSE] > 0) {

        f64 fwd_rate = calculate_retransmission_rate(tcp_session, SASC_FLOW_FORWARD);
        f64 rev_rate = calculate_retransmission_rate(tcp_session, SASC_FLOW_REVERSE);
        f64 fwd_delay = calculate_avg_retransmit_delay(tcp_session, SASC_FLOW_FORWARD);
        f64 rev_delay = calculate_avg_retransmit_delay(tcp_session, SASC_FLOW_REVERSE);

        s = format(s, ", retransmits fwd:%u(%.2f%%,%.1fms) rev:%u(%.2f%%,%.1fms)",
                   tcp_session->retransmit_count[SASC_FLOW_FORWARD], fwd_rate * 100.0,
                   fwd_delay * 1000.0, tcp_session->retransmit_count[SASC_FLOW_REVERSE],
                   rev_rate * 100.0, rev_delay * 1000.0);
    }

    if (tcp_session->reorder_count[SASC_FLOW_FORWARD] > 0 ||
        tcp_session->reorder_count[SASC_FLOW_REVERSE] > 0) {
        s = format(s, ", reorders fwd:%u rev:%u", tcp_session->reorder_count[SASC_FLOW_FORWARD],
                   tcp_session->reorder_count[SASC_FLOW_REVERSE]);
    }

    /* Display session-specific anomaly counters */
    u32 total_anomalies = tcp_session->invalid_tcp_header_count +
                          tcp_session->malformed_flags_count + tcp_session->unexpected_syn_count +
                          tcp_session->protocol_violation_count +
                          tcp_session->invalid_fin_ack_count + tcp_session->fast_retransmit_count +
                          tcp_session->window_probe_count + tcp_session->handshake_timeout_count;

    if (total_anomalies > 0) {
        s = format(s, ", anomalies total:%u", total_anomalies);

        if (tcp_session->invalid_tcp_header_count > 0)
            s = format(s, " invalid_hdr:%u", tcp_session->invalid_tcp_header_count);

        if (tcp_session->malformed_flags_count > 0)
            s = format(s, " malformed_flags:%u", tcp_session->malformed_flags_count);

        if (tcp_session->unexpected_syn_count > 0)
            s = format(s, " unexpected_syn:%u", tcp_session->unexpected_syn_count);

        if (tcp_session->protocol_violation_count > 0)
            s = format(s, " protocol_viol:%u", tcp_session->protocol_violation_count);

        if (tcp_session->invalid_fin_ack_count > 0)
            s = format(s, " invalid_fin_ack:%u", tcp_session->invalid_fin_ack_count);

        if (tcp_session->fast_retransmit_count > 0)
            s = format(s, " fast_retransmit:%u", tcp_session->fast_retransmit_count);

        if (tcp_session->window_probe_count > 0)
            s = format(s, " window_probe:%u", tcp_session->window_probe_count);

        if (tcp_session->handshake_timeout_count > 0)
            s = format(s, " handshake_timeout:%u", tcp_session->handshake_timeout_count);
    }

    /* Display RTT statistics if available */
    if (tcp_session->rtt_count[SASC_FLOW_FORWARD] > 0 ||
        tcp_session->rtt_count[SASC_FLOW_REVERSE] > 0) {
        s = format(s, ", RTT fwd:");
        if (tcp_session->rtt_count[SASC_FLOW_FORWARD] > 0) {
            f64 avg_rtt =
                tcp_session->rtt_sum[SASC_FLOW_FORWARD] / tcp_session->rtt_count[SASC_FLOW_FORWARD];
            s = format(s, "avg:%.2fms min:%.2fms max:%.2fms", avg_rtt * 1000.0,
                       tcp_session->rtt_min[SASC_FLOW_FORWARD] * 1000.0,
                       tcp_session->rtt_max[SASC_FLOW_FORWARD] * 1000.0);
        } else {
            s = format(s, "N/A");
        }

        s = format(s, " rev:");
        if (tcp_session->rtt_count[SASC_FLOW_REVERSE] > 0) {
            f64 avg_rtt =
                tcp_session->rtt_sum[SASC_FLOW_REVERSE] / tcp_session->rtt_count[SASC_FLOW_REVERSE];
            s = format(s, "avg:%.2fms min:%.2fms max:%.2fms", avg_rtt * 1000.0,
                       tcp_session->rtt_min[SASC_FLOW_REVERSE] * 1000.0,
                       tcp_session->rtt_max[SASC_FLOW_REVERSE] * 1000.0);
        } else {
            s = format(s, "N/A");
        }
    }

    return s;
}

static cbor_item_t *
format_sasc_tcp_check_service_cbor(u32 thread_index, u32 session_index) {
    sasc_tcp_check_main_t *tcm = &sasc_tcp_check_main;
    sasc_tcp_check_session_state_t *tcp_session = &tcm->state[session_index];

    cbor_item_t *obj = cbor_new_definite_map(6);
    bool success = true;

    /* Basic info */
    success &=
        cbor_map_add(obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("session")),
                                             .value = cbor_move(cbor_build_uint32(session_index))});

    success &= cbor_map_add(
        obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("flags")),
                                .value = cbor_move(cbor_build_uint32(tcp_session->flags))});

    /* Retransmit info */
    if (tcp_session->retransmit_count[SASC_FLOW_FORWARD] > 0 ||
        tcp_session->retransmit_count[SASC_FLOW_REVERSE] > 0) {
        cbor_item_t *retransmit = cbor_new_definite_map(2);
        success &= cbor_map_add(
            retransmit, (struct cbor_pair){.key = cbor_move(cbor_build_string("forward")),
                                           .value = cbor_move(cbor_build_uint32(
                                               tcp_session->retransmit_count[SASC_FLOW_FORWARD]))});
        success &= cbor_map_add(
            retransmit, (struct cbor_pair){.key = cbor_move(cbor_build_string("reverse")),
                                           .value = cbor_move(cbor_build_uint32(
                                               tcp_session->retransmit_count[SASC_FLOW_REVERSE]))});
        success &=
            cbor_map_add(obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("retransmits")),
                                                 .value = cbor_move(retransmit)});
    }

    /* Reorder info */
    if (tcp_session->reorder_count[SASC_FLOW_FORWARD] > 0 ||
        tcp_session->reorder_count[SASC_FLOW_REVERSE] > 0) {
        cbor_item_t *reorder = cbor_new_definite_map(2);
        success &= cbor_map_add(
            reorder, (struct cbor_pair){.key = cbor_move(cbor_build_string("forward")),
                                        .value = cbor_move(cbor_build_uint32(
                                            tcp_session->reorder_count[SASC_FLOW_FORWARD]))});
        success &= cbor_map_add(
            reorder, (struct cbor_pair){.key = cbor_move(cbor_build_string("reverse")),
                                        .value = cbor_move(cbor_build_uint32(
                                            tcp_session->reorder_count[SASC_FLOW_REVERSE]))});
        success &=
            cbor_map_add(obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("reorders")),
                                                 .value = cbor_move(reorder)});
    }

    /* Anomalies */
    u32 total_anomalies = tcp_session->invalid_tcp_header_count +
                          tcp_session->malformed_flags_count + tcp_session->unexpected_syn_count +
                          tcp_session->protocol_violation_count +
                          tcp_session->invalid_fin_ack_count + tcp_session->fast_retransmit_count +
                          tcp_session->window_probe_count + tcp_session->handshake_timeout_count;
    if (total_anomalies > 0) {
        success &= cbor_map_add(
            obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("anomalies")),
                                    .value = cbor_move(cbor_build_uint32(total_anomalies))});
    }

    /* RTT info */
    if (tcp_session->rtt_count[SASC_FLOW_FORWARD] > 0 ||
        tcp_session->rtt_count[SASC_FLOW_REVERSE] > 0) {
        cbor_item_t *rtt = cbor_new_definite_map(2);

        if (tcp_session->rtt_count[SASC_FLOW_FORWARD] > 0) {
            f64 avg_rtt =
                tcp_session->rtt_sum[SASC_FLOW_FORWARD] / tcp_session->rtt_count[SASC_FLOW_FORWARD];
            success &= cbor_map_add(
                rtt, (struct cbor_pair){.key = cbor_move(cbor_build_string("forward_avg_ms")),
                                        .value = cbor_move(cbor_build_float4(avg_rtt * 1000.0))});
        }

        if (tcp_session->rtt_count[SASC_FLOW_REVERSE] > 0) {
            f64 avg_rtt =
                tcp_session->rtt_sum[SASC_FLOW_REVERSE] / tcp_session->rtt_count[SASC_FLOW_REVERSE];
            success &= cbor_map_add(
                rtt, (struct cbor_pair){.key = cbor_move(cbor_build_string("reverse_avg_ms")),
                                        .value = cbor_move(cbor_build_float4(avg_rtt * 1000.0))});
        }

        success &= cbor_map_add(obj, (struct cbor_pair){.key = cbor_move(cbor_build_string("rtt")),
                                                        .value = cbor_move(rtt)});
    }
    return success ? obj : 0;
}

/**
 * @brief Parses TCP options to extract timestamp values.
 *
 * @param tcp Pointer to the TCP header.
 * @param tcp_hdr_len Length of the TCP header.
 * @param ts_val Pointer to store the parsed TSval.
 * @param ts_ecr Pointer to store the parsed TSecr.
 * @return true if timestamps were found and parsed, false otherwise.
 */
static_always_inline bool
parse_tcp_timestamps(tcp_header_t *tcp, u8 tcp_hdr_len, u32 *ts_val, u32 *ts_ecr) {
    if (tcp_hdr_len <= 20)
        return false;

    u8 *options = (u8 *)tcp + 20;
    u8 options_len = tcp_hdr_len - 20;
    u8 i = 0;
    *ts_val = 0;
    *ts_ecr = 0;

    while (i < options_len) {
        u8 kind = options[i];
        if (kind == 0) /* End of options list */
            break;
        if (kind == 1) { /* No-Op (padding) */
            i++;
            continue;
        }

        if (i + 1 >= options_len) /* Malformed options */
            break;
        u8 len = options[i + 1];
        if (len < 2) /* Malformed length */
            break;

        if (kind == 8 && len == 10) { /* Timestamp option */
            if (i + 9 >= options_len) /* Check bounds */
                break;
            clib_memcpy(ts_val, &options[i + 2], sizeof(u32));
            clib_memcpy(ts_ecr, &options[i + 6], sizeof(u32));
            *ts_val = clib_net_to_host_u32(*ts_val);
            *ts_ecr = clib_net_to_host_u32(*ts_ecr);
            return true;
        }
        i += len;
    }
    return false;
}

/**
 * @brief Centralized function to update RTT statistics.
 *
 * @param tcp_session Pointer to the session state.
 * @param dir The direction for which to update stats.
 * @param rtt The calculated RTT value.
 */
static_always_inline void
do_rtt_stat_update(sasc_tcp_check_session_state_t *tcp_session, u8 dir, f64 rtt) {
    u32 thread_index = vlib_get_thread_index();
    if (rtt < 0)
        return; /* Clock issues or very long-delayed packet */

    if (tcp_session->rtt_count[dir] == 0) {
        tcp_session->rtt_min[dir] = rtt;
        tcp_session->rtt_max[dir] = rtt;
    } else {
        if (rtt < tcp_session->rtt_min[dir])
            tcp_session->rtt_min[dir] = rtt;
        if (rtt > tcp_session->rtt_max[dir])
            tcp_session->rtt_max[dir] = rtt;
    }

    tcp_session->rtt_sum[dir] += rtt;
    tcp_session->rtt_count[dir]++;

    /* Update histogram using log2 bins for better resolution at lower RTT values */
    u32 rtt_ms = rtt * 1000;
    u8 bin_index = vlib_log2_histogram_bin_index(&sasc_tcp_check_main.rtt_histogram, rtt_ms);
    vlib_increment_log2_histogram_bin(&sasc_tcp_check_main.rtt_histogram, thread_index, bin_index,
                                      1);
    tcp_session->rtt_histogram[dir][bin_index]++;
}

/**
 * @brief Updates Round-Trip Time (RTT) statistics for a TCP session.
 *
 * @param tcp_session Pointer to the session state.
 * @param current_time The current time.
 * @param dir The direction of the current packet.
 * @param ts_val The TSval from the current packet's TCP options.
 * @param ts_ecr The TSecr from the current packet's TCP options.
 */
static_always_inline void
update_rtt_stats(sasc_tcp_check_session_state_t *tcp_session, f64 current_time, u8 dir, u32 ts_val,
                 u32 ts_ecr) {
    u8 other_dir = (dir == SASC_FLOW_FORWARD) ? SASC_FLOW_REVERSE : SASC_FLOW_FORWARD;

    if (ts_ecr != 0 && tcp_session->last_ts_val[other_dir] != 0 &&
        ts_ecr == tcp_session->last_ts_val[other_dir]) {
        f64 rtt = current_time - tcp_session->last_ts_time[other_dir];
        do_rtt_stat_update(tcp_session, other_dir, rtt);
    }

    if (ts_val != 0) {
        tcp_session->last_ts_val[dir] = ts_val;
        tcp_session->last_ts_time[dir] = current_time;
    }
}

/**
 * @brief Updates RTT statistics using sequence and acknowledgment numbers.
 *
 * @param tcp_session Pointer to the session state.
 * @param current_time The current time.
 * @param dir The direction of the current packet.
 * @param tcp Pointer to the TCP header.
 * @param data_len The data length of the packet.
 */
static_always_inline void
update_rtt_stats_no_ts(sasc_tcp_check_session_state_t *tcp_session, f64 current_time, u8 dir,
                       tcp_header_t *tcp, u32 data_len) {
    u32 seqnum = clib_net_to_host_u32(tcp->seq_number);
    u32 acknum = clib_net_to_host_u32(tcp->ack_number);
    u8 other_dir = (dir == SASC_FLOW_FORWARD) ? SASC_FLOW_REVERSE : SASC_FLOW_FORWARD;

    // Check if this packet is an ACK for a data segment we sent in the other direction
    if ((tcp->flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) && tcp_session->rtt_seq[other_dir] != 0 &&
        acknum >= tcp_session->rtt_seq[other_dir]) {
        f64 rtt = current_time - tcp_session->rtt_time[other_dir];
        do_rtt_stat_update(tcp_session, other_dir, rtt);
        tcp_session->rtt_seq[other_dir] = 0; // Clear the tracked sequence
    }

    // If this packet has data and we aren't already tracking a segment for RTT in this direction
    if (data_len > 0 && tcp_session->rtt_seq[dir] == 0) {
        tcp_session->rtt_seq[dir] = seqnum + data_len;
        tcp_session->rtt_time[dir] = current_time;
    }
}

/**
 * @brief Process TCP RTT from TCP options.
 *
 * @param tcp_session Pointer to the session state.
 * @param current_time The current time.
 * @param dir The direction of the current packet.
 * @param tcp Pointer to the TCP header.
 * @param data_len The data length of the packet.
 */
static_always_inline void
process_tcp_rtt(sasc_tcp_check_session_state_t *tcp_session, f64 current_time, u8 dir,
                tcp_header_t *tcp, u32 data_len) {
    u8 tcp_hdr_len = ((tcp->data_offset_and_reserved >> 4) & 0xF) * 4;
    u32 ts_val, ts_ecr;
    if (parse_tcp_timestamps(tcp, tcp_hdr_len, &ts_val, &ts_ecr)) {
        update_rtt_stats(tcp_session, current_time, dir, ts_val, ts_ecr);
    } else {
        update_rtt_stats_no_ts(tcp_session, current_time, dir, tcp, data_len);
    }
}

static_always_inline void
check_tcp_anomalies(sasc_tcp_check_main_t *stcm, u32 thread_index, u16 tenant_idx,
                    sasc_tcp_check_session_state_t *tcp_session, sasc_session_t *session,
                    f64 current_time, u8 dir, tcp_header_t *tcp, u32 packet_length) {
    u32 seqnum = clib_net_to_host_u32(tcp->seq_number);
    u32 acknum = clib_net_to_host_u32(tcp->ack_number);
    u16 window_size = clib_net_to_host_u16(tcp->window);
    u8 flags = tcp->flags & SASC_TCP_CHECK_TCP_FLAGS_MASK;

    sasc_log_debug("Processing: %U\n%U", format_sasc_session_key, &session->forward_key,
                   format_tcp_header, tcp, 40);

    // Calculate TCP header length
    u8 tcp_hdr_len = ((tcp->data_offset_and_reserved >> 4) & 0xF) * 4;
    if (tcp_hdr_len < 20) {
        // Invalid TCP header length
        tcp_session->invalid_tcp_header_count++;
        vlib_increment_simple_counter(&stcm->counters[SASC_TCP_CHECK_COUNTER_INVALID_TCP_HEADER],
                                      thread_index, tenant_idx, 1);

        sasc_log_warn("Invalid TCP header length: %u", tcp_hdr_len);
        return;
    }

    // Validate TCP flags for common malformations
    if ((flags & SASC_TCP_CHECK_TCP_FLAGS_SYN) && (flags & SASC_TCP_CHECK_TCP_FLAGS_FIN)) {
        // SYN and FIN cannot be set together
        tcp_session->malformed_flags_count++;
        vlib_increment_simple_counter(&stcm->counters[SASC_TCP_CHECK_COUNTER_MALFORMED_TCP_FLAGS],
                                      thread_index, tenant_idx, 1);

        sasc_log_warn("Malformed TCP flags: SYN and FIN set together");
        return;
    }

    if ((flags & SASC_TCP_CHECK_TCP_FLAGS_SYN) && (flags & SASC_TCP_CHECK_TCP_FLAGS_RST)) {
        // SYN and RST cannot be set together
        tcp_session->malformed_flags_count++;
        vlib_increment_simple_counter(&stcm->counters[SASC_TCP_CHECK_COUNTER_MALFORMED_TCP_FLAGS],
                                      thread_index, tenant_idx, 1);

        sasc_log_warn("Malformed TCP flags: SYN and RST set together");
        return;
    }

    // Skip anomaly detection for SYN/FIN/RST packets
    if (flags & (SASC_TCP_CHECK_TCP_FLAGS_SYN | SASC_TCP_CHECK_TCP_FLAGS_FIN |
                 SASC_TCP_CHECK_TCP_FLAGS_RST)) {
        return;
    }

    // Calculate data length
    u32 data_len = 0;
    if (packet_length > 0) {
        const u32 ip_hdr_len = 20; // Assumes no IP options
        if (packet_length > (ip_hdr_len + tcp_hdr_len))
            data_len = packet_length - ip_hdr_len - tcp_hdr_len;
    }

    // First packet in this direction: initialize session
    if (tcp_session->last_seq[dir] == 0 && tcp_session->last_ack[dir] == 0) {
        tcp_session->last_seq[dir] = seqnum;
        tcp_session->last_ack[dir] = acknum;
        tcp_session->last_pkt_time[dir] = current_time;
        tcp_session->last_flags[dir] = flags;
        tcp_session->last_data_len[dir] = data_len;
        tcp_session->last_window[dir] = window_size;
        if (data_len > 0)
            tcp_session->expected_seq[dir] = seqnum + data_len;

        // Initialize packet counters
        tcp_session->packet_count[dir]++;
        if (data_len > 0) {
            tcp_session->data_packet_count[dir]++;
        } else if (flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) {
            tcp_session->ack_packet_count[dir]++;
        }
        return;
    }

    // Update packet counters
    tcp_session->packet_count[dir]++;
    if (data_len > 0) {
        tcp_session->data_packet_count[dir]++;
    } else if (flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) {
        tcp_session->ack_packet_count[dir]++;
    }

    // Check for retransmission: same SEQ and ACK and same data state
    if (tcp_session->last_seq[dir] == seqnum && tcp_session->last_ack[dir] == acknum) {
        bool current_is_data = (data_len > 0);
        bool last_was_data = (tcp_session->last_data_len[dir] > 0);

        if (current_is_data == last_was_data) {
            // Calculate retransmission delay
            f64 retransmit_delay = current_time - tcp_session->last_pkt_time[dir];

            // Track retransmission delay
            if (tcp_session->retransmit_delay_count[dir] < 16) {
                tcp_session->retransmit_delays[dir][tcp_session->retransmit_delay_count[dir]] =
                    retransmit_delay;
                tcp_session->retransmit_delay_count[dir]++;
            }

            // Detect retransmission bursts (consecutive retransmits within 100ms)
            if (current_time - tcp_session->last_retransmit_time[dir] < 0.1) {
                tcp_session->retransmit_burst_count[dir]++;
                vlib_increment_simple_counter(
                    &stcm->counters[SASC_TCP_CHECK_COUNTER_RETRANSMIT_BURST], thread_index,
                    tenant_idx, 1);
            } else {
                tcp_session->retransmit_burst_count[dir] = 1;
                tcp_session->last_retransmit_burst_start[dir] = current_time;
            }

            vlib_increment_simple_counter(
                &sasc_tcp_check_main.counters[SASC_TCP_CHECK_COUNTER_RETRANSMIT], thread_index,
                tenant_idx, 1);
            tcp_session->retransmit_count[dir]++;
            tcp_session->last_retransmit_time[dir] = current_time;

            sasc_log_debug("TCP retransmit: session %u, dir %u, count %u, delay %.3fms, "
                           "burst_count %u, seq %u, ack %u",
                           session - sasc_main.sessions, dir, tcp_session->retransmit_count[dir],
                           retransmit_delay * 1000.0, tcp_session->retransmit_burst_count[dir],
                           seqnum, acknum);

            // Analyze retransmission patterns and generate alerts
            f64 retransmit_rate = calculate_retransmission_rate(tcp_session, dir);
            f64 avg_delay = calculate_avg_retransmit_delay(tcp_session, dir);

            // Alert on high retransmission rates (>5%)
            if (retransmit_rate > 0.05) {
                sasc_log_warn("High retransmission rate: %.2f%% in direction %u for session %u",
                              retransmit_rate * 100.0, dir, session - sasc_main.sessions);
            }

            // Alert on retransmission bursts (>3 consecutive retransmits)
            if (tcp_session->retransmit_burst_count[dir] > 3) {
                sasc_log_warn("Retransmission burst detected: %u consecutive retransmits in "
                              "direction %u for session %u",
                              tcp_session->retransmit_burst_count[dir], dir,
                              session - sasc_main.sessions);
            }

            // Alert on excessive retransmission delays (>1 second)
            if (avg_delay > 1.0) {
                sasc_log_warn(
                    "Excessive retransmission delay: %.3fms average in direction %u for session %u",
                    avg_delay * 1000.0, dir, session - sasc_main.sessions);
            }
        }
    } else {
        // Check for reordering: non-matching expected SEQ
        if (tcp_session->expected_seq[dir] != 0 && data_len > 0 &&
            seqnum != tcp_session->expected_seq[dir]) {
            u32 expected = tcp_session->expected_seq[dir];
            u32 seq_diff = (seqnum > expected) ?
                               (seqnum - expected) :
                               (0xFFFFFFFF - expected) + seqnum + 1; // Wraparound handling

            u32 tolerance = tcp_session->reorder_tolerance > 0 ? tcp_session->reorder_tolerance :
                                                                 100000; // Default tolerance

            if (seq_diff < tolerance && seq_diff < window_size) {
                tcp_session->reorder_count[dir]++;
                vlib_increment_simple_counter(&stcm->counters[SASC_TCP_CHECK_COUNTER_REORDER],
                                              thread_index, tenant_idx, 1);
                sasc_log_warn("TCP reorder detected: session %u, direction %u, count %u, "
                              "expected_seq %u, actual_seq %u, diff %u, window=%u",
                              session - sasc_main.sessions, dir, tcp_session->reorder_count[dir],
                              expected, seqnum, seq_diff, window_size);
            }
        }
    }

    // Check for fast retransmit (3 duplicate ACKs)
    if (flags & SASC_TCP_CHECK_TCP_FLAGS_ACK && data_len == 0) {
        if (acknum == tcp_session->last_dup_ack_seq[dir]) {
            tcp_session->dup_ack_count[dir]++;
            if (tcp_session->dup_ack_count[dir] >= 3) {
                tcp_session->fast_retransmit_count++;
                vlib_increment_simple_counter(
                    &stcm->counters[SASC_TCP_CHECK_COUNTER_FAST_RETRANSMIT], thread_index,
                    tenant_idx, 1);
                sasc_log_warn(
                    "Fast retransmit detected: session %u, direction %u, dup_ack_count %u, ack %u",
                    session - sasc_main.sessions, dir, tcp_session->dup_ack_count[dir], acknum);
                // Reset counter after detection
                tcp_session->dup_ack_count[dir] = 0;
            }
        } else {
            tcp_session->dup_ack_count[dir] = 1;
            tcp_session->last_dup_ack_seq[dir] = acknum;
        }
    } else {
        // Reset duplicate ACK count if not a pure ACK
        tcp_session->dup_ack_count[dir] = 0;
    }

    // Process ACK to update expected_seq for other direction
    if (flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) {
        u8 other_dir = (dir == SASC_FLOW_FORWARD) ? SASC_FLOW_REVERSE : SASC_FLOW_FORWARD;
        u32 acked_data =
            (acknum > tcp_session->last_ack[dir]) ? (acknum - tcp_session->last_ack[dir]) : 0;

        if (acked_data > 0) {
            tcp_session->expected_seq[other_dir] = acknum;
            sasc_log_debug(
                "ACK processing: dir=%u, acknum=%u, acked_data=%u, updated expected_seq[%u]=%u",
                dir, acknum, acked_data, other_dir, acknum);
        }

        // Pure ACK (no data) that might reflect peer's expected seq
        if (acked_data == 0 && tcp_session->last_data_len[other_dir] > 0) {
            tcp_session->expected_seq[other_dir] = acknum;
            sasc_log_debug("Pure ACK processing: dir=%u, acknum=%u, updated expected_seq[%u]=%u",
                           dir, acknum, other_dir, acknum);
        }
    }

    // Update tracking state
    tcp_session->last_seq[dir] = seqnum;
    tcp_session->last_ack[dir] = acknum;
    tcp_session->last_pkt_time[dir] = current_time;
    tcp_session->last_flags[dir] = flags;
    tcp_session->last_data_len[dir] = data_len;
    tcp_session->last_window[dir] = window_size;

    // Update expected_seq[dir] if this packet carries data
    if (data_len > 0) {
        tcp_session->expected_seq[dir] = seqnum + data_len;
        sasc_log_debug("Data packet: dir=%u, seq=%u, data_len=%u, updated expected_seq[%u]=%u", dir,
                       seqnum, data_len, dir, tcp_session->expected_seq[dir]);
    }
}

/**
 * Initialize or reset TCP session state
 *
 * This function handles session initialization and reset logic,
 * including version mismatch detection and default threshold setup.
 *
 * @param tcp_session TCP session state
 * @param session SASC session
 * @param flags TCP flags from current packet
 * @return 0 on success, -1 if session should be blocked
 */
static_always_inline int
init_tcp_session(sasc_tcp_check_session_state_t *tcp_session, sasc_session_t *session, u8 flags) {
    /* Reset session state if version mismatch */
    clib_memset(tcp_session, 0, sizeof(*tcp_session));
    tcp_session->version = session->session_version;

    /* Initialize configurable thresholds with defaults */
    tcp_session->retransmit_threshold = 0.1; // 100ms default
    tcp_session->reorder_tolerance = 100000; // Default tolerance

    if (flags != SASC_TCP_CHECK_TCP_FLAGS_SYN) {
        /* Abnormal, put the session in blocked state */
        sasc_log_warn("Session starts with non-SYN packet");
        tcp_session->flags = SASC_TCP_CHECK_SESSION_FLAG_BLOCKED;
        return -1;
    }

    return 0;
}

/**
 * Process TCP flags and update session state flags
 *
 * This function handles the state machine transitions based on TCP flags
 * and direction. It processes SYN, ACK, FIN, and RST flags according to
 * the TCP state machine rules.
 *
 * @param tcp_session TCP session state
 * @param session SASC session
 * @param dir Packet direction (forward/reverse)
 * @param flags TCP flags
 * @param seqnum TCP sequence number
 * @param acknum TCP acknowledgment number
 * @param sf Current state flags
 * @param nsf New state flags (output)
 * @param remove_session Session removal flag (output)
 * @return 0 on success, -1 if session should be removed
 */
static_always_inline int
process_tcp_flags(sasc_tcp_check_session_state_t *tcp_session, sasc_session_t *session, u8 dir,
                  u8 flags, u32 seqnum, u32 acknum, u32 sf, u32 *nsf, u8 *remove_session) {
    *nsf = sf;
    *remove_session = 0;

    if (dir == SASC_FLOW_FORWARD) {
        if (sf & SASC_TCP_CHECK_SESSION_FLAG_BLOCKED)
            return 0;

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_SYN) {
            /* New session, must be a SYN otherwise bad */
            if (sf == 0) {
                *nsf = SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN |
                       SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN;
            } else {
                tcp_session->unexpected_syn_count++;
                *remove_session = 1;
                return -1;
            }
        }

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) {
            /* Either ACK to SYN */
            if (sf & SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN)
                *nsf &= ~SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN;
            /* Or ACK to FIN */
            if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP &&
                acknum == tcp_session->fin_num[SASC_FLOW_REVERSE])
                *nsf |= SASC_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_INIT;
            else if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP) {
                /* Invalid ACK to FIN - wrong sequence number */
                tcp_session->invalid_fin_ack_count++;
            }
            /* Or regular ACK */
        }

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_FIN) {
            /* If we were up, we are not anymore */
            *nsf &= ~SASC_TCP_CHECK_SESSION_FLAG_ESTABLISHED;
            /* Seen our FIN, wait for the other FIN and for an ACK */
            tcp_session->fin_num[SASC_FLOW_FORWARD] = seqnum + 1;
            *nsf |= SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT;
        }

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_RST) {
            /* Reason to kill the connection */
            tcp_session->protocol_violation_count++;
            *remove_session = 1;
            return -1;
        }
    }

    if (dir == SASC_FLOW_REVERSE) {
        if (sf & SASC_TCP_CHECK_SESSION_FLAG_BLOCKED)
            return 0;

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_SYN) {
            if (sf & SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN) {
                *nsf &= ~SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_SYN;
                *nsf |= SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_INIT_ACK_TO_SYN;
            }
        }

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_ACK) {
            /* Either ACK to SYN */
            if (sf & SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN)
                *nsf &= ~SASC_TCP_CHECK_SESSION_FLAG_WAIT_FOR_RESP_ACK_TO_SYN;
            /* Or ACK to FIN */
            if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT &&
                acknum == tcp_session->fin_num[SASC_FLOW_FORWARD])
                *nsf |= SASC_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_RESP;
            else if (sf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_INIT) {
                /* Invalid ACK to FIN - wrong sequence number */
                tcp_session->invalid_fin_ack_count++;
            }
            /* Or regular ACK */
        }

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_FIN) {
            /* If we were up, we are not anymore */
            *nsf &= ~SASC_TCP_CHECK_SESSION_FLAG_ESTABLISHED;
            /* Seen our FIN, wait for the other FIN and for an ACK */
            tcp_session->fin_num[SASC_FLOW_REVERSE] = seqnum + 1;
            *nsf |= SASC_TCP_CHECK_SESSION_FLAG_SEEN_FIN_RESP;
        }

        if (flags & SASC_TCP_CHECK_TCP_FLAGS_RST) {
            /* Reason to kill the connection */
            tcp_session->protocol_violation_count++;
            *nsf = SASC_TCP_CHECK_SESSION_FLAG_REMOVING;
            *remove_session = 1;
            return -1;
        }
    }

    /* If all flags are cleared connection is established! */
    if (*nsf == 0) {
        *nsf = SASC_TCP_CHECK_SESSION_FLAG_ESTABLISHED;
        /* Set the session state to TCP_ESTABLISHED when 3-way handshake is complete */
        session->state = SASC_SESSION_STATE_TCP_ESTABLISHED;
        sasc_log_debug("TCP session [%u] established after 3-way handshake validation",
                       session - sasc_main.sessions);
    }

    /* If all FINs are ACKED, game over */
    if ((*nsf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_INIT) &&
        (*nsf & SASC_TCP_CHECK_SESSION_FLAG_SEEN_ACK_TO_FIN_RESP)) {
        *nsf = SASC_TCP_CHECK_SESSION_FLAG_REMOVING;
        *remove_session = 1;
        return -1;
    }

    return 0;
}

/**
 * Handle final state transitions and session cleanup
 *
 * This function handles the final state updates and determines if a session
 * should be removed based on the processed flags and state transitions.
 *
 * @param tcp_session TCP session state
 * @param nsf New state flags
 * @param remove_session Session removal flag
 * @param result Processing result from flag processing
 */
static_always_inline void
finalize_session_state(sasc_session_t *session, sasc_tcp_check_session_state_t *tcp_session,
                       u32 nsf, u8 remove_session, int result) {
    /* Update session state */
    tcp_session->flags = nsf;

    if (remove_session || result == -1) {
        sasc_log_debug("Session is being removed");
        session->state = SASC_SESSION_STATE_TCP_TRANSITORY;
    }
}

static_always_inline void
update_state_one_pkt(sasc_tcp_check_main_t *stcm, u32 thread_index, u16 tenant_idx,
                     sasc_tcp_check_session_state_t *tcp_session, sasc_session_t *session,
                     f64 current_time, u8 dir, tcp_header_t *tcp, u32 *sf, u32 *nsf,
                     u32 packet_length) {
    u8 flags = tcp->flags & SASC_TCP_CHECK_TCP_FLAGS_MASK;
    u32 acknum = clib_net_to_host_u32(tcp->ack_number);
    u32 seqnum = clib_net_to_host_u32(tcp->seq_number);
    u8 remove_session = 0;

    /* Handle session version mismatch */
    if (PREDICT_FALSE(tcp_session->version != session->session_version)) {
        if (init_tcp_session(tcp_session, session, flags) == -1) {
            /* Session is blocked, set flags and return */
            *sf = tcp_session->flags;
            *nsf = *sf;
            return;
        }
    }

    /* Initialize state flags */
    *sf = tcp_session->flags;
    *nsf = *sf;

    /* Calculate data length */
    u32 data_len = 0;
    if (packet_length > 0) {
        u8 tcp_hdr_len = ((tcp->data_offset_and_reserved >> 4) & 0xF) * 4;
        const u32 ip_hdr_len = 20; // Assumes no IP options
        if (packet_length > (ip_hdr_len + tcp_hdr_len))
            data_len = packet_length - ip_hdr_len - tcp_hdr_len;
    }

    /* Update RTT stats */
    process_tcp_rtt(tcp_session, current_time, dir, tcp, data_len);

    /* Check for anomalies */
    check_tcp_anomalies(stcm, thread_index, tenant_idx, tcp_session, session, current_time, dir,
                        tcp, packet_length);

    /* Process TCP flags and update state */
    int result = process_tcp_flags(tcp_session, session, dir, flags, seqnum, acknum, *sf, nsf,
                                   &remove_session);

    /* Handle final state transitions and session cleanup */
    finalize_session_state(session, tcp_session, *nsf, remove_session, result);
}

VLIB_NODE_FN(sasc_tcp_check_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame) {

    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
    sasc_main_t *sasc = &sasc_main;
    sasc_tcp_check_main_t *stcm = &sasc_tcp_check_main;
    sasc_session_t *session;
    // sasc_tenant_t *tenant;
    u32 session_idx;
    sasc_tcp_check_session_state_t *tcp_session;
    u32 *from = vlib_frame_vector_args(frame);
    u32 n_left = frame->n_vectors;
    u16 next_indices[VLIB_FRAME_SIZE], *to_next = next_indices;
    u32 state_flags[VLIB_FRAME_SIZE], *sf = state_flags;
    u32 new_state_flags[VLIB_FRAME_SIZE], *nsf = new_state_flags;
    f64 current_time = vlib_time_now(vm);
    u32 thread_index = vlib_get_thread_index();

    vlib_get_buffers(vm, from, bufs, n_left);
    while (n_left > 0) {
        session_idx = sasc_session_from_flow_index(b[0]->flow_id);
        session = sasc_session_at_index(sasc, session_idx);
        tcp_session = vec_elt_at_index(stcm->state, session_idx);
        u32 dir = sasc_direction_from_flow_index(b[0]->flow_id);
        u16 tenant_idx = sasc_buffer(b[0])->tenant_index;
        // tenant = sasc_tenant_at_index(sasc, tenant_idx);
        tcp_header_t *tcp = 0;
        // Check if l4_hdr_offset flag is valid is set
        if (b[0]->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID) {
            tcp = (tcp_header_t *)(b[0]->data + vnet_buffer(b[0])->l4_hdr_offset);
        } else {
            sasc_log_warn("TCP packet received but l4_hdr_offset flag is not valid");
        }
        update_state_one_pkt(stcm, thread_index, tenant_idx, tcp_session, session, current_time,
                             dir, tcp, sf, nsf, b[0]->current_length);
        sasc_next(b[0], to_next);
        n_left -= 1;
        b += 1;
        to_next += 1;
        sf += 1;
        nsf += 1;
    }
    vlib_buffer_enqueue_to_next(vm, node, from, next_indices, frame->n_vectors);
    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
        int i;
        b = bufs;
        sf = state_flags;
        nsf = new_state_flags;
        n_left = frame->n_vectors;
        for (i = 0; i < n_left; i++) {
            if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
                sasc_tcp_check_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
                t->flow_id = b[0]->flow_id;
                t->old_state_flags = sf[0];
                t->new_state_flags = nsf[0];
                b++;
                sf++;
                nsf++;
            } else
                break;
        }
    }
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(sasc_tcp_check_node) = {
    .name = "sasc-tcp-check",
    .vector_size = sizeof(u32),
    .format_trace = format_sasc_tcp_check_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = SASC_TCP_CHECK_N_ERROR,
    .error_counters = sasc_tcp_check_error_counters,
};

SASC_SERVICE_DEFINE(tcp_check) = {
    .node_name = "sasc-tcp-check",
    .protocol_mask = SASC_PROTO_MASK_TCP,
    .format_service = format_sasc_tcp_check_service,
    .format_service_cbor = format_sasc_tcp_check_service_cbor,
};
