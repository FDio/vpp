// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <sasc/sasc.h>
#include <sasc/sasc_funcs.h>
#include "packet_stats.h"
#include "format.h"

static clib_error_t *
show_packet_stats_session_command_fn(vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd) {
    sasc_main_t *sasc = &sasc_main;
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;
    u32 session_idx = ~0;

    if (unformat(input, "%u", &session_idx)) {
        if (session_idx >= pool_elts(sasc->sessions)) {
            return clib_error_return(0, "Invalid session index %u", session_idx);
        }

        sasc_session_t *session = sasc_session_at_index(sasc, session_idx);
        if (!session) {
            return clib_error_return(0, "Session %u not found", session_idx);
        }

        if (session_idx < vec_len(psm->session_data)) {
            sasc_packet_stats_session_data_t *data = &psm->session_data[session_idx];

            vlib_cli_output(vm, "Session %u Packet Statistics:\n", session_idx);
            vlib_cli_output(vm, "Total Packets: %lu\n", data->total_packets);
            vlib_cli_output(vm, "Total Bytes: %lu\n", data->total_bytes);
            vlib_cli_output(vm, "Flow Duration: %lu ns\n", data->flow_duration_ns);

            u8 *s = 0;
            s = format_protocol_stats(s, data);
            vlib_cli_output(vm, "%v", s);
            vec_reset_length(s);

            s = format_packet_size_histogram(s, data->size_buckets);
            vlib_cli_output(vm, "%v", s);
            vec_reset_length(s);

            s = format_gap_histogram(s, data->gap_buckets);
            vlib_cli_output(vm, "%v", s);
            vec_reset_length(s);

            s = format_vector_size_histogram(s, data->vector_size_buckets);
            vlib_cli_output(vm, "%v", s);
            vec_reset_length(s);

            if (data->inter_packet_samples > 0) {
                s = format_timing_stats(s, data);
                vlib_cli_output(vm, "%v", s);
                vec_reset_length(s);
            }

            s = format_rate_stats(s, data);
            vlib_cli_output(vm, "%v", s);
            vec_reset_length(s);

            vec_free(s);
        } else {
            vlib_cli_output(vm, "No packet statistics available for session %u\n", session_idx);
        }
    } else {
        return clib_error_return(0, "Please specify a session index");
    }

    return 0;
}

VLIB_CLI_COMMAND(show_packet_stats_session_command, static) = {
    .path = "show sasc packet-stats session",
    .short_help = "show sasc packet-stats session <session-index>",
    .function = show_packet_stats_session_command_fn,
};

static clib_error_t *
show_packet_stats_summary_command_fn(vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd) {
    // sasc_main_t *sasc = &sasc_main;
    sasc_packet_stats_main_t *psm = &sasc_packet_stats_main;

    u64 total_packets = 0;
    u64 total_bytes = 0;
    u64 total_tcp = 0;
    u64 total_udp = 0;
    u64 total_icmp = 0;
    u64 total_other = 0;
    u64 active_sessions = 0;

    for (u32 i = 0; i < vec_len(psm->session_data); i++) {
        sasc_packet_stats_session_data_t *data = &psm->session_data[i];
        if (data->total_packets > 0) {
            total_packets += data->total_packets;
            total_bytes += data->total_bytes;
            total_tcp += data->tcp_packets;
            total_udp += data->udp_packets;
            total_icmp += data->icmp_packets;
            total_other += data->other_packets;
            active_sessions++;
        }
    }

    vlib_cli_output(vm, "Packet Statistics Summary:\n");
    vlib_cli_output(vm, "Active Sessions: %lu\n", active_sessions);
    vlib_cli_output(vm, "Total Packets: %lu\n", total_packets);
    vlib_cli_output(vm, "Total Bytes: %lu\n", total_bytes);
    vlib_cli_output(vm, "Protocol Distribution:\n");
    vlib_cli_output(vm, "  TCP: %lu packets\n", total_tcp);
    vlib_cli_output(vm, "  UDP: %lu packets\n", total_udp);
    vlib_cli_output(vm, "  ICMP: %lu packets\n", total_icmp);
    vlib_cli_output(vm, "  Other: %lu packets\n", total_other);

    return 0;
}

VLIB_CLI_COMMAND(show_packet_stats_summary_command, static) = {
    .path = "show sasc packet-stats summary",
    .short_help = "show sasc packet-stats summary",
    .function = show_packet_stats_summary_command_fn,
};