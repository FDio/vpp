// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.

#include <vlib/vlib.h>
#include <vnet/buffer.h>
#include <sasc/service.h>
#include <sasc/sasc.h>
#include <sasc/session.h>
#include <vlib/trace_funcs.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <sasc/services/tcp-check/tcp_check.h>
#include "scapy.h"
#include <vnet/ip/ip46_address.h>
#include <vnet/ip/ip_types.h>
#include <sasc/sasc_funcs.h>
#include "test.h"

/* --- Test Registry Structures --- */

clib_error_t *
sasc_unittest_init(vlib_main_t *vm) {
    clib_warning("SASC Unit testing");

    ASSERT(scapy_start() == 0);

    return 0;
}

VLIB_INIT_FUNCTION(sasc_unittest_init) = {
    .runs_after = VLIB_INITS("sasc_init"),
};

/* Helper function to create reverse direction packet */
void
tcp_packet_info_reverse(tcp_packet_info_t *src, tcp_packet_info_t *dst) {
    dst->src_ip = src->dst_ip;
    dst->dst_ip = src->src_ip;
    dst->sport = src->dport;
    dst->dport = src->sport;
    dst->seq_num = src->ack_num;
    dst->ack_num = src->seq_num;
    dst->flags = src->flags;
}

/* -- Table-Driven Test Framework -- */

/* --- Test Case Data Definitions --- */

/* 1. TCP Session Establishment */
static const test_packet_template_t establishment_packets[] = {
    {0x0a000001, 0x0a000002, 12345, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12345, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12345, 80, 1001, 2001, TCP_FLAG_ACK},
};

/* 2. TCP Session Closure */
static const test_packet_template_t closure_packets[] = {
    {0x0a000001, 0x0a000002, 12345, 80, 5000, 4000, TCP_FLAG_FIN | TCP_FLAG_ACK},
    {0x0a000002, 0x0a000001, 80, 12345, 4000, 5001, TCP_FLAG_ACK},
    {0x0a000002, 0x0a000001, 80, 12345, 4000, 5001, TCP_FLAG_FIN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12345, 80, 5001, 4001, TCP_FLAG_ACK},
};

/* 3. TCP Session Reset */
static const test_packet_template_t reset_packets[] = {
    {0x0a000001, 0x0a000002, 12345, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12345, 2000, 1001, TCP_FLAG_RST | TCP_FLAG_ACK},
};

/* 4. TCP Session Data Transfer */
static const test_packet_template_t data_transfer_packets[] = {
    {0x0a000001, 0x0a000002, 12345, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12345, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12345, 80, 1001, 2001, TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12345, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    {0x0a000002, 0x0a000001, 80, 12345, 2001, 1041, TCP_FLAG_ACK},
    {0x0a000002, 0x0a000001, 80, 12345, 2001, 1041, TCP_FLAG_FIN | TCP_FLAG_ACK},
};

/* 5. TCP Session Timeout */
static const test_packet_template_t timeout_packets[] = {
    {0x0a000001, 0x0a000002, 12345, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12345, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12345, 80, 1001, 2001, TCP_FLAG_ACK},
};

/* 6. Multiple TCP Sessions */
static const test_packet_template_t multiple_sessions_packets[] = {
    /* Session 1 */
    {0x0a000001, 0x0a000010, 12345, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000010, 0x0a000001, 80, 12345, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000010, 12345, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Session 2 */
    {0x0a000002, 0x0a000011, 12346, 81, 2000, 0, TCP_FLAG_SYN},
    {0x0a000011, 0x0a000002, 81, 12346, 3000, 2001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000002, 0x0a000011, 12346, 81, 2001, 3001, TCP_FLAG_ACK},
};

/* 7. TCP Retransmit Detection - Basic Retransmit */
static const test_packet_template_t retransmit_basic_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12345, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12345, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12345, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Send data packet */
    {0x0a000001, 0x0a000002, 12345, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Retransmit the same data packet (same seq/ack) */
    {0x0a000001, 0x0a000002, 12345, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
};

/* 8. TCP Retransmit Detection - Multiple Retransmits */
static const test_packet_template_t retransmit_multiple_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12346, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12346, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12346, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Send data packet */
    {0x0a000001, 0x0a000002, 12346, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* First retransmit */
    {0x0a000001, 0x0a000002, 12346, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Second retransmit */
    {0x0a000001, 0x0a000002, 12346, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Third retransmit */
    {0x0a000001, 0x0a000002, 12346, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
};

/* 9. TCP Retransmit Detection - Bidirectional Retransmits */
static const test_packet_template_t retransmit_bidirectional_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12347, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12347, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12347, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Forward direction data */
    {0x0a000001, 0x0a000002, 12347, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Forward direction retransmit */
    {0x0a000001, 0x0a000002, 12347, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Reverse direction data */
    {0x0a000002, 0x0a000001, 80, 12347, 2001, 1041, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Reverse direction retransmit */
    {0x0a000002, 0x0a000001, 80, 12347, 2001, 1041, TCP_FLAG_ACK | TCP_FLAG_PSH},
};

/* 10. TCP Retransmit Detection - No Retransmit (Control Packets) */
static const test_packet_template_t retransmit_control_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12348, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12348, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12348, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Send data packet */
    {0x0a000001, 0x0a000002, 12348, 80, 1041, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Send same SYN again (should not trigger retransmit detection) */
    {0x0a000001, 0x0a000002, 12348, 80, 1000, 0, TCP_FLAG_SYN},
    /* Send same FIN again (should not trigger retransmit detection) */
    {0x0a000001, 0x0a000002, 12348, 80, 5000, 4000, TCP_FLAG_FIN | TCP_FLAG_ACK},
};

/* 11. TCP Retransmit Detection - Normal Progression (No Retransmit) */
static const test_packet_template_t retransmit_normal_progression_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12349, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12349, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12349, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Normal data progression - clearly different sequence numbers */
    {0x0a000001, 0x0a000002, 12349, 80, 1041, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    {0x0a000002, 0x0a000001, 80, 12349, 2001, 1081, TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12349, 80, 1081, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    {0x0a000002, 0x0a000001, 80, 12349, 2001, 1121, TCP_FLAG_ACK},
    /* Continue with more clearly different sequence numbers */
    {0x0a000001, 0x0a000002, 12349, 80, 1121, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    {0x0a000002, 0x0a000001, 80, 12349, 2001, 1161, TCP_FLAG_ACK},
};

/* 12. TCP Reorder Detection - Basic Reorder */
static const test_packet_template_t reorder_basic_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12350, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12350, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12350, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Send first data packet (seq 1001) */
    {0x0a000001, 0x0a000002, 12350, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Send third data packet (seq 1041) - arrives before second packet */
    {0x0a000001, 0x0a000002, 12350, 80, 1041, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Send second data packet (seq 1021) - arrives out of order */
    {0x0a000001, 0x0a000002, 12350, 80, 1021, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
};

/* 13. TCP Reorder Detection - Multiple Reorders */
static const test_packet_template_t reorder_multiple_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12351, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12351, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12351, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Send first data packet (seq 1001) */
    {0x0a000001, 0x0a000002, 12351, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Send fourth data packet (seq 1061) - arrives before second and third */
    {0x0a000001, 0x0a000002, 12351, 80, 1061, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Send second data packet (seq 1021) - arrives out of order */
    {0x0a000001, 0x0a000002, 12351, 80, 1021, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Send third data packet (seq 1041) - arrives out of order */
    {0x0a000001, 0x0a000002, 12351, 80, 1041, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
};

/* 14. TCP Reorder Detection - Bidirectional Reorders */
static const test_packet_template_t reorder_bidirectional_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12352, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12352, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12352, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Forward direction: first packet */
    {0x0a000001, 0x0a000002, 12352, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Forward direction: third packet arrives before second */
    {0x0a000001, 0x0a000002, 12352, 80, 1041, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Forward direction: second packet arrives out of order */
    {0x0a000001, 0x0a000002, 12352, 80, 1021, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Reverse direction: first packet */
    {0x0a000002, 0x0a000001, 80, 12352, 2001, 1041, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Reverse direction: third packet arrives before second */
    {0x0a000002, 0x0a000001, 80, 12352, 2041, 1041, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Reverse direction: second packet arrives out of order */
    {0x0a000002, 0x0a000001, 80, 12352, 2021, 1041, TCP_FLAG_ACK | TCP_FLAG_PSH},
};

static const test_packet_template_t reorder_normal_progression_packets[] = {
    /* 3-way handshake */
    {0x0a000001, 0x0a000002, 12353, 80, 1000, 0, TCP_FLAG_SYN},                   // SYN
    {0x0a000002, 0x0a000001, 80, 12353, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK}, // SYN-ACK
    {0x0a000001, 0x0a000002, 12353, 80, 1001, 2001, TCP_FLAG_ACK},                // ACK

    /* Data packets: 1 byte each */
    {0x0a000001, 0x0a000002, 12353, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH}, // SEQ 1001
    {0x0a000002, 0x0a000001, 80, 12353, 2001, 1002, TCP_FLAG_ACK},                // ACK 1002

    {0x0a000001, 0x0a000002, 12353, 80, 1002, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH}, // SEQ 1002
    {0x0a000002, 0x0a000001, 80, 12353, 2001, 1003, TCP_FLAG_ACK},                // ACK 1003

    {0x0a000001, 0x0a000002, 12353, 80, 1003, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH}, // SEQ 1003
    {0x0a000002, 0x0a000001, 80, 12353, 2001, 1004, TCP_FLAG_ACK},                // ACK 1004
};

/* 16. TCP Data Length Detection - Packets with Actual Data */
static const test_packet_template_t data_length_detection_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12360, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12360, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12360, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Send data packet with actual data (simulated by PSH flag) */
    {0x0a000001, 0x0a000002, 12360, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Send pure ACK packet (no data) */
    {0x0a000002, 0x0a000001, 80, 12360, 2001, 1041, TCP_FLAG_ACK},
    /* Retransmit the data packet */
    {0x0a000001, 0x0a000002, 12360, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
};

/* 17. TCP Window-Based Reorder Detection - Within Window */
static const test_packet_template_t window_reorder_within_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12361, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12361, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12361, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Send first data packet */
    {0x0a000001, 0x0a000002, 12361, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Send third data packet (out of order, but within window) */
    {0x0a000001, 0x0a000002, 12361, 80, 1041, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Send second data packet (the missing one) */
    {0x0a000001, 0x0a000002, 12361, 80, 1021, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
};

/* 18. TCP Window-Based Reorder Detection - Outside Window */
static const test_packet_template_t window_reorder_outside_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12362, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12362, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12362, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Send first data packet */
    {0x0a000001, 0x0a000002, 12362, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Send packet with sequence number far outside window (should be ignored) */
    {0x0a000001, 0x0a000002, 12362, 80, 50000, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Send normal next packet */
    {0x0a000001, 0x0a000002, 12362, 80, 1041, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
};

/* 19. TCP Fast Retransmit Detection */
static const test_packet_template_t fast_retransmit_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12363, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12363, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12363, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Send data packet */
    {0x0a000001, 0x0a000002, 12363, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Fast retransmit (same packet quickly) - window size would be reduced in real scenario */
    {0x0a000001, 0x0a000002, 12363, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Another fast retransmit */
    {0x0a000001, 0x0a000002, 12363, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
};

/* 20. TCP Timeout Retransmit Detection */
static const test_packet_template_t timeout_retransmit_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12364, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12364, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12364, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Send data packet */
    {0x0a000001, 0x0a000002, 12364, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Timeout retransmit (same packet after long delay) - in real scenario this would be > 1 second
     */
    {0x0a000001, 0x0a000002, 12364, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
};

/* 21. TCP Pure ACK Retransmit (Should Not Be Flagged) */
static const test_packet_template_t pure_ack_retransmit_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12365, 80, 1000, 0, TCP_FLAG_SYN},
    {0x0a000002, 0x0a000001, 80, 12365, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK},
    {0x0a000001, 0x0a000002, 12365, 80, 1001, 2001, TCP_FLAG_ACK},
    /* Send data packet */
    {0x0a000001, 0x0a000002, 12365, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH},
    /* Pure ACK packet (no data) */
    {0x0a000002, 0x0a000001, 80, 12365, 2001, 1041, TCP_FLAG_ACK},
    /* Retransmit the same ACK (should not be flagged as retransmit) */
    {0x0a000002, 0x0a000001, 80, 12365, 2001, 1041, TCP_FLAG_ACK},
    /* Another ACK retransmit */
    {0x0a000002, 0x0a000001, 80, 12365, 2001, 1041, TCP_FLAG_ACK},
};

/* 22. TCP Options - MSS and Window Scale */
static const test_packet_template_t tcp_options_mss_wscale_packets[] = {
    /* SYN with MSS and Window Scale options */
    {0x0a000001, 0x0a000002, 12370, 80, 1000, 0, TCP_FLAG_SYN, "('MSS', 1460), ('WScale', 7)"},
    /* SYN-ACK with MSS and Window Scale options */
    {0x0a000002, 0x0a000001, 80, 12370, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK,
     "('MSS', 1460), ('WScale', 8)"},
    /* ACK (no options) */
    {0x0a000001, 0x0a000002, 12370, 80, 1001, 2001, TCP_FLAG_ACK, NULL},
    /* Data packet (no options) */
    {0x0a000001, 0x0a000002, 12370, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH, NULL},
    /* ACK for data (no options) */
    {0x0a000002, 0x0a000001, 80, 12370, 2001, 1041, TCP_FLAG_ACK, NULL},
};

/* 23. TCP Options - Timestamp */
static const test_packet_template_t tcp_options_timestamp_packets[] = {
    /* SYN with Timestamp option */
    {0x0a000001, 0x0a000002, 12371, 80, 1000, 0, TCP_FLAG_SYN, "('Timestamp', (123456789, 0))"},
    /* SYN-ACK with Timestamp option */
    {0x0a000002, 0x0a000001, 80, 12371, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK,
     "('Timestamp', (987654321, 123456789))"},
    /* ACK with Timestamp option */
    {0x0a000001, 0x0a000002, 12371, 80, 1001, 2001, TCP_FLAG_ACK,
     "('Timestamp', (123456790, 987654321))"},
    /* Data packet with Timestamp */
    {0x0a000001, 0x0a000002, 12371, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
     "('Timestamp', (123456791, 987654321))"},
    /* ACK for data with Timestamp */
    {0x0a000002, 0x0a000001, 80, 12371, 2001, 1041, TCP_FLAG_ACK,
     "('Timestamp', (987654322, 123456791))"},
};

/* 24. TCP Options - SACK Permitted */
static const test_packet_template_t tcp_options_sack_packets[] = {
    /* SYN with SACK Permitted option */
    {0x0a000001, 0x0a000002, 12372, 80, 1000, 0, TCP_FLAG_SYN, "('SAckOK', '')"},
    /* SYN-ACK with SACK Permitted option */
    {0x0a000002, 0x0a000001, 80, 12372, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK, "('SAckOK', '')"},
    /* ACK (no options) */
    {0x0a000001, 0x0a000002, 12372, 80, 1001, 2001, TCP_FLAG_ACK, NULL},
    /* Data packet (no options) */
    {0x0a000001, 0x0a000002, 12372, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH, NULL},
    /* ACK for data (no options) */
    {0x0a000002, 0x0a000001, 80, 12372, 2001, 1041, TCP_FLAG_ACK, NULL},
};

/* 25. TCP Options - Multiple Options Combined */
static const test_packet_template_t tcp_options_combined_packets[] = {
    /* SYN with MSS, Window Scale, Timestamp, and SACK options */
    {0x0a000001, 0x0a000002, 12373, 80, 1000, 0, TCP_FLAG_SYN,
     "('MSS', 1460), ('WScale', 7), ('Timestamp', (123456789, 0)), ('SAckOK', '')"},
    /* SYN-ACK with MSS, Window Scale, Timestamp, and SACK options */
    {0x0a000002, 0x0a000001, 80, 12373, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK,
     "('MSS', 1460), ('WScale', 8), ('Timestamp', (987654321, 123456789)), ('SAckOK', '')"},
    /* ACK with Timestamp option */
    {0x0a000001, 0x0a000002, 12373, 80, 1001, 2001, TCP_FLAG_ACK,
     "('Timestamp', (123456790, 987654321))"},
    /* Data packet with Timestamp */
    {0x0a000001, 0x0a000002, 12373, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
     "('Timestamp', (123456791, 987654321))"},
    /* ACK for data with Timestamp */
    {0x0a000002, 0x0a000001, 80, 12373, 2001, 1041, TCP_FLAG_ACK,
     "('Timestamp', (987654322, 123456791))"},
};

#if 0 // SACK building is not supported in Scapy
/* 26. TCP Options - Selective ACK (SACK) */
static const test_packet_template_t tcp_options_selective_ack_packets[] = {
    /* Establish connection */
    {0x0a000001, 0x0a000002, 12374, 80, 1000, 0, TCP_FLAG_SYN, "('SAckOK', '')"},
    {0x0a000002, 0x0a000001, 80, 12374, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK, "('SAckOK', '')"},
    {0x0a000001, 0x0a000002, 12374, 80, 1001, 2001, TCP_FLAG_ACK, NULL},
    /* Send first data packet */
    {0x0a000001, 0x0a000002, 12374, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH, NULL},
    /* Send third data packet (out of order) */
    {0x0a000001, 0x0a000002, 12374, 80, 1041, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH, NULL},
    /* ACK with SACK for received packets */
    {0x0a000002, 0x0a000001, 80, 12374, 2001, 1002, TCP_FLAG_ACK, "('SAck', [(1001, 1002), (1041, 1042)])"},
    /* Send second data packet (the missing one) */
    {0x0a000001, 0x0a000002, 12374, 80, 1021, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH, NULL},
    /* ACK with SACK for all packets */
    {0x0a000002, 0x0a000001, 80, 12374, 2001, 1062, TCP_FLAG_ACK, "('SAck', [(1001, 1002), (1021, 1022), (1041, 1042)])"},
};
#endif
/* 27. TCP Options - Window Scale with Large Window */
static const test_packet_template_t tcp_options_large_window_packets[] = {
    /* SYN with Window Scale option */
    {0x0a000001, 0x0a000002, 12375, 80, 1000, 0, TCP_FLAG_SYN, "('WScale', 14)"},
    /* SYN-ACK with Window Scale option */
    {0x0a000002, 0x0a000001, 80, 12375, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK, "('WScale', 14)"},
    /* ACK (no options) */
    {0x0a000001, 0x0a000002, 12375, 80, 1001, 2001, TCP_FLAG_ACK, NULL},
    /* Data packet with large window advertisement */
    {0x0a000001, 0x0a000002, 12375, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH, NULL},
    /* ACK with large window */
    {0x0a000002, 0x0a000001, 80, 12375, 2001, 1041, TCP_FLAG_ACK, NULL},
};

/* UDP tests */
static const test_packet_template_t udp_basic_packets[] = {
    {0x0a000001, 0x0a000002, 12380, 80, 1000, 0, 0},
    {0x0a000002, 0x0a000001, 80, 12380, 2000, 1001, 0},
    {0x0a000001, 0x0a000002, 12380, 80, 1001, 2001, 0},
};

/* ICMP packet templates */
/* Note: For ICMP packets, flags field is used as: (type << 8) | code */
static const test_packet_template_t icmp_basic_packets[] = {
    /* ICMP Echo Request */
    {.src_ip = 0x0A000001,
     .dst_ip = 0x0A000002,
     .sport = 1234,
     .dport = 5678,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0800}, /* type=8, code=0 */
};

static const test_packet_template_t icmp_multiple_packets[] = {
    /* ICMP Echo Request */
    {.src_ip = 0x0A000001,
     .dst_ip = 0x0A000002,
     .sport = 1234,
     .dport = 5678,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0800}, /* type=8, code=0 */
    /* ICMP Echo Reply */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 5678,
     .dport = 1234,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0000}, /* type=0, code=0 */
};

static const test_packet_template_t icmp_bidirectional_packets[] = {
    /* ICMP Echo Request */
    {.src_ip = 0x0A000001,
     .dst_ip = 0x0A000002,
     .sport = 1234,
     .dport = 5678,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0800}, /* type=8, code=0 */
    /* ICMP Echo Reply */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 5678,
     .dport = 1234,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0000}, /* type=0, code=0 */
    /* ICMP Destination Unreachable */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0300}, /* type=3, code=0 */
};

/* ICMP Error packet templates */
static const test_packet_template_t icmp_ttl_expired_packets[] = {
    /* ICMP Time Exceeded - TTL expired in transit */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0B00}, /* type=11, code=0 */
};

static const test_packet_template_t icmp_packet_too_big_packets[] = {
    /* ICMP Destination Unreachable - Fragmentation needed and DF set */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0304}, /* type=3, code=4 */
};

static const test_packet_template_t icmp_destination_unreachable_packets[] = {
    /* ICMP Destination Unreachable - Network unreachable */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0300}, /* type=3, code=0 */
    /* ICMP Destination Unreachable - Host unreachable */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0301}, /* type=3, code=1 */
    /* ICMP Destination Unreachable - Protocol unreachable */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0302}, /* type=3, code=2 */
    /* ICMP Destination Unreachable - Port unreachable */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0303}, /* type=3, code=3 */
};

static const test_packet_template_t icmp_parameter_problem_packets[] = {
    /* ICMP Parameter Problem */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0C00}, /* type=12, code=0 */
};

static const test_packet_template_t icmp_source_quench_packets[] = {
    /* ICMP Source Quench */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0400}, /* type=4, code=0 */
};

static const test_packet_template_t icmp_redirect_packets[] = {
    /* ICMP Redirect - Network redirect */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0500}, /* type=5, code=0 */
    /* ICMP Redirect - Host redirect */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0501}, /* type=5, code=1 */
};

static const test_packet_template_t icmp_comprehensive_error_packets[] = {
    /* ICMP Echo Request (trigger) */
    {.src_ip = 0x0A000001,
     .dst_ip = 0x0A000002,
     .sport = 1234,
     .dport = 5678,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0800}, /* type=8, code=0 */
    /* ICMP Time Exceeded - TTL expired */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0B00}, /* type=11, code=0 */
    /* ICMP Destination Unreachable - Port unreachable */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0303}, /* type=3, code=3 */
    /* ICMP Destination Unreachable - Fragmentation needed */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0304}, /* type=3, code=4 */
    /* ICMP Parameter Problem */
    {.src_ip = 0x0A000002,
     .dst_ip = 0x0A000001,
     .sport = 0,
     .dport = 0,
     .seq_num = 0,
     .ack_num = 0,
     .flags = 0x0C00}, /* type=12, code=0 */
};

/* --- Generic Test Generation --- */

/* Special handler for timeout test */
static int
post_test_wait_for_timeout(void) {
    clib_warning("Waiting for session timeout...");
    vlib_main_t *vm = vlib_get_main();
    vlib_process_suspend(vm, 2.0); // Wait longer than session timeout
    return 0;                      /* Success */
}

// /* Special handler for retransmit tests - no longer needed since we removed time-based detection
// */ static int post_test_retransmit_delay(void)
// {
//     /* No delay needed - retransmit detection is now immediate */
//     return 0; /* Success */
// }

/* Test registry initialization */
static clib_error_t *
sasc_test_registry_init(vlib_main_t *vm) {
    extern sasc_test_t *__start_sasc_tests;
    extern sasc_test_t *__stop_sasc_tests;

    sasc_test_t **start = &__start_sasc_tests;
    sasc_test_t **stop = &__stop_sasc_tests;

    sasc_test_registry_size = stop - start;
    sasc_test_registry = start;

    clib_warning("SASC Test Registry initialized with %u tests", sasc_test_registry_size);

    return 0;
}

VLIB_INIT_FUNCTION(sasc_test_registry_init) = {
    .runs_after = VLIB_INITS("sasc_unittest_init"),
};

/* --- Test Registration --- */

/* TCP Lifecycle tests */
SASC_TEST_REGISTER_TCP(establishment, "TCP establishment test", establishment_packets, 0);
SASC_TEST_REGISTER_TCP(closure, "TCP closure test", closure_packets, 0);
SASC_TEST_REGISTER_TCP(reset, "TCP reset test", reset_packets, 0);
SASC_TEST_REGISTER_TCP(data_transfer, "TCP data transfer test", data_transfer_packets, 0);
SASC_TEST_REGISTER_TCP(timeout, "TCP timeout test", timeout_packets, post_test_wait_for_timeout);
SASC_TEST_REGISTER_TCP(multiple_sessions, "Multiple TCP sessions test", multiple_sessions_packets,
                       0);

/* Retransmit detection tests */
SASC_TEST_REGISTER_RETRANSMIT(retransmit_basic, "TCP basic retransmit detection test",
                              retransmit_basic_packets, true, 0);
SASC_TEST_REGISTER_RETRANSMIT(retransmit_multiple, "TCP multiple retransmit detection test",
                              retransmit_multiple_packets, true, 0);
SASC_TEST_REGISTER_RETRANSMIT(retransmit_bidirectional,
                              "TCP bidirectional retransmit detection test",
                              retransmit_bidirectional_packets, true, 0);
SASC_TEST_REGISTER_RETRANSMIT(retransmit_control_packets,
                              "TCP control packet retransmit detection test",
                              retransmit_control_packets, false, 0);
SASC_TEST_REGISTER_RETRANSMIT(retransmit_normal_progression,
                              "TCP normal progression retransmit detection test",
                              retransmit_normal_progression_packets, false, 0);

/* Reorder detection tests */
SASC_TEST_REGISTER_REORDER(reorder_basic, "TCP basic reorder detection test", reorder_basic_packets,
                           true, 0);
SASC_TEST_REGISTER_REORDER(reorder_multiple, "TCP multiple reorder detection test",
                           reorder_multiple_packets, true, 0);
SASC_TEST_REGISTER_REORDER(reorder_bidirectional, "TCP bidirectional reorder detection test",
                           reorder_bidirectional_packets, true, 0);
SASC_TEST_REGISTER_REORDER(reorder_normal_progression,
                           "TCP normal progression reorder detection test",
                           reorder_normal_progression_packets, false, 0);

/* Advanced TCP tests */
SASC_TEST_REGISTER_TCP(data_length_detection, "TCP data length detection test",
                       data_length_detection_packets, 0);
SASC_TEST_REGISTER_TCP(window_reorder_within, "TCP window reorder within test",
                       window_reorder_within_packets, 0);
SASC_TEST_REGISTER_TCP(window_reorder_outside, "TCP window reorder outside test",
                       window_reorder_outside_packets, 0);
SASC_TEST_REGISTER_TCP(fast_retransmit, "TCP fast retransmit test", fast_retransmit_packets, 0);
SASC_TEST_REGISTER_TCP(timeout_retransmit, "TCP timeout retransmit test",
                       timeout_retransmit_packets, 0);
SASC_TEST_REGISTER_TCP(pure_ack_retransmit, "TCP pure ACK retransmit test",
                       pure_ack_retransmit_packets, 0);

/* TCP Options tests */
SASC_TEST_REGISTER_TCP(tcp_options_mss_wscale, "TCP MSS and Window Scale options test",
                       tcp_options_mss_wscale_packets, 0);
SASC_TEST_REGISTER_TCP(tcp_options_timestamp, "TCP Timestamp options test",
                       tcp_options_timestamp_packets, 0);
SASC_TEST_REGISTER_TCP(tcp_options_sack, "TCP SACK options test", tcp_options_sack_packets, 0);
SASC_TEST_REGISTER_TCP(tcp_options_combined, "TCP multiple options test",
                       tcp_options_combined_packets, 0);
// SASC_TEST_REGISTER_TCP(tcp_options_selective_ack, "TCP selective ACK test",
// tcp_options_selective_ack_packets, 0);
SASC_TEST_REGISTER_TCP(tcp_options_large_window, "TCP large window test",
                       tcp_options_large_window_packets, 0);

/* UDP tests */
SASC_TEST_REGISTER_UDP(udp_basic, "UDP basic test", udp_basic_packets, 0);
// SASC_TEST_REGISTER_UDP(udp_multiple, "UDP multiple test", udp_multiple_packets, 0);
// SASC_TEST_REGISTER_UDP(udp_bidirectional, "UDP bidirectional test", udp_bidirectional_packets,
// 0); SASC_TEST_REGISTER_UDP(udp_normal_progression, "UDP normal progression test",
// udp_normal_progression_packets, 0);

/* ICMP tests */
SASC_TEST_REGISTER_ICMP(icmp_basic, "ICMP basic test", icmp_basic_packets, 0);
SASC_TEST_REGISTER_ICMP(icmp_multiple, "ICMP multiple test", icmp_multiple_packets, 0);
SASC_TEST_REGISTER_ICMP(icmp_bidirectional, "ICMP bidirectional test", icmp_bidirectional_packets,
                        0);

/* ICMP Error tests */
SASC_TEST_REGISTER_ICMP(icmp_ttl_expired, "ICMP TTL expired test", icmp_ttl_expired_packets, 0);
SASC_TEST_REGISTER_ICMP(icmp_packet_too_big, "ICMP packet too big test",
                        icmp_packet_too_big_packets, 0);
SASC_TEST_REGISTER_ICMP(icmp_destination_unreachable, "ICMP destination unreachable test",
                        icmp_destination_unreachable_packets, 0);
SASC_TEST_REGISTER_ICMP(icmp_parameter_problem, "ICMP parameter problem test",
                        icmp_parameter_problem_packets, 0);
SASC_TEST_REGISTER_ICMP(icmp_source_quench, "ICMP source quench test", icmp_source_quench_packets,
                        0);
SASC_TEST_REGISTER_ICMP(icmp_redirect, "ICMP redirect test", icmp_redirect_packets, 0);
SASC_TEST_REGISTER_ICMP(icmp_comprehensive_error, "ICMP comprehensive error test",
                        icmp_comprehensive_error_packets, 0);
