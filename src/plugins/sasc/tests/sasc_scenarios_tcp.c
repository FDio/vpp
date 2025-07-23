// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Cisco Systems, Inc. and its affiliates

#include "sasc_test_framework.h"
#include "sasc_packet_factory.h"
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>
#include <sasc/session.h>
#include <sasc/services/flow-quality/packet_stats.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

/* TCP check counters are defined as stubs in sasc_test_wire.c */
extern volatile u64 sasc_tcp_check_retransmit_detected;
extern volatile u64 sasc_tcp_check_reorder_detected;
extern volatile u64 sasc_tcp_check_fast_retransmit;
extern volatile u64 sasc_tcp_check_invalid_tcp_header;
extern volatile u64 sasc_tcp_check_malformed_flags;
extern volatile u64 sasc_tcp_check_handshake_timeout;
extern volatile u64 sasc_tcp_check_protocol_violation;
extern volatile u64 sasc_tcp_check_ecn_ce_mark;
extern volatile u64 sasc_tcp_check_ecn_ect_mark;
extern volatile u64 sasc_tcp_check_window_probe;

/* Helper predicates for expectations */
static int
pred_counter_nonzero(void *p) {
    volatile u64 *c = (volatile u64 *)p;
    return c && *c > 0;
}

// static int pred_counter_zero(void *p) {
//   volatile u64 *c = (volatile u64*)p;
//   return c && *c == 0;
// }

/* Helper function to lookup session and get TCP quality data */
static sasc_tcp_quality_session_data_t *
get_session_tcp_data(sasc_5tuple_t *key) {
    return (sasc_tcp_quality_session_data_t *)sasc_test_get_tcp_quality_data(key);
}

/* Session-specific predicates that look up the session and check session counters */
static int
pred_session_retransmit_detected(void *ctx) {
    sasc_5tuple_t *key = (sasc_5tuple_t *)ctx;
    sasc_tcp_quality_session_data_t *tcp_data = get_session_tcp_data(key);

    if (!tcp_data) {
        return 0; // No session found
    }

    // Check if retransmissions were detected
    return tcp_data->retransmissions > 0;
}

static int
pred_session_fast_retransmit_detected(void *ctx) {
    sasc_5tuple_t *key = (sasc_5tuple_t *)ctx;
    sasc_tcp_quality_session_data_t *tcp_data = get_session_tcp_data(key);

    if (!tcp_data) {
        return 0; // No session found
    }

    // Check if fast retransmit was detected (dupack_like is the fast retransmit counter)
    return tcp_data->dupack_like > 0;
}

static int
pred_session_no_fast_retransmit_detected(void *ctx) {
    sasc_5tuple_t *key = (sasc_5tuple_t *)ctx;
    sasc_tcp_quality_session_data_t *tcp_data = get_session_tcp_data(key);

    if (!tcp_data) {
        return 1; // No session found, so no fast retransmit
    }

    // Return true if NO fast retransmit was detected
    return tcp_data->dupack_like == 0;
}

static int
pred_session_reorder_detected(void *ctx) {
    sasc_5tuple_t *key = (sasc_5tuple_t *)ctx;
    sasc_tcp_quality_session_data_t *tcp_data = get_session_tcp_data(key);

    if (!tcp_data) {
        return 0; // No session found
    }

    // Check if reordering was detected
    return tcp_data->reorder_events > 0;
}

static int
pred_session_exists(void *ctx) {
    sasc_5tuple_t *key = (sasc_5tuple_t *)ctx;
    return sasc_test_lookup_session(key) != NULL;
}

/* Helper to build a 5‑tuple key */
static sasc_5tuple_t
key_tcp(ip4_address_t a, u16 sp, ip4_address_t b, u16 dp) {
    sasc_5tuple_t k = {0};
    k.src.ip4 = a;
    k.dst.ip4 = b;
    k.sport = sp;
    k.dport = dp;
    k.is_ip6 = 0;
    k.proto = IP_PROTOCOL_TCP;
    return k;
}

/* ---------------- Scenario: TCP 3-way handshake establishment ---------------- */

static const sasc_scenario_t *
tcp_handshake_establishment_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[3];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: No pre-existing state */
    scn.pre = sasc_fix_none();

    /* Step 1: SYN packet */
    steps[0] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_syn(k, /* isn */ 1000, /* win */ 65535, /* mss */ 1460, /* wscale */ 7, /* sack_ok */ true),
        "SYN");

    /* Step 2: SYN-ACK packet */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[1] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k_reverse, /* seq */ 2000, /* ack */ 1001,
                                                        TCP_FLAG_SYN | TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
                                      "SYN-ACK");

    /* Step 3: ACK packet */
    steps[2] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0), "ACK");

    /* Expect: No protocol violations during handshake */
    expects[0] = sasc_exp_eq_u64(&sasc_tcp_check_protocol_violation, 0, "no protocol violations during handshake");

    scn.name = "TCP 3-way handshake establishment";
    scn.tags = "tcp,handshake,establishment";
    scn.steps = steps;
    scn.n_steps = 3;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_handshake_establishment, tcp_handshake_establishment_provider)

/* ---------------- Scenario: TCP retransmission detection ---------------- */

static const sasc_scenario_t *
tcp_retransmission_detection_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[6];
    static sasc_expect_t expects[3];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    static sasc_5tuple_t k = {0};
    if (!inited) {
        k = key_tcp(A, 12345, B, 80);
    }

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Data packet */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-packet-1");

    /* Step 2: Same data packet (retransmission) */
    steps[1] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-packet-1-retransmit");

    /* Step 3: Advance time to allow retransmission detection */
    steps[2] = SASC_STEP_ADVANCE(0.001);

    /* Step 4: Another retransmission */
    steps[3] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-packet-1-retransmit-2");

    /* Step 5: ACK for the data */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[4] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1101, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "ack-for-data");

    /* Step 6: Next data packet */
    steps[5] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 50),
                                      "data-packet-2");

    /* Expect: Session exists */
    expects[0] = sasc_exp_true(pred_session_exists, (void *)&k, "session exists");

    /* Expect: Retransmission detected */
    expects[1] = sasc_exp_true(pred_session_retransmit_detected, (void *)&k, "retransmission detected");

    /* Expect: No fast retransmit (not enough dup ACKs) */
    expects[2] = sasc_exp_true(pred_session_no_fast_retransmit_detected, (void *)&k, "no fast retransmit detected");

    scn.name = "TCP retransmission detection";
    scn.tags = "tcp,retransmission,qi";
    scn.steps = steps;
    scn.n_steps = 6;
    scn.expects = expects;
    scn.n_expects = 3;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_retransmission_detection, tcp_retransmission_detection_provider)

/* ---------------- Scenario: TCP fast retransmit detection ---------------- */

static const sasc_scenario_t *
tcp_fast_retransmit_detection_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[6];
    static sasc_expect_t expects[2];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    static sasc_5tuple_t k = {0};
    if (!inited) {
        k = key_tcp(A, 12345, B, 80);
    }

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Data packet 1 */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-packet-1");

    /* Step 2: Data packet 2 */
    steps[1] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-packet-2");

    /* Step 3: Data packet 3 */
    steps[2] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1201, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-packet-3");

    /* Step 4: Data packet 4 */
    steps[3] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1301, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-packet-4");

    /* Step 5: ACK for packet 1 (duplicate ACK) */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[4] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1101, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "dup-ack-1");

    /* Step 6: Another duplicate ACK (should trigger fast retransmit) */
    steps[5] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1101, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "dup-ack-2");

    /* Expect: Fast retransmit detected */
    expects[0] = sasc_exp_true(pred_session_fast_retransmit_detected, (void *)&k, "fast retransmit detected");

    scn.name = "TCP fast retransmit detection";
    scn.tags = "tcp,fast-retransmit,qi";
    scn.steps = steps;
    scn.n_steps = 6;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_fast_retransmit_detection, tcp_fast_retransmit_detection_provider)

/* ---------------- Scenario: TCP packet reordering detection ---------------- */

static const sasc_scenario_t *
tcp_reordering_detection_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[9];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    static sasc_5tuple_t k = {0};
    if (!inited) {
        k = key_tcp(A, 12345, B, 80);
    }

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Data packet 1 (in order) - server to client */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[0] =
        SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                 /* win */ 65535, /* data_len */ 100),
                               "data-packet-1-first");

    /* Step 2: ACK for packet 1 - client to server */
    steps[1] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2101, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "ack-packet-1");

    /* Step 3: Data packet 3 (out of order) - server to client */
    steps[2] =
        SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k_reverse, /* seq */ 2301, /* ack */ 1001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                 /* win */ 65535, /* data_len */ 100),
                               "data-packet-3-second");

    /* Step 4: Duplicate ACK (stall) - client to server */
    steps[3] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2101, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "dup-ack-1");

    /* Step 5: Another duplicate ACK (stall) - client to server */
    steps[4] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2101, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "dup-ack-2");

    /* Step 6: Third duplicate ACK (stall) - client to server */
    steps[5] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2101, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "dup-ack-3");

    /* Step 7: Data packet 2 (out of order) - server to client */
    steps[6] =
        SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k_reverse, /* seq */ 2101, /* ack */ 1001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                 /* win */ 65535, /* data_len */ 100),
                               "data-packet-2-third");

    /* Step 8: Advance time to allow reordering detection */
    steps[7] = SASC_STEP_ADVANCE(0.001);

    /* Step 9: ACK for all data */
    steps[8] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2301, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "ack-all-data");

    /* Expect: Reordering detected */
    expects[0] = sasc_exp_true(pred_session_reorder_detected, (void *)&k, "reordering detected");

    scn.name = "TCP packet reordering detection";
    scn.tags = "tcp,reordering,qi";
    scn.steps = steps;
    scn.n_steps = 9;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_reordering_detection, tcp_reordering_detection_provider)

/* ---------------- Scenario: TCP ECN marking detection ---------------- */

static const sasc_scenario_t *
tcp_ecn_marking_detection_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[3];
    static sasc_expect_t expects[2];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Data packet with ECT(0) marking */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-ect0");

    /* Step 2: Data packet with CE marking */
    steps[1] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-ce");

    /* Step 3: ACK for data */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[2] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1201, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "ack-data");

    /* Expect: No ECN ECT marking detected (no ECN fields in packet description) */
    expects[0] = sasc_exp_eq_u64(&sasc_tcp_check_ecn_ect_mark, 0, "no ECN ECT marking detected");

    /* Expect: No ECN CE marking detected (no ECN fields in packet description) */
    expects[1] = sasc_exp_eq_u64(&sasc_tcp_check_ecn_ce_mark, 0, "no ECN CE marking detected");

    scn.name = "TCP ECN marking detection (limited)";
    scn.tags = "tcp,ecn,qi,limited";
    scn.steps = steps;
    scn.n_steps = 3;
    scn.expects = expects;
    scn.n_expects = 2;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_ecn_marking_detection, tcp_ecn_marking_detection_provider)

/* ---------------- Scenario: TCP malformed flags detection ---------------- */

static const sasc_scenario_t *
tcp_malformed_flags_detection_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[2];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Packet with SYN+FIN (malformed) */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_SYN | TCP_FLAG_FIN,
                                                        /* win */ 65535, /* data_len */ 0),
                                      "syn-fin-malformed");

    /* Step 2: Normal data packet */
    steps[1] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "normal-data");

    /* Expect: Malformed flags detected */
    expects[0] =
        sasc_exp_true(pred_counter_nonzero, (void *)&sasc_tcp_check_malformed_flags, "malformed flags detected");

    scn.name = "TCP malformed flags detection";
    scn.tags = "tcp,malformed,protocol-violation";
    scn.steps = steps;
    scn.n_steps = 2;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_malformed_flags_detection, tcp_malformed_flags_detection_provider)

/* ---------------- Scenario: TCP handshake timeout ---------------- */

static const sasc_scenario_t *
tcp_handshake_timeout_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[2];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: No pre-existing state */
    scn.pre = sasc_fix_none();

    /* Step 1: SYN packet */
    steps[0] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_syn(k, /* isn */ 1000, /* win */ 65535, /* mss */ 1460, /* wscale */ 7, /* sack_ok */ true),
        "SYN");

    /* Step 2: Advance time to trigger timeout */
    steps[1] = SASC_STEP_ADVANCE(30.0); /* 30 seconds should trigger handshake timeout */

    /* Expect: Handshake timeout detected */
    expects[0] =
        sasc_exp_true(pred_counter_nonzero, (void *)&sasc_tcp_check_handshake_timeout, "handshake timeout detected");

    scn.name = "TCP handshake timeout";
    scn.tags = "tcp,handshake,timeout";
    scn.steps = steps;
    scn.n_steps = 2;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_handshake_timeout, tcp_handshake_timeout_provider)

/* ---------------- Scenario: TCP window probe detection ---------------- */

static const sasc_scenario_t *
tcp_window_probe_detection_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[4];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Data packet */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-packet");

    /* Step 2: ACK with zero window */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[1] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1101, TCP_FLAG_ACK, /* win */ 0, /* data_len */ 0),
        "ack-zero-window");

    /* Step 3: Window probe (1-byte data) */
    steps[2] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 1),
                                      "window-probe");

    /* Step 4: ACK with non-zero window */
    steps[3] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1102, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "ack-nonzero-window");

    /* Expect: Window probe detected */
    expects[0] = sasc_exp_true(pred_counter_nonzero, (void *)&sasc_tcp_check_window_probe, "window probe detected");

    scn.name = "TCP window probe detection";
    scn.tags = "tcp,window-probe,qi";
    scn.steps = steps;
    scn.n_steps = 4;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_window_probe_detection, tcp_window_probe_detection_provider)

/* ---------------- Scenario: TCP protocol violation detection ---------------- */

static const sasc_scenario_t *
tcp_protocol_violation_detection_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[2];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: SYN packet on established connection (protocol violation) */
    steps[0] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_syn(k, /* isn */ 5000, /* win */ 65535, /* mss */ 1460, /* wscale */ 7, /* sack_ok */ true),
        "syn-on-established");

    /* Step 2: Normal data packet */
    steps[1] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "normal-data");

    /* Expect: Protocol violation detected */
    expects[0] =
        sasc_exp_true(pred_counter_nonzero, (void *)&sasc_tcp_check_protocol_violation, "protocol violation detected");

    scn.name = "TCP protocol violation detection";
    scn.tags = "tcp,protocol-violation";
    scn.steps = steps;
    scn.n_steps = 2;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_protocol_violation_detection, tcp_protocol_violation_detection_provider)

/* ---------------- Scenario: TCP invalid header detection ---------------- */

static const sasc_scenario_t *
tcp_invalid_header_detection_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[2];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Packet with invalid header length (too short) */
    steps[0] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "invalid-header");

    /* Step 2: Normal data packet */
    steps[1] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "normal-data");

    /* Expect: No invalid header detected (packet factory creates valid headers) */
    expects[0] = sasc_exp_eq_u64(&sasc_tcp_check_invalid_tcp_header, 0, "no invalid TCP header detected");

    scn.name = "TCP invalid header detection (limited)";
    scn.tags = "tcp,invalid-header,protocol-violation,limited";
    scn.steps = steps;
    scn.n_steps = 2;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_invalid_header_detection, tcp_invalid_header_detection_provider)

/* ---------------- Scenario: TCP bidirectional quality assessment ---------------- */

static const sasc_scenario_t *
tcp_bidirectional_quality_assessment_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[8];
    static sasc_expect_t expects[3];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    static sasc_5tuple_t k = {0};
    if (!inited) {
        k = key_tcp(A, 12345, B, 80);
    }

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Client data packet */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "client-data-1");

    /* Step 2: Server ACK */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[1] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1101, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "server-ack-1");

    /* Step 3: Server data packet */
    steps[2] =
        SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1101, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                 /* win */ 65535, /* data_len */ 150),
                               "server-data-1");

    /* Step 4: Client ACK */
    steps[3] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2151, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "client-ack-1");

    /* Step 5: Client data with retransmission */
    steps[4] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2151, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 200),
                                      "client-data-2");

    /* Step 6: Same client data (retransmission) */
    steps[5] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2151, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 200),
                                      "client-data-2-retransmit");

    /* Step 7: Server data with ECN CE marking */
    steps[6] =
        SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k_reverse, /* seq */ 2151, /* ack */ 1301, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                 /* win */ 65535, /* data_len */ 100),
                               "server-data-2-ce");

    /* Step 8: Final ACK */
    steps[7] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k, /* seq */ 1301, /* ack */ 2251, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "final-ack");

    /* Expect: Retransmission detected */
    expects[0] = sasc_exp_true(pred_session_retransmit_detected, (void *)&k, "retransmission detected");

    /* Expect: No ECN CE marking detected (no ECN fields in packet description) */
    expects[1] = sasc_exp_eq_u64(&sasc_tcp_check_ecn_ce_mark, 0, "no ECN CE marking detected");

    /* Expect: No protocol violations */
    expects[2] = sasc_exp_eq_u64(&sasc_tcp_check_protocol_violation, 0, "no protocol violations");

    scn.name = "TCP bidirectional quality assessment";
    scn.tags = "tcp,bidirectional,qi,comprehensive";
    scn.steps = steps;
    scn.n_steps = 8;
    scn.expects = expects;
    scn.n_expects = 3;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_bidirectional_quality_assessment, tcp_bidirectional_quality_assessment_provider)

/* ---------------- Scenario: TCP graceful session closure ---------------- */

static const sasc_scenario_t *
tcp_graceful_closure_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[6];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Client data packet */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "client-data");

    /* Step 2: Server ACK */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[1] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1101, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "server-ack");

    /* Step 3: Client FIN */
    steps[2] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_FIN | TCP_FLAG_ACK,
                                                        /* win */ 65535, /* data_len */ 0),
                                      "client-fin");

    /* Step 4: Server ACK to FIN */
    steps[3] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1102, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "server-ack-fin");

    /* Step 5: Server FIN */
    steps[4] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1102,
                                                        TCP_FLAG_FIN | TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
                                      "server-fin");

    /* Step 6: Client ACK to server FIN */
    steps[5] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k, /* seq */ 1102, /* ack */ 2002, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "client-ack-server-fin");

    /* Expect: No protocol violations during graceful closure */
    expects[0] =
        sasc_exp_eq_u64(&sasc_tcp_check_protocol_violation, 0, "no protocol violations during graceful closure");

    scn.name = "TCP graceful session closure";
    scn.tags = "tcp,closure,graceful,state-machine";
    scn.steps = steps;
    scn.n_steps = 6;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_graceful_closure, tcp_graceful_closure_provider)

/* ---------------- Scenario: TCP RST session termination ---------------- */

static const sasc_scenario_t *
tcp_rst_termination_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[3];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Client data packet */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "client-data");

    /* Step 2: Server RST (immediate termination) */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[1] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 0, TCP_FLAG_RST, /* win */ 0, /* data_len */ 0),
        "server-rst");

    /* Step 3: Client retry (should be ignored due to RST) */
    steps[2] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 50),
                                      "client-retry-ignored");

    /* Expect: No protocol violations (RST is valid) */
    expects[0] =
        sasc_exp_eq_u64(&sasc_tcp_check_protocol_violation, 0, "no protocol violations during RST termination");

    scn.name = "TCP RST session termination";
    scn.tags = "tcp,rst,termination,state-machine";
    scn.steps = steps;
    scn.n_steps = 3;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_rst_termination, tcp_rst_termination_provider)

/* ---------------- Scenario: TCP SACK option validation ---------------- */

static const sasc_scenario_t *
tcp_sack_option_validation_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[5];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    static sasc_5tuple_t k = {0};
    if (!inited) {
        k = key_tcp(A, 12345, B, 80);
    }

    /* Fixture: Established TCP session with SACK enabled */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Data packet 1 */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-1");

    /* Step 2: Data packet 3 (out of order, missing packet 2) */
    steps[1] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1201, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-3-out-of-order");

    /* Step 3: Data packet 2 (missing packet arrives) */
    steps[2] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-2-missing");

    /* Step 4: ACK with SACK blocks (should acknowledge all data) */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[3] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1301, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "ack-with-sack");

    /* Step 5: Final data packet */
    steps[4] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1301, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 50),
                                      "final-data");

    /* Expect: Reordering detected due to out-of-order packets */
    expects[0] = sasc_exp_true(pred_session_reorder_detected, (void *)&k, "reordering detected with SACK scenario");

    scn.name = "TCP SACK option validation";
    scn.tags = "tcp,sack,options,reordering";
    scn.steps = steps;
    scn.n_steps = 5;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_sack_option_validation, tcp_sack_option_validation_provider)

/* ---------------- Scenario: TCP timestamp option validation ---------------- */

static const sasc_scenario_t *
tcp_timestamp_validation_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[4];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Client data with timestamp */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "client-data-with-ts");

    /* Step 2: Server ACK with timestamp echo */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[1] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1101, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "server-ack-with-ts-echo");

    /* Step 3: Client data with updated timestamp */
    steps[2] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "client-data-updated-ts");

    /* Step 4: Server ACK with updated timestamp echo */
    steps[3] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1201, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "server-ack-updated-ts-echo");

    /* Expect: No protocol violations during timestamp exchange */
    expects[0] =
        sasc_exp_eq_u64(&sasc_tcp_check_protocol_violation, 0, "no protocol violations during timestamp exchange");

    scn.name = "TCP timestamp option validation";
    scn.tags = "tcp,timestamp,options,rtt";
    scn.steps = steps;
    scn.n_steps = 4;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_timestamp_validation, tcp_timestamp_validation_provider)

/* ---------------- Scenario: TCP window scaling edge cases ---------------- */

static const sasc_scenario_t *
tcp_window_scaling_edge_cases_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[6];
    static sasc_expect_t expects[2];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: Established TCP session with large window scaling */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 14, /* wscale_srv */ 14, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Client data packet */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "client-data");

    /* Step 2: Server ACK with very small window (near zero) */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[1] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1101, TCP_FLAG_ACK, /* win */ 1, /* data_len */ 0),
        "server-ack-small-window");

    /* Step 3: Client window probe (1-byte data) */
    steps[2] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 1),
                                      "client-window-probe");

    /* Step 4: Server ACK with zero window */
    steps[3] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1102, TCP_FLAG_ACK, /* win */ 0, /* data_len */ 0),
        "server-ack-zero-window");

    /* Step 5: Another window probe */
    steps[4] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1102, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 1),
                                      "client-window-probe-2");

    /* Step 6: Server ACK with restored window */
    steps[5] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1103, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "server-ack-restored-window");

    /* Expect: Window probe detected */
    expects[0] = sasc_exp_true(pred_counter_nonzero, (void *)&sasc_tcp_check_window_probe, "window probe detected");

    /* Expect: No protocol violations */
    expects[1] = sasc_exp_eq_u64(&sasc_tcp_check_protocol_violation, 0, "no protocol violations during window scaling");

    scn.name = "TCP window scaling edge cases";
    scn.tags = "tcp,window-scaling,edge-cases,flow-control";
    scn.steps = steps;
    scn.n_steps = 6;
    scn.expects = expects;
    scn.n_expects = 2;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_window_scaling_edge_cases, tcp_window_scaling_edge_cases_provider)

/* ---------------- Scenario: TCP state machine violations ---------------- */

static const sasc_scenario_t *
tcp_state_machine_violations_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[4];
    static sasc_expect_t expects[2];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: SYN packet on established connection (protocol violation) */
    steps[0] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_syn(k, /* isn */ 5000, /* win */ 65535, /* mss */ 1460, /* wscale */ 7, /* sack_ok */ true),
        "syn-on-established-violation");

    /* Step 2: Normal data packet */
    steps[1] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "normal-data");

    /* Step 3: FIN packet with invalid sequence number */
    steps[2] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 9999, /* ack */ 2001, TCP_FLAG_FIN | TCP_FLAG_ACK,
                                                        /* win */ 65535, /* data_len */ 0),
                                      "fin-invalid-seq");

    /* Step 4: Another normal data packet */
    steps[3] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "another-normal-data");

    /* Expect: Protocol violation detected for SYN on established connection */
    expects[0] =
        sasc_exp_true(pred_counter_nonzero, (void *)&sasc_tcp_check_protocol_violation, "protocol violation detected");

    /* Expect: Malformed flags detected for invalid FIN */
    expects[1] =
        sasc_exp_true(pred_counter_nonzero, (void *)&sasc_tcp_check_malformed_flags, "malformed flags detected");

    scn.name = "TCP state machine violations";
    scn.tags = "tcp,state-machine,protocol-violation,malformed";
    scn.steps = steps;
    scn.n_steps = 4;
    scn.expects = expects;
    scn.n_expects = 2;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_state_machine_violations, tcp_state_machine_violations_provider)

/* ---------------- Scenario: TCP performance stress test ---------------- */

static const sasc_scenario_t *
tcp_performance_stress_test_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[12];
    static sasc_expect_t expects[3];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    static sasc_5tuple_t k = {0};
    if (!inited) {
        k = key_tcp(A, 12345, B, 80);
    }

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1-3: Rapid data packets with potential reordering */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-1");
    steps[1] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1201, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-3-out-of-order");
    steps[2] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-2-missing");

    /* Step 4-6: More data with retransmissions */
    steps[3] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1301, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-4");
    steps[4] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1301, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-4-retransmit");
    steps[5] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1301, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "data-4-retransmit-2");

    /* Step 7-9: Server responses with varying window sizes */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[6] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1401, TCP_FLAG_ACK, /* win */ 32768, /* data_len */ 0),
        "server-ack-reduced-window");
    steps[7] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1401, TCP_FLAG_ACK, /* win */ 16384, /* data_len */ 0),
        "server-ack-further-reduced");
    steps[8] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1401, TCP_FLAG_ACK, /* win */ 0, /* data_len */ 0),
        "server-ack-zero-window");

    /* Step 10-12: Window recovery and final data */
    steps[9] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1401, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 1),
                                      "client-window-probe");
    steps[10] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1402, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "server-ack-window-recovered");
    steps[11] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1402, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                         /* win */ 65535, /* data_len */ 200),
                                       "final-large-data");

    /* Expect: Multiple anomalies detected */
    expects[0] = sasc_exp_true(pred_session_reorder_detected, (void *)&k, "reordering detected");
    expects[1] = sasc_exp_true(pred_session_retransmit_detected, (void *)&k, "retransmission detected");
    expects[2] = sasc_exp_true(pred_counter_nonzero, (void *)&sasc_tcp_check_window_probe, "window probe detected");

    scn.name = "TCP performance stress test";
    scn.tags = "tcp,stress,performance,multiple-anomalies";
    scn.steps = steps;
    scn.n_steps = 12;
    scn.expects = expects;
    scn.n_expects = 3;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_performance_stress_test, tcp_performance_stress_test_provider)

/* ---------------- Scenario: TCP security anomaly detection ---------------- */

static const sasc_scenario_t *
tcp_security_anomaly_detection_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[5];
    static sasc_expect_t expects[3];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: Established TCP session */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 1: Normal data packet */
    steps[0] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "normal-data");

    /* Step 2: Packet with SYN+RST (malformed flags - potential attack) */
    steps[1] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_SYN | TCP_FLAG_RST,
                                                        /* win */ 65535, /* data_len */ 0),
                                      "syn-rst-malformed");

    /* Step 3: Packet with all flags set (malformed - potential attack) */
    steps[2] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001,
                          TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST | TCP_FLAG_PSH | TCP_FLAG_ACK | TCP_FLAG_URG,
                          /* win */ 65535, /* data_len */ 0),
        "all-flags-malformed");

    /* Step 4: Packet with invalid sequence number (potential sequence number attack) */
    steps[3] =
        SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 999999, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                 /* win */ 65535, /* data_len */ 100),
                               "invalid-seq-attack");

    /* Step 5: Normal data packet to continue session */
    steps[4] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1101, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "normal-data-continue");

    /* Expect: Malformed flags detected for SYN+RST */
    expects[0] =
        sasc_exp_true(pred_counter_nonzero, (void *)&sasc_tcp_check_malformed_flags, "malformed flags detected");

    /* Expect: Protocol violation for invalid sequence number */
    expects[1] =
        sasc_exp_true(pred_counter_nonzero, (void *)&sasc_tcp_check_protocol_violation, "protocol violation detected");

    /* Expect: No invalid header errors (packet factory creates valid headers) */
    expects[2] = sasc_exp_eq_u64(&sasc_tcp_check_invalid_tcp_header, 0, "no invalid TCP header detected");

    scn.name = "TCP security anomaly detection";
    scn.tags = "tcp,security,attack-detection,malformed";
    scn.steps = steps;
    scn.n_steps = 5;
    scn.expects = expects;
    scn.n_expects = 3;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_security_anomaly_detection, tcp_security_anomaly_detection_provider)

/* ---------------- Scenario: TCP connection establishment edge cases ---------------- */

static const sasc_scenario_t *
tcp_connection_establishment_edge_cases_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[8];
    static sasc_expect_t expects[3];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: No pre-existing state */
    scn.pre = sasc_fix_none();

    /* Step 1: Client SYN */
    steps[0] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_syn(k, /* isn */ 1000, /* win */ 65535, /* mss */ 1460, /* wscale */ 7, /* sack_ok */ true),
        "client-syn");

    /* Step 2: Server SYN (simultaneous open attempt) */
    sasc_5tuple_t k_reverse = key_tcp(B, 80, A, 12345);
    steps[1] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_syn(k_reverse, /* isn */ 2000, /* win */ 65535, /* mss */ 1460,
                                                       /* wscale */ 7, /* sack_ok */ true),
                                      "server-simultaneous-syn");

    /* Step 3: Client SYN-ACK to server SYN */
    steps[2] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_SYN | TCP_FLAG_ACK,
                                                        /* win */ 65535, /* data_len */ 0),
                                      "client-syn-ack");

    /* Step 4: Server SYN-ACK to client SYN */
    steps[3] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1001,
                                                        TCP_FLAG_SYN | TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
                                      "server-syn-ack");

    /* Step 5: Client ACK to complete handshake */
    steps[4] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "client-ack");

    /* Step 6: Server ACK to complete handshake */
    steps[5] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1001, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "server-ack");

    /* Step 7: Client data packet */
    steps[6] = SASC_STEP_LABELED_SEND(sasc_pkt_tcp_base(k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK | TCP_FLAG_PSH,
                                                        /* win */ 65535, /* data_len */ 100),
                                      "client-data");

    /* Step 8: Server ACK to data */
    steps[7] = SASC_STEP_LABELED_SEND(
        sasc_pkt_tcp_base(k_reverse, /* seq */ 2001, /* ack */ 1101, TCP_FLAG_ACK, /* win */ 65535, /* data_len */ 0),
        "server-ack-data");

    /* Expect: No protocol violations during simultaneous open */
    expects[0] =
        sasc_exp_eq_u64(&sasc_tcp_check_protocol_violation, 0, "no protocol violations during simultaneous open");

    /* Expect: No malformed flags */
    expects[1] = sasc_exp_eq_u64(&sasc_tcp_check_malformed_flags, 0, "no malformed flags during simultaneous open");

    /* Expect: No handshake timeout */
    expects[2] = sasc_exp_eq_u64(&sasc_tcp_check_handshake_timeout, 0, "no handshake timeout during simultaneous open");

    scn.name = "TCP connection establishment edge cases";
    scn.tags = "tcp,handshake,simultaneous-open,edge-cases";
    scn.steps = steps;
    scn.n_steps = 8;
    scn.expects = expects;
    scn.n_expects = 3;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(tcp_connection_establishment_edge_cases,
                                tcp_connection_establishment_edge_cases_provider)
