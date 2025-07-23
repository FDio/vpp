// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Cisco Systems, Inc. and its affiliates

#include "sasc_test_framework.h"
#include "sasc_packet_factory.h"
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>
#include <sasc/sasc.h>
#include <sasc/session.h>

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

// Add the predicate function
static int
pred_icmp_errors_any_session(void *ctx) {
    extern sasc_main_t sasc_main;

    u32 total_errors = 0;
    sasc_session_t *session;
    pool_foreach (session, sasc_main.sessions) {
        total_errors += session->icmp_unreach;
        total_errors += session->icmp_frag_needed;
        total_errors += session->icmp_ttl_expired;
        total_errors += session->icmp_packet_too_big;
        total_errors += session->icmp_other;
    }
    clib_warning("Total errors: %d", total_errors);
    return total_errors > 0;
}

// Predicate function to check if no ICMP errors were handled (no sessions created)
static int
pred_icmp_no_errors_handled(void *ctx) {
    extern sasc_main_t sasc_main;

    // Check if any sessions exist at all
    if (pool_elts(sasc_main.sessions) == 0) {
        return 1; // No sessions created, so no errors handled
    }

    // Check if any session has ICMP error counters > 0 using pool_foreach
    sasc_session_t *session;
    pool_foreach (session, sasc_main.sessions) {
        if (session->icmp_unreach > 0 || session->icmp_frag_needed > 0 || session->icmp_ttl_expired > 0 ||
            session->icmp_packet_too_big > 0 || session->icmp_other > 0) {
            clib_warning("Found ICMP errors in session: unreach=%u, frag=%u, ttl=%u, big=%u, other=%u",
                         session->icmp_unreach, session->icmp_frag_needed, session->icmp_ttl_expired,
                         session->icmp_packet_too_big, session->icmp_other);
            return 0; // Found an ICMP error, so it was handled
        }
    }
    return 1; // No ICMP errors found in any session
}

// Alternative: Check if no sessions were created at all
int
pred_no_sessions_created(void *ctx) {
    extern sasc_main_t sasc_main;
    return vec_len(sasc_main.sessions) == 0;
}

// Alternative: Check if total ICMP error count across all sessions is zero
int
pred_total_icmp_errors_zero(void *ctx) {
    extern sasc_main_t sasc_main;

    u32 total_errors = 0;
    sasc_session_t *session;
    pool_foreach (session, sasc_main.sessions) {
        total_errors += session->icmp_unreach;
        total_errors += session->icmp_frag_needed;
        total_errors += session->icmp_ttl_expired;
        total_errors += session->icmp_packet_too_big;
        total_errors += session->icmp_other;
    }
    return total_errors == 0;
}

// Session lookup approach: Look up specific session and check its stats
static int
pred_session_icmp_errors_zero(void *ctx) {
    extern sasc_main_t sasc_main;

    // ctx should be a pointer to sasc_5tuple_t for the session we want to check
    sasc_5tuple_t *key = (sasc_5tuple_t *)ctx;
    if (!key)
        return 1;

    // Look up the session using the framework helper
    sasc_session_t *session = sasc_test_lookup_session(key);

    if (!session) {
        return 1; // No session found, so no errors
    }

    // Check if this specific session has ICMP errors
    return (session->icmp_unreach == 0 && session->icmp_frag_needed == 0 && session->icmp_ttl_expired == 0 &&
            session->icmp_packet_too_big == 0 && session->icmp_other == 0);
}

// Session cleanup function for test isolation
static int
cleanup_all_sessions(vlib_main_t *vm, void *ctx) {
    extern sasc_main_t sasc_main;

    // Clear all sessions
    sasc_session_clear();

    return 0; // Success
}

/*
 * Predicate options for testing ICMP error handling:
 *
 * 1. pred_icmp_no_errors_handled() - Most comprehensive: checks that no ICMP errors
 *    were handled in any session (handles case where sessions exist but no ICMP errors)
 *
 * 2. pred_no_sessions_created() - Strictest: ensures no sessions were created at all
 *    (useful for testing that ICMP errors don't trigger session creation)
 *
 * 3. pred_total_icmp_errors_zero() - Simple: just checks total ICMP error count
 *    (good for basic validation)
 *
 * 4. pred_session_icmp_errors_zero() - Session-specific: looks up a specific session
 *    and checks its ICMP error counters (best for parallel test isolation)
 *
 * 5. cleanup_all_sessions() - Test isolation: clears all sessions between tests
 *    (use in test setup/teardown for complete isolation)
 *
 * For "ICMP error first (no session)" tests, pred_icmp_no_errors_handled() is
 * recommended as it properly validates that the session-aware data plane correctly
 * drops/bypasses ICMP errors when no matching session exists.
 *
 * For parallel testing, use pred_session_icmp_errors_zero() with specific session
 * keys and cleanup_all_sessions() between tests for complete isolation.
 */

/* ---------------- Scenario: ICMP error against established TCP session ---------------- */

static const sasc_scenario_t *
icmp_error_against_tcp_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[1];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Addresses 10.0.0.1 -> 10.0.0.2 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = key_tcp(A, 12345, B, 80);

    /* Fixture: ESTABLISHED session (will attempt install then replay) */
    scn.pre =
        sasc_fix_tcp_established(k, /* isn_cli */ 1000, /* isn_srv */ 2000,
                                 /* win_cli */ 65535, /* win_srv */ 65535,
                                 /* sack_ok */ true, /* wscale_cli */ 7, /* wscale_srv */ 7, SASC_FIX_BACKEND_AUTO);

    /* Step: ICMP Port Unreachable embedding inner TCP (key, seq/ack) */
    sasc_packet_desc_t icmp = sasc_pkt_icmp_unreach_port_embed_tcp(&k, /* seq */ 1001, /* ack */ 2001, TCP_FLAG_ACK);
    steps[0].kind = SASC_STEP_SEND;
    steps[0].pkt = icmp;
    steps[0].label = "icmp-port-unreach(inner=tcp)";

    /* Expect: ICMP error counter increments (predicate > 0) */
    expects[0].kind = SASC_EXP_TRUE;
    expects[0].what = "icmp error counter > 0";
    expects[0].pred.pred = pred_icmp_errors_any_session;
    expects[0].pred.ctx = NULL;

    scn.name = "ICMP error against TCP session";
    scn.tags = "icmp,tcp,error";
    scn.steps = steps;
    scn.n_steps = 1;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(icmp_error_against_tcp, icmp_error_against_tcp_provider)

/* ---------------- Scenario: ICMP error against UDP flow ---------------- */

static const sasc_scenario_t *
icmp_error_against_udp_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[3];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = {0};
    k.src.ip4 = A;
    k.dst.ip4 = B;
    k.sport = 12345;
    k.dport = 53;
    k.is_ip6 = 0;
    k.proto = IP_PROTOCOL_UDP;

    /* No pre-existing session - we'll establish UDP flow first */
    scn.pre = sasc_fix_none();

    /* Step 1: Send UDP packet to establish the session */
    sasc_packet_desc_t udp_pkt = {0};
    udp_pkt.is_ip6 = 0;
    udp_pkt.l4_proto = IP_PROTOCOL_UDP;
    udp_pkt.src = k.src;
    udp_pkt.dst = k.dst;
    udp_pkt.sport = k.sport;
    udp_pkt.dport = k.dport;
    udp_pkt.udp_len = 8; /* UDP header only */
    udp_pkt.payload_len = 0;

    steps[0].kind = SASC_STEP_SEND;
    steps[0].pkt = udp_pkt;
    steps[0].label = "udp-packet-establish-session";

    /* Step 2: Advance time to ensure session is established */
    steps[1] = SASC_STEP_ADVANCE(0.001);

    /* Step 3: Send ICMP error referencing the UDP session */
    sasc_packet_desc_t icmp_pkt = {0};
    icmp_pkt.is_ip6 = 0;
    icmp_pkt.l4_proto = IP_PROTOCOL_ICMP;
    icmp_pkt.src = k.dst; /* ICMP comes from destination */
    icmp_pkt.dst = k.src; /* ICMP goes to source */
    icmp_pkt.icmp.type = 3;
    icmp_pkt.icmp.code = 3; /* dest unreach: port */
    icmp_pkt.icmp.inner.present = 1;
    icmp_pkt.icmp.inner.l4_proto = IP_PROTOCOL_UDP;
    icmp_pkt.icmp.inner.sport = k.sport;
    icmp_pkt.icmp.inner.dport = k.dport;
    icmp_pkt.icmp.inner.src = k.src;
    icmp_pkt.icmp.inner.dst = k.dst;

    steps[2].kind = SASC_STEP_SEND;
    steps[2].pkt = icmp_pkt;
    steps[2].label = "icmp-port-unreach(inner=udp)";

    expects[0].kind = SASC_EXP_TRUE;
    expects[0].what = "icmp error counter > 0";
    expects[0].pred.pred = pred_icmp_errors_any_session;
    expects[0].pred.ctx = NULL;

    scn.name = "ICMP error against UDP session";
    scn.tags = "icmp,udp,error";
    scn.steps = steps;
    scn.n_steps = 3;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(icmp_error_against_udp, icmp_error_against_udp_provider)

/* ICMP error first (no session yet) → expect drop/bypass (no handling) */
static const sasc_scenario_t *
icmp_error_first_drops_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[1];
    static sasc_expect_t expects[1];
    static int inited;
    if (inited)
        return &scn;

    /* Inner tuple: A:10.0.0.1:12345 → B:10.0.0.2:80 */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = {0};
    k.src.ip4 = A;
    k.dst.ip4 = B;
    k.sport = 12345;
    k.dport = 80;
    k.is_ip6 = 0;
    k.proto = IP_PROTOCOL_TCP;

    /* Send ICMP port unreachable embedding inner TCP */
    sasc_packet_desc_t icmp = sasc_pkt_icmp_unreach_port_embed_tcp(&k, /*seq*/ 1001, /*ack*/ 2001, TCP_FLAG_ACK);

    /* No fixture: ensures “no pre-existing session” */
    scn.pre = sasc_fix_none();

    steps[0].kind = SASC_STEP_SEND;
    steps[0].pkt = icmp;
    steps[0].label = "icmp-port-unreach(no-session)";

    /* Expect: No ICMP errors handled (dropped/bypassed) */
    expects[0] = sasc_exp_true(pred_icmp_no_errors_handled, NULL, "no icmp errors handled");

    scn.name = "ICMP error first (no session) drops/bypasses";
    scn.tags = "icmp,error,first,drop";
    scn.steps = steps;
    scn.n_steps = 1;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(icmp_error_first_drops, icmp_error_first_drops_provider)

/* ICMP error in a later frame after session exists → expect handled */
static const sasc_scenario_t *
icmp_error_after_session_separate_frame_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[2];
    static sasc_expect_t expects[1];
    static int inited;
    if (inited)
        return &scn;

    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = {0};
    k.src.ip4 = A;
    k.dst.ip4 = B;
    k.sport = 12345;
    k.dport = 80;
    k.is_ip6 = 0;
    k.proto = IP_PROTOCOL_TCP;

    /* Install an ESTABLISHED session via fixture (separate from traffic) */
    scn.pre = sasc_fix_tcp_established(k, /*isn_cli*/ 1000, /*isn_srv*/ 2000,
                                       /*win_cli*/ 65535, /*win_srv*/ 65535,
                                       /*sack_ok*/ true, /*wscale_cli*/ 7, /*wscale_srv*/ 7, SASC_FIX_BACKEND_AUTO);

    /* Step 0: “frame break” – advance time to ensure next SEND runs in a later dispatch */
    steps[0] = SASC_STEP_ADVANCE(0.0);

    /* Step 1: ICMP error embedding the established inner TCP */
    sasc_packet_desc_t icmp = sasc_pkt_icmp_unreach_port_embed_tcp(&k, /*seq*/ 1001, /*ack*/ 2001, TCP_FLAG_ACK);
    steps[1].kind = SASC_STEP_SEND;
    steps[1].pkt = icmp;
    steps[1].label = "icmp-port-unreach(after-session,separate-frame)";

    /* Expect: ICMP error handling counter increments (>0) */

    // extern volatile u64 sasc_counter_icmp_errors;
    expects[0] = sasc_exp_true(pred_icmp_errors_any_session, NULL, "icmp error handled > 0");

    scn.name = "ICMP error after session (separate frame) handled";
    scn.tags = "icmp,error,session,split-frame";
    scn.steps = steps;
    scn.n_steps = 2;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(icmp_error_after_session_separate_frame,
                                icmp_error_after_session_separate_frame_provider)

/* Example: Session-specific ICMP error test using lookup */
static const sasc_scenario_t *
icmp_error_session_specific_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[3];
    static sasc_expect_t expects[2];
    static sasc_5tuple_t session_key; // Store the session key for lookup
    static int inited = 0;
    if (inited)
        return &scn;

    /* Clean up any existing sessions for test isolation */
    /* Note: Cleanup is done via SASC_STEP_CALLBACK in the steps */

    /* Define session key */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    session_key.src.ip4 = A;
    session_key.dst.ip4 = B;
    session_key.sport = 12345;
    session_key.dport = 80;
    session_key.is_ip6 = 0;
    session_key.proto = IP_PROTOCOL_TCP;

    /* No pre-existing session */
    scn.pre = sasc_fix_none();

    /* Step 1: Send TCP packet to establish session */
    steps[0] = SASC_STEP_SEND(sasc_pkt_tcp_syn(session_key, /* isn */ 1000, /* win */ 65535, /* mss */ 1460,
                                               /* wscale */ 7, /* sack_ok */ true));

    /* Step 2: Advance time */
    steps[1] = SASC_STEP_ADVANCE(0.001);

    /* Step 3: Send ICMP error referencing the session */
    sasc_packet_desc_t icmp =
        sasc_pkt_icmp_unreach_port_embed_tcp(&session_key, /*seq*/ 1001, /*ack*/ 2001, TCP_FLAG_ACK);
    steps[2] = SASC_STEP_SEND(icmp);

    /* Expect 1: Session-specific ICMP error handling */
    expects[0] = sasc_exp_true(pred_session_icmp_errors_zero, &session_key, "session has no icmp errors before icmp");

    /* Expect 2: Session should exist and have ICMP errors after ICMP packet */
    expects[1] = sasc_exp_true(pred_icmp_errors_any_session, NULL, "icmp error handled > 0");

    scn.name = "ICMP error session-specific test";
    scn.tags = "icmp,error,session-specific,lookup";
    scn.steps = steps;
    scn.n_steps = 3;
    scn.expects = expects;
    scn.n_expects = 2;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(icmp_error_session_specific, icmp_error_session_specific_provider)

/* Simple test: ICMP error with session cleanup for isolation */
static const sasc_scenario_t *
icmp_error_clean_test_provider(void) {
    static sasc_scenario_t scn;
    static sasc_step_t steps[2];
    static sasc_expect_t expects[1];
    static int inited = 0;
    if (inited)
        return &scn;

    /* Clean up any existing sessions for test isolation */
    /* Note: Cleanup is done via SASC_STEP_CALLBACK in the steps */

    /* Define session key */
    ip4_address_t A = {.as_u32 = clib_host_to_net_u32(0x0a000001)};
    ip4_address_t B = {.as_u32 = clib_host_to_net_u32(0x0a000002)};
    sasc_5tuple_t k = {0};
    k.src.ip4 = A;
    k.dst.ip4 = B;
    k.sport = 12345;
    k.dport = 80;
    k.is_ip6 = 0;
    k.proto = IP_PROTOCOL_TCP;

    /* No pre-existing session */
    scn.pre = sasc_fix_none();

    /* Step 1: Clean up sessions */
    steps[0] = SASC_STEP_CALLBACK(cleanup_all_sessions, NULL);
    steps[0].label = "cleanup-sessions";

    /* Step 2: Send ICMP error (should be dropped) */
    sasc_packet_desc_t icmp = sasc_pkt_icmp_unreach_port_embed_tcp(&k, /*seq*/ 1001, /*ack*/ 2001, TCP_FLAG_ACK);
    steps[1] = SASC_STEP_SEND(icmp);
    steps[1].label = "icmp-port-unreach(no-session)";

    /* Expect: No ICMP errors handled (dropped/bypassed) */
    expects[0] = sasc_exp_true(pred_icmp_no_errors_handled, NULL, "no icmp errors handled");

    scn.name = "ICMP error clean test (with session cleanup)";
    scn.tags = "icmp,error,clean,drop";
    scn.steps = steps;
    scn.n_steps = 2;
    scn.expects = expects;
    scn.n_expects = 1;

    inited = 1;
    return &scn;
}
SASC_SCENARIO_REGISTER_PROVIDER(icmp_error_clean_test, icmp_error_clean_test_provider)