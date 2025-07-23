// SPDX-License-Identifier: Apache-2.0
// Framework: scenario + fixtures + steps + expectations + single generic runner.

#pragma once
#include <vlib/vlib.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <stdbool.h>
#include <stdint.h>
#include <sasc/session.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------- configuration -------- */
extern u32 sasc_test_processing_wait_max_retries;
extern f64 sasc_test_processing_wait_interval;

void sasc_test_set_processing_wait_config(u32 max_retries, f64 interval);
void sasc_test_get_processing_wait_config(u32 *max_retries, f64 *interval);

/* -------------------- Test-time virtual clock -------------------- */

typedef f64 (*sasc_now_fn_t)(void);
void sasc_test_set_now_fn(sasc_now_fn_t fn);
f64 sasc_test_now(void); // use this instead of vlib_time_now() inside tests

/* -------------------- Packet description (provided by factory) -------------------- */

typedef struct {
    ip46_address_t src, dst;
    u16 sport, dport;
    u8 is_ip6;   // 0 = IPv4 (factory here implements IPv4 only)
    u8 l4_proto; // IPPROTO_TCP / UDP / ICMP
    struct {
        u32 seq, ack;
        u8 flags;
        u16 win;
        u16 data_len;
        u32 tsval, tsecr;
        u16 mss;
        u8 wscale;
        u8 ts_present : 1, sack_ok : 1, wscale_present : 1, mss_present : 1;
    } tcp;
    struct {
        u8 type, code; /* for ICMP errors */
        struct {
            u8 present;
            u8 l4_proto;
            u32 seq;
            u32 ack;
            u8 tcp_flags;
            u16 sport, dport;
            ip46_address_t src, dst;
        } inner;
    } icmp;
    u16 udp_len;
    u16 payload_len; // generic payload length (if any)
} sasc_packet_desc_t;

/* from sasc_packet_factory.c */
vlib_buffer_t *sasc_pkt_build(vlib_main_t *vm, const sasc_packet_desc_t *d);

/* -------------------- 5‑tuple key -------------------- */

typedef struct {
    ip46_address_t src, dst;
    u16 sport, dport;
    u8 is_ip6;
    u8 proto; // IPPROTO_TCP/UDP/ICMP
} sasc_5tuple_t;

/* -------------------- Inject & session hooks (overridable by the testbed) -------------------- */

/* Where to send the constructed packet (graph under test).
 * Return 0 on success; buffer ownership is consumed.
 */
typedef int (*sasc_inject_fn_t)(vlib_main_t *vm, vlib_buffer_t *b);
void sasc_test_set_inject_fn(sasc_inject_fn_t fn);

/* Optional: direct session install hook for fixtures (fast path).
 * Return 0 if installed; non-zero to fall back to replay fixture.
 */
typedef int (*sasc_install_tcp_fn_t)(vlib_main_t *vm, const sasc_5tuple_t *key, u32 isn_cli, u32 isn_srv, u16 win_cli,
                                     u16 win_srv, u8 sack_ok, u8 wscale_cli, u8 wscale_srv);
void sasc_test_set_install_tcp_fn(sasc_install_tcp_fn_t fn);

/* -------------------- Fixtures (expected start state) -------------------- */

typedef enum {
    SASC_FIX_NONE = 0,
    SASC_FIX_TCP_ESTABLISHED,
    SASC_FIX_UDP_FLOW,
    SASC_FIX_ICMP_ECHO_FLOW,
    SASC_FIX_COUNTERS_ZEROED
} sasc_fixture_kind_t;

typedef enum {
    SASC_FIX_BACKEND_AUTO = 0, // try direct install; fallback to replay
    SASC_FIX_BACKEND_REPLAY,
    SASC_FIX_BACKEND_INSTALL
} sasc_fixture_backend_t;

typedef struct {
    sasc_fixture_kind_t kind;
    sasc_fixture_backend_t backend;
    sasc_5tuple_t key;
    struct {
        u32 isn_cli, isn_srv;
        u16 win_cli, win_srv;
        u8 sack_ok, wscale_cli, wscale_srv;
    } tcp;
} sasc_fixture_t;

/* Convenience constructors */
static inline sasc_fixture_t
sasc_fix_none(void) {
    sasc_fixture_t f = {.kind = SASC_FIX_NONE, .backend = SASC_FIX_BACKEND_AUTO};
    return f;
}
sasc_fixture_t sasc_fix_tcp_established(sasc_5tuple_t key, u32 isn_cli, u32 isn_srv, u16 win_cli, u16 win_srv,
                                        bool sack_ok, u8 wscale_cli, u8 wscale_srv, sasc_fixture_backend_t backend);
sasc_fixture_t sasc_fix_counters_zeroed(void);

/* -------------------- Steps (timeline) -------------------- */

typedef enum {
    SASC_STEP_SEND = 1,
    SASC_STEP_ADVANCE,
    SASC_STEP_CALLBACK,
    SASC_STEP_WAIT_FOR_PROCESSING
} sasc_step_kind_t;

typedef int (*sasc_step_cb_t)(vlib_main_t *vm, void *ctx);

typedef struct {
    sasc_step_kind_t kind;
    union {
        sasc_packet_desc_t pkt; // materialized by factory when executed
        f64 advance_seconds;
        struct {
            sasc_step_cb_t fn;
            void *ctx;
        } cb;
        struct {
            u32 max_retries;
            f64 retry_interval;
        } wait; // for SASC_STEP_WAIT_FOR_PROCESSING
    };
    const char *label; // optional for diagnostics
} sasc_step_t;

/* Shortcuts */
#define SASC_STEP_LABELED_SEND(desc, lbl) ((sasc_step_t){.kind = SASC_STEP_SEND, .pkt = (desc), .label = (lbl)})
#define SASC_STEP_SEND(desc)              SASC_STEP_LABELED_SEND((desc), NULL)
#define SASC_STEP_ADVANCE(sec)            ((sasc_step_t){.kind = SASC_STEP_ADVANCE, .advance_seconds = (sec)})
#define SASC_STEP_CALLBACK(fn, ctx)       ((sasc_step_t){.kind = SASC_STEP_CALLBACK, .cb = {(fn), (ctx)}})
#define SASC_STEP_WAIT_FOR_PROCESSING(max_retries, interval)                                                           \
    ((sasc_step_t){.kind = SASC_STEP_WAIT_FOR_PROCESSING, .wait = {(max_retries), (interval)}})

/*
 * Example usage of synchronization steps:
 *
 * // Option 1: Use explicit wait step
 * steps[0] = SASC_STEP_SEND(syn_packet);
 * steps[1] = SASC_STEP_SEND(synack_packet);
 * steps[2] = SASC_STEP_SEND(ack_packet);
 * steps[3] = SASC_STEP_WAIT_FOR_PROCESSING(10, 0.001);  // Wait up to 10ms
 *
 * // Option 2: Use advance step (if using virtual time)
 * steps[0] = SASC_STEP_SEND(syn_packet);
 * steps[1] = SASC_STEP_ADVANCE(0.001);  // Advance time by 1ms
 * steps[2] = SASC_STEP_SEND(synack_packet);
 * steps[3] = SASC_STEP_ADVANCE(0.001);  // Advance time by 1ms
 * steps[4] = SASC_STEP_SEND(ack_packet);
 * steps[5] = SASC_STEP_ADVANCE(0.001);  // Advance time by 1ms
 *

 */

/* -------------------- Expectations (assertions) -------------------- */

typedef enum {
    SASC_EXP_EQ_U64 = 1,
    SASC_EXP_TRUE,
    SASC_EXP_SESSION_STATE, // optional: if you expose state lookup
} sasc_expect_kind_t;

typedef int (*sasc_pred_fn_t)(void *ctx); // return non-zero if condition holds

typedef struct {
    sasc_expect_kind_t kind;
    const char *what; // description printed on failure
    union {
        struct {
            volatile u64 *counter;
            u64 want;
        } eq_u64;
        struct {
            sasc_pred_fn_t pred;
            void *ctx;
        } pred;
        struct {
            sasc_5tuple_t key;
            u8 want_state;
        } sess; // filled if you wire a lookup
    };
} sasc_expect_t;

static inline sasc_expect_t
sasc_exp_eq_u64(volatile u64 *counter, u64 want, const char *what) {
    sasc_expect_t e = {.kind = SASC_EXP_EQ_U64, .what = what};
    e.eq_u64.counter = counter;
    e.eq_u64.want = want;
    return e;
}
static inline sasc_expect_t
sasc_exp_true(sasc_pred_fn_t pred, void *ctx, const char *what) {
    sasc_expect_t e = {.kind = SASC_EXP_TRUE, .what = what};
    e.pred.pred = pred;
    e.pred.ctx = ctx;
    return e;
}

/* -------------------- Scenario -------------------- */

typedef struct {
    const char *name;
    const char *tags;   // optional
    sasc_fixture_t pre; // expected start state
    const sasc_step_t *steps;
    u32 n_steps;
    const sasc_expect_t *expects;
    u32 n_expects;
} sasc_scenario_t;

/* -------------------- Runner -------------------- */

typedef struct {
    u32 n_failed;
    u32 n_steps_executed;
    u32 n_expect_checked;
} sasc_run_result_t;

sasc_run_result_t sasc_run_scenario(vlib_main_t *vm, const sasc_scenario_t *scn);

/* -------------------- Registration helper (weak symbol array) -------------------- */

typedef const sasc_scenario_t *(*sasc_scn_provider_t)(void);
#define SASC_SCENARIO_SECTION __attribute__((section("sasc_scenarios"), used))

#define SASC_SCENARIO_REGISTER(name_literal, scenario_expr)                                                            \
    static const sasc_scenario_t *name_literal##_provider(void) {                                                      \
        static const sasc_scenario_t _s = scenario_expr;                                                               \
        return &_s;                                                                                                    \
    }                                                                                                                  \
    static sasc_scn_provider_t name_literal##_reg SASC_SCENARIO_SECTION = name_literal##_provider;

/* Register a scenario via an existing provider function that returns a pointer.
 * Use this when your scenario needs runtime initialization (non-constant setup).
 */
#define SASC_SCENARIO_REGISTER_PROVIDER(name_literal, provider_fn)                                                     \
    static sasc_scn_provider_t name_literal##_reg SASC_SCENARIO_SECTION = (provider_fn);
/* Utility: run all registered scenarios */
void sasc_run_all_registered(vlib_main_t *vm);

/* -------------------- Session lookup helpers -------------------- */

/* Look up a session by 5-tuple and return session data for various plugins */
sasc_session_t *sasc_test_lookup_session(const sasc_5tuple_t *key);

/* Get TCP quality session data for a 5-tuple (returns NULL if session not found) */
void *sasc_test_get_tcp_quality_data(const sasc_5tuple_t *key);

/* Get packet stats session data for a 5-tuple (returns NULL if session not found) */
void *sasc_test_get_packet_stats_data(const sasc_5tuple_t *key);

/*
 * Example usage for session-specific predicates:
 *
 * // For TCP quality data (retransmissions, reordering, etc.)
 * static int pred_session_retransmit_detected(void *ctx) {
 *     sasc_5tuple_t *key = (sasc_5tuple_t *)ctx;
 *     sasc_tcp_quality_session_data_t *tcp_data = sasc_test_get_tcp_quality_data(key);
 *     if (!tcp_data) return 0;
 *     return tcp_data->retransmissions > 0;
 * }
 *
 * // For packet stats data (ECN, TTL, etc.)
 * static int pred_session_ecn_ce_detected(void *ctx) {
 *     sasc_5tuple_t *key = (sasc_5tuple_t *)ctx;
 *     sasc_packet_stats_session_data_t *stats = sasc_test_get_packet_stats_data(key);
 *     if (!stats) return 0;
 *     return stats->ecn_ce > 0;
 * }
 *
 * // For direct session access
 * static int pred_session_exists(void *ctx) {
 *     sasc_5tuple_t *key = (sasc_5tuple_t *)ctx;
 *     return sasc_test_lookup_session(key) != NULL;
 * }
 */

#ifdef __cplusplus
}
#endif
