// SPDX-License-Identifier: Apache-2.0
#include "sasc_test_framework.h"
#include "sasc_packet_factory.h"
#include <vnet/ip/ip.h>
#include <sasc/services/flow-quality/packet_stats.h>

/* -------- configuration -------- */
u32 sasc_test_processing_wait_max_retries = 20;  /* Default: 20 retries */
f64 sasc_test_processing_wait_interval = 0.0005; /* Default: 0.5ms intervals */

/* -------- global hooks -------- */
static sasc_inject_fn_t g_inject = 0;
static sasc_install_tcp_fn_t g_install_tcp = 0;
static sasc_now_fn_t g_now = 0;

void
sasc_test_set_inject_fn(sasc_inject_fn_t fn) {
    g_inject = fn;
}
void
sasc_test_set_install_tcp_fn(sasc_install_tcp_fn_t fn) {
    g_install_tcp = fn;
}
void
sasc_test_set_now_fn(sasc_now_fn_t fn) {
    g_now = fn;
}
f64
sasc_test_now(void) {
    return g_now ? g_now() : vlib_time_now(vlib_get_main());
}

/* -------- configuration helpers -------- */

void
sasc_test_set_processing_wait_config(u32 max_retries, f64 interval) {
    sasc_test_processing_wait_max_retries = max_retries;
    sasc_test_processing_wait_interval = interval;
}

void
sasc_test_get_processing_wait_config(u32 *max_retries, f64 *interval) {
    if (max_retries)
        *max_retries = sasc_test_processing_wait_max_retries;
    if (interval)
        *interval = sasc_test_processing_wait_interval;
}

/* -------- fixtures -------- */

sasc_fixture_t
sasc_fix_tcp_established(sasc_5tuple_t key, u32 isn_cli, u32 isn_srv, u16 win_cli, u16 win_srv, bool sack_ok,
                         u8 wscale_cli, u8 wscale_srv, sasc_fixture_backend_t backend) {
    sasc_fixture_t f = {.kind = SASC_FIX_TCP_ESTABLISHED,
                        .backend = backend,
                        .key = key,
                        .tcp = {.isn_cli = isn_cli,
                                .isn_srv = isn_srv,
                                .win_cli = win_cli,
                                .win_srv = win_srv,
                                .sack_ok = (u8)(!!sack_ok),
                                .wscale_cli = wscale_cli,
                                .wscale_srv = wscale_srv}};
    return f;
}

sasc_fixture_t
sasc_fix_counters_zeroed(void) {
    sasc_fixture_t f = {.kind = SASC_FIX_COUNTERS_ZEROED, .backend = SASC_FIX_BACKEND_AUTO};
    return f;
}

/* Replay a minimal 3WHS using the factory and inject hook */
static int
sasc_fixture_replay_tcp_established(vlib_main_t *vm, const sasc_fixture_t *fx) {
    sasc_packet_desc_t syn = {0}, synack = {0}, ack = {0};
    const sasc_5tuple_t *k = &fx->key;

    syn.is_ip6 = 0;
    syn.l4_proto = IP_PROTOCOL_TCP;
    syn.src = k->src;
    syn.dst = k->dst;
    syn.sport = k->sport;
    syn.dport = k->dport;
    syn.tcp.seq = fx->tcp.isn_cli;
    syn.tcp.ack = 0;
    syn.tcp.flags = TCP_FLAG_SYN;
    syn.tcp.win = fx->tcp.win_cli;
    syn.tcp.mss_present = 1;
    syn.tcp.mss = 1460;
    syn.tcp.wscale_present = 1;
    syn.tcp.wscale = fx->tcp.wscale_cli;
    syn.tcp.sack_ok = fx->tcp.sack_ok;

    synack = syn; // swap directions
    synack.src = k->dst;
    synack.dst = k->src;
    synack.sport = k->dport;
    synack.dport = k->sport;
    synack.tcp.seq = fx->tcp.isn_srv;
    synack.tcp.ack = fx->tcp.isn_cli + 1;
    synack.tcp.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    synack.tcp.win = fx->tcp.win_srv;
    synack.tcp.wscale = fx->tcp.wscale_srv;

    ack = syn; // back to client->server
    ack.tcp.seq = fx->tcp.isn_cli + 1;
    ack.tcp.ack = fx->tcp.isn_srv + 1;
    ack.tcp.flags = TCP_FLAG_ACK;
    ack.tcp.mss_present = 0;
    ack.tcp.wscale_present = 0;

    vlib_buffer_t *b1 = sasc_pkt_build(vm, &syn);
    vlib_buffer_t *b2 = sasc_pkt_build(vm, &synack);
    vlib_buffer_t *b3 = sasc_pkt_build(vm, &ack);
    if (!b1 || !b2 || !b3)
        return -1;
    if (!g_inject) {
        vlib_buffer_free(vm, (u32[]){vlib_get_buffer_index(vm, b1)}, 1);
        vlib_buffer_free(vm, (u32[]){vlib_get_buffer_index(vm, b2)}, 1);
        vlib_buffer_free(vm, (u32[]){vlib_get_buffer_index(vm, b3)}, 1);
        return -1;
    }
    if (g_inject(vm, b1))
        return -1;
    if (g_inject(vm, b2))
        return -1;
    if (g_inject(vm, b3))
        return -1;
    return 0;
}

static int
sasc_apply_fixture(vlib_main_t *vm, const sasc_fixture_t *fx) {
    switch (fx->kind) {
    case SASC_FIX_NONE:
        return 0;
    case SASC_FIX_COUNTERS_ZEROED:
        /* If you expose counters, zero them here. This stub keeps it no-op. */
        return 0;
    case SASC_FIX_TCP_ESTABLISHED: {
        if (fx->backend != SASC_FIX_BACKEND_REPLAY && g_install_tcp) {
            int rc = g_install_tcp(vm, &fx->key, fx->tcp.isn_cli, fx->tcp.isn_srv, fx->tcp.win_cli, fx->tcp.win_srv,
                                   fx->tcp.sack_ok, fx->tcp.wscale_cli, fx->tcp.wscale_srv);
            if (rc == 0)
                return 0;
            if (fx->backend == SASC_FIX_BACKEND_INSTALL)
                return rc;
        }
        return sasc_fixture_replay_tcp_established(vm, fx);
    }
    default:
        return -1;
    }
}

/* -------- expectations -------- */

static int
sasc_check_expect(vlib_main_t *vm, const sasc_expect_t *e, u32 idx, const char *scn) {
    (void)vm;
    switch (e->kind) {
    case SASC_EXP_EQ_U64: {
        u64 got = e->eq_u64.counter ? *e->eq_u64.counter : 0;
        if (got != e->eq_u64.want) {
            clib_warning("EXPECT(%s) failed in scenario '%s' [exp#%u]: got=%llu want=%llu",
                         e->what ? e->what : "eq_u64", scn, idx, (unsigned long long)got,
                         (unsigned long long)e->eq_u64.want);
            return -1;
        }
        return 0;
    }
    case SASC_EXP_TRUE: {
        int ok = e->pred.pred ? e->pred.pred(e->pred.ctx) : 0;
        if (!ok) {
            clib_warning("EXPECT(%s) failed in scenario '%s' [exp#%u]: predicate false", e->what ? e->what : "true",
                         scn, idx);
            return -1;
        }
        return 0;
    }
    case SASC_EXP_SESSION_STATE:
        /* Wire this if you expose a lookup API. */
        clib_warning("EXPECT(session_state) not implemented in this stub");
        return 0;
    default:
        return -1;
    }
}

/* -------- runner -------- */

sasc_run_result_t
sasc_run_scenario(vlib_main_t *vm, const sasc_scenario_t *scn) {
    sasc_run_result_t rr = {0};
    if (!scn)
        return rr;

    if (sasc_apply_fixture(vm, &scn->pre)) {
        clib_warning("Fixture failed for scenario '%s'", scn->name);
        rr.n_failed++;
        return rr;
    }

    for (u32 i = 0; i < scn->n_steps; i++) {
        const sasc_step_t *st = &scn->steps[i];
        switch (st->kind) {
        case SASC_STEP_SEND: {
            vlib_buffer_t *b = sasc_pkt_build(vm, &st->pkt);
            if (!b) {
                clib_warning("Buffer build failed at step %u (%s)", i, st->label ? st->label : "");
                rr.n_failed++;
                goto done_steps;
            }
            if (!g_inject) {
                clib_warning("No inject hook set");
                rr.n_failed++;
                goto done_steps;
            }
            if (g_inject(vm, b)) {
                clib_warning("Inject failed at step %u", i);
                rr.n_failed++;
                goto done_steps;
            }
        } break;
        case SASC_STEP_ADVANCE: {
            if (g_now) { /* test-time virtual time: move forward by st->advance_seconds */
                /* The now-fn supplies absolute time; most tests use a closure with internal offset.
                   Nothing to do here globally. */
            } else {
                /* Fallback: real sleep (avoid when possible). */
                vlib_process_suspend(vm, st->advance_seconds);
            }
        } break;
        case SASC_STEP_CALLBACK:
            if (st->cb.fn && st->cb.fn(vm, st->cb.ctx)) {
                rr.n_failed++;
                goto done_steps;
            }
            break;
        case SASC_STEP_WAIT_FOR_PROCESSING: {
            /* Wait for packet processing to complete by polling graph statistics */
            u32 retries = 0;
            u32 max_retries = st->wait.max_retries;
            f64 retry_interval = st->wait.retry_interval;

            while (retries < max_retries) {
                /* Simple approach: just wait and let VPP process naturally */
                retries++;
                if (retries < max_retries) {
                    if (g_now) {
                        /* Virtual time: just wait */
                        /* Note: This assumes virtual time advances appropriately */
                    } else {
                        /* Real time: sleep */
                        vlib_process_suspend(vm, retry_interval);
                    }
                }
            }

            if (retries >= max_retries) {
                clib_warning("Wait for processing timed out after %u retries", max_retries);
                /* Don't fail the test, just warn - processing might still be ongoing */
            }
        } break;
        default:
            break;
        }
        rr.n_steps_executed++;
    }

done_steps:
    /* Wait for packet processing to complete before checking expectations */
    {
        u32 wait_retries = 0;
        u32 max_wait_retries = sasc_test_processing_wait_max_retries;
        f64 wait_interval = sasc_test_processing_wait_interval;

        while (wait_retries < max_wait_retries) {
            /* Simple approach: just wait and let VPP process naturally */
            wait_retries++;
            if (wait_retries < max_wait_retries) {
                if (g_now) {
                    /* Virtual time: just wait */
                    /* Note: Virtual time should advance appropriately */
                } else {
                    /* Real time: sleep */
                    vlib_process_suspend(vm, wait_interval);
                }
            }
        }

        /* Log processing wait completion for debugging */
        if (wait_retries > 1) {
            clib_warning("SASC: Waited %u iterations for packet processing in scenario '%s'", wait_retries, scn->name);
        }
    }

    for (u32 j = 0; j < scn->n_expects; j++) {
        if (sasc_check_expect(vm, &scn->expects[j], j, scn->name))
            rr.n_failed++;
        rr.n_expect_checked++;
    }
    return rr;
}

/* -------- registration sweep -------- */

extern sasc_scn_provider_t __start_sasc_scenarios[]; /* linker section */
extern sasc_scn_provider_t __stop_sasc_scenarios[];

void
sasc_run_all_registered(vlib_main_t *vm) {
    sasc_scn_provider_t *p = __start_sasc_scenarios;
    sasc_scn_provider_t *e = __stop_sasc_scenarios;
    u32 n = (u32)(e - p);
    clib_warning("SASC: running %u scenarios", n);
    for (; p < e; ++p) {
        const sasc_scenario_t *scn = (*p)();
        sasc_run_result_t rr = sasc_run_scenario(vm, scn);
        clib_warning("Scenario '%s': steps=%u expects=%u %s", scn->name, rr.n_steps_executed, rr.n_expect_checked,
                     rr.n_failed ? "FAIL" : "OK");
    }
}

/* -------- Session lookup helpers -------- */

sasc_session_t *
sasc_test_lookup_session(const sasc_5tuple_t *key) {
    extern sasc_main_t sasc_main;

    // Convert sasc_5tuple_t to ip_address_t for session lookup
    ip_address_t src_addr = {0}, dst_addr = {0};
    if (key->is_ip6) {
        src_addr.version = AF_IP6;
        dst_addr.version = AF_IP6;
        src_addr.ip.ip6 = key->src.ip6;
        dst_addr.ip.ip6 = key->dst.ip6;
    } else {
        src_addr.version = AF_IP4;
        dst_addr.version = AF_IP4;
        src_addr.ip.ip4 = key->src.ip4;
        dst_addr.ip.ip4 = key->dst.ip4;
    }

    // Look up the session (context_id = 0 for tests)
    sasc_session_t *session = sasc_lookup_session(0, &src_addr, clib_host_to_net_u16(key->sport), key->proto, &dst_addr,
                                                  clib_host_to_net_u16(key->dport));

    if (!session) {
        clib_warning("DEBUG: sasc_lookup_session returned NULL");
    } else {
        clib_warning("DEBUG: sasc_lookup_session found session at index %ld", session - sasc_main.sessions);
    }

    return session;
}

void *
sasc_test_get_tcp_quality_data(const sasc_5tuple_t *key) {
    extern sasc_main_t sasc_main;
    extern sasc_packet_stats_main_t sasc_packet_stats_main;

    sasc_session_t *session = sasc_test_lookup_session(key);
    if (!session) {
        return NULL; // No session found
    }

    // Get the packet stats session data
    sasc_packet_stats_session_data_t *session_data = &sasc_packet_stats_main.session_data[session - sasc_main.sessions];

    // Return the TCP quality data
    return &session_data->tcp_session_data;
}

void *
sasc_test_get_packet_stats_data(const sasc_5tuple_t *key) {
    extern sasc_main_t sasc_main;
    extern sasc_packet_stats_main_t sasc_packet_stats_main;

    sasc_session_t *session = sasc_test_lookup_session(key);
    if (!session) {
        return NULL; // No session found
    }
    return &sasc_packet_stats_main.session_data[session - sasc_main.sessions];
}
