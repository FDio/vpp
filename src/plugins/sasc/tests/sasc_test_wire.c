// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Cisco Systems, Inc. and its affiliates

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_input.h>
#include <vnet/buffer.h>
#include "sasc_test_framework.h"

static u32 debug_level = 0;

/* If your plugin exposes a fast session install function, declare it here and
 * wire it into the install hook below. If not, we’ll fallback to replay.
 *
 * Example idea (adjust/remove if you don’t have it):
 *   int sasc_test_install_tcp_established(vlib_main_t *vm, const sasc_5tuple_t *key,
 *                                         u32 isn_cli, u32 isn_srv,
 *                                         u16 win_cli, u16 win_srv,
 *                                         u8 sack_ok, u8 wscale_cli, u8 wscale_srv);
 */
static int
sasc_install_tcp_established_stub(vlib_main_t *vm, const sasc_5tuple_t *key, u32 isn_cli, u32 isn_srv, u16 win_cli,
                                  u16 win_srv, u8 sack_ok, u8 wscale_cli, u8 wscale_srv) {
    (void)vm;
    (void)key;
    (void)isn_cli;
    (void)isn_srv;
    (void)win_cli;
    (void)win_srv;
    (void)sack_ok;
    (void)wscale_cli;
    (void)wscale_srv;
    /* Return non-zero to signal “not supported”; the framework will replay 3WHS. */
    return -1;
}

/* ---------------- Packet injection hook ----------------
 *
 * We inject L3 IPv4 packets directly into the "ip4-input" node.
 * If you prefer to start at your plugin’s node, change node_name.
 */
static u32 test_ingress_node_index = ~0u;

static int
sasc_inject_to_ip4_input(vlib_main_t *vm, vlib_buffer_t *b) {
    if (PREDICT_FALSE(test_ingress_node_index == ~0u)) {
        vlib_node_t *n = vlib_get_node_by_name(vm, (u8 *)"sasc-lookup-ip4");
        if (!n) {
            clib_warning("sasc tests: node 'sasc-lookup-ip4' not found");
            // vlib_buffer_free(vm, &b->buffer_index, 1);
            return -1;
        }
        test_ingress_node_index = n->index;
    }

    /* Buffer metadata: tell VPP this is an L3 packet starting at current_data */
    vnet_buffer(b)->sw_if_index[VLIB_RX] = 0; /* no real RX iface using local */
    vnet_buffer(b)->sw_if_index[VLIB_TX] = 0;
    vnet_buffer(b)->l3_hdr_offset = b->current_data;
    b->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;

    // DEBUG
    if (debug_level > 0) {
        ip4_header_t *ip = (ip4_header_t *)b->data;
        vlib_cli_output(vm, "sasc tests: injecting packet %U to node %u", format_ip4_header, ip, 40,
                        test_ingress_node_index);
    }

    /* One-buffer enqueue */
    vlib_frame_t *f = vlib_get_frame_to_node(vm, test_ingress_node_index);
    u32 *to_next = vlib_frame_vector_args(f);
    to_next[0] = vlib_get_buffer_index(vm, b);
    f->n_vectors = 1;
    vlib_put_frame_to_node(vm, test_ingress_node_index, f);
    return 0;
}

/* ---------------- Optional: virtual time (leave unused if you don’t need it) ------------
 * Example: monotonic test clock advanced by steps, if you choose to use it later.
 */
// static f64 sasc_test_clock_now(void) { static f64 t = 0; return t; }
// You can provide a STEP_CALLBACK that bumps an internal offset; the now-fn can read it.

/* ---------------- Init: set hooks so the framework can run ---------------- */

static clib_error_t *
sasc_tests_wire_init(vlib_main_t *vm) {
    sasc_test_set_inject_fn(sasc_inject_to_ip4_input);

    /* If you have a fast install function, set it here instead of the stub */
    sasc_test_set_install_tcp_fn(sasc_install_tcp_established_stub);

    /* Optional: virtual time — leave commented out unless your code reads sasc_test_now()
     * sasc_test_set_now_fn(sasc_test_clock_now);
     */
    return 0;
}
/* ---------------- Test counters (stubs for scenarios) ---------------- */

/* Stub counters for tests - replace with real counters from your plugin */
volatile u64 sasc_counter_icmp_errors = 0;
volatile u64 sasc_tcp_check_retransmit_detected = 0;
volatile u64 sasc_tcp_check_reorder_detected = 0;
volatile u64 sasc_tcp_check_fast_retransmit = 0;
volatile u64 sasc_tcp_check_invalid_tcp_header = 0;
volatile u64 sasc_tcp_check_malformed_flags = 0;
volatile u64 sasc_tcp_check_handshake_timeout = 0;
volatile u64 sasc_tcp_check_protocol_violation = 0;
volatile u64 sasc_tcp_check_ecn_ce_mark = 0;
volatile u64 sasc_tcp_check_ecn_ect_mark = 0;
volatile u64 sasc_tcp_check_window_probe = 0;

/* Run after IP + your plugin has initialized */
VLIB_INIT_FUNCTION(sasc_tests_wire_init) = {
    .runs_after = VLIB_INITS("ip4_init"),
};

/* ---------------- CLI: run all or filtered scenarios ---------------- */

static clib_error_t *
sasc_cli_run_all(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    (void)input;
    (void)cmd;
    sasc_run_all_registered(vm);
    return 0;
}

VLIB_CLI_COMMAND(cmd_sasc_run_all, static) = {
    .path = "test sasc run-all",
    .short_help = "Run all registered SASC scenarios",
    .function = sasc_cli_run_all,
};

extern sasc_scn_provider_t __start_sasc_scenarios[];
extern sasc_scn_provider_t __stop_sasc_scenarios[];

static clib_error_t *
sasc_cli_run_filter(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    (void)cmd;
    u8 *needle = 0;
    if (unformat(input, "%U", unformat_token, " \t", &needle) == 0) {
        return clib_error_return(0, "usage: test sasc run <substring>");
    }

    sasc_scn_provider_t *p = __start_sasc_scenarios;
    sasc_scn_provider_t *e = __stop_sasc_scenarios;
    u32 ran = 0, failed = 0;

    for (; p < e; ++p) {
        const sasc_scenario_t *scn = (*p)();
        if (!scn || !scn->name)
            continue;
        if (!strstr(scn->name, (char *)needle) && !(scn->tags && strstr(scn->tags, (char *)needle)))
            continue;

        sasc_run_result_t rr = sasc_run_scenario(vm, scn);
        ran++;
        failed += (rr.n_failed != 0);
        vlib_cli_output(vm, "Scenario '%s': steps=%u expects=%u %s", scn->name, rr.n_steps_executed,
                        rr.n_expect_checked, rr.n_failed ? "FAIL" : "OK");
    }

    if (!ran)
        vlib_cli_output(vm, "No scenarios matched '%s'", (char *)needle);
    else
        vlib_cli_output(vm, "Ran %u scenario(s), %u failed", ran, failed);

    vec_free(needle);
    return 0;
}

VLIB_CLI_COMMAND(cmd_sasc_run_filter, static) = {
    .path = "test sasc run",
    .short_help = "test sasc run <substring|tag>",
    .function = sasc_cli_run_filter,
};

/* ---------------- CLI: list registered scenarios ---------------- */

static clib_error_t *
sasc_cli_list(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    (void)input;
    (void)cmd;

    extern sasc_scn_provider_t __start_sasc_scenarios[];
    extern sasc_scn_provider_t __stop_sasc_scenarios[];

    sasc_scn_provider_t *p = __start_sasc_scenarios;
    sasc_scn_provider_t *e = __stop_sasc_scenarios;
    u32 idx = 0;

    vlib_cli_output(vm, "%-4s %-40s %-20s", "ID", "Name", "Tags");
    vlib_cli_output(vm, "%-4s %-40s %-20s", "----", "----------------------------------------", "--------------------");

    for (; p < e; ++p) {
        const sasc_scenario_t *scn = (*p)();
        if (!scn || !scn->name)
            continue;
        vlib_cli_output(vm, "%-4u %-40s %-20s", idx++, scn->name, scn->tags ? scn->tags : "");
    }

    vlib_cli_output(vm, "Total: %u scenario(s)", idx);
    return 0;
}

VLIB_CLI_COMMAND(cmd_sasc_list, static) = {
    .path = "test sasc list",
    .short_help = "List all registered SASC test scenarios",
    .function = sasc_cli_list,
};

/* ---------------- Helpers shared by list/run-id ---------------- */

extern sasc_scn_provider_t __start_sasc_scenarios[];
extern sasc_scn_provider_t __stop_sasc_scenarios[];

static inline u32
sasc_scenario_count(void) {
    return (u32)(__stop_sasc_scenarios - __start_sasc_scenarios);
}

static inline const sasc_scenario_t *
sasc_scenario_by_index(u32 idx) {
    u32 n = sasc_scenario_count();
    if (idx >= n)
        return 0;
    return __start_sasc_scenarios[idx]();
}

/* ---------------- CLI: run scenario by ID ---------------- */

static clib_error_t *
sasc_cli_run_id(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    (void)cmd;
    u32 id = ~0u;
    if (!unformat(input, "%u", &id)) {
        return clib_error_return(0, "usage: test sasc run-id <ID>\nTip: see 'test sasc list' for IDs.");
    }
    if (!unformat(input, "debug %u", &debug_level)) {
        debug_level = 0;
    }

    const sasc_scenario_t *scn = sasc_scenario_by_index(id);
    if (!scn) {
        return clib_error_return(0, "No scenario with ID %u (total %u).", id, sasc_scenario_count());
    }

    sasc_run_result_t rr = sasc_run_scenario(vm, scn);
    vlib_cli_output(vm, "Scenario '%s' (ID=%u): steps=%u expects=%u %s", scn->name, id, rr.n_steps_executed,
                    rr.n_expect_checked, rr.n_failed ? "FAIL" : "OK");
    return 0;
}

VLIB_CLI_COMMAND(cmd_sasc_run_id, static) = {
    .path = "test sasc run-id",
    .short_help = "test sasc run-id <ID>  (run a single registered scenario by ID)",
    .function = sasc_cli_run_id,
};
