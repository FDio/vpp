// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vcdp/vcdp.h>
#include <vcdp_services/tcp-check/tcp_check.h>

static clib_error_t *
vcdp_tcp_check_show_sessions_command_fn(vlib_main_t *vm, unformat_input_t *input,
                                        vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    clib_error_t *err = 0;
    vcdp_main_t *vcdp = &vcdp_main;
    vcdp_tcp_check_main_t *vtcm = &vcdp_tcp;
    vcdp_per_thread_data_t *ptd;
    vcdp_tcp_check_per_thread_data_t *vptd;
    vcdp_session_t *session;
    vcdp_tcp_check_session_state_t *tcp_session;
    vcdp_tenant_t *tenant;
    u32 thread_index;
    u32 session_index;
    u32 tenant_id = ~0;
    u8 first;
    if (unformat_user(input, unformat_line_input, line_input)) {
        while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
            if (unformat(line_input, "tenant %d", &tenant_id))
                ;
            else {
                err = unformat_parse_error(line_input);
                break;
            }
        }
        unformat_free(line_input);
    }

    if (!err)
        vec_foreach_index (thread_index, vcdp->per_thread_data) {
            ptd = vec_elt_at_index(vcdp->per_thread_data, thread_index);
            vptd = vec_elt_at_index(vtcm->ptd, thread_index);
            first = 1;
            table_t session_table_ = {}, *session_table = &session_table_;
            u32 n = 0;
            table_add_header_col(session_table, 8, "id", "tenant", "index", "type", "context",
                                 "ingress", "egress", "flags");
            pool_foreach_index (session_index, vcdp->sessions) {
                session = vcdp_session_at_index(ptd, session_index);
                tenant = vcdp_tenant_at_index(vcdp, session->tenant_idx);
                if (tenant_id != ~0 && tenant_id != tenant->tenant_id)
                    continue;
                if (session->proto != IP_PROTOCOL_TCP)
                    continue;
                if (first) {
                    first = 0;
                    table_format_title(session_table, "Thread #%d:", thread_index);
                }
                tcp_session = vec_elt_at_index(vptd->state, session_index);
                n = vcdp_table_format_insert_tcp_check_session(session_table, n, vcdp,
                                                               session_index, session, tcp_session);
            }
            if (!first)
                vlib_cli_output(vm, "%U", format_table, session_table);
            table_free(session_table);
        }

    return err;
}

VLIB_CLI_COMMAND(show_vcdp_tcp_check_sessions_command, static) = {
    .path = "show vcdp tcp session-table",
    .short_help = "show vcdp tcp session-table [tenant <tenant-id>]",
    .function = vcdp_tcp_check_show_sessions_command_fn,
};