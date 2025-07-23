// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.

#include <vlib/vlib.h>
#include "sasc.h"
#include "service.h"
#include "format.h"
#include "sasc_funcs.h"
#include "session.h"
#include "export.h"
/*
 * Display the set of available services.
 */
static clib_error_t *
sasc_show_services_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    sasc_service_main_t *sm = &sasc_service_main;
    sasc_service_registration_t **services = sm->services;
    sasc_service_registration_t *service;
    vlib_cli_output(vm, "Available services:");

    for (uword i = 0; i < vec_len(services); i++) {
        service = vec_elt_at_index(services, i)[0];
        vlib_cli_output(vm, "  %s", service->node_name);
    }
    return 0;
}

VLIB_CLI_COMMAND(sasc_show_services_command, static) = {
    .path = "show sasc services",
    .short_help = "show sasc services [verbose]",
    .function = sasc_show_services_command_fn,
};

static clib_error_t *
sasc_set_services_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    clib_error_t *err = 0;
    u32 service_index = ~0;
    u32 *services = 0;
    u32 chain_id = ~0;

    if (!unformat_user(input, unformat_line_input, line_input))
        return 0;
    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(line_input, "%d", &chain_id))
            ;
        if (unformat_user(line_input, unformat_sasc_service, &service_index)) {
            vec_add1(services, service_index);
        } else {
            err = unformat_parse_error(line_input);
            goto done;
        }
    }
    if (chain_id == ~0) {
        err = clib_error_return(0, "missing chain id");
        goto done;
    }
    if (sasc_set_services(chain_id, services) != 0) {
        err = clib_error_return(0, "Service chain does not terminate.");
        goto done;
    }

done:
    vec_free(services);
    unformat_free(line_input);
    return err;
}

VLIB_CLI_COMMAND(sasc_set_services_command, static) = {
    .path = "set sasc services",
    .short_help = "set sasc services <service-chain-id> [SERVICE_NAME]+",
    .function = sasc_set_services_command_fn,
};

static clib_error_t *
show_sasc_service_chains_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    sasc_main_t *sasc = &sasc_main;
    u32 *chain;
    u32 *entry;
    u32 chain_index;

    vlib_cli_output(vm, "Service Chains:");
    vlib_cli_output(vm, "%-10s %-20s", "Chain ID", "Service");

    vec_foreach_index (chain_index, sasc->chains) {
        chain = *vec_elt_at_index(sasc->chains, chain_index);

        vlib_cli_output(vm, "Chain %d:", chain_index);

        /* Show all services in the chain */
        vec_foreach (entry, chain) {
            // u32 is_last = (entry == vec_end(chain) - 1);
            const char *service_name = sasc_service_name_from_index(*entry);
            if (service_name) {
                vlib_cli_output(vm, "  %-20s (next: %u)", service_name, *entry);
            } else {
                vlib_cli_output(vm, "  %-20s (next: %u)", "unknown-service", *entry);
            }
        }
    }

    return 0;
}

VLIB_CLI_COMMAND(show_sasc_service_chains_command, static) = {
    .path = "show sasc service-chains",
    .short_help = "Show service chains",
    .function = show_sasc_service_chains_command_fn,
};

static clib_error_t *
sasc_tenant_add_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    clib_error_t *err = 0;
    sasc_main_t *sasc = &sasc_main;
    u32 tenant_idx = ~0;
    u32 context_id = ~0;
    u32 chain_ids[SASC_SERVICE_CHAIN_N] = {[0 ... SASC_SERVICE_CHAIN_N - 1] = ~0};

    if (!unformat_user(input, unformat_line_input, line_input))
        return 0;
    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
        if (unformat(line_input, "%d", &tenant_idx))
            ;
        else if (unformat(line_input, "context %d", &context_id))
            ;
#define _(n, str)                                                                                                      \
    else if (unformat(line_input, str " %d", &chain_ids[SASC_SERVICE_CHAIN_##n])) {                                    \
        ;                                                                                                              \
    }
        foreach_sasc_service_chain_type
#undef _
            else {
            err = unformat_parse_error(line_input);
            goto done;
        }
    }
    if (tenant_idx == ~0) {
        err = clib_error_return(0, "missing tenant index");
        goto done;
    }
    if (context_id == ~0)
        context_id = 0;
    err = sasc_tenant_add_del(sasc, tenant_idx, context_id, chain_ids[SASC_SERVICE_CHAIN_FORWARD],
                              chain_ids[SASC_SERVICE_CHAIN_REVERSE], chain_ids[SASC_SERVICE_CHAIN_MISS],
                              chain_ids[SASC_SERVICE_CHAIN_ICMP_ERROR], true);
done:
    unformat_free(line_input);
    return err;
}

VLIB_CLI_COMMAND(sasc_tenant_add_del_command, static) = {
    .path = "set sasc tenant",
    .short_help = "set sasc tenant <tenant-index> context <context-id> forward <service-chain-id> reverse "
                  "<service-chain-id> miss <service-chain-id> icmp-error <service-chain-id>",
    .function = sasc_tenant_add_command_fn,
};

static clib_error_t *
sasc_show_tenant_detail_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    clib_error_t *err = 0;
    sasc_main_t *sasc = &sasc_main;
    sasc_tenant_t *tenant;
    char *tenant_id = NULL;
    u16 tenant_idx;
    u8 detail = 0;
    if (unformat_user(input, unformat_line_input, line_input)) {
        while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
            if (unformat(line_input, "%s detail", &tenant_id))
                detail = 1;
            else if (unformat(line_input, "%s", &tenant_id))
                ;
            else {
                err = unformat_parse_error(line_input);
                break;
            }
        }
        unformat_free(line_input);
    }
    if (err)
        return err;

    pool_foreach_index (tenant_idx, sasc->tenants) {
        tenant = sasc_tenant_at_index(sasc, tenant_idx);

        vlib_cli_output(vm, "Tenant %d", tenant_idx);
        vlib_cli_output(vm, "  %U", format_sasc_tenant, sasc, tenant_idx, tenant);
        if (detail)
            vlib_cli_output(vm, "  %U", format_sasc_tenant_extra, sasc, tenant_idx, tenant);
    }

    return err;
}

VLIB_CLI_COMMAND(show_sasc_tenant, static) = {
    .path = "show sasc tenant",
    .short_help = "show sasc tenant [<tenant-index> [detail]]",
    .function = sasc_show_tenant_detail_command_fn,
};

static clib_error_t *
sasc_show_sessions_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    clib_error_t *err = 0;
    sasc_main_t *sasc = &sasc_main;
    sasc_session_t *session;
    f64 now = vlib_time_now(vm);
    bool detail = false;
    u32 session_index = ~0;

    if (unformat_user(input, unformat_line_input, line_input)) {
        while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
            if (unformat(line_input, "detail")) {
                detail = true;
            } else if (unformat(line_input, "%d", &session_index)) {
                ;
            } else {
                err = unformat_parse_error(line_input);
                break;
            }
        }
        unformat_free(line_input);
    }

    if (err)
        return err;

    // Original format
    vlib_cli_output(vm, "session id         thread tenant  index  type proto        state TTL(s)");
    if (session_index != ~0) {
        session = sasc_session_at_index_check(sasc, session_index);
        if (!session) {
            err = clib_error_return(0, "session index %d not found", session_index);
            return err;
        }
        f64 remaining_time = sasc_session_remaining_time(session, now);
        sasc_session_slow_path_t *sp = vec_elt_at_index(sasc->sp_sessions, session_index);
        vlib_cli_output(vm, "%u %d %U %U %U %d %d/%d %s", session - sasc->sessions, session->tenant_idx,
                        format_sasc_session_key, &sp->forward_key, format_ip_protocol, sp->keys[0].proto,
                        format_sasc_session_state, session->state, (int)remaining_time,
                        session->service_chain[SASC_FLOW_FORWARD], session->service_chain[SASC_FLOW_REVERSE],
                        session->flags & SASC_SESSION_F_PCAP_SAMPLE ? "PCAP" : "");
        vlib_cli_output(vm, "%U", format_sasc_session_detail, session, detail);
    } else {
        pool_foreach (session, sasc->sessions) {
            f64 remaining_time = sasc_session_remaining_time(session, now);
            sasc_session_slow_path_t *sp = vec_elt_at_index(sasc->sp_sessions, session - sasc->sessions);

            // if (remaining_time <= 0 && session->state != SASC_SESSION_STATE_STATIC)
            //     continue;

            vlib_cli_output(vm, "%u %d %U %U %U %d %d/%d %s", session - sasc->sessions, session->tenant_idx,
                            format_sasc_session_key, &sp->forward_key, format_ip_protocol, sp->keys[0].proto,
                            format_sasc_session_state, session->state, (int)remaining_time,
                            session->service_chain[SASC_FLOW_FORWARD], session->service_chain[SASC_FLOW_REVERSE],
                            session->flags & SASC_SESSION_F_PCAP_SAMPLE ? "PCAP" : "");
            vlib_cli_output(vm, "%U", format_sasc_session_detail, session, detail);
        }
    }

    return 0;
}

VLIB_CLI_COMMAND(show_sasc_sessions_command, static) = {
    .path = "show sasc session",
    .short_help = "show sasc session [session index] [thread <n>] [tenant <tenant-id>] "
                  "[0x<session-id>] [detail|compact]",
    .function = sasc_show_sessions_command_fn,
};

static clib_error_t *
sasc_show_next_indices_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cli) {
    sasc_main_t *sasc = &sasc_main;
    u32 *effective_services;
    u32 *next_indices;
    u32 next_indices_index;
    vlib_node_t *node;
    u32 max_chain_id = vec_len(sasc->chains);

    vlib_cli_output(vm, "Service Chains:\n");
    vlib_cli_output(vm, "===============\n");

    // Show all configured chains
    for (u32 chain_id = 0; chain_id < max_chain_id; chain_id++) {
        u32 *chain = *vec_elt_at_index(sasc->chains, chain_id);
        if (!chain)
            continue; // Skip unconfigured chains

        vlib_cli_output(vm, "Service Chain %d:\n", chain_id);
        vlib_cli_output(vm, "-------------------\n");

        // Show effective service chains for each protocol group
        for (sasc_proto_group_t proto_group = 0; proto_group < SASC_PROTO_GROUP_N; proto_group++) {
            const char *proto_names[] = {[SASC_PROTO_GROUP_ALL] = "All", [SASC_PROTO_GROUP_TCP] = "TCP"};

            // Get the effective service chain directly from the array
            u32 effective_index = (chain_id * SASC_PROTO_GROUP_N) + proto_group;
            effective_services = sasc->effective_service_chains[effective_index];
            if (!effective_services || vec_len(effective_services) == 0) {
                vlib_cli_output(vm, "  Protocol Group: %s - No effective services\n", proto_names[proto_group]);
                continue;
            }

            vlib_cli_output(vm, "  Protocol Group: %s\n", proto_names[proto_group]);
            vlib_cli_output(vm, "    Effective Services: %U\n", format_sasc_service_chain_from_vector,
                            effective_services);

            // Show next indices for each ingress node
            for (u32 ingress_idx = 0; ingress_idx < SASC_INGRESS_NODE_N_LOOKUPS; ingress_idx++) {
                const char *ingress_names[] = {[SASC_INGRESS_NODE_LOOKUP_IP4] = "sasc-lookup-ip4"};

                // Calculate next_indices index
                next_indices_index = sasc_service_chain_next_index(ingress_idx, proto_group, chain_id);
                if (next_indices_index >= vec_len(sasc->next_indices) || !sasc->next_indices[next_indices_index]) {
                    continue;
                }
                next_indices = sasc->next_indices[next_indices_index];
                if (!next_indices || vec_len(next_indices) == 0) {
                    continue;
                }

                vlib_cli_output(vm, "    Ingress Node: %s\n", ingress_names[ingress_idx]);
                vlib_cli_output(vm, "      Next Nodes:\n");

                // Get the ingress node
                u32 ingress_node_index = sasc_ingress_node_index(ingress_idx);
                node = vlib_get_node(vm, ingress_node_index);
                if (!node) {
                    continue;
                }

                // Show the chain of next nodes
                u32 *next_index;
                vec_foreach (next_index, next_indices) {
                    u32 next_node_index = node->next_nodes[*next_index];
                    vlib_node_t *next_node = vlib_get_node(vm, next_node_index);
                    if (next_node) {
                        vlib_cli_output(vm, "        %s (local index: %d, global index: %d)", next_node->name,
                                        *next_index, next_node_index);
                        // Update current node for next iteration
                        node = next_node;
                    }
                }
            }
            vlib_cli_output(vm, "\n");
        }
        vlib_cli_output(vm, "\n");
    }

    return 0;
}

VLIB_CLI_COMMAND(show_sasc_next_indices_command, static) = {
    .path = "show sasc next-indices",
    .short_help = "show sasc next-indices",
    .function = sasc_show_next_indices_command_fn,
};

static clib_error_t *
sasc_set_timeout_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    unformat_input_t line_input_, *line_input = &line_input_;
    clib_error_t *err = 0;
    sasc_main_t *sasc = &sasc_main;
    u32 timeouts[SASC_SESSION_N_STATE] = {0};
    if (!unformat_user(input, unformat_line_input, line_input))
        return 0;
    while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT) {
        if (0)
            ;
#define _(x, y, z) else if (unformat(line_input, z " %d", &timeouts[SASC_SESSION_STATE_##x]));
        foreach_sasc_session_state
#undef _
            else {
            err = unformat_parse_error(line_input);
            goto done;
        }
    }

    int rv = sasc_set_timeout(sasc, timeouts);
    if (rv != 0) {
        err = clib_error_return(0, "Failed to set timeout");
        goto done;
    }
done:
    unformat_free(line_input);
    return err;
}

VLIB_CLI_COMMAND(sasc_set_timeout_command, static) = {.path = "set sasc timeout",
                                                      .short_help = "set sasc timeout"
                                                                    " <timeout-name> <timeout-value>",
                                                      .function = sasc_set_timeout_command_fn};

u32 sasc_table_memory_size(void);
static clib_error_t *
sasc_show_summary_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    sasc_main_t *sasc = &sasc_main;

    vlib_cli_output(vm, "Configuration:");
    //   vlib_cli_output(vm, "Max Tenants: %d", sasc_cfg_main.no_tenants);
    vlib_cli_output(vm, "Max Sessions: %d", sasc->no_sessions);
    //   vlib_cli_output(vm, "Max NAT instances: %d", sasc_cfg_main.no_nat_instances);
    //   vlib_cli_output(vm, "Max Tunnels: %d", sasc_cfg_main.no_tunnels);

    //   vlib_cli_output(vm, "Threads: %d", vec_len(sasc->per_thread_data));
    vlib_cli_output(vm, "Active tenants: %d", pool_elts(sasc->tenants));
    vlib_cli_output(vm, "Timers:");

#define _(x, y, z) vlib_cli_output(vm, "  " z ": %d", sasc->timeouts[SASC_SESSION_STATE_##x]);
    foreach_sasc_session_state
#undef _

        vlib_cli_output(vm, "Active sessions: %d", pool_elts(sasc->sessions));
    vlib_cli_output(vm, "Session hash memory usage: %llu", sasc_table_memory_size());
    vlib_cli_output(vm, "Session main table memory usage: %llu", sizeof(sasc_session_t) * sasc->no_sessions);
    vlib_cli_output(vm, "Memory usage (per-session):");
    vlib_cli_output(vm, "  main session: %llu", sizeof(sasc_session_t));
    vlib_cli_output(vm, "%U", format_sasc_memory_usage);
    // u32 tenant_idx;
    // pool_foreach_index (tenant_idx, sasc->tenants) {
    //     vlib_cli_output(vm, "%d: %U", sasc->tenants[tenant_idx].context_id, format_sasc_tenant,
    //                     sasc, tenant_idx);
    // }

    return 0;
}

VLIB_CLI_COMMAND(show_sasc_summary, static) = {
    .path = "show sasc summary",
    .short_help = "show sasc summary",
    .function = sasc_show_summary_command_fn,
};

static clib_error_t *
sasc_clear_sessions_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    sasc_session_clear();
    return 0;
}

VLIB_CLI_COMMAND(clear_sasc_sessions, static) = {
    .path = "clear sasc sessions",
    .short_help = "clear sasc sessions",
    .function = sasc_clear_sessions_command_fn,
};
