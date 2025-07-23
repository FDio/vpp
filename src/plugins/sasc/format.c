// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Cisco Systems, Inc. and/or its affiliates.

#include <vlib/vlib.h>
#include "service.h"
#include "sasc.h"

#include <vnet/vnet.h>
#include <vnet/format_fns.h>
// #include <vppinfra/format_table.h>

uword
unformat_sasc_service(unformat_input_t *input, va_list *args) {
    sasc_service_main_t *sm = &sasc_service_main;
    u32 *result = va_arg(*args, u32 *);
    char *node_name = 0;

    /* First try to match against registered services */
    for (int i = 0; i < vec_len(sm->services); i++) {
        sasc_service_registration_t *reg = vec_elt_at_index(sm->services, i)[0];
        if (unformat(input, reg->node_name)) {
            *result = i;
            return 1;
        }
    }

    /* If no service match, try to match any node name */
    if (unformat(input, "%s", &node_name)) {
        vlib_main_t *vm = vlib_get_main();
        vlib_node_t *node = vlib_get_node_by_name(vm, (u8 *)node_name);
        if (node) {
            /* For arbitrary nodes, use a special index range */
            *result = ~0 - node->index;
            return 1;
        }
    }

    return 0;
}

u8 *
format_sasc_session_key(u8 *s, va_list *args) {
    sasc_session_key_t *key = va_arg(*args, sasc_session_key_t *);
    u32 context_id = key->context_id;
    s = format(s, "%d: %U: %U:%d %U:%d", context_id, format_ip_protocol, key->proto, format_ip46_address, &key->src,
               IP46_TYPE_ANY, clib_net_to_host_u16(key->sport), format_ip46_address, &key->dst, IP46_TYPE_ANY,
               clib_net_to_host_u16(key->dport));
    return s;
}

/**
 * Generic function to format any vector of service indices.
 */
u8 *
format_sasc_service_chain_helper(u8 *s, u32 *service_indices) {
    if (!service_indices) {
        return s;
    }

    u32 *service_index;
    vec_foreach (service_index, service_indices) {
        if (*service_index == ~0) {
            s = format(s, "error-drop ");
        } else {
            const char *service_name = sasc_service_name_from_index(*service_index);
            if (service_name) {
                s = format(s, "%s ", service_name);
            } else {
                s = format(s, "unknown-service-%u ", *service_index);
            }
        }
    }

    // Remove trailing space
    if (vec_len(service_indices) > 0 && vec_len(s) > 0) {
        s[vec_len(s) - 1] = '\0';
    }
    return s;
}

u8 *
format_sasc_service_chain(u8 *s, va_list *args) {
    u32 chain_id = va_arg(*args, u32);
    sasc_main_t *sasc = &sasc_main;

    if (chain_id >= vec_len(sasc->chains)) {
        return s;
    }

    u32 *chain = *vec_elt_at_index(sasc->chains, chain_id);
    return format_sasc_service_chain_helper(s, chain);
}

u8 *
format_sasc_service_chain_from_vector(u8 *s, va_list *args) {
    u32 *chain = va_arg(*args, u32 *);
    return format_sasc_service_chain_helper(s, chain);
}

/**
 * Format effective service chain from index.
 */
u8 *
format_sasc_effective_service_chain(u8 *s, va_list *args) {
    u32 effective_chain_index = va_arg(*args, u32);
    sasc_main_t *sasc = &sasc_main;

    if (effective_chain_index >= vec_len(sasc->effective_service_chains)) {
        return s;
    }

    u32 *effective_services = sasc->effective_service_chains[effective_chain_index];
    return format_sasc_service_chain_helper(s, effective_services);
}

u8 *
format_sasc_tenant(u8 *s, va_list *args) {

    u8 indent = format_get_indent(s);
    __clib_unused sasc_main_t *sasc = va_arg(*args, sasc_main_t *);
    u32 tenant_idx = va_arg(*args, u32);
    sasc_tenant_t *tenant = va_arg(*args, sasc_tenant_t *);
    s = format(s, "index: %d\n", tenant_idx);
    s = format(s, "%Ucontext: %d\n", format_white_space, indent, tenant->context_id);

    static const char *chain_names[] = {
#define _(n, str) [SASC_SERVICE_CHAIN_##n] = str,
        foreach_sasc_service_chain_type
#undef _
    };
    for (int i = 0; i < SASC_SERVICE_CHAIN_N; i++) {
        if (tenant->service_chains[i] != ~0U) {
            s = format(s, "%U%s: %d: %U\n", format_white_space, indent, chain_names[i], tenant->service_chains[i],
                       format_sasc_service_chain, tenant->service_chains[i]);
        }
    }
    return s;
}

u8 *
format_sasc_tenant_extra(u8 *s, va_list *args) {
    // u32 indent = format_get_indent(s);
    // sasc_main_t *sasc = va_arg(*args, sasc_main_t *);
    // u32 tenant_idx = va_arg(*args, u32);
    // __clib_unused sasc_tenant_t *tenant = va_arg(*args, sasc_tenant_t *);

    // counter_t ctr;
    // vlib_counter_t ctr2;
    s = format(s, "%s\n", "Counters:");

    // ctr = vlib_get_simple_counter(&sasc->tenant_simple_ctr[SASC_TENANT_COUNTER_CREATED],
    // tenant_idx); s = format(s, "%Ucreated: %llu\n", format_white_space, indent + 2, ctr); ctr =
    // vlib_get_simple_counter(&sasc->tenant_simple_ctr[SASC_TENANT_COUNTER_REMOVED], tenant_idx);
    // s = format(s, "%Uexpired: %llu\n", format_white_space, indent + 2, ctr);

    // vlib_get_combined_counter(&sasc->tenant_combined_ctr[SASC_TENANT_COUNTER_RX], tenant_idx,
    // &ctr2); s = format(s, "%Urx: %llu packets\n", format_white_space, indent + 2, ctr2.packets);
    // s = format(s, "%U  %llu bytes\n", format_white_space, indent + strlen("rx") + 2, ctr2.bytes);
    // vlib_get_combined_counter(&sasc->tenant_combined_ctr[SASC_TENANT_COUNTER_TX], tenant_idx,
    // &ctr2); s = format(s, "%Utx: %llu packets\n", format_white_space, indent + 2, ctr2.packets);
    // s = format(s, "%U  %llu bytes\n", format_white_space, indent + strlen("tx") + 2, ctr2.bytes);

    return s;
}

u8 *
format_sasc_session_state(u8 *s, va_list *args) {
    u8 session_state = va_arg(*args, u32);
#define _(n, timeout, str)                                                                                             \
    if (session_state == SASC_SESSION_STATE_##n)                                                                       \
        s = format(s, "%s", (str));
    foreach_sasc_session_state
#undef _
        return s;
}

u8 *
format_sasc_session_services(u8 *s, va_list *args) {
    sasc_session_t *session = va_arg(*args, sasc_session_t *);
    bool detail = va_arg(*args, int);
    sasc_main_t *sasc = &sasc_main;
    sasc_service_main_t *sm = &sasc_service_main;
    u32 *service_index;
    u32 session_idx = session - sasc->sessions;
    u32 thread_index = 0;

    if (session->service_chain[SASC_FLOW_FORWARD] != 0xFFFF) {
        u32 *forward_chain = sasc->effective_service_chains[session->service_chain[SASC_FLOW_FORWARD]];
        vec_foreach (service_index, forward_chain) {
            if (*service_index < vec_len(sm->services) && sm->services[*service_index]->format_service)
                s = sm->services[*service_index]->format_service(s, thread_index, session_idx, detail);
        }
    }
    return s;
}

u8 *sasc_format_text_session(u8 *s, u32 session_index);
u8 *
format_sasc_session_detail(u8 *s, va_list *args) {
    sasc_session_t *session = va_arg(*args, sasc_session_t *);
    bool detail = va_arg(*args, int);

    if (detail) {
        s = sasc_format_text_session(s, session - sasc_main.sessions);
        s = format(s, "\n");
    } else {
        s = format(s, "%Upackets: %llu / %llu", format_white_space, 2, session->pkts[SASC_FLOW_FORWARD],
                   session->pkts[SASC_FLOW_REVERSE]);
        s = format(s, "\n%Ubytes: %llu / %llu", format_white_space, 2, session->bytes[SASC_FLOW_FORWARD],
                   session->bytes[SASC_FLOW_REVERSE]);
        s = format(s, "\n%Uduration: %u", format_white_space, 2, session->last_heard - session->created);
    }
    s = format(s, "\n%U", format_sasc_session_services, session, detail);
    return s;
}

u8 *
format_sasc_memory_usage(u8 *s, va_list *args) {
    sasc_service_main_t *sm = &sasc_service_main;
    sasc_service_registration_t **services = sm->services;
    sasc_service_registration_t *service;

    for (uword i = 0; i < vec_len(services); i++) {
        service = vec_elt_at_index(services, i)[0];
        if (service->memory_usage) {
            s = format(s, "%U%s: %llu\n", format_white_space, 2, service->node_name, service->memory_usage());
        }
    }
    return s;
}