// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#include "vppinfra/byte_order.h"
#include <sasc/sasc.h>
#include <sasc/service.h>
#include <sasc/session.h>
#include <sasc/sasc_funcs.h>
#include <sasc/ingress/ingress.h>

#include <stdbool.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/format_fns.h>

#include <sasc/sasc.api_enum.h>
#include <sasc/sasc.api_types.h>

#define REPLY_MSG_ID_BASE sasc->msg_id_base
#include <vlibapi/api_helper_macros.h>

// FIXME - Specify which APIs are mp-safe

static void
vl_api_sasc_interface_enable_disable_t_handler(vl_api_sasc_interface_enable_disable_t *mp) {
    sasc_main_t *sasc = &sasc_main;
    vl_api_sasc_interface_enable_disable_reply_t *rmp;
    int rv = 0;

    u32 sw_if_index = clib_net_to_host_u32(mp->sw_if_index);
    u32 tenant_idx = clib_net_to_host_u32(mp->tenant_idx);
    bool is_output = mp->is_output;
    bool is_enable = mp->is_enable;

    rv = sasc_interface_input_enable_disable(sw_if_index, tenant_idx, is_output, is_enable);

    REPLY_MACRO(VL_API_SASC_INTERFACE_ENABLE_DISABLE_REPLY);
}

static void
send_sasc_interface_details(vl_api_registration_t *reg, u32 context, u32 sw_if_index, u32 tenant_id, u8 is_output) {
    vl_api_sasc_interface_details_t *rmp;

    rmp = vl_msg_api_alloc(sizeof(*rmp));
    clib_memset(rmp, 0, sizeof(*rmp));
    rmp->_vl_msg_id = ntohs(VL_API_SASC_INTERFACE_DETAILS + sasc_main.msg_id_base);
    rmp->context = context;
    rmp->sw_if_index = ntohl(sw_if_index);
    rmp->tenant_id = ntohl(tenant_id);
    rmp->is_output = is_output;

    vl_api_send_msg(reg, (u8 *)rmp);
}

static void
vl_api_sasc_interface_dump_t_handler(vl_api_sasc_interface_dump_t *mp) {
    vl_api_registration_t *reg;
    sasc_ingress_main_t *sasc_ingress = &sasc_ingress_main;
    u32 sw_if_index;
    u32 filter_sw_if_index;

    reg = vl_api_client_index_to_registration(mp->client_index);
    if (!reg)
        return;

    filter_sw_if_index = ntohl(mp->sw_if_index);

    /* Iterate over all interfaces with SASC input ingress configuration */
    vec_foreach_index (sw_if_index, sasc_ingress->tenant_idx_by_sw_if_idx[0]) {
        /* Skip if filtering by specific interface */
        if (filter_sw_if_index != ~0 && sw_if_index != filter_sw_if_index)
            continue;

        u32 tenant_id = sasc_ingress->tenant_idx_by_sw_if_idx[0][sw_if_index];

        /* Skip entry if tenant-id is invalid */
        if (tenant_id == UINT16_MAX)
            continue;

        send_sasc_interface_details(reg, mp->context, sw_if_index, tenant_id, false /* is_output */);
    }

    /* Iterate over all interfaces with SASC output ingress configuration */
    vec_foreach_index (sw_if_index, sasc_ingress->tenant_idx_by_sw_if_idx[1]) {
        /* Skip if filtering by specific interface */
        if (filter_sw_if_index != ~0 && sw_if_index != filter_sw_if_index)
            continue;

        u32 tenant_id = sasc_ingress->tenant_idx_by_sw_if_idx[1][sw_if_index];

        /* Skip entry if tenant-id is invalid */
        if (tenant_id == UINT16_MAX)
            continue;

        send_sasc_interface_details(reg, mp->context, sw_if_index, tenant_id, true /* is_output */);
    }
}

static void
vl_api_sasc_set_services_t_handler(vl_api_sasc_set_services_t *mp) {
    sasc_main_t *sasc = &sasc_main;
    vl_api_sasc_set_services_reply_t *rmp;
    int rv = 0;

    u32 chain_id = clib_net_to_host_u32(mp->chain_id);
    u32 n_services = clib_net_to_host_u32(mp->n_services);
    u32 *services = 0;

    for (u32 i = 0; i < n_services; i++) {
        u32 service_index = clib_net_to_host_u32(mp->services[i]);
        vec_add1(services, service_index);
    }

    rv = sasc_set_services(chain_id, services);
    vec_free(services);

    REPLY_MACRO(VL_API_SASC_SET_SERVICES_REPLY);
}

static void
vl_api_sasc_tenant_add_t_handler(vl_api_sasc_tenant_add_t *mp) {
    sasc_main_t *sasc = &sasc_main;
    vl_api_sasc_tenant_add_reply_t *rmp;
    int rv = 0;

    u32 context_id = clib_net_to_host_u32(mp->context_id);
    u32 forward_chain_id = clib_net_to_host_u32(mp->forward_chain_id);
    u32 reverse_chain_id = clib_net_to_host_u32(mp->reverse_chain_id);
    u32 miss_chain_id = clib_net_to_host_u32(mp->miss_chain_id);
    u32 icmp_error_chain_id = clib_net_to_host_u32(mp->icmp_error_chain_id);

    /* Tenant is allocated from a pool - we expect the new tenant id to be returned
    through the API reply */
    u32 tenant_idx = ~0;

    clib_error_t *err = sasc_tenant_add(sasc, &tenant_idx, context_id, forward_chain_id, reverse_chain_id,
                                        miss_chain_id, icmp_error_chain_id);

    if (err) {
        rv = -1;
        clib_error_free(err);
    }

    REPLY_MACRO2(VL_API_SASC_TENANT_ADD_REPLY, ({ rmp->tenant_idx = clib_host_to_net_u32(tenant_idx); }));
}

static void
vl_api_sasc_tenant_del_t_handler(vl_api_sasc_tenant_del_t *mp) {
    sasc_main_t *sasc = &sasc_main;
    vl_api_sasc_tenant_del_reply_t *rmp;
    int rv = 0;

    u32 tenant_idx = clib_net_to_host_u32(mp->tenant_idx);

    clib_error_t *err = sasc_tenant_del(sasc, tenant_idx);

    if (err) {
        rv = -1;
        clib_error_free(err);
    }

    REPLY_MACRO(VL_API_SASC_TENANT_DEL_REPLY);
}

static void
vl_api_sasc_set_timeout_t_handler(vl_api_sasc_set_timeout_t *mp) {
    sasc_main_t *sasc = &sasc_main;
    vl_api_sasc_set_timeout_reply_t *rmp;
    int rv = 0;

    u32 timeouts[SASC_SESSION_N_STATE] = {0};

    timeouts[SASC_SESSION_STATE_FSOL] = clib_net_to_host_u32(mp->fsol_timeout);
    timeouts[SASC_SESSION_STATE_ESTABLISHED] = clib_net_to_host_u32(mp->established_timeout);
    timeouts[SASC_SESSION_STATE_TIME_WAIT] = clib_net_to_host_u32(mp->time_wait_timeout);
    timeouts[SASC_SESSION_STATE_TCP_TRANSITORY] = clib_net_to_host_u32(mp->tcp_transitory_timeout);
    timeouts[SASC_SESSION_STATE_TCP_FAST_TRANSITORY] = clib_net_to_host_u32(mp->tcp_fast_transitory_timeout);
    timeouts[SASC_SESSION_STATE_TCP_ESTABLISHED] = clib_net_to_host_u32(mp->tcp_established_timeout);

    rv = sasc_set_timeout(sasc, timeouts);

    REPLY_MACRO(VL_API_SASC_SET_TIMEOUT_REPLY);
}

static void
vl_api_sasc_session_clear_t_handler(vl_api_sasc_session_clear_t *mp) {
    sasc_main_t *sasc = &sasc_main;
    vl_api_sasc_session_clear_reply_t *rmp;
    int rv = 0;

    // FIXME - Worker barrier should be used before calling clear
    sasc_session_clear();

    REPLY_MACRO(VL_API_SASC_SESSION_CLEAR_REPLY);
}

static vl_api_sasc_session_state_t
sasc_session_state_encode(sasc_session_state_t state) {
    switch (state) {
#define _(name, val, str)                                                                                              \
    case SASC_SESSION_STATE_##name:                                                                                    \
        return SASC_API_SESSION_STATE_##name;
        foreach_sasc_session_state
#undef _
            default : return SASC_API_SESSION_STATE_EXPIRED;
    }
}

static void
sasc_session_key_encode(sasc_session_key_t *key, vl_api_sasc_session_key_t *out) {
    out->context_id = clib_host_to_net_u32(key->context_id);
    /* Port information in key is already in network byte order */
    out->sport = (key->sport);
    out->dport = (key->dport);

    /* Encode source and destination addresses */
    ip_address_encode(&key->src, ip46_address_get_type(&key->src), &out->src);
    ip_address_encode(&key->dst, ip46_address_get_type(&key->dst), &out->dst);
}

static void
sasc_send_session_details(vl_api_registration_t *rp, u32 context, u32 session_index, sasc_session_t *session,
                          sasc_session_slow_path_t *sp) {
    sasc_main_t *sasc = &sasc_main;
    vlib_main_t *vm = vlib_get_main();
    vl_api_sasc_session_details_t *mp;
    f64 now = vlib_time_now(vm);

    mp = vl_msg_api_alloc_zero(sizeof(*mp));
    mp->_vl_msg_id = clib_host_to_net_u16(VL_API_SASC_SESSION_DETAILS + sasc->msg_id_base);
    mp->context = context;

    mp->session_index = clib_host_to_net_u32(session_index);
    mp->tenant_idx = clib_host_to_net_u16(session->tenant_idx);
    mp->protocol = ip_proto_encode(session->protocol);
    // FIXME - Check if session state is properly encoded
    mp->state = sasc_session_state_encode(session->state);
    mp->remaining_time = clib_host_to_net_f64(sasc_session_remaining_time(session, now));
    // FIXME - The session currently stores/returns effective chain IDs, can we convert them
    // to absolute IDs ?
    mp->forward_chain_id = clib_host_to_net_u16(session->service_chain[SASC_FLOW_FORWARD]);
    mp->reverse_chain_id = clib_host_to_net_u16(session->service_chain[SASC_FLOW_REVERSE]);
    mp->bytes_forward = clib_host_to_net_u64(session->bytes[SASC_FLOW_FORWARD]);
    mp->bytes_reverse = clib_host_to_net_u64(session->bytes[SASC_FLOW_REVERSE]);
    mp->pkts_forward = clib_host_to_net_u32(session->pkts[SASC_FLOW_FORWARD]);
    mp->pkts_reverse = clib_host_to_net_u32(session->pkts[SASC_FLOW_REVERSE]);

    /* Encode information for Forward and Reverse flow keys */
    sasc_session_key_encode(&sp->forward_key, &mp->forward_key);
    sasc_session_key_encode(&sp->reverse_key, &mp->reverse_key);

    vl_api_send_msg(rp, (u8 *)mp);
}

static void
vl_api_sasc_session_dump_t_handler(vl_api_sasc_session_dump_t *mp) {
    sasc_main_t *sasc = &sasc_main;
    sasc_session_t *session;
    vl_api_registration_t *rp;

    rp = vl_api_client_index_to_registration(mp->client_index);
    if (rp == 0)
        return;

    pool_foreach (session, sasc->sessions) {
        // FIXME - Are we sure that corresponding slow-path information always exists ?
        u32 session_index = session - sasc->sessions;
        sasc_session_slow_path_t *sp = vec_elt_at_index(sasc->sp_sessions, session_index);
        sasc_send_session_details(rp, mp->context, session_index, session, sp);
    }
}

static void
sasc_send_tenant_details(vl_api_registration_t *rp, u32 context, u32 tenant_idx, sasc_tenant_t *tenant) {
    sasc_main_t *sasc = &sasc_main;
    vl_api_sasc_tenant_details_t *mp;

    mp = vl_msg_api_alloc_zero(sizeof(*mp));
    mp->_vl_msg_id = clib_host_to_net_u16(VL_API_SASC_TENANT_DETAILS + sasc->msg_id_base);
    mp->context = context;

    mp->tenant_idx = clib_host_to_net_u32(tenant_idx);
    mp->context_id = clib_host_to_net_u32(tenant->context_id);
    // FIXME - Are the tenant chain IDs set as effective IDs ?
    mp->forward_chain_id = clib_host_to_net_u32(tenant->service_chains[SASC_SERVICE_CHAIN_FORWARD]);
    mp->reverse_chain_id = clib_host_to_net_u32(tenant->service_chains[SASC_SERVICE_CHAIN_REVERSE]);
    mp->miss_chain_id = clib_host_to_net_u32(tenant->service_chains[SASC_SERVICE_CHAIN_MISS]);
    mp->icmp_error_chain_id = clib_host_to_net_u32(tenant->service_chains[SASC_SERVICE_CHAIN_ICMP_ERROR]);

    vl_api_send_msg(rp, (u8 *)mp);
}

static void
vl_api_sasc_tenant_dump_t_handler(vl_api_sasc_tenant_dump_t *mp) {
    sasc_main_t *sasc = &sasc_main;
    sasc_tenant_t *tenant;
    u32 tenant_idx;
    vl_api_registration_t *rp;

    rp = vl_api_client_index_to_registration(mp->client_index);
    if (rp == 0)
        return;

    pool_foreach_index (tenant_idx, sasc->tenants) {
        tenant = sasc_tenant_at_index(sasc, tenant_idx);
        sasc_send_tenant_details(rp, mp->context, tenant_idx, tenant);
    }
}

static void
sasc_send_service_details(vl_api_registration_t *rp, u32 context, u32 service_index, const char *name) {
    sasc_main_t *sasc = &sasc_main;
    vl_api_sasc_service_details_t *mp;

    mp = vl_msg_api_alloc_zero(sizeof(*mp));
    mp->_vl_msg_id = clib_host_to_net_u16(VL_API_SASC_SERVICE_DETAILS + sasc->msg_id_base);
    mp->context = context;

    mp->service_index = clib_host_to_net_u32(service_index);
    if (name) {
        size_t len = clib_min(strlen(name), sizeof(mp->name) - 1);
        clib_memcpy(mp->name, name, len);
    }

    vl_api_send_msg(rp, (u8 *)mp);
}

static void
vl_api_sasc_service_dump_t_handler(vl_api_sasc_service_dump_t *mp) {
    sasc_service_main_t *sm = &sasc_service_main;
    sasc_service_registration_t *service;
    vl_api_registration_t *rp;

    rp = vl_api_client_index_to_registration(mp->client_index);
    if (rp == 0)
        return;

    // FIXME - More information could be sent about the service, such as dependencies/conflicts
    // memory consumption, and cbor schema

    for (u32 i = 0; i < vec_len(sm->services); i++) {
        service = sm->services[i];
        sasc_send_service_details(rp, mp->context, i, service->node_name);
    }
}

static void
sasc_send_service_chain_details(vl_api_registration_t *rp, u32 context, u32 chain_id, u32 *chain) {
    sasc_main_t *sasc = &sasc_main;
    vl_api_sasc_service_chain_details_t *mp;
    u32 n_services = vec_len(chain);
    size_t msg_size = sizeof(*mp) + sizeof(mp->services[0]) * n_services;

    mp = vl_msg_api_alloc_zero(msg_size);
    mp->_vl_msg_id = clib_host_to_net_u16(VL_API_SASC_SERVICE_CHAIN_DETAILS + sasc->msg_id_base);
    mp->context = context;

    // FIXME - Chain ID for services are fine, but if we refer to a chain ID
    // for a VPP node (i.e error drop) the returned ID will be "~0 - node_index"
    mp->chain_id = clib_host_to_net_u32(chain_id);
    mp->n_services = clib_host_to_net_u32(n_services);

    for (u32 i = 0; i < n_services; i++) {
        mp->services[i] = clib_host_to_net_u32(chain[i]);
    }

    vl_api_send_msg(rp, (u8 *)mp);
}

static void
vl_api_sasc_service_chain_dump_t_handler(vl_api_sasc_service_chain_dump_t *mp) {
    sasc_main_t *sasc = &sasc_main;
    vl_api_registration_t *rp;

    rp = vl_api_client_index_to_registration(mp->client_index);
    if (rp == 0)
        return;

    for (u32 i = 0; i < vec_len(sasc->chains); i++) {
        u32 *chain = sasc->chains[i];
        if (chain) {
            sasc_send_service_chain_details(rp, mp->context, i, chain);
        }
    }
}

u32 sasc_table_memory_size(void);

static void
vl_api_sasc_summary_t_handler(vl_api_sasc_summary_t *mp) {
    sasc_main_t *sasc = &sasc_main;
    vl_api_sasc_summary_reply_t *rmp;
    int rv = 0;

    REPLY_MACRO2(VL_API_SASC_SUMMARY_REPLY, ({
                     rmp->max_sessions = clib_host_to_net_u32(sasc->no_sessions);
                     rmp->active_sessions = clib_host_to_net_u32(pool_elts(sasc->sessions));
                     rmp->active_tenants = clib_host_to_net_u32(pool_elts(sasc->tenants));
                     rmp->session_hash_memory = clib_host_to_net_u64(sasc_table_memory_size());
                     rmp->session_table_memory = clib_host_to_net_u64(sizeof(sasc_session_t) * sasc->no_sessions);
                 }));
}

#include <sasc/sasc.api.c>
static clib_error_t *
sasc_plugin_api_hookup(vlib_main_t *vm) {
    sasc_main_t *sasc = &sasc_main;
    sasc->msg_id_base = setup_message_id_table();
    return 0;
}
VLIB_API_INIT_FUNCTION(sasc_plugin_api_hookup);
