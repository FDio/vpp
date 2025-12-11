/*
 * SASC VAT support
 *
 * Copyright (c) 2025 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "vnet/ip/ip_types.h"
#include <inttypes.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <sasc/sasc.h>
#include <vnet/ip/ip_types_api.h>

#include <vppinfra/error.h>

#define __plugin_msg_base sasc_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#include <vnet/format_fns.h>
#include <sasc/sasc.api_enum.h>
#include <sasc/sasc.api_types.h>
#include <vlibmemory/vlib.api_types.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    u32 ping_id;
    vat_main_t *vat_main;
} sasc_test_main_t;

sasc_test_main_t sasc_test_main;

/* Format functions for session state */
static u8 *
format_sasc_session_state_api(u8 *s, va_list *args) {
    vl_api_sasc_session_state_t state = va_arg(*args, int);
    switch (state) {
    case SASC_API_SESSION_STATE_FSOL:
        return format(s, "fsol");
    case SASC_API_SESSION_STATE_ESTABLISHED:
        return format(s, "established");
    case SASC_API_SESSION_STATE_TIME_WAIT:
        return format(s, "time-wait");
    case SASC_API_SESSION_STATE_TCP_TRANSITORY:
        return format(s, "tcp-transitory");
    case SASC_API_SESSION_STATE_TCP_FAST_TRANSITORY:
        return format(s, "tcp-fast-transitory");
    case SASC_API_SESSION_STATE_TCP_ESTABLISHED:
        return format(s, "tcp-established");
    case SASC_API_SESSION_STATE_STATIC:
        return format(s, "static");
    case SASC_API_SESSION_STATE_EXPIRED:
        return format(s, "expired");
    default:
        return format(s, "unknown(%d)", state);
    }
}

/* Handler for sasc_session_details */
static void
vl_api_sasc_session_details_t_handler(vl_api_sasc_session_details_t *mp) {
    vat_main_t *vam = &vat_main;
    ip_address_t fwd_src, fwd_dst, rev_src, rev_dst;
    ip_address_decode2(&mp->forward_key.src, &fwd_src);
    ip_address_decode2(&mp->forward_key.dst, &fwd_dst);
    ip_address_decode2(&mp->reverse_key.src, &rev_src);
    ip_address_decode2(&mp->reverse_key.dst, &rev_dst);

    fformat(vam->ofp, "  session_index: %u, tenant: %u, proto: %u, state: %U\n", ntohl(mp->session_index),
            ntohs(mp->tenant_idx), mp->protocol, format_sasc_session_state_api, mp->state);
    fformat(vam->ofp, "    remaining_time: %.2f, chains: fwd=%u rev=%u\n", mp->remaining_time,
            ntohs(mp->forward_chain_id), ntohs(mp->reverse_chain_id));
    fformat(vam->ofp, "    bytes: fwd=%" PRIu64 " rev=%" PRIu64 "\n", clib_net_to_host_u64(mp->bytes_forward),
            clib_net_to_host_u64(mp->bytes_reverse));
    fformat(vam->ofp, "    pkts: fwd=%u rev=%u\n", ntohl(mp->pkts_forward), ntohl(mp->pkts_reverse));
    fformat(vam->ofp, "    forward-key: context-id=%u src-ip=%U dst-ip=%U src-port=%u, dst-port=%u\n",
            ntohl(mp->forward_key.context_id), format_ip_address, &fwd_src, format_ip_address, &fwd_dst,
            ntohs(mp->forward_key.sport), ntohs(mp->forward_key.dport));
    fformat(vam->ofp, "    reverse-key: context-id=%u src-ip=%U dst-ip=%U src-port=%u, dst-port=%u\n",
            ntohl(mp->reverse_key.context_id), format_ip_address, &rev_src, format_ip_address, &rev_dst,
            ntohs(mp->reverse_key.sport), ntohs(mp->reverse_key.dport));
}

/* Handler for sasc_tenant_details */
static void
vl_api_sasc_tenant_details_t_handler(vl_api_sasc_tenant_details_t *mp) {
    vat_main_t *vam = &vat_main;

    fformat(vam->ofp, "  tenant_idx: %u, context_id: %u\n", ntohl(mp->tenant_idx), ntohl(mp->context_id));
    fformat(vam->ofp, "    chains: forward=%u reverse=%u miss=%u icmp_error=%u\n", ntohl(mp->forward_chain_id),
            ntohl(mp->reverse_chain_id), ntohl(mp->miss_chain_id), ntohl(mp->icmp_error_chain_id));
}

/* Handler for sasc_service_details */
static void
vl_api_sasc_service_details_t_handler(vl_api_sasc_service_details_t *mp) {
    vat_main_t *vam = &vat_main;

    fformat(vam->ofp, "  service_index: %u, name: %s\n", ntohl(mp->service_index), mp->name);
}

/* Handler for sasc_service_chain_details */
static void
vl_api_sasc_service_chain_details_t_handler(vl_api_sasc_service_chain_details_t *mp) {
    vat_main_t *vam = &vat_main;
    u32 n_services = ntohl(mp->n_services);

    fformat(vam->ofp, "  chain_id: %u, n_services: %u\n", ntohl(mp->chain_id), n_services);
    fformat(vam->ofp, "    services: [");
    for (u32 i = 0; i < n_services; i++) {
        if (i > 0)
            fformat(vam->ofp, ", ");
        fformat(vam->ofp, "%u", ntohl(mp->services[i]));
    }
    fformat(vam->ofp, "]\n");
}

/* Handler for sasc_summary_reply */
static void
vl_api_sasc_summary_reply_t_handler(vl_api_sasc_summary_reply_t *mp) {
    vat_main_t *vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    if (retval == 0) {
        fformat(vam->ofp, "SASC Summary:\n");
        fformat(vam->ofp, "  max_sessions: %u\n", ntohl(mp->max_sessions));
        fformat(vam->ofp, "  active_sessions: %u\n", ntohl(mp->active_sessions));
        fformat(vam->ofp, "  active_tenants: %u\n", ntohl(mp->active_tenants));
        fformat(vam->ofp, "  session_hash_memory: %" PRIu64 "\n", clib_net_to_host_u64(mp->session_hash_memory));
        fformat(vam->ofp, "  session_table_memory: %" PRIu64 "\n", clib_net_to_host_u64(mp->session_table_memory));
    }

    vam->retval = retval;
    vam->result_ready = 1;
}

/* Handler for sasc_add_tenant_reply */
static void
vl_api_sasc_tenant_add_reply_t_handler(vl_api_sasc_tenant_add_reply_t *mp) {
    vat_main_t *vam = &vat_main;
    i32 retval = ntohl(mp->retval);

    if (retval == 0) {
        fformat(vam->ofp, "created tenant-id: %u\n", ntohl(mp->tenant_idx));
    }

    vam->retval = retval;
    vam->result_ready = 1;
}

/* API: sasc_interface_enable_disable */
static int
api_sasc_interface_enable_disable(vat_main_t *vam) {
    unformat_input_t *i = vam->input;
    vl_api_sasc_interface_enable_disable_t *mp;
    u32 sw_if_index = ~0;
    u32 tenant_idx = ~0;
    u8 is_output = 0;
    u8 is_enable = 1;
    int ret;

    while (unformat_check_input(i) != UNFORMAT_END_OF_INPUT) {
        if (unformat(i, "%U", api_unformat_sw_if_index, vam, &sw_if_index))
            ;
        else if (unformat(i, "sw_if_index %u", &sw_if_index))
            ;
        else if (unformat(i, "tenant %u", &tenant_idx))
            ;
        else if (unformat(i, "output"))
            is_output = 1;
        else if (unformat(i, "input"))
            is_output = 0;
        else if (unformat(i, "enable"))
            is_enable = 1;
        else if (unformat(i, "disable"))
            is_enable = 0;
        else {
            errmsg("unknown input '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (sw_if_index == ~0) {
        errmsg("missing interface name or sw_if_index");
        return -99;
    }

    if (tenant_idx == ~0) {
        errmsg("missing tenant index");
        return -99;
    }

    M(SASC_INTERFACE_ENABLE_DISABLE, mp);
    mp->sw_if_index = htonl(sw_if_index);
    mp->tenant_idx = htonl(tenant_idx);
    mp->is_output = is_output;
    mp->is_enable = is_enable;

    S(mp);
    W(ret);
    return ret;
}

/* Handler for ingress interface details - called for each interface in dump */
static void
vl_api_sasc_interface_details_t_handler(vl_api_sasc_interface_details_t *mp) {
    vat_main_t *vam = sasc_test_main.vat_main;
    u32 sw_if_index = ntohl(mp->sw_if_index);
    u32 tenant_id = ntohl(mp->tenant_id);
    u8 is_output = mp->is_output;

    fformat(vam->ofp,
            "Ingress Interface:\n"
            "  sw_if_index: %u\n"
            "  tenant_id: %u\n"
            "  is_output: %s\n"
            "---\n",
            sw_if_index, tenant_id, is_output ? "yes" : "no");
}

/* Test API function for dumping ingress interfaces */
static int
api_sasc_interface_dump(vat_main_t *vam) {
    unformat_input_t *i = vam->input;
    vl_api_sasc_interface_dump_t *mp;
    vl_api_control_ping_t *mp_ping;
    u32 sw_if_index = ~0; /* default: dump all */
    int ret;

    /* Parse optional arguments */
    while (unformat_check_input(i) != UNFORMAT_END_OF_INPUT) {
        if (unformat(i, "sw_if_index %u", &sw_if_index))
            ;
        else if (unformat(i, "interface %U", unformat_vnet_sw_interface, vnet_get_main(), &sw_if_index))
            ;
        else {
            clib_warning("unknown input '%U'", format_unformat_error, i);
            return -99;
        }
    }

    /* Construct and send the dump request */
    M(SASC_INTERFACE_DUMP, mp);
    mp->sw_if_index = htonl(sw_if_index);
    S(mp);

    /* Send control ping to signal end of dump */
    PING(&sasc_test_main, mp_ping);
    S(mp_ping);

    W(ret);
    return ret;
}

/* API: sasc_set_services */
static int
api_sasc_set_services(vat_main_t *vam) {
    unformat_input_t *i = vam->input;
    vl_api_sasc_set_services_t *mp;
    u32 chain_id = ~0;
    u32 *services = 0;
    u32 service_index;
    int ret;

    while (unformat_check_input(i) != UNFORMAT_END_OF_INPUT) {
        if (unformat(i, "chain %u", &chain_id))
            ;
        else if (unformat(i, "%u", &service_index))
            vec_add1(services, service_index);
        else {
            errmsg("unknown input '%U'", format_unformat_error, i);
            vec_free(services);
            return -99;
        }
    }

    if (chain_id == ~0) {
        errmsg("missing chain_id");
        vec_free(services);
        return -99;
    }

    u32 n_services = vec_len(services);
    size_t msg_size = sizeof(*mp) + sizeof(mp->services[0]) * n_services;
    mp = vl_msg_api_alloc_as_if_client(msg_size);
    clib_memset(mp, 0, msg_size);

    mp->_vl_msg_id = ntohs(VL_API_SASC_SET_SERVICES + sasc_test_main.msg_id_base);
    mp->client_index = vam->my_client_index;
    mp->chain_id = htonl(chain_id);
    mp->n_services = htonl(n_services);

    for (u32 j = 0; j < n_services; j++)
        mp->services[j] = htonl(services[j]);

    vec_free(services);

    S(mp);
    W(ret);
    return ret;
}

/* API: sasc_tenant_add */
static int
api_sasc_tenant_add(vat_main_t *vam) {
    unformat_input_t *i = vam->input;
    vl_api_sasc_tenant_add_t *mp;
    u32 context_id = 0;
    u32 forward_chain_id = ~0;
    u32 reverse_chain_id = ~0;
    u32 miss_chain_id = ~0;
    u32 icmp_error_chain_id = ~0;
    int ret;

    while (unformat_check_input(i) != UNFORMAT_END_OF_INPUT) {
        if (unformat(i, "context %u", &context_id))
            ;
        else if (unformat(i, "forward %u", &forward_chain_id))
            ;
        else if (unformat(i, "reverse %u", &reverse_chain_id))
            ;
        else if (unformat(i, "miss %u", &miss_chain_id))
            ;
        else if (unformat(i, "icmp-error %u", &icmp_error_chain_id))
            ;
        else {
            errmsg("unknown input '%U'", format_unformat_error, i);
            return -99;
        }
    }

    M(SASC_TENANT_ADD, mp);
    mp->context_id = htonl(context_id);
    mp->forward_chain_id = htonl(forward_chain_id);
    mp->reverse_chain_id = htonl(reverse_chain_id);
    mp->miss_chain_id = htonl(miss_chain_id);
    mp->icmp_error_chain_id = htonl(icmp_error_chain_id);

    S(mp);
    W(ret);
    return ret;
}

/* API: sasc_tenant_del */
static int
api_sasc_tenant_del(vat_main_t *vam) {
    unformat_input_t *i = vam->input;
    vl_api_sasc_tenant_del_t *mp;
    u32 tenant_idx = ~0;
    int ret;

    while (unformat_check_input(i) != UNFORMAT_END_OF_INPUT) {
        if (unformat(i, "tenant %u", &tenant_idx))
            ;
        else {
            errmsg("unknown input '%U'", format_unformat_error, i);
            return -99;
        }
    }

    if (tenant_idx == ~0) {
        errmsg("missing tenant index");
        return -99;
    }

    M(SASC_TENANT_DEL, mp);
    mp->tenant_idx = htonl(tenant_idx);

    S(mp);
    W(ret);
    return ret;
}

/* API: sasc_set_timeout */
static int
api_sasc_set_timeout(vat_main_t *vam) {
    unformat_input_t *i = vam->input;
    vl_api_sasc_set_timeout_t *mp;
    u32 fsol_timeout = 0;
    u32 established_timeout = 0;
    u32 time_wait_timeout = 0;
    u32 tcp_transitory_timeout = 0;
    u32 tcp_fast_transitory_timeout = 0;
    u32 tcp_established_timeout = 0;
    int ret;

    while (unformat_check_input(i) != UNFORMAT_END_OF_INPUT) {
        if (unformat(i, "fsol %u", &fsol_timeout))
            ;
        else if (unformat(i, "established %u", &established_timeout))
            ;
        else if (unformat(i, "time-wait %u", &time_wait_timeout))
            ;
        else if (unformat(i, "tcp-transitory %u", &tcp_transitory_timeout))
            ;
        else if (unformat(i, "tcp-fast-transitory %u", &tcp_fast_transitory_timeout))
            ;
        else if (unformat(i, "tcp-established %u", &tcp_established_timeout))
            ;
        else {
            errmsg("unknown input '%U'", format_unformat_error, i);
            return -99;
        }
    }

    M(SASC_SET_TIMEOUT, mp);
    mp->fsol_timeout = htonl(fsol_timeout);
    mp->established_timeout = htonl(established_timeout);
    mp->time_wait_timeout = htonl(time_wait_timeout);
    mp->tcp_transitory_timeout = htonl(tcp_transitory_timeout);
    mp->tcp_fast_transitory_timeout = htonl(tcp_fast_transitory_timeout);
    mp->tcp_established_timeout = htonl(tcp_established_timeout);

    S(mp);
    W(ret);
    return ret;
}

/* API: sasc_session_clear */
static int
api_sasc_session_clear(vat_main_t *vam) {
    vl_api_sasc_session_clear_t *mp;
    int ret;

    M(SASC_SESSION_CLEAR, mp);

    S(mp);
    W(ret);
    return ret;
}

/* API: sasc_session_dump */
static int
api_sasc_session_dump(vat_main_t *vam) {
    sasc_test_main_t *stm = &sasc_test_main;
    vl_api_sasc_session_dump_t *mp;
    vl_api_control_ping_t *mp_ping;
    int ret;

    if (vam->json_output) {
        clib_warning("JSON output not supported for sasc_session_dump");
        return -99;
    }

    fformat(vam->ofp, "SASC Sessions:\n");

    M(SASC_SESSION_DUMP, mp);
    S(mp);

    /* Use a control ping for synchronization */
    if (!stm->ping_id)
        stm->ping_id = vl_msg_api_get_msg_index((u8 *)(VL_API_CONTROL_PING_CRC));
    mp_ping = vl_msg_api_alloc_as_if_client(sizeof(*mp_ping));
    mp_ping->_vl_msg_id = htons(stm->ping_id);
    mp_ping->client_index = vam->my_client_index;

    vam->result_ready = 0;
    S(mp_ping);

    W(ret);
    return ret;
}

/* API: sasc_tenant_dump */
static int
api_sasc_tenant_dump(vat_main_t *vam) {
    sasc_test_main_t *stm = &sasc_test_main;
    vl_api_sasc_tenant_dump_t *mp;
    vl_api_control_ping_t *mp_ping;
    int ret;

    if (vam->json_output) {
        clib_warning("JSON output not supported for sasc_tenant_dump");
        return -99;
    }

    fformat(vam->ofp, "SASC Tenants:\n");

    M(SASC_TENANT_DUMP, mp);
    S(mp);

    /* Use a control ping for synchronization */
    if (!stm->ping_id)
        stm->ping_id = vl_msg_api_get_msg_index((u8 *)(VL_API_CONTROL_PING_CRC));
    mp_ping = vl_msg_api_alloc_as_if_client(sizeof(*mp_ping));
    mp_ping->_vl_msg_id = htons(stm->ping_id);
    mp_ping->client_index = vam->my_client_index;

    vam->result_ready = 0;
    S(mp_ping);

    W(ret);
    return ret;
}

/* API: sasc_service_dump */
static int
api_sasc_service_dump(vat_main_t *vam) {
    sasc_test_main_t *stm = &sasc_test_main;
    vl_api_sasc_service_dump_t *mp;
    vl_api_control_ping_t *mp_ping;
    int ret;

    if (vam->json_output) {
        clib_warning("JSON output not supported for sasc_service_dump");
        return -99;
    }

    fformat(vam->ofp, "SASC Services:\n");

    M(SASC_SERVICE_DUMP, mp);
    S(mp);

    /* Use a control ping for synchronization */
    if (!stm->ping_id)
        stm->ping_id = vl_msg_api_get_msg_index((u8 *)(VL_API_CONTROL_PING_CRC));
    mp_ping = vl_msg_api_alloc_as_if_client(sizeof(*mp_ping));
    mp_ping->_vl_msg_id = htons(stm->ping_id);
    mp_ping->client_index = vam->my_client_index;

    vam->result_ready = 0;
    S(mp_ping);

    W(ret);
    return ret;
}

/* API: sasc_service_chain_dump */
static int
api_sasc_service_chain_dump(vat_main_t *vam) {
    sasc_test_main_t *stm = &sasc_test_main;
    vl_api_sasc_service_chain_dump_t *mp;
    vl_api_control_ping_t *mp_ping;
    int ret;

    if (vam->json_output) {
        clib_warning("JSON output not supported for sasc_service_chain_dump");
        return -99;
    }

    fformat(vam->ofp, "SASC Service Chains:\n");

    M(SASC_SERVICE_CHAIN_DUMP, mp);
    S(mp);

    /* Use a control ping for synchronization */
    if (!stm->ping_id)
        stm->ping_id = vl_msg_api_get_msg_index((u8 *)(VL_API_CONTROL_PING_CRC));
    mp_ping = vl_msg_api_alloc_as_if_client(sizeof(*mp_ping));
    mp_ping->_vl_msg_id = htons(stm->ping_id);
    mp_ping->client_index = vam->my_client_index;

    vam->result_ready = 0;
    S(mp_ping);

    W(ret);
    return ret;
}

/* API: sasc_summary */
static int
api_sasc_summary(vat_main_t *vam) {
    vl_api_sasc_summary_t *mp;
    int ret;

    M(SASC_SUMMARY, mp);

    S(mp);
    W(ret);
    return ret;
}

#include <sasc/sasc.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
