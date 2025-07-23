// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_sasc_funcs_h
#define included_sasc_funcs_h

#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/vnet.h>
#include <sasc/sasc.h>

static_always_inline u32
sasc_session_from_flow_index(u32 flow_index) {
    return flow_index >> 1;
}

static_always_inline sasc_session_t *
sasc_session_at_index(sasc_main_t *sasc, u32 idx) {
    return pool_elt_at_index(sasc->sessions, idx);
}

static_always_inline sasc_session_t *
sasc_session_at_index_check(sasc_main_t *sasc, u32 idx) {
    if (pool_is_free_index(sasc->sessions, idx))
        return 0;
    return pool_elt_at_index(sasc->sessions, idx);
}

static_always_inline u32
sasc_thread_index_from_lookup(u64 val) {
    return val >> 32;
}

static_always_inline u32
sasc_direction_from_flow_index(u32 flow_index) {
    return (flow_index & 0x1);
}

// static_always_inline sasc_session_key_t *
// sasc_session_get_key(sasc_session_t *session, u32 key_index) {
//     return &session->keys[key_index];
// }

static_always_inline u64
sasc_session_mk_table_value(u32 thread_index, u32 key_index) {
    return ((u64)thread_index << 32) | key_index;
}

static inline ip4_header_t *
sasc_get_ip4_header(vlib_buffer_t *b) {
    return vlib_buffer_get_current(b) + vnet_buffer(b)->ip.save_rewrite_length;
}

static inline ip6_header_t *
sasc_get_ip6_header(vlib_buffer_t *b) {
    return vlib_buffer_get_current(b) + vnet_buffer(b)->ip.save_rewrite_length;
}

/* TODO: Fix this so it works in all cases */
static inline u16
sasc_get_l3_length(vlib_main_t *vm, vlib_buffer_t *b) {
    return vlib_buffer_length_in_chain(vm, b);
}

static_always_inline sasc_tenant_t *
sasc_tenant_at_index(sasc_main_t *sasc, u32 idx) {
    if (pool_is_free_index(sasc->tenants, idx))
        return 0;
    return pool_elt_at_index(sasc->tenants, idx);
}

static inline int
sasc_session_get_timeout(sasc_main_t *sasc, sasc_session_t *s) {
    return sasc->timeouts[s->state];
}

static_always_inline f64
sasc_session_remaining_time(sasc_session_t *s, f64 now) {
    sasc_main_t *sasc = &sasc_main;
    f64 timeout = s->last_heard + (f64)sasc_session_get_timeout(sasc, s);
    f64 remaining = timeout - now;
    return remaining > 0 ? remaining : 0;
}

/**
 * Get effective service chain for a specific chain_id and protocol group.
 *
 * @param sasc Pointer to sasc_main_t
 * @param chain_id The configured chain ID
 * @param proto_group The protocol group
 * @return Pointer to vector of effective service indices, or NULL if not found
 */
static_always_inline u32
sasc_get_effective_service_chain_index(sasc_main_t *sasc, u32 chain_id, sasc_proto_group_t proto_group) {
    if (chain_id >= vec_len(sasc->chains)) {
        return ~0U;
    }
    return (chain_id * SASC_PROTO_GROUP_N) + proto_group;
}
static_always_inline u32 *
sasc_get_effective_service_chain(sasc_main_t *sasc, u32 chain_id, sasc_proto_group_t proto_group) {
    u32 effective_index = sasc_get_effective_service_chain_index(sasc, chain_id, proto_group);
    if (effective_index == ~0U) {
        return 0;
    }

    return sasc->effective_service_chains[effective_index];
}

/* Parse IP header for ECN, TTL, and DSCP */
static inline void
sasc_parse_ip_header(vlib_buffer_t *b, u32 *l3_len, u32 *ecn, u8 *ttl, u32 *dscp) {
    ip4_header_t *ip4 = (ip4_header_t *)(b->data + vnet_buffer(b)->l3_hdr_offset);
    if (ip4->ip_version_and_header_length >> 4 == 4) {
        /* IPv4 */
        *l3_len = clib_net_to_host_u16(ip4->length);
        *ecn = ip4_header_get_ecn(ip4);
        *ttl = ip4->ttl;
        *dscp = ip4_header_get_dscp(ip4);
    } else {
        // /* IPv6 */
        // ip6_header_t *ip6 = (ip6_header_t *)(b->data + vnet_buffer(b)->l3_hdr_offset);
        // *ecn = ip6_header_get_ecn(ip6);
        // *ttl = ip6_header_get_hop_limit(ip6);
        // *dscp = ip6_header_get_dscp(ip6);
    }
}
#endif
