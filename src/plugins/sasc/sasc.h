// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#ifndef __INCLUDED_SESSCHAIN_H__
#define __INCLUDED_SESSCHAIN_H__

#include <vlib/vlib.h>
#include <vnet/buffer.h>
#include <vppinfra/bihash_40_8.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/ip/ip_types.h>
#include <sasc/format.h>

/* logging */
#define sasc_log_err(...)    vlib_log(VLIB_LOG_LEVEL_ERR, sasc_main.log_class, __VA_ARGS__)
#define sasc_log_warn(...)   vlib_log(VLIB_LOG_LEVEL_WARNING, sasc_main.log_class, __VA_ARGS__)
#define sasc_log_notice(...) vlib_log(VLIB_LOG_LEVEL_NOTICE, sasc_main.log_class, __VA_ARGS__)
#define sasc_log_info(...)   vlib_log(VLIB_LOG_LEVEL_INFO, sasc_main.log_class, __VA_ARGS__)
#define sasc_log_debug(...)  vlib_log(VLIB_LOG_LEVEL_DEBUG, sasc_main.log_class, __VA_ARGS__)

typedef enum {
    SASC_FLOW_FORWARD = 0,
    SASC_FLOW_REVERSE = 1,
    SASC_FLOW_F_B_N = 2,
} sasc_session_direction_t;

enum {
    SASC_SESSION_KEY_PRIMARY = 0,
    SASC_SESSION_KEY_SECONDARY = 1,
    SASC_SESSION_N_KEY = 2,
};

enum sasc_lookup_mode_e {
    SASC_LOOKUP_MODE_DEFAULT = 0,
    SASC_LOOKUP_MODE_4TUPLE,
    SASC_LOOKUP_MODE_3TUPLE,
    SASC_LOOKUP_MODE_1TUPLE,
};

#define foreach_sasc_session_state                                                                                     \
    _(FSOL, 10, "fsol")                                                                                                \
    _(ESTABLISHED, 240, "established")                                                                                 \
    _(TIME_WAIT, 30, "time-wait")                                                                                      \
    _(TCP_TRANSITORY, 30, "tcp-transitory")                                                                            \
    _(TCP_FAST_TRANSITORY, 3, "tcp-fast-transitory")                                                                   \
    _(TCP_ESTABLISHED, 7440, "tcp-established")                                                                        \
    _(STATIC, 0, "static")                                                                                             \
    _(EXPIRED, 0, "expired")

typedef enum __attribute__((packed)) {
#define _(name, val, str) SASC_SESSION_STATE_##name,
    foreach_sasc_session_state
#undef _
        SASC_SESSION_N_STATE
} sasc_session_state_t;
_Static_assert(sizeof(sasc_session_state_t) == 1, "sasc_session_state_t must fit in u8");
typedef struct __attribute__((packed)) {
    ip46_address_t src;
    ip46_address_t dst;
    u32 proto : 8;
    u32 context_id : 24;
    u16 sport;
    u16 dport;
} sasc_session_key_t;
_Static_assert(sizeof(sasc_session_key_t) == 40, "Size of sasc_session_key_t should be 40");

typedef u16 session_version_t;
typedef struct {
    /* First cache line (64 bytes) - Fast path fields */
    u64 bytes[SASC_FLOW_F_B_N];         // 16 bytes
    u32 pkts[SASC_FLOW_F_B_N];          // 8 bytes
    u32 last_heard;                     // 4 bytes
    u32 created;                        // 4 bytes - seconds since VPP start
    u16 service_chain[SASC_FLOW_F_B_N]; // 4 bytes
    u16 thread_index;                   // 4 bytes - matches table value type
    u16 tenant_idx;                     // 2 bytes
    session_version_t session_version;  // 2 bytes - 44 bytes
    u16 icmp_mtu;                       // 2 bytes - ICMP MTU
    sasc_session_state_t state;         // 1 byte
    u8 protocol;                        // 1 byte - protocol
    u8 flags;                           // 1 byte - session flags
    u8 icmp_unreach;                    // 1 byte - ICMP unreachable count
    u8 icmp_frag_needed;                // 1 byte - ICMP fragment needed count
    u8 icmp_ttl_expired;                // 1 byte - ICMP TTL expired count
    u8 icmp_packet_too_big;             // 1 byte - ICMP packet too big count
    u8 icmp_other;                      // 1 byte - ICMP other count
    u8 _pad0[12];                       // 2 bytes - pad to keep fast-path block 64 bytes
} __attribute__((aligned(64))) sasc_session_t;
_Static_assert(sizeof(sasc_session_t) == 64, "Size of sasc_session_t should be 64");

typedef struct {
    /* Debug keys - array index matches SASC_SESSION_KEY_PRIMARY/SECONDARY */
    union {
        sasc_session_key_t keys[SASC_SESSION_N_KEY]; // 2x 40 bytes
        struct {
            sasc_session_key_t forward_key; // 40 bytes
            sasc_session_key_t reverse_key; // 40 bytes
        };
    };
} sasc_session_slow_path_t;
_Static_assert(sizeof(sasc_session_slow_path_t) == 80, "Size of sasc_session_slow_path_t should be 80");

#define sasc_chain_entries_foreach(_entry, _chain) vec_foreach (_entry, ((_chain)->entries))

#define foreach_sasc_service_chain_type                                                                                \
    _(FORWARD, "forward")                                                                                              \
    _(REVERSE, "reverse")                                                                                              \
    _(MISS, "miss")                                                                                                    \
    _(ICMP_ERROR, "icmp-error")

typedef enum {
#define _(n, str) SASC_SERVICE_CHAIN_##n,
    foreach_sasc_service_chain_type
#undef _
        SASC_SERVICE_CHAIN_N
} sasc_service_chain_type_t;

typedef struct {
    u32 context_id;
    u32 service_chains[SASC_SERVICE_CHAIN_N];
} sasc_tenant_t;

typedef struct {
    u32 **chains;                   /* Vector of service chains */
    u32 **next_indices;             /* Vector of next indices for each ingress_node + chain combination */
    u32 **effective_service_chains; /* Vector of effective service chains */

    /* Session tracking */
    clib_bihash_40_8_t session_hash;
    sasc_session_t *sessions;              /* fixed pool */
    sasc_session_slow_path_t *sp_sessions; /* fixed pool */
    u32 frame_queue_index;                 /* Frame queue index for thread handoff */
    vlib_log_class_t log_class;
    sasc_tenant_t *tenants;             /* Sparse vector of tenants */
    u32 timeouts[SASC_SESSION_N_STATE]; /* Timeout values for each session state */

    /* Counters */
    vlib_simple_counter_main_t *counters;
    int active_sessions;

    /* Configuration*/
    u32 no_sessions;

    /* Time */
    u64 unix_time_0;

    u16 msg_id_base;

    /* Sampling configuration */
    // struct {
    //     /* per-mille rate to sample new TCP sessions (0..1000). 0 disables. */
    //     u16 per_mille;
    //     /* Hard cap for newly sampled sessions per second per-thread. 0 disables. */
    //     u16 cap_per_sec;
    // } sampling;
} sasc_main_t;

extern sasc_main_t sasc_main;

// Buffer flags
typedef enum {
    SASC_BUFFER_F_PCAP_TRACE = 1 << 0,
} sasc_buffer_flags_t;

// Session flags
typedef enum {
    SASC_SESSION_F_PCAP_SAMPLE = 1 << 0,
} sasc_session_flags_t;

typedef struct {
    u32 pad[2]; // do not overlay with ip.adj_index[0,1]
    u32 context_id;
    u16 next_indices_index; // Index into sasc->next_indices
    u16 position;           // Position within the next_indices vector
    u16 tenant_index;       // Added for tenant tracking
    u8 flags;
} sasc_buffer_opaque_t;
#define sasc_buffer(b) ((sasc_buffer_opaque_t *)vnet_buffer(b)->unused)

typedef enum {
    SASC_INGRESS_NODE_LOOKUP_IP4 = 0,
    SASC_INGRESS_NODE_N_LOOKUPS,
} sasc_ingress_node_index_t;

/* Protocol groups for service chains */
typedef enum {
    SASC_PROTO_GROUP_ALL = 0, // Services that work with any protocol
    SASC_PROTO_GROUP_TCP,     // TCP-specific services
    SASC_PROTO_GROUP_N,       // Number of protocol groups
} sasc_proto_group_t;

/* Convert protocol number to protocol group */
static_always_inline sasc_proto_group_t
sasc_proto_to_group(u8 proto) {
    switch (proto) {
    case IP_PROTOCOL_TCP:
        return SASC_PROTO_GROUP_TCP;
    default:
        return SASC_PROTO_GROUP_ALL;
    }
}

/* Service protocol mask bits */
#define SASC_PROTO_MASK_ALL (1 << SASC_PROTO_GROUP_ALL)
#define SASC_PROTO_MASK_TCP (1 << SASC_PROTO_GROUP_TCP)

#define SASC_MAX_CHAINS 64

static_always_inline u32
sasc_service_chain_next_index(u32 ingress_node_index, sasc_proto_group_t proto_group, u32 chain_id) {
    return (ingress_node_index * SASC_MAX_CHAINS * SASC_PROTO_GROUP_N) + (chain_id * SASC_PROTO_GROUP_N) + proto_group;
}

static_always_inline void
sasc_buffer_init_chain(u32 ingress_node_index, u8 proto, vlib_buffer_t *b, u32 effective_index) {
    sasc_buffer_opaque_t *sbo = sasc_buffer(b);
    sbo->next_indices_index = (ingress_node_index * SASC_MAX_CHAINS * SASC_PROTO_GROUP_N) + effective_index;
    sbo->position = 0;
}

static_always_inline void
sasc_next(vlib_buffer_t *b, u16 *next_index) {
    sasc_buffer_opaque_t *sbo = sasc_buffer(b);
    sasc_main_t *sasc = &sasc_main;
    u32 *next_indices = sasc->next_indices[sbo->next_indices_index];
    ASSERT(sbo->position < vec_len(next_indices));
    *next_index = (u16)next_indices[sbo->position];
    sbo->position++;
}

typedef void (*sasc_tenant_add_del_cb_t)(u32 tenant_index, bool is_add);

// ICMP error callback types
typedef enum {
    SASC_ICMP_ERROR_DEST_UNREACH = 0,
    SASC_ICMP_ERROR_FRAG_NEEDED,
    SASC_ICMP_ERROR_TTL_EXPIRED,
    SASC_ICMP_ERROR_PARAM_PROBLEM,
    SASC_ICMP_ERROR_REDIRECT,
    SASC_ICMP_ERROR_TIME_EXCEEDED,
    SASC_ICMP_ERROR_PACKET_TOO_BIG,
    SASC_ICMP_ERROR_N_TYPES,
} sasc_icmp_error_type_t;

typedef struct {
    u32 session_index;
    sasc_icmp_error_type_t error_type;
    u8 icmp_type;
    u8 icmp_code;
    u32 data; // Additional ICMP error data
} sasc_icmp_error_info_t;

typedef void (*sasc_icmp_error_cb_t)(const sasc_icmp_error_info_t *error_info);

// Hijack the protocol number for ICMP error packets
#define SASC_IP_PROTOCOL_ICMP_ERROR 200

uword unformat_sasc_service(unformat_input_t *input, va_list *args);
int sasc_set_services(u32 chain_id, u32 *services);
int sasc_build_effective_service_chains(sasc_main_t *sasc);
int sasc_build_next_indices_from_effective_chains(sasc_main_t *sasc);
clib_error_t *sasc_tenant_add_del(sasc_main_t *sasc, u32 tenant_idx, u32 context_id, u32 forward_chain_id,
                                  u32 reverse_chain_id, u32 miss_chain_id, u32 icmp_error_chain_id, bool is_add);
u32 sasc_ingress_node_index(sasc_ingress_node_index_t index);
int sasc_set_timeout(sasc_main_t *sasc, u32 timeouts[]);
int sasc_tenant_add_del_cb_register(sasc_tenant_add_del_cb_t callback);
int sasc_tenant_add_del_cb_unregister(sasc_tenant_add_del_cb_t callback);

// ICMP error callback registration functions
int sasc_icmp_error_cb_register(sasc_icmp_error_cb_t callback);
int sasc_icmp_error_cb_unregister(sasc_icmp_error_cb_t callback);

// ICMP error notification function (for use by ICMP error service)
void sasc_icmp_error_notify(const sasc_icmp_error_info_t *error_info);

// Helper function to convert ICMP type/code to SASC error type
sasc_icmp_error_type_t sasc_icmp_type_to_error_type(u8 icmp_type, u8 icmp_code);

#endif /* __INCLUDED_SESSCHAIN_H__ */