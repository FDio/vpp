// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include "sasc.h"
#include "service.h"
#include "sasc_funcs.h"
#include "counter.h"

sasc_main_t sasc_main;
#define MAX_SASC_SESSIONS 1024 * 128 // TODO: Make this configurable

static clib_error_t *
sasc_init(vlib_main_t *vm) {
    sasc_main_t *sasc = &sasc_main;

    // Initialize vectors to 0
    sasc->unix_time_0 = time(0);
    sasc->chains = 0;
    sasc->tenants = 0;
    sasc->next_indices = 0;
    sasc->no_sessions = MAX_SASC_SESSIONS;

    sasc->log_class = vlib_log_register_class("sasc", 0);

    u32 n_buckets = 1024; // TODO: Make this configurable
    clib_bihash_init_40_8(&sasc->session_hash, "sasc session hash table", n_buckets, 0);
    pool_init_fixed(sasc->sessions, MAX_SASC_SESSIONS);
    vec_validate(sasc->sp_sessions, MAX_SASC_SESSIONS);

#define _(x, y, z) sasc->timeouts[SASC_SESSION_STATE_##x] = y;
    foreach_sasc_session_state
#undef _

        // /* Start the session expiry process */
        // vlib_process_signal_event(vm, sasc_session_expiry_node.index, SASC_EVENT_START_EXPIRY,
        // 0);

        return 0;
}

VLIB_INIT_FUNCTION(sasc_init);
extern vlib_node_registration_t sasc_lookup_ip4_node;

u32
sasc_ingress_node_index(sasc_ingress_node_index_t index) {
    return sasc_lookup_ip4_node.index;
}

// Helper function to check if a service is valid for a protocol group
static_always_inline bool
sasc_service_valid_for_proto(sasc_service_registration_t *service, sasc_proto_group_t proto_group) {
    // For ALL protocol group (proto_group = 0), only include protocol-agnostic services
    if (proto_group == SASC_PROTO_GROUP_ALL) {
        // Only include services with mask 0 (protocol-agnostic)
        bool valid = (service->protocol_mask == 0);
        return valid;
    }

    // If mask is 0, service works with all protocols (default behavior)
    if (service->protocol_mask == 0) {
        return true;
    }

    // Check if service supports this specific protocol group using bit shift
    bool valid = (service->protocol_mask & (1 << proto_group)) != 0;
    return valid;
}

// Helper function to get next node and add it to the chain
static_always_inline bool
sasc_add_node_to_chain(vlib_main_t *vm, vlib_node_t *node, u32 service_index, u32 **next_indices, u32 *next_index) {
    const char *service_name = sasc_service_name_from_index(service_index);
    if (!service_name) {
        clib_warning("Failed to get service name for service index %d", service_index);
        return false;
    }
    vlib_node_t *next_node = vlib_get_node_by_name(vm, (u8 *)service_name);
    if (!next_node) {
        clib_warning("Failed to find node for service index %d (%s)", service_index, service_name);
        return false;
    }
    *next_index = vlib_node_add_next(vm, node->index, next_node->index);
    vec_add1(*next_indices, *next_index);
    return true;
}

// Helper function to convert effective service chain to next indices
static bool
sasc_build_next_indices_from_effective_chain(vlib_main_t *vm, u32 *effective_services, vlib_node_t *start_node,
                                             u32 **next_indices) {
    if (!effective_services || vec_len(effective_services) == 0) {
        return false;
    }

    vlib_node_t *current_node = start_node;

    // Process each service in the effective chain
    u32 *service_index;
    vec_foreach (service_index, effective_services) {
        u32 next_index;
        if (!sasc_add_node_to_chain(vm, current_node, *service_index, next_indices, &next_index)) {
            clib_warning("Failed to add service %d to next_indices chain", *service_index);
            return false;
        }

        // Get the next node for the next iteration
        const char *service_name = sasc_service_name_from_index(*service_index);
        if (!service_name) {
            clib_warning("Failed to get service name for service index %d", *service_index);
            return false;
        }
        current_node = vlib_get_node_by_name(vm, (u8 *)service_name);
        if (!current_node) {
            clib_warning("Failed to find node for service %s", service_name);
            return false;
        }
    }

    return true;
}

// New function to build next_indices from effective_service_chains
int
sasc_build_next_indices_from_effective_chains(sasc_main_t *sasc) {
    vlib_main_t *vm = vlib_get_main();

    // Free existing next_indices if they exist
    if (sasc->next_indices) {
        vec_free(sasc->next_indices);
        sasc->next_indices = 0;
    }

    // Calculate total size needed for next_indices
    u32 max_chain_id = vec_len(sasc->chains);
    u32 total_next_indices = SASC_INGRESS_NODE_N_LOOKUPS * max_chain_id * SASC_PROTO_GROUP_N;

    // Allocate the next_indices vector
    vec_validate(sasc->next_indices, total_next_indices - 1);

    // Initialize all entries to NULL
    for (u32 i = 0; i < total_next_indices; i++) {
        sasc->next_indices[i] = 0;
    }

    // Build next_indices for each ingress node, chain, and protocol group
    for (u32 ingress_idx = 0; ingress_idx < SASC_INGRESS_NODE_N_LOOKUPS; ingress_idx++) {
        u32 ingress_node_index = sasc_ingress_node_index(ingress_idx);
        vlib_node_t *ingress_node = vlib_get_node(vm, ingress_node_index);
        if (!ingress_node) {
            clib_warning("Ingress node %d not found", ingress_node_index);
            continue;
        }

        for (u32 chain_id = 0; chain_id < max_chain_id; chain_id++) {
            for (sasc_proto_group_t proto_group = 0; proto_group < SASC_PROTO_GROUP_N; proto_group++) {
                // Get the effective service chain
                u32 *effective_services = sasc_get_effective_service_chain(sasc, chain_id, proto_group);
                if (!effective_services) {
                    continue;
                }
                // Calculate next_indices index
                u32 next_indices_index = sasc_service_chain_next_index(ingress_idx, proto_group, chain_id);

                // Build next_indices from effective services
                u32 *next_indices = 0;
                bool success =
                    sasc_build_next_indices_from_effective_chain(vm, effective_services, ingress_node, &next_indices);

                if (success && vec_len(next_indices) > 0) {
                    sasc->next_indices[next_indices_index] = vec_dup(next_indices);
                } else {
                    // For invalid chains, point to error-drop
                    vlib_node_t *error_drop_node = vlib_get_node_by_name(vm, (u8 *)"error-drop");
                    if (error_drop_node) {
                        vec_add1(next_indices, vlib_node_add_next(vm, ingress_node->index, error_drop_node->index));
                    }
                    sasc->next_indices[next_indices_index] = vec_dup(next_indices);
                }
                vec_free(next_indices);
            }
        }
    }

    return 0;
}

int
sasc_set_services(u32 chain_id, u32 *services) {
    sasc_main_t *sasc = &sasc_main;

    // Initialize outer vector
    vec_validate(sasc->chains, chain_id);

    // Initialize inner vector if it doesn't exist
    if (sasc->chains[chain_id] == 0)
        vec_validate(sasc->chains[chain_id], 0);

    // Now we can safely access the chain
    u32 **chain = vec_elt_at_index(sasc->chains, chain_id);

    // Just store the service indices
    vec_reset_length(*chain);
    vec_append(*chain, services);

    // Build effective service chains first (protocol-filtered)
    sasc_build_effective_service_chains(sasc);

    // Then build next_indices from effective_service_chains
    sasc_build_next_indices_from_effective_chains(sasc);

    return 0;
}

/* Vector of registered callbacks */
static sasc_tenant_add_del_cb_t *tenant_add_del_callbacks;

int
sasc_tenant_add_del_cb_register(sasc_tenant_add_del_cb_t callback) {
    vec_add1(tenant_add_del_callbacks, callback);
    return 0;
}

int
sasc_tenant_add_del_cb_unregister(sasc_tenant_add_del_cb_t callback) {
    u32 i;
    vec_foreach_index (i, tenant_add_del_callbacks) {
        if (tenant_add_del_callbacks[i] == callback) {
            vec_delete(tenant_add_del_callbacks, 1, i);
            return 0;
        }
    }
    return -1;
}

/* Call all registered callbacks with the expired sessions */
static void
sasc_tenant_add_del_notify(u32 tenant_index, bool is_add) {
    sasc_tenant_add_del_cb_t *cb;
    vec_foreach (cb, tenant_add_del_callbacks) {
        (*cb)(tenant_index, is_add);
    }
}

/* Vector of registered ICMP error callbacks */
static sasc_icmp_error_cb_t *icmp_error_callbacks;

int
sasc_icmp_error_cb_register(sasc_icmp_error_cb_t callback) {
    vec_add1(icmp_error_callbacks, callback);
    return 0;
}

int
sasc_icmp_error_cb_unregister(sasc_icmp_error_cb_t callback) {
    u32 i;
    vec_foreach_index (i, icmp_error_callbacks) {
        if (icmp_error_callbacks[i] == callback) {
            vec_delete(icmp_error_callbacks, 1, i);
            return 0;
        }
    }
    return -1;
}

/* Call all registered ICMP error callbacks */
void
sasc_icmp_error_notify(const sasc_icmp_error_info_t *error_info) {
    sasc_icmp_error_cb_t *cb;
    vec_foreach (cb, icmp_error_callbacks) {
        (*cb)(error_info);
    }
}
#include <vnet/ip/icmp46_packet.h>
// Helper function to convert ICMP type/code to SASC error type
sasc_icmp_error_type_t
sasc_icmp_type_to_error_type(u8 icmp_type, u8 icmp_code) {
    switch (icmp_type) {
    case ICMP4_destination_unreachable:
        if (icmp_code == ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set) {
            return SASC_ICMP_ERROR_FRAG_NEEDED;
        }
        return SASC_ICMP_ERROR_DEST_UNREACH;

    case ICMP4_time_exceeded:
        if (icmp_code == ICMP4_time_exceeded_ttl_exceeded_in_transit) {
            return SASC_ICMP_ERROR_TTL_EXPIRED;
        }
        return SASC_ICMP_ERROR_TIME_EXCEEDED;

    case ICMP4_parameter_problem:
        return SASC_ICMP_ERROR_PARAM_PROBLEM;

    case ICMP4_redirect:
        return SASC_ICMP_ERROR_REDIRECT;

    // IPv6 equivalents
    case ICMP6_destination_unreachable:
        return SASC_ICMP_ERROR_DEST_UNREACH;

        // case ICMP6_time_exceeded:
        //     if (icmp_code == ICMP6_time_exceeded_ttl_exceeded_in_transit) {
        //         return SASC_ICMP_ERROR_TTL_EXPIRED;
        //     }
        //     return SASC_ICMP_ERROR_TIME_EXCEEDED;

    case ICMP6_parameter_problem:
        return SASC_ICMP_ERROR_PARAM_PROBLEM;

    case ICMP6_packet_too_big:
        return SASC_ICMP_ERROR_PACKET_TOO_BIG;

    default:
        return SASC_ICMP_ERROR_DEST_UNREACH; // Default fallback
    }
}
clib_error_t *
sasc_tenant_add_del(sasc_main_t *sasc, u32 tenant_idx, u32 context_id, u32 forward_chain_id, u32 reverse_chain_id,
                    u32 miss_chain_id, u32 icmp_error_chain_id, bool is_add) {
    clib_error_t *err = 0;
    sasc_tenant_t *tenant = sasc_tenant_at_index(sasc, tenant_idx);

    if (is_add) {
        if (tenant_idx >= CLIB_U16_MAX)
            return clib_error_return(0, "Can't create tenant with id %d. Maximum limit reached %d", tenant_idx,
                                     CLIB_U16_MAX);

        if (tenant) {
            return clib_error_return(0, "Can't create tenant with id %d. Already exists", tenant_idx);
        }

        pool_get(sasc->tenants, tenant);
        tenant_idx = tenant - sasc->tenants;

        tenant->service_chains[SASC_SERVICE_CHAIN_FORWARD] = forward_chain_id;
        tenant->service_chains[SASC_SERVICE_CHAIN_REVERSE] = reverse_chain_id;
        tenant->service_chains[SASC_SERVICE_CHAIN_MISS] = miss_chain_id;
        tenant->service_chains[SASC_SERVICE_CHAIN_ICMP_ERROR] = icmp_error_chain_id;
        tenant->context_id = context_id;

    } else {
        if (!tenant) {
            return clib_error_return(0, "Can't delete tenant with id %d. Not found", tenant_idx);
        }
        pool_put_index(sasc->tenants, tenant_idx);
    }
    sasc_tenant_add_del_notify(tenant_idx, is_add);
    return err;
}

int
sasc_set_timeout(sasc_main_t *sasc, u32 timeouts[]) {
#define _(name, val, str)                                                                                              \
    if (timeouts[SASC_SESSION_STATE_##name] > 0) {                                                                     \
        sasc->timeouts[SASC_SESSION_STATE_##name] = timeouts[SASC_SESSION_STATE_##name];                               \
    }
    foreach_sasc_session_state
#undef _

        return 0;
}

/**
 * Build effective service chains for all configured chains and protocol groups.
 * Creates a 2D vector indexed by [chain_id][proto_group] containing the filtered service chains.
 *
 * @param sasc Pointer to sasc_main_t
 * @return 0 on success, -1 on failure
 */
int
sasc_build_effective_service_chains(sasc_main_t *sasc) {
    sasc_service_main_t *sm = &sasc_service_main;

    // Free existing effective service chains if they exist
    if (sasc->effective_service_chains) {
        vec_free(sasc->effective_service_chains);
        sasc->effective_service_chains = 0;
    }

    // Calculate total size needed: chain_id * proto_group
    u32 max_chain_id = vec_len(sasc->chains);
    u32 total_entries = max_chain_id * SASC_PROTO_GROUP_N;

    // Allocate the 2D vector as a flat array
    vec_validate(sasc->effective_service_chains, total_entries - 1);

    // Initialize all entries to NULL
    for (u32 i = 0; i < total_entries; i++) {
        sasc->effective_service_chains[i] = 0;
    }

    // Build effective chains for each configured chain
    for (u32 chain_id = 0; chain_id < max_chain_id; chain_id++) {
        u32 *chain = *vec_elt_at_index(sasc->chains, chain_id);
        if (!chain)
            continue;

        // For each protocol group
        for (sasc_proto_group_t proto_group = 0; proto_group < SASC_PROTO_GROUP_N; proto_group++) {
            u32 effective_index = (chain_id * SASC_PROTO_GROUP_N) + proto_group;
            u32 *effective_services = 0;

            // Filter the chain for this protocol group
            u32 *service_index;
            vec_foreach (service_index, chain) {
                if (*service_index < vec_len(sm->services)) {
                    sasc_service_registration_t *service = vec_elt_at_index(sm->services, *service_index)[0];

                    // Check if service is valid for this protocol group
                    if (sasc_service_valid_for_proto(service, proto_group)) {
                        vec_add1(effective_services, *service_index);
                    }
                } else {
                    // Non-service node (like error-drop), always include
                    vec_add1(effective_services, *service_index);
                }
            }

            // Store the effective chain
            sasc->effective_service_chains[effective_index] = effective_services;

            sasc_log_debug("Built effective chain %d for proto_group %d with %d services", chain_id, proto_group,
                           vec_len(effective_services));
        }
    }

    return 0;
}

u32
sasc_table_memory_size(void) {
    sasc_main_t *sasc = &sasc_main;
    u64 total_size = 0;

    if (BV(clib_bihash_is_initialised)(&sasc->session_hash)) {
        BVT(clib_bihash_alloc_chunk) *c = sasc->session_hash.chunks;
        while (c) {
            total_size += c->size;
            c = c->next;
        }
    }
    return total_size;
}
