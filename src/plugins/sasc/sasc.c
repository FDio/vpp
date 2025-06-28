// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include "sasc.h"
#include "service.h"
#include "sasc_funcs.h"

sasc_main_t sasc_main;

static clib_error_t *sasc_init(vlib_main_t *vm) {
    sasc_main_t *sasc = &sasc_main;

    // Initialize vectors to 0
    sasc->chains = 0;
    sasc->tenants = 0;
    sasc->next_indices = 0;

    sasc->log_class = vlib_log_register_class("sasc", 0);

    u32 n_buckets = 1024;
    clib_bihash_init_40_8(&sasc->session_hash, "sasc session hash table", n_buckets, 0);
    pool_init_fixed(sasc->sessions, 1024);

#define _(x, y, z) sasc->timeouts[SASC_SESSION_STATE_##x] = y;
  foreach_sasc_session_state
#undef _

    // /* Start the session expiry process */
    // vlib_process_signal_event(vm, sasc_session_expiry_node.index, SASC_EVENT_START_EXPIRY, 0);

    return 0;
}

VLIB_INIT_FUNCTION(sasc_init);
extern vlib_node_registration_t sasc_lookup_ip4_node;

u32 sasc_ingress_node_index(sasc_ingress_node_index_t index) { return sasc_lookup_ip4_node.index; }

// Helper function to check if a service is valid for a protocol group
static_always_inline bool
sasc_service_valid_for_proto(sasc_service_registration_t *service, sasc_proto_group_t proto_group)
{
    // clib_warning("Checking if service %s is valid for protocol group %d (mask: 0x%x)", 
    //             service->node_name, proto_group, service->protocol_mask);
    // If mask is 0, service works with all protocols
    if (service->protocol_mask == 0)
        return true;    
        
    // Check if service supports this protocol group using bit shift
    bool valid = (service->protocol_mask & (1 << proto_group)) != 0;
    // if (!valid) {
    //     clib_warning("Service %s does not support protocol group %d (mask: 0x%x)", 
    //                 service->node_name, proto_group, service->protocol_mask);
    // }
    return valid;
}

// Helper function to get next node and add it to the chain
static_always_inline bool
sasc_add_node_to_chain(vlib_main_t *vm, vlib_node_t *node, u32 service_index, 
                      u32 **next_indices, u32 *next_index)
{
    const char *service_name = sasc_service_name_from_index(service_index);
    if (!service_name) {
        clib_warning("Failed to get service name for service index %d", service_index);
        return false;
    }
    vlib_node_t *next_node = vlib_get_node_by_name(vm, (u8 *)service_name);
    if (!next_node) {
        clib_warning("Failed to find node for service index %d (%s)", 
                    service_index, service_name);
        return false;
    }
    *next_index = vlib_node_add_next(vm, node->index, next_node->index);
    vec_add1(*next_indices, *next_index);
    return true;
}

int sasc_apply_chain_to_ingress(u32 chain_id) {
    vlib_main_t *vm = vlib_get_main();
    sasc_main_t *sasc = &sasc_main;
    u32 *chain = *vec_elt_at_index(sasc->chains, chain_id);

    // For each ingress node
    for (int i = 0; i < SASC_INGRESS_NODE_N_LOOKUPS; i++) {
        u32 ingress_node_index = sasc_ingress_node_index(i);
        vlib_node_t *node = vlib_get_node(vm, ingress_node_index);
        if (!node) {
            clib_warning("Node %d not found", ingress_node_index);
            return -1;
        }

        // For each protocol group
        for (int proto_group = 0; proto_group < SASC_PROTO_GROUP_N; proto_group++) {
            u32 next_indices_index = (i * SASC_MAX_CHAINS * SASC_PROTO_GROUP_N) + 
                                   (chain_id * SASC_PROTO_GROUP_N) + proto_group;
            vec_validate(sasc->next_indices, next_indices_index);
            
            // Create a new vector for this chain
            u32 *next_indices = 0;
            
            // Free the old chain if it exists
            if (sasc->next_indices[next_indices_index]) {
                vec_free(sasc->next_indices[next_indices_index]);
                sasc->next_indices[next_indices_index] = 0;
            }

            // Check if first service is valid for this protocol
            if (chain[0] < vec_len(sasc_service_main.services)) {
                sasc_service_registration_t *service = 
                    vec_elt_at_index(sasc_service_main.services, chain[0])[0];
                if (!sasc_service_valid_for_proto(service, proto_group)) {
                    clib_warning("First service in chain does not support protocol group %d", proto_group);
                    goto next_proto;
                }
            }

            // Add first node to chain
            u32 next_index;
            if (!sasc_add_node_to_chain(vm, node, chain[0], &next_indices, &next_index)) {
                clib_warning("Failed to add first node to chain");
                goto next_proto;
            }

            // Build the rest of the chain
            bool chain_valid = true;
            const char *first_node_name = sasc_service_name_from_index(chain[0]);
            if (!first_node_name) {
                clib_warning("Failed to get service name for first service in chain");
                chain_valid = false;
                goto next_proto;
            }
            vlib_node_t *current_node = vlib_get_node_by_name(vm, (u8 *)first_node_name);
            
            for (int j = 0; j < vec_len(chain) - 1; j++) {
                const char *current_node_name = sasc_service_name_from_index(chain[j]);
                const char *next_node_name = sasc_service_name_from_index(chain[j + 1]);
                
                if (!current_node_name || !next_node_name) {
                    clib_warning("Failed to get service name for service at position %d or %d", j, j + 1);
                    chain_valid = false;
                    break;
                }
                
                // clib_warning("Processing chain link %d: %s -> %s", 
                //            j, current_node_name, next_node_name);
                
                if (!current_node) {
                    clib_warning("Failed to find current node %s", current_node_name);
                    chain_valid = false;
                    break;
                }
                
                // Check protocol for service nodes
                if (chain[j + 1] < vec_len(sasc_service_main.services)) {
                    sasc_service_registration_t *service = 
                        vec_elt_at_index(sasc_service_main.services, chain[j + 1])[0];
                    if (!sasc_service_valid_for_proto(service, proto_group)) {
                        // clib_warning("Service at position %d does not support protocol group %d", 
                        //            j + 1, proto_group);
                        chain_valid = false;
                        break;
                    }
                }

                // Add next node
                if (!sasc_add_node_to_chain(vm, current_node, chain[j + 1], &next_indices, &next_index)) {
                    clib_warning("Failed to add node at position %d to chain", j + 1);
                    chain_valid = false;
                    break;
                }
                
                // Update current node for next iteration
                current_node = vlib_get_node_by_name(vm, (u8 *)next_node_name);
            }

            // Store the next indices
            if (chain_valid && vec_len(next_indices) > 0) {
                sasc->next_indices[next_indices_index] = vec_dup(next_indices);
            } else {
                // clib_warning("Chain validation failed: valid=%d, nodes=%d", 
                //            chain_valid, vec_len(next_indices));
                // For invalid chains, point to error-drop
                if (current_node) {
                    vec_add1(next_indices, vlib_node_add_next(vm, current_node->index, 
                        vlib_get_node_by_name(vm, (u8 *)"error-drop")->index));
                    sasc->next_indices[next_indices_index] = vec_dup(next_indices);
                    // clib_warning("Chain invalid for protocol group %d, pointing to error-drop", proto_group);
                } else {
                    clib_warning("Cannot add error-drop - current node is NULL");
                    sasc->next_indices[next_indices_index] = vec_dup(next_indices);
                }
            }
            vec_free(next_indices);
        next_proto:
            continue;
        }
    }
    return 0;
}

int sasc_set_services(u32 chain_id, u32 *services) {
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

    sasc_apply_chain_to_ingress(chain_id);

    return 0;
}

clib_error_t *sasc_tenant_add_del(sasc_main_t *sasc, u32 tenant_idx, u32 context_id,
                                  u32 forward_chain_id, u32 reverse_chain_id, u32 miss_chain_id,
                                  bool is_add) {
    clib_error_t *err = 0;
    sasc_tenant_t *tenant = sasc_tenant_at_index(sasc, tenant_idx);

    if (is_add) {
        if (tenant_idx >= CLIB_U16_MAX)
            return clib_error_return(0, "Can't create tenant with id %d. Maximum limit reached %d",
                                     tenant_idx, CLIB_U16_MAX);

        if (tenant) {
            return clib_error_return(0, "Can't create tenant with id %d. Already exists",
                                     tenant_idx);
        }

        pool_get(sasc->tenants, tenant);
        tenant_idx = tenant - sasc->tenants;

        tenant->service_chains[SASC_SERVICE_CHAIN_FORWARD] = forward_chain_id;
        tenant->service_chains[SASC_SERVICE_CHAIN_REVERSE] = reverse_chain_id;
        tenant->service_chains[SASC_SERVICE_CHAIN_MISS] = miss_chain_id;
        tenant->context_id = context_id;

    } else {
        if (!tenant) {
            return clib_error_return(0, "Can't delete tenant with id %d. Not found", tenant_idx);
        }
        pool_put_index(sasc->tenants, tenant_idx);
    }
    return err;
}

int
sasc_set_timeout(sasc_main_t *sasc, u32 timeouts[])
{
#define _(name, val, str)                                                                                              \
  if (timeouts[SASC_SESSION_STATE_##name] > 0) {                                                                             \
    sasc->timeouts[SASC_SESSION_STATE_##name] = timeouts[SASC_SESSION_STATE_##name];                                               \
  }
  foreach_sasc_session_state
#undef _

    return 0;
}
