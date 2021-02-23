/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include "pnat.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vppinfra/clib_error.h>

/*
 * This is the main control plane part of the PNAT (Policy 1:1 NAT) feature.
 */

pnat_main_t pnat_main;

/*
 * Do a lookup in the interface vector (interface_by_sw_if_index)
 * and return pool entry.
 */
pnat_interface_t *pnat_interface_by_sw_if_index(u32 sw_if_index) {
    pnat_main_t *pm = &pnat_main;

    if (!pm->interface_by_sw_if_index ||
        sw_if_index > (vec_len(pm->interface_by_sw_if_index) - 1))
        return 0;
    u32 index = pm->interface_by_sw_if_index[sw_if_index];
    if (index == ~0)
        return 0;
    if (pool_is_free_index(pm->interfaces, index))
        return 0;
    return pool_elt_at_index(pm->interfaces, index);
}

static pnat_mask_fast_t pnat_mask2fast(pnat_mask_t lookup_mask) {
    pnat_mask_fast_t m = {0};

    if (lookup_mask & PNAT_SA)
        m.as_u64[0] = 0xffffffff00000000;
    if (lookup_mask & PNAT_DA)
        m.as_u64[0] |= 0x00000000ffffffff;
    m.as_u64[1] = 0xffffffff00000000;
    if (lookup_mask & PNAT_SPORT)
        m.as_u64[1] |= 0x00000000ffff0000;
    if (lookup_mask & PNAT_DPORT)
        m.as_u64[1] |= 0x000000000000ffff;
    return m;
}

/*
 * Create new PNAT interface object and register the pnat feature in the
 * corresponding feature chain.
 * Also enable shallow virtual reassembly, to ensure that we have
 * L4 ports available for all packets we receive.
 */
static clib_error_t *pnat_enable_interface(u32 sw_if_index,
                                           pnat_attachment_point_t attachment,
                                           pnat_mask_t mask) {
    pnat_main_t *pm = &pnat_main;
    pnat_interface_t *interface = pnat_interface_by_sw_if_index(sw_if_index);

    if (!interface) {
        pool_get_zero(pm->interfaces, interface);
        interface->sw_if_index = sw_if_index;
        vec_validate_init_empty(pm->interface_by_sw_if_index, sw_if_index, ~0);
        pm->interface_by_sw_if_index[sw_if_index] = interface - pm->interfaces;
    }

    char *nodename;
    char *arcname;
    bool input = false;
    switch (attachment) {
    case PNAT_IP4_INPUT:
        nodename = "pnat-input";
        arcname = "ip4-unicast";
        input = true;
        break;

    case PNAT_IP4_OUTPUT:
        nodename = "pnat-output";
        arcname = "ip4-output";
        break;
    default:
        return clib_error_return(0, "Unknown attachment point %u %u",
                                 sw_if_index, attachment);
    }

    if (!interface->enabled[attachment]) {
        if (vnet_feature_enable_disable(arcname, nodename, sw_if_index, 1, 0,
                                        0) != 0)
            return clib_error_return(0, "PNAT feature enable failed on %u",
                                     sw_if_index);

        if (input) {
            /* TODO: Make shallow virtual reassembly configurable */
            ip4_sv_reass_enable_disable_with_refcnt(sw_if_index, 1);
        } else {
            ip4_sv_reass_output_enable_disable_with_refcnt(sw_if_index, 1);
        }

        interface->lookup_mask[attachment] = mask;
        interface->lookup_mask_fast[attachment] = pnat_mask2fast(mask);
        interface->enabled[attachment] = true;

    } else {
        pnat_mask_t current_mask = interface->lookup_mask[attachment];
        if (current_mask != mask) {
            return clib_error_return(0,
                                     "PNAT lookup mask must be consistent per "
                                     "interface/direction %u",
                                     sw_if_index);
        }
    }

    interface->refcount++;

    return 0;
}

/*
 * Delete interface object when no rules reference the interface.
 */
static int pnat_disable_interface(u32 sw_if_index,
                                  pnat_attachment_point_t attachment) {
    pnat_main_t *pm = &pnat_main;
    pnat_interface_t *interface = pnat_interface_by_sw_if_index(sw_if_index);

    if (!interface)
        return 0;
    if (interface->refcount == 0)
        return 0;

    if (interface->enabled[attachment] && attachment == PNAT_IP4_INPUT) {
        if (ip4_sv_reass_enable_disable_with_refcnt(sw_if_index, 0) != 0)
            return -1;
        if (vnet_feature_enable_disable("ip4-unicast", "pnat-input",
                                        sw_if_index, 0, 0, 0) != 0)
            return -1;
    }
    if (interface->enabled[attachment] && attachment == PNAT_IP4_OUTPUT) {
        if (ip4_sv_reass_output_enable_disable_with_refcnt(sw_if_index, 0) != 0)
            return -1;
        if (vnet_feature_enable_disable("ip4-output", "pnat-output",
                                        sw_if_index, 0, 0, 0) != 0)
            return -1;
    }

    interface->lookup_mask[attachment] = 0;
    interface->enabled[attachment] = false;

    interface->refcount--;
    if (interface->refcount == 0) {
        pm->interface_by_sw_if_index[sw_if_index] = ~0;
        pool_put(pm->interfaces, interface);
    }
    return 0;
}

/*
 * From a 5-tuple (with mask) calculate the key used in the flow cache lookup.
 */
static inline void pnat_calc_key_from_5tuple(u32 sw_if_index,
                                             pnat_attachment_point_t attachment,
                                             pnat_match_tuple_t *match,
                                             clib_bihash_kv_16_8_t *kv) {
    pnat_mask_fast_t mask = pnat_mask2fast(match->mask);
    ip4_address_t src, dst;
    clib_memcpy(&src, &match->src, 4);
    clib_memcpy(&dst, &match->dst, 4);
    pnat_calc_key(sw_if_index, attachment, src, dst, match->proto,
                  htons(match->sport), htons(match->dport), mask, kv);
}

/*
 * Map between the 5-tuple mask and the instruction set of the rewrite node.
 */
pnat_instructions_t pnat_instructions_from_mask(pnat_mask_t m) {
    pnat_instructions_t i = 0;

    if (m & PNAT_SA)
        i |= PNAT_INSTR_SOURCE_ADDRESS;
    if (m & PNAT_DA)
        i |= PNAT_INSTR_DESTINATION_ADDRESS;
    if (m & PNAT_SPORT)
        i |= PNAT_INSTR_SOURCE_PORT;
    if (m & PNAT_DPORT)
        i |= PNAT_INSTR_DESTINATION_PORT;
    if (m & PNAT_COPY_BYTE)
        i |= PNAT_INSTR_COPY_BYTE;
    if (m & PNAT_CLEAR_BYTE)
        i |= PNAT_INSTR_CLEAR_BYTE;
    return i;
}

/*
 * "Init" the PNAT datastructures. Called upon first creation of a PNAT rule.
 * TODO: Make number of buckets configurable.
 */
static void pnat_enable(void) {
    pnat_main_t *pm = &pnat_main;
    if (pm->enabled)
        return;

    /* Create new flow cache table */
    clib_bihash_init_16_8(&pm->flowhash, "PNAT flow hash",
                          PNAT_FLOW_HASH_BUCKETS, 0);

    pm->enabled = true;
}
static void pnat_disable(void) {
    pnat_main_t *pm = &pnat_main;

    if (!pm->enabled)
        return;
    if (pool_elts(pm->translations))
        return;

    /* Delete flow cache table */
    clib_bihash_free_16_8(&pm->flowhash);

    pm->enabled = false;
}

/*
 * Ensure that a new rule lookup mask matches what's installed on interface
 */
static int pnat_interface_check_mask(u32 sw_if_index,
                                     pnat_attachment_point_t attachment,
                                     pnat_mask_t mask) {
    pnat_interface_t *interface = pnat_interface_by_sw_if_index(sw_if_index);
    if (!interface)
        return 0;
    if (!interface->enabled[attachment])
        return 0;
    if (interface->lookup_mask[attachment] != mask)
        return -1;

    return 0;
}

/*
 * Add a binding to the binding table.
 * Returns 0 on success.
 *  -1: Invalid mask
 *  -2: Only matches ports for UDP or TCP
 *
 */
int pnat_binding_add(pnat_match_tuple_t *match, pnat_rewrite_tuple_t *rewrite,
                     u32 *index) {
    pnat_main_t *pm = &pnat_main;

    *index = -1;

    /* If we aren't matching or rewriting, why are we here? */
    if (match->mask == 0 || rewrite->mask == 0)
        return -1;

    /* Check if protocol is set if ports are set */
    if ((match->dport || match->sport) &&
        (match->proto != IP_API_PROTO_UDP && match->proto != IP_API_PROTO_TCP))
        return -2;

    /* Create pool entry */
    pnat_translation_t *t;
    pool_get_zero(pm->translations, t);
    memcpy(&t->post_da, &rewrite->dst, 4);
    memcpy(&t->post_sa, &rewrite->src, 4);
    t->post_sp = rewrite->sport;
    t->post_dp = rewrite->dport;
    t->from_offset = rewrite->from_offset;
    t->to_offset = rewrite->to_offset;
    t->clear_offset = rewrite->clear_offset;
    t->instructions = pnat_instructions_from_mask(rewrite->mask);

    /* These are only used for show commands and trace */
    t->match = *match;
    t->rewrite = *rewrite;

    *index = t - pm->translations;

    return 0;
}

/*
 * Looks a match flow in the flow cache, returns the index  in the binding table
 */
u32 pnat_flow_lookup(u32 sw_if_index, pnat_attachment_point_t attachment,
                     pnat_match_tuple_t *match) {
    pnat_main_t *pm = &pnat_main;
    clib_bihash_kv_16_8_t kv, value;
    pnat_calc_key_from_5tuple(sw_if_index, attachment, match, &kv);
    if (clib_bihash_search_16_8(&pm->flowhash, &kv, &value) == 0) {
        return value.value;
    }
    return ~0;
}

/*
 * Attach a binding to an interface / direction.
 * Returns 0 on success.
 * -1: Binding does not exist
 * -2: Interface mask does not match
 * -3: Existing match entry in flow table
 * -4: Adding flow table entry failed
 */
int pnat_binding_attach(u32 sw_if_index, pnat_attachment_point_t attachment,
                        u32 binding_index) {
    pnat_main_t *pm = &pnat_main;

    if (!pm->translations ||
        pool_is_free_index(pm->translations, binding_index))
        return -1;

    pnat_translation_t *t = pool_elt_at_index(pm->translations, binding_index);

    if (pnat_interface_check_mask(sw_if_index, attachment, t->match.mask) != 0)
        return -2;

    pnat_enable();

    /* Verify non-duplicate */
    clib_bihash_kv_16_8_t kv, value;
    pnat_calc_key_from_5tuple(sw_if_index, attachment, &t->match, &kv);
    if (clib_bihash_search_16_8(&pm->flowhash, &kv, &value) == 0) {
        return -3;
    }

    /* Create flow cache */
    kv.value = binding_index;
    if (clib_bihash_add_del_16_8(&pm->flowhash, &kv, 1)) {
        pool_put(pm->translations, t);
        return -4;
    }

    /* Register interface */
    pnat_enable_interface(sw_if_index, attachment, t->match.mask);

    return 0;
}

int pnat_binding_detach(u32 sw_if_index, pnat_attachment_point_t attachment,
                        u32 binding_index) {
    pnat_main_t *pm = &pnat_main;

    if (!pm->translations ||
        pool_is_free_index(pm->translations, binding_index))
        return -1;

    pnat_translation_t *t = pool_elt_at_index(pm->translations, binding_index);

    /* Verify non-duplicate */
    clib_bihash_kv_16_8_t kv;
    pnat_calc_key_from_5tuple(sw_if_index, attachment, &t->match, &kv);
    if (clib_bihash_add_del_16_8(&pm->flowhash, &kv, 0)) {
        return -2;
    }

    /* Deregister interface */
    pnat_disable_interface(sw_if_index, attachment);

    pnat_disable();

    return 0;
}

/*
 * Delete a translation using the index returned from pnat_add_translation.
 */
int pnat_binding_del(u32 index) {
    pnat_main_t *pm = &pnat_main;

    if (pool_is_free_index(pm->translations, index)) {
        clib_warning("Binding delete: translation does not exist: %d", index);
        return -1;
    }

    pnat_translation_t *t = pool_elt_at_index(pm->translations, index);
    pool_put(pm->translations, t);

    return 0;
}
