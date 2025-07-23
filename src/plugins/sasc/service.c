// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vppinfra/ptclosure.h>
#include "service.h"

static clib_error_t *
sasc_service_init(vlib_main_t *vm) {
    sasc_service_main_t *sm = &sasc_service_main;
    sasc_service_registration_t *current_reg;
    uword *service_index_by_name = hash_create_string(0, sizeof(uword));
    uword current_index = 0;
    current_reg = sm->next_service;

    /* Parse the registrations linked list */
    while (current_reg) {
        const char *name = current_reg->node_name;
        uword *res = hash_get_mem(service_index_by_name, name);
        if (res)
            clib_panic("Trying to register %s twice!", name);
        hash_set_mem(service_index_by_name, name, current_index);
        vec_add1(sm->services, current_reg);
        current_index++;
        current_reg = current_reg->next;
    }
    sm->service_index_by_name = service_index_by_name;

    return 0;
}

VLIB_INIT_FUNCTION(sasc_service_init);
sasc_service_main_t sasc_service_main;

const char *
sasc_service_name_from_index(u32 index) {
    sasc_service_main_t *sm = &sasc_service_main;
    vlib_main_t *vm = vlib_get_main();

    if (index >= vec_len(sm->services)) {
        /* Check if this is an arbitrary node index */
        u32 node_index = ~0 - index;
        vlib_node_t *node = vlib_get_node(vm, node_index);
        if (node)
            return (const char *)node->name;
        return NULL;
    }

    return sm->services[index]->node_name;
}