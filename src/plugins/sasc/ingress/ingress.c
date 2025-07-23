// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2025 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <sasc/sasc.h>
#include "ingress.h"
#include <vnet/vnet.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

sasc_ingress_main_t sasc_ingress_main;

/*
 * Note, do not try to enable the same feature multiple times.
 */
int
sasc_interface_input_enable_disable(u32 sw_if_index, u32 tenant_idx, bool output_arc, bool is_enable) {
    sasc_ingress_main_t *sasc_ingress = &sasc_ingress_main;
    sasc_main_t *sasc = &sasc_main;
    u16 *config;

    int dir = output_arc ? VLIB_TX : VLIB_RX;

    if (is_enable) {
        sasc_tenant_t *tenant = pool_elt_at_index(sasc->tenants, tenant_idx);
        if (!tenant)
            return -1;

        vec_validate_init_empty(sasc_ingress->tenant_idx_by_sw_if_idx[dir], sw_if_index, 0xFFFF);

        config = vec_elt_at_index(sasc_ingress->tenant_idx_by_sw_if_idx[dir], sw_if_index);
        config[0] = tenant_idx;
    }
    if (output_arc)
        return vnet_feature_enable_disable("ip4-output", "sasc-input-out", sw_if_index, is_enable, 0, 0);
    else
        return vnet_feature_enable_disable("ip4-unicast", "sasc-input", sw_if_index, is_enable, 0, 0);
}
