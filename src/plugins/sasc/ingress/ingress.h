// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#ifndef included_ingress_h
#define included_ingress_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct {
    u16 msg_id_base;

    u16 *tenant_idx_by_sw_if_idx[VLIB_N_DIR];
} sasc_ingress_main_t;

extern sasc_ingress_main_t sasc_ingress_main;

static inline u16
sasc_tenant_idx_from_sw_if_index(u32 sw_if_index, u32 dir) {
    sasc_ingress_main_t *sasc_ingress = &sasc_ingress_main;
    if (sw_if_index >= vec_len(sasc_ingress->tenant_idx_by_sw_if_idx[dir]))
        return UINT16_MAX;
    return vec_elt(sasc_ingress->tenant_idx_by_sw_if_idx[dir], sw_if_index);
}

int sasc_interface_input_enable_disable(u32 sw_if_index, u32 tenant_id, bool output_arc, bool is_enable);

#endif /* included_ingress_h */
