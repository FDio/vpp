/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef POLICER_OP_H
#define POLICER_OP_H

#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <policer/policer.h>
#include <policer/xlate.h>

int pol_logical_2_physical (const qos_pol_cfg_params_st *cfg, policer_t *phys);

int policer_add (vlib_main_t *vm, const u8 *name, const qos_pol_cfg_params_st *cfg,
		 u32 *policer_index);

int policer_update (vlib_main_t *vm, u32 policer_index, const qos_pol_cfg_params_st *cfg);
int policer_del (vlib_main_t *vm, u32 policer_index);
int policer_reset (vlib_main_t *vm, u32 policer_index);
int policer_bind_worker (u32 policer_index, u32 worker, bool bind);
int policer_input (u32 policer_index, u32 sw_if_index, vlib_dir_t dir, bool apply);

#endif
