/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#pragma once

#include <vlua/vlua.h>
#include <vnet/vnet.h>

typedef clib_error_t *(*vlua_if_config_fn_t) (vnet_main_t *vnm, u32 sw_if_index,
					      const vlua_val_t *config);

void vlua_register_interface_config_handler (char *name,
					     vlua_if_config_fn_t fn);
