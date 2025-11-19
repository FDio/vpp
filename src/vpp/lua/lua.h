/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#pragma once

#include <vlua/vlua.h>
#include <vlib/vlib.h>

vlua_handle_t vpp_lua_get_main_handle (void);
void vpp_lua_process_wakeup (vlib_main_t *vm);
