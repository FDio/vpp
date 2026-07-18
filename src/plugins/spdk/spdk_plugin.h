/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#ifndef __included_spdk_plugin_h__
#define __included_spdk_plugin_h__

#include <vlib/vlib.h>
#include <vppinfra/clib.h>

int spdk_vpp_attach (void);
u32 spdk_vpp_app_index (void);
u8 *format_spdk_vpp_state (u8 *s);
void spdk_vpp_env_set_current_core (u32 core);

int spdk_plugin_lcore_for_vpp_thread (u32 thread_index, u32 *lcore);
int spdk_plugin_vpp_thread_for_lcore (u32 lcore, u32 *thread_index);

int spdk_plugin_start_app (vlib_main_t *vm, const char *name, const char *json_config,
			   const char *reactor_mask, const char *rpc_addr, int no_pci);
void spdk_plugin_stop_app (void);
u8 *format_spdk_plugin_state (u8 *s, va_list *args);

#endif /* __included_spdk_plugin_h__ */
