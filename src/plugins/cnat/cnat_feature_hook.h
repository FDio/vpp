/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */
#ifndef __CNAT_FEATURE_HOOK_H__
#define __CNAT_FEATURE_HOOK_H__

#include <cnat/cnat_types.h>

typedef enum cnat_hook_order_
{
  CNAT_HOOK_PREPEND = 0, /* run before existing hooks (e.g. pre-DNAT) */
  CNAT_HOOK_APPEND = 1,	 /* run after existing hooks (e.g. post-DNAT) */
} cnat_hook_order_t;

void cnat_dnat_input_slow_path (vlib_main_t *vm, vlib_buffer_t *b, ip_address_family_t af,
				cnat_timestamp_t *ts);
void cnat_snat_output_slow_path (vlib_main_t *vm, vlib_buffer_t *b, ip_address_family_t af,
				 cnat_timestamp_t *ts);

/* Ensure the built-in DNAT/SNAT hooks are registered before any external
 * plugin adds its own hooks, idempotent. */
void cnat_feature_hooks_ensure_init (void);

/* Register or unregister an input/output slow-path hook with CNAT.
 * is_add: 1 to add, 0 to remove
 * func:   hook function matching cnat_slow_path_fn_t
 * order:  CNAT_HOOK_PREPEND to run before existing hooks,
 *         CNAT_HOOK_APPEND to run after existing hooks
 *
 * Hooks run in vec order; short-circuit on deny.
 * Returns 0 on success, -1 if not found (del), -2 if duplicate (add).
 * Must be called from the main thread only.
 */
int cnat_feature_hook_input_add_del (int is_add, cnat_slow_path_fn_t func, cnat_hook_order_t order);
int cnat_feature_hook_output_add_del (int is_add, cnat_slow_path_fn_t func,
				      cnat_hook_order_t order);

/* Signal a deny verdict for the given location, hooks can call this. */
static_always_inline void
cnat_hook_deny (cnat_timestamp_t *ts, cnat_session_location_t loc)
{
  ts->cts_rewrites[loc].cts_dpoi_next_node = CTS_DPOI_NEXT_DROP;
  ts->ts_rw_bm &= ~(1 << loc);
}

#endif
