/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/callbacks.h>

sfdp_callback_main_t sfdp_callback_main;

static clib_error_t *
sfdp_callback_init (vlib_main_t *vm)
{
#define _(x, ...) SFDP_CALLBACK_BUILD_EFFECTIVE_LIST (x);
  foreach_sfdp_callback_type
#undef _
    return 0;
}

VLIB_INIT_FUNCTION (sfdp_callback_init);