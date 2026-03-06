/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/ipsec/ipsec.h>

void
ipsec_default_build_op_tmpl (IPSEC_BUILD_OP_TMPL_ARGS)
{
  /* no-op */
}

/* full op builder (no-op default) */
void
ipsec_default_build_op (IPSEC_BUILD_OP_ARGS)
{
  /* no-op */
}

ipsec_main_t ipsec_main = {};
