/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <sfdp_services/base/tcp-check/tcp_check.h>

sfdp_tcp_check_main_t sfdp_tcp;

static clib_error_t *
sfdp_tcp_check_init (vlib_main_t *vm)
{
  sfdp_tcp_check_main_t *vtcm = &sfdp_tcp;
  vec_validate (vtcm->state, sfdp_num_sessions ());
  return 0;
};

VLIB_INIT_FUNCTION (sfdp_tcp_check_init);
