/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef __included_verdict_testbench_h__
#define __included_verdict_testbench_h__

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/service.h>

SFDP_SERVICE_DECLARE (verdict_testbench);

#define VT_PKT_THRESHOLD      10
#define VT_HOST_PORT_ID_UNSET (u16) ~0

typedef struct
{
  u32 sw_if_index;
  u32 hw_if_index;
  u16 host_port_id; /* VT_HOST_PORT_ID_UNSET if not specified */
  u8 is_enabled;

  u32 verdict_template_index;
  u8 template_on_hw;
} verdict_testbench_main_t;

extern verdict_testbench_main_t verdict_testbench_main;

clib_error_t *verdict_testbench_enable (verdict_testbench_main_t *vt, u32 sw_if_index,
					u16 host_port_id);
clib_error_t *verdict_testbench_disable (verdict_testbench_main_t *vt);

#endif /* __included_verdict_testbench_h__ */
