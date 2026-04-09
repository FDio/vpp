/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef __VERDICT_TESTBENCH_H__
#define __VERDICT_TESTBENCH_H__

#include <vlib/vlib.h>

#define VT_PKT_THRESHOLD 10

#define VT_PROTO_UDP (1 << 0)
#define VT_PROTO_TCP (1 << 1)

/* Currently only a single rx/tx interface pair is supported, unlike
 * interface_input which maintains a vector of interfaces. */
typedef struct
{
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
  u32 hw_if_index;
  u32 tx_hw_if_index;
  u32 udp_template_index;
  u32 tcp_template_index;
  u8 is_enabled;
  u8 templates_on_hw;
  u8 enable_counters;
  u8 enabled_protos; /* bitmask of VT_PROTO_UDP | VT_PROTO_TCP */
} verdict_testbench_main_t;

extern verdict_testbench_main_t verdict_testbench_main;

clib_error_t *verdict_testbench_enable (verdict_testbench_main_t *vt, u32 tx_sw_if_index,
					u32 rx_sw_if_index, u8 enable_counters, u8 protos);
clib_error_t *verdict_testbench_disable (verdict_testbench_main_t *vt);

#endif /* __VERDICT_TESTBENCH_H__ */
