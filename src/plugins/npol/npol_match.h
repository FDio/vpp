/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef included_npol_match_h
#define included_npol_match_h

#include <vlib/counter.h>
#include <npol/npol_ipset.h>
#include <npol/npol_policy.h>
#include <npol/npol_rule.h>
#include <cnat/cnat_feature_hook.h>

typedef enum
{
  NPOL_FLOW_COUNTER_RX_ALLOW,
  NPOL_FLOW_COUNTER_RX_DENY,
  NPOL_FLOW_COUNTER_TX_ALLOW,
  NPOL_FLOW_COUNTER_TX_DENY,
  NPOL_N_FLOW_COUNTERS,
} npol_flow_counter_t;

extern vlib_simple_counter_main_t npol_flow_counters[NPOL_N_FLOW_COUNTERS];

void npol_flow_counters_validate (u32 sw_if_index);

int npol_match_func (u32 sw_if_index, u32 is_inbound, cnat_5tuple_t *pkt_5tuple, int is_ip6,
		     u8 *r_action);

void npol_cnat_slow_path_input (vlib_main_t *vm, vlib_buffer_t *b, ip_address_family_t af,
				cnat_timestamp_t *ts);
void npol_cnat_slow_path_output (vlib_main_t *vm, vlib_buffer_t *b, ip_address_family_t af,
				 cnat_timestamp_t *ts);

#endif
