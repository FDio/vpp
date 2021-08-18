/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef included_npol_match_h
#define included_npol_match_h

#include <acl/acl.h>
#include <acl/fa_node.h>

#include <npol/npol_ipset.h>
#include <npol/npol_policy.h>
#include <npol/npol_rule.h>

int npol_match_func (u32 sw_if_index, u32 is_inbound, fa_5tuple_t *pkt_5tuple,
		     int is_ip6, u8 *r_action);

#endif
