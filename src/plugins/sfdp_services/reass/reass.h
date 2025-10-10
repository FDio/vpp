/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_lookup_reass_h__
#define __included_lookup_reass_h__

#include <vlib/vlib.h>
typedef struct
{
  /* Shallow Virtual Reassembly */
  u16 ip4_sv_reass_next_index;
  u16 ip6_sv_reass_next_index;

  /* Full Reassembly */
  u16 ip4_full_reass_next_index;
  u16 ip6_full_reass_next_index;

  /* Full Reassembly error next index */
  u16 ip4_full_reass_err_next_index;
  u16 ip6_full_reass_err_next_index;
} sfdp_reass_main_t;
extern sfdp_reass_main_t sfdp_reass_main;
#endif