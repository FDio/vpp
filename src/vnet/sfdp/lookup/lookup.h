/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_lookup_h__
#define __included_lookup_h__

#define SFDP_LV_TO_SP ((u64) 0x1 << 63)
#define foreach_sfdp_lookup_error                                                                  \
  _ (MISS, "flow miss")                                                                            \
  _ (LOCAL, "local flow")                                                                          \
  _ (REMOTE, "remote flow")                                                                        \
  _ (COLLISION, "hash add collision")                                                              \
  _ (CON_DROP, "handoff drop")                                                                     \
  _ (TABLE_OVERFLOW, "table overflow")                                                             \
  _ (FLOW_OFFLOAD_ADD_FAILED, "flow offload add failed")                                           \
  _ (FLOW_OFFLOAD_ENABLE_FAILED, "flow offload enable failed")                                     \
  _ (FLOW_OFFLOAD_DELETE_FAILED, "flow offload delete failed")                                     \
  _ (FLOW_OFFLOAD_DISABLE_FAILED, "flow offload disable failed")

typedef enum
{
#define _(sym, str) SFDP_LOOKUP_ERROR_##sym,
  foreach_sfdp_lookup_error
#undef _
    SFDP_LOOKUP_N_ERROR,
} sfdp_lookup_error_t;
__clib_unused static char *sfdp_lookup_error_strings[] = {
#define _(sym, string) string,
  foreach_sfdp_lookup_error
#undef _
};

#endif