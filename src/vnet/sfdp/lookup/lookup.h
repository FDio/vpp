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
  _ (FIRST_PACKET_NON_TCP, "first packet non-tcp")                                                 \
  _ (FIRST_PACKET_TCP_SYN, "first packet tcp syn")                                                 \
  _ (FIRST_PACKET_TCP_SYN_ACK, "first packet tcp syn-ack")                                         \
  _ (FIRST_PACKET_TCP_FIN, "first packet tcp fin")                                                 \
  _ (FIRST_PACKET_TCP_FIN_ACK, "first packet tcp fin-ack")                                         \
  _ (FIRST_PACKET_TCP_RST, "first packet tcp rst")                                                 \
  _ (FIRST_PACKET_TCP_RST_ACK, "first packet tcp rst-ack")                                         \
  _ (FIRST_PACKET_TCP_ACK, "first packet tcp ack")                                                 \
  _ (FIRST_PACKET_TCP_OTHER, "first packet tcp other")

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
