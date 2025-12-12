/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef _IGMP_ERROR_H_
#define _IGMP_ERROR_H_

#define foreach_igmp_error					\
  _ (NONE, "valid igmp packets")				\
  _ (UNSPECIFIED, "unspecified error")				\
  _ (INVALID_PROTOCOL, "invalid ip4 protocol")			\
  _ (BAD_CHECKSUM, "bad checksum")				\
  _ (BAD_LENGTH, "bad length")                                  \
  _ (UNKNOWN_TYPE, "unknown igmp message type")			\
  _ (NOT_ENABLED, "IGMP not enabled on this interface")         \

typedef enum
{
#define _(sym,str) IGMP_ERROR_##sym,
  foreach_igmp_error
#undef _
    IGMP_N_ERROR,
} igmp_error_t;

#endif /* IGMP_ERROR_H */
