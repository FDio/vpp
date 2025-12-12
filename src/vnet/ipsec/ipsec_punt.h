/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#ifndef __IPSEC_PUNT_H__
#define __IPSEC_PUNT_H__

#include <vlib/vlib.h>

#define foreach_ipsec_punt_reason                                             \
  _ (IP4_SPI_UDP_0, "ipsec4-spi-o-udp-0", IP4_PACKET)                         \
  _ (IP4_NO_SUCH_TUNNEL, "ipsec4-no-such-tunnel", IP4_PACKET)                 \
  _ (IP6_NO_SUCH_TUNNEL, "ipsec6-no-such-tunnel", IP6_PACKET)                 \
  _ (IP6_SPI_UDP_0, "ipsec6-spi-o-udp-0", IP6_PACKET)

typedef enum ipsec_punt_reason_t_
{
#define _(s, v, f) IPSEC_PUNT_##s,
  foreach_ipsec_punt_reason
#undef _
    IPSEC_PUNT_N_REASONS,
} ipsec_punt_reason_type_t;

extern u8 *format_ipsec_punt_reason (u8 * s, va_list * args);

extern vlib_punt_reason_t ipsec_punt_reason[IPSEC_PUNT_N_REASONS];

#endif /* __IPSEC_SPD_H__ */
