/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __IPSEC_PUNT_H__
#define __IPSEC_PUNT_H__

#include <vlib/vlib.h>

#define foreach_ipsec_punt_reason                                             \
  _ (IP4_SPI_UDP_0, "ipsec4-spi-o-udp-0", IP4_PACKET)                         \
  _ (IP4_NO_SUCH_TUNNEL, "ipsec4-no-such-tunnel", IP4_PACKET)                 \
  _ (IP6_NO_SUCH_TUNNEL, "ipsec6-no-such-tunnel", IP6_PACKET)

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
