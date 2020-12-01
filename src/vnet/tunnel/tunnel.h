/*
 * tunnel.h: shared definitions for tunnels.
 *
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

#ifndef __TUNNEL_H__
#define __TUNNEL_H__

#include <vlib/vlib.h>

#define foreach_tunnel_mode     \
  _(P2P, "point-to-point")      \
  _(MP, "multi-point")          \

typedef enum tunnel_mode_t_
{
#define _(n, s) TUNNEL_MODE_##n,
  foreach_tunnel_mode
#undef _
} __clib_packed tunnel_mode_t;

extern u8 *format_tunnel_mode (u8 * s, va_list * args);
extern uword unformat_tunnel_mode (unformat_input_t * input, va_list * args);

/**
 * Keep these idenitical to those in ipip.api
 */
#define forech_tunnel_encap_decap_flag              \
  _(NONE, "none", 0x0)                              \
  _(ENCAP_COPY_DF, "encap-copy-df", 0x1)            \
  _(ENCAP_SET_DF, "encap-set-df", 0x2)              \
  _(ENCAP_COPY_DSCP, "encap-copy-dscp", 0x4)        \
  _(ENCAP_COPY_ECN, "encap-copy-ecn", 0x8)          \
  _(DECAP_COPY_ECN, "decap-copy-ecn", 0x10)

typedef enum tunnel_encap_decap_flags_t_
{
#define _(a,b,c) TUNNEL_ENCAP_DECAP_FLAG_##a = c,
  forech_tunnel_encap_decap_flag
#undef _
} __clib_packed tunnel_encap_decap_flags_t;

#define TUNNEL_FLAG_MASK (0x1f)

extern u8 *format_tunnel_encap_decap_flags (u8 * s, va_list * args);
extern uword
unformat_tunnel_encap_decap_flags (unformat_input_t * input, va_list * args);
#endif
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
