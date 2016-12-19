#ifndef included_vnet_gre_packet_h
#define included_vnet_gre_packet_h

/*
 * GRE packet format
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#define foreach_gre_protocol			\
_ (0x0800, ip4)                                 \
_ (0x86DD, ip6)                                 \
_ (0x6558, teb)                                 \
_ (0x0806, arp)					\
_ (0x8847, mpls_unicast)			\
_ (0x894F, nsh)

typedef enum {
#define _(n,f) GRE_PROTOCOL_##f = n,
  foreach_gre_protocol
#undef _
} gre_protocol_t;

typedef struct {
  /* flags and version */
  u16 flags_and_version;
  /* unimplemented at the moment */
#define GRE_FLAGS_CHECKSUM (1 << 15)

  /* deprecated, according to rfc2784 */
#define GRE_FLAGS_ROUTING (1 << 14)
#define GRE_FLAGS_KEY (1 << 13)
#define GRE_FLAGS_SEQUENCE (1 << 12)
#define GRE_FLAGS_STRICT_SOURCE_ROUTE (1 << 11)

  /* version 1 is PPTP which we don't support */
#define GRE_SUPPORTED_VERSION 0
#define GRE_VERSION_MASK 0x7

  /* 0x800 for ip4, etc. */
  u16 protocol;
} gre_header_t;

#endif /* included_vnet_gre_packet_h */
