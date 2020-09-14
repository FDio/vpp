/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief NAT port/address allocation lib
 */
#ifndef included_nat_lib_h__
#define included_nat_lib_h__

#include <vlibapi/api.h>

/* NAT API Configuration flags */
#define foreach_nat_config_flag \
  _(0x01, IS_TWICE_NAT)         \
  _(0x02, IS_SELF_TWICE_NAT)    \
  _(0x04, IS_OUT2IN_ONLY)       \
  _(0x08, IS_ADDR_ONLY)         \
  _(0x10, IS_OUTSIDE)           \
  _(0x20, IS_INSIDE)            \
  _(0x40, IS_STATIC)            \
  _(0x80, IS_EXT_HOST_VALID)

typedef enum nat_config_flags_t_
{
#define _(n,f) NAT_API_##f = n,
  foreach_nat_config_flag
#undef _
} nat_config_flags_t;

#define foreach_nat_counter _ (tcp) _ (udp) _ (icmp) _ (other) _ (drops)

#define foreach_nat_error                      \
  _ (VALUE_EXIST, -1, "Value already exists")  \
  _ (NO_SUCH_ENTRY, -2, "No such entry")       \
  _ (UNKNOWN_PROTOCOL, -3, "Unknown protocol") \
  _ (OUT_OF_TRANSLATIONS, -4, "Out of translations")

typedef enum
{
#define _(N, i, s) NAT_ERROR_##N = i,
  foreach_nat_error
#undef _
} nat_error_t;

#define foreach_nat_protocol   \
  _ (OTHER, 0, other, "other") \
  _ (UDP, 1, udp, "udp")       \
  _ (TCP, 2, tcp, "tcp")       \
  _ (ICMP, 3, icmp, "icmp")

typedef enum
{
#define _(N, i, n, s) NAT_PROTOCOL_##N = i,
  foreach_nat_protocol
#undef _
} nat_protocol_t;

/* default session timeouts */
#define NAT_UDP_TIMEOUT 300
#define NAT_TCP_TRANSITORY_TIMEOUT 240
#define NAT_TCP_ESTABLISHED_TIMEOUT 7440
#define NAT_ICMP_TIMEOUT 60

// TODO: move common formating definitions here

#endif /* included_nat_lib_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
