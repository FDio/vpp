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

#define foreach_nat_error \
  _(VALUE_EXIST, -1, "Value already exists") \
  _(NO_SUCH_ENTRY, -2, "No such entry") \
  _(UNKNOWN_PROTOCOL, -3, "Unknown protocol") \
  _(OUT_OF_TRANSLATIONS, -4, "Out of translations")

typedef enum
{
#define _(N, i, s) NAT_ERROR_##N = i,
  foreach_nat_error
#undef _
} nat_error_t;

#define foreach_nat_protocol \
  _(OTHER, 0, other, "other")\
  _(UDP, 1, udp, "udp")       \
  _(TCP, 2, tcp, "tcp")       \
  _(ICMP, 3, icmp, "icmp")

typedef enum
{
#define _(N, i, n, s) NAT_PROTOCOL_##N = i,
  foreach_nat_protocol
#undef _
} nat_protocol_t;

#endif /* included_nat_lib_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
