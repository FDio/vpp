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

#ifndef included_ip_format_fns_h
#define included_ip_format_fns_h

static inline u8 *format_vl_api_ip6_address_t (u8 * s, va_list * args);
static inline u8 *format_vl_api_ip4_address_t (u8 * s, va_list * args);

#include <vnet/ip/format.h>
#include <vnet/ip/ip_types.api_types.h>

static inline u8 *
format_vl_api_ip6_address_t (u8 * s, va_list * args)
{
  vl_api_ip6_address_t *a = va_arg (*args, vl_api_ip6_address_t *);
  u32 indent __attribute__((unused)) = va_arg (*args, u32);

  return format (s, "%U", format_ip6_address, a);
}

static inline u8 *
format_vl_api_ip6_prefix_t (u8 * s, va_list * args)
{
  vl_api_ip6_prefix_t *a = va_arg (*args, vl_api_ip6_prefix_t *);
  u32 indent __attribute__((unused)) = va_arg (*args, u32);

  return format (s, "%U/%u", format_ip6_address, &a->address, a->len);
}

static inline u8 *
format_vl_api_ip4_address_t (u8 * s, va_list * args)
{
  vl_api_ip4_address_t *a = va_arg (*args, vl_api_ip4_address_t *);
  u32 indent __attribute__((unused)) = va_arg (*args, u32);

  return format (s, "%U", format_ip4_address, a);
}

static inline u8 *
format_vl_api_ip4_prefix_t (u8 * s, va_list * args)
{
  vl_api_ip4_prefix_t *a = va_arg (*args, vl_api_ip4_prefix_t *);
  u32 indent __attribute__((unused)) = va_arg (*args, u32);

  return format (s, "%U/%u", format_ip4_address, &a->address, a->len);
}

static inline u8 *
format_vl_api_address_t (u8 * s, va_list * args)
{
  vl_api_address_t *a = va_arg (*args, vl_api_address_t *);
  u32 indent __attribute__((unused)) = va_arg (*args, u32);

  switch (a->af)  {
  case ADDRESS_IP4:
    return format(s, "%U", format_ip4_address, &a->un.ip4);
  case ADDRESS_IP6:
    return format(s, "%U", format_ip6_address, &a->un.ip6);
  }
  return format (s, "unknown-af");
}

static inline u8 *
format_vl_api_prefix_t (u8 * s, va_list * args)
{
  vl_api_prefix_t *a = va_arg (*args, vl_api_prefix_t *);
  u32 indent __attribute__((unused)) = va_arg (*args, u32);

  return format (s, "%U/%u", format_vl_api_address_t, &a->address, indent, a->len);
}

static inline u8 *
format_vl_api_address_with_prefix_t (u8 * s, va_list * args)
{
  return format_vl_api_prefix_t (s, args);
}

static inline u8 *
format_vl_api_ip4_address_with_prefix_t (u8 * s, va_list * args)
{
        return format_vl_api_ip4_prefix_t (s, args);
}

static inline u8 *
format_vl_api_ip6_address_with_prefix_t (u8 * s, va_list * args)
{
        return format_vl_api_ip6_prefix_t (s, args);
}

#endif
