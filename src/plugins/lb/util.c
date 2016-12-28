/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <lb/util.h>

void ip46_prefix_normalize(ip46_address_t *prefix, u8 plen)
{
  if (plen == 0) {
    prefix->as_u64[0] = 0;
    prefix->as_u64[1] = 0;
  } else if (plen <= 64) {
    prefix->as_u64[0] &= clib_host_to_net_u64(0xffffffffffffffffL << (64 - plen));
    prefix->as_u64[1] = 0;
  } else {
    prefix->as_u64[1] &= clib_host_to_net_u64(0xffffffffffffffffL << (128 - plen));
  }

}

uword unformat_ip46_prefix (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  u8 *len = va_arg (*args, u8 *);
  ip46_type_t type = va_arg (*args, ip46_type_t);

  u32 l;
  if ((type != IP46_TYPE_IP6) && unformat(input, "%U/%u", unformat_ip4_address, &ip46->ip4, &l)) {
    if (l > 32)
      return 0;
    *len = l + 96;
    ip46->pad[0] = ip46->pad[1] = ip46->pad[2] = 0;
  } else if ((type != IP46_TYPE_IP4) && unformat(input, "%U/%u", unformat_ip6_address, &ip46->ip6, &l)) {
    if (l > 128)
      return 0;
    *len = l;
  } else {
    return 0;
  }
  return 1;
}

u8 *format_ip46_prefix (u8 * s, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  u32 len = va_arg (*args, u32); //va_arg cannot use u8 or u16
  ip46_type_t type = va_arg (*args, ip46_type_t);

  int is_ip4 = 0;
  if (type == IP46_TYPE_IP4)
    is_ip4 = 1;
  else if (type == IP46_TYPE_IP6)
    is_ip4 = 0;
  else
    is_ip4 = (len >= 96) && ip46_address_is_ip4(ip46);

  return is_ip4 ?
      format(s, "%U/%d", format_ip4_address, &ip46->ip4, len - 96):
      format(s, "%U/%d", format_ip6_address, &ip46->ip6, len);
}

