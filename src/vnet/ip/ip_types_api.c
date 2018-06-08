/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/ip/ip_types_api.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun


void
ip_address_decode (const vl_api_address_t * in, ip46_address_t * out)
{
  switch (in->af)
    {
    case ADDRESS_IP4:
      memset (out, 0, sizeof (*out));
      clib_memcpy (&out->ip4, &in->un.ip4, sizeof (out->ip4));
      break;
    case ADDRESS_IP6:
      clib_memcpy (&out->ip6, &in->un.ip6, sizeof (out->ip6));
      break;
    }
}

void
ip_address_encode (const ip46_address_t * in, vl_api_address_t * out)
{
  if (ip46_address_is_ip4 (in))
    {
      memset (out, 0, sizeof (*out));
      out->af = ADDRESS_IP4;
      clib_memcpy (&out->un.ip4, &in->ip4, sizeof (out->un.ip4));
    }
  else
    {
      out->af = ADDRESS_IP6;
      clib_memcpy (&out->un.ip6, &in->ip6, sizeof (out->un.ip6));
    }
}

void
ip_prefix_decode (const vl_api_prefix_t * in, fib_prefix_t * out)
{
  switch (in->address.af)
    {
    case ADDRESS_IP4:
      out->fp_proto = FIB_PROTOCOL_IP4;
      break;
    case ADDRESS_IP6:
      out->fp_proto = FIB_PROTOCOL_IP6;
      break;
    }
  out->fp_len = in->address_length;
  ip_address_decode (&in->address, &out->fp_addr);
}

void
ip_prefix_encode (const fib_prefix_t * in, vl_api_prefix_t * out)
{
  switch (in->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
      out->address.af = ADDRESS_IP4;
      break;
    case FIB_PROTOCOL_IP6:
      out->address.af = ADDRESS_IP6;
      break;
    case FIB_PROTOCOL_MPLS:
      ASSERT (0);
      break;
    }
  out->address_length = in->fp_len;
  ip_address_encode (&in->fp_addr, &out->address);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
