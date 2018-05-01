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

#include <vnet/ip/ip_types.h>

#include <vnet/vnet_msg_enum.h>

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
ip_api_address_decode (const vl_api_address_t * in, ip46_address_t * out)
{
  ip_api_address_union_decode (&in->un, in->af, out);
}

void
ip_api_address_union_decode (const vl_api_address_union_t * in, int af,	//vl_api_address_family_t
			     ip46_address_t * out)
{
  switch (af)
    {
    case ADDRESS_IP4:
      memcpy (&out->ip4, &in->ip4, sizeof (out->ip4));
      break;
    case ADDRESS_IP6:
      memcpy (&out->ip6, &in->ip6, sizeof (out->ip6));
      break;
    default:
      ASSERT (!"Unkown address family in API address type");
      break;
    }
}

void
ip_api_address_encode (const ip46_address_t * in, int af,	//vl_api_address_family_t
		       vl_api_address_t * out)
{
  out->af = af;
  ip_api_address_union_encode (in, af, &out->un);
}

void
ip_api_address_union_encode (const ip46_address_t * in, int af,	//vl_api_address_family_t
			     vl_api_address_union_t * out)
{
  if (ADDRESS_IP6 == af)
    memcpy (out->ip6.address, &in->ip6, sizeof (out->ip6));
  else
    memcpy (out->ip4.address, &in->ip4, sizeof (out->ip4));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
