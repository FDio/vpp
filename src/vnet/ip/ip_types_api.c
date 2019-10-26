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

#include <vlibapi/api_types.h>
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

int
ip_address_family_decode (int _af, ip_address_family_t * out)
{
  vl_api_address_family_t af = clib_host_to_net_u32 (_af);

  switch (af)
    {
    case ADDRESS_IP4:
      *out = AF_IP4;
      return (0);
    case ADDRESS_IP6:
      *out = AF_IP6;
      return (0);
    }
  return (-1);
}

int
ip_address_family_encode (ip_address_family_t af)
{
  switch (af)
    {
    case AF_IP4:
      return (clib_host_to_net_u32 (ADDRESS_IP4));
    case AF_IP6:
      return (clib_host_to_net_u32 (ADDRESS_IP6));
    }

  ASSERT (0);
  return (clib_host_to_net_u32 (ADDRESS_IP4));
}

int
ip_proto_decode (int _ipp, ip_protocol_t * out)
{
  ip_protocol_t ipp = clib_host_to_net_u32 (_ipp);

  switch (ipp)
    {
#define ip_protocol(n,s)                       \
      case IP_PROTOCOL_##s:                    \
        *out = IP_PROTOCOL_##s;                \
        return (0);
#include "protocols.def"
#undef ip_protocol
    }
  return (-1);
}

int
ip_proto_encode (ip_protocol_t ipp)
{
  switch (ipp)
    {
#define ip_protocol(n,s)                                \
      case IP_PROTOCOL_##s:                             \
        return (clib_host_to_net_u32 (IP_PROTOCOL_##s));
#include "protocols.def"
#undef ip_protocol
    }

  ASSERT (0);
  return (clib_host_to_net_u32 (IP_API_PROTO_TCP));
}

ip_dscp_t
ip_dscp_decode (u8 in)
{
  return ((ip_dscp_t) in);
}

u8
ip_dscp_encode (ip_dscp_t dscp)
{
  return (dscp);
}

void
ip6_address_encode (const ip6_address_t * in, vl_api_ip6_address_t out)
{
  clib_memcpy (out, in, sizeof (*in));
}

void
ip6_address_decode (const vl_api_ip6_address_t in, ip6_address_t * out)
{
  clib_memcpy (out, in, sizeof (*out));
}

void
ip4_address_encode (const ip4_address_t * in, vl_api_ip4_address_t out)
{
  clib_memcpy (out, in, sizeof (*in));
}

void
ip4_address_decode (const vl_api_ip4_address_t in, ip4_address_t * out)
{
  clib_memcpy (out, in, sizeof (*out));
}

static ip46_type_t
ip_address_union_decode (const vl_api_address_union_t * in,
			 vl_api_address_family_t af, ip46_address_t * out)
{
  ip46_type_t type;

  switch (clib_net_to_host_u32 (af))
    {
    case ADDRESS_IP4:
      clib_memset (out, 0, sizeof (*out));
      clib_memcpy (&out->ip4, &in->ip4, sizeof (out->ip4));
      type = IP46_TYPE_IP4;
      break;
    case ADDRESS_IP6:
      clib_memcpy (&out->ip6, &in->ip6, sizeof (out->ip6));
      type = IP46_TYPE_IP6;
      break;
    default:
      ASSERT (!"Unknown address family in API address type");
      type = IP46_TYPE_ANY;
      break;
    }

  return type;
}

ip46_type_t
ip_address_decode (const vl_api_address_t * in, ip46_address_t * out)
{
  return (ip_address_union_decode (&in->un, in->af, out));
}

static void
ip_address_union_encode (const ip46_address_t * in,
			 vl_api_address_family_t af,
			 vl_api_address_union_t * out)
{
  if (ADDRESS_IP6 == clib_net_to_host_u32 (af))
    ip6_address_encode (&in->ip6, out->ip6);
  else
    ip4_address_encode (&in->ip4, out->ip4);
}

void
ip_address_encode (const ip46_address_t * in,
		   ip46_type_t type, vl_api_address_t * out)
{
  switch (type)
    {
    case IP46_TYPE_IP4:
      out->af = clib_net_to_host_u32 (ADDRESS_IP4);
      break;
    case IP46_TYPE_IP6:
      out->af = clib_net_to_host_u32 (ADDRESS_IP6);
      break;
    case IP46_TYPE_ANY:
      if (ip46_address_is_ip4 (in))
	out->af = clib_net_to_host_u32 (ADDRESS_IP4);
      else
	out->af = clib_net_to_host_u32 (ADDRESS_IP6);
      break;
    }
  ip_address_union_encode (in, out->af, &out->un);
}

void
ip_prefix_decode (const vl_api_prefix_t * in, fib_prefix_t * out)
{
  switch (clib_net_to_host_u32 (in->address.af))
    {
    case ADDRESS_IP4:
      out->fp_proto = FIB_PROTOCOL_IP4;
      break;
    case ADDRESS_IP6:
      out->fp_proto = FIB_PROTOCOL_IP6;
      break;
    }
  out->fp_len = in->len;
  out->___fp___pad = 0;
  ip_address_decode (&in->address, &out->fp_addr);
}

void
ip_prefix_encode (const fib_prefix_t * in, vl_api_prefix_t * out)
{
  out->len = in->fp_len;
  ip_address_encode (&in->fp_addr,
		     fib_proto_to_ip46 (in->fp_proto), &out->address);
}

void
ip_mprefix_encode (const mfib_prefix_t * in, vl_api_mprefix_t * out)
{
  out->af = (FIB_PROTOCOL_IP6 == in->fp_proto ? ADDRESS_IP6 : ADDRESS_IP4);
  out->af = clib_host_to_net_u32 (out->af);
  out->grp_address_length = clib_host_to_net_u16 (in->fp_len);

  ip_address_union_encode (&in->fp_grp_addr, out->af, &out->grp_address);
  ip_address_union_encode (&in->fp_src_addr, out->af, &out->src_address);
}

void
ip_mprefix_decode (const vl_api_mprefix_t * in, mfib_prefix_t * out)
{
  out->fp_proto = (ADDRESS_IP6 == clib_net_to_host_u32 (in->af) ?
		   FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4);
  out->fp_len = clib_net_to_host_u16 (in->grp_address_length);

  ip_address_union_decode (&in->grp_address, in->af, &out->fp_grp_addr);
  ip_address_union_decode (&in->src_address, in->af, &out->fp_src_addr);

  if (!ip46_address_is_zero (&out->fp_src_addr))
    out->fp_len = (out->fp_proto == FIB_PROTOCOL_IP6 ? 256 : 64);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
