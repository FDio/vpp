/*
 * ipip_api.c - ipip api
 *
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

#include <vnet/api_errno.h>
#include <vnet/ipip/ipip_types_api.h>

#include <vnet/ipip/ipip_types.api_enum.h>
#include <vnet/ipip/ipip_types.api_types.h>


STATIC_ASSERT (sizeof (vl_api_ipip_tunnel_flags_t) ==
	       sizeof (ipip_tunnel_flags_t),
	       "IPIP tunnel API and internal flags enum size differ");

int
ipip_tunnel_flags_decode (vl_api_ipip_tunnel_flags_t f,
			  ipip_tunnel_flags_t * o)
{
  if (f & ~IPIP_TUNNEL_FLAG_MASK)
    /* unknown flags set */
    return (VNET_API_ERROR_INVALID_VALUE_2);

  *o = (ipip_tunnel_flags_t) f;
  return (0);
}

vl_api_ipip_tunnel_flags_t
ipip_tunnel_flags_encode (ipip_tunnel_flags_t f)
{
  return ((vl_api_ipip_tunnel_flags_t) f);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
