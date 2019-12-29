/*
 * tunnel_api.c - tunnel api
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
#include <vnet/tunnel/tunnel_types_api.h>

#include <vnet/tunnel/tunnel_types.api_enum.h>
#include <vnet/tunnel/tunnel_types.api_types.h>


STATIC_ASSERT (sizeof (vl_api_tunnel_encap_decap_flags_t) ==
	       sizeof (tunnel_encap_decap_flags_t),
	       "tunnel API and internal flags enum size differ");

int
tunnel_encap_decap_flags_decode (vl_api_tunnel_encap_decap_flags_t f,
				 tunnel_encap_decap_flags_t * o)
{
  if (f & ~TUNNEL_FLAG_MASK)
    /* unknown flags set */
    return (VNET_API_ERROR_INVALID_VALUE_2);

  *o = (tunnel_encap_decap_flags_t) f;
  return (0);
}

vl_api_tunnel_encap_decap_flags_t
tunnel_encap_decap_flags_encode (tunnel_encap_decap_flags_t f)
{
  return ((vl_api_tunnel_encap_decap_flags_t) f);
}

int
tunnel_mode_decode (vl_api_tunnel_mode_t in, tunnel_mode_t * out)
{
  switch (in)
    {
#define _(n, v)                                       \
      case TUNNEL_API_MODE_##n:                       \
        *out = TUNNEL_MODE_##n;                       \
        return (0);
      foreach_tunnel_mode
#undef _
    }

  return (VNET_API_ERROR_INVALID_VALUE_2);
}

vl_api_tunnel_mode_t
tunnel_mode_encode (tunnel_mode_t in)
{
  vl_api_tunnel_mode_t out = TUNNEL_API_MODE_P2P;

  switch (in)
    {
#define _(n, v)                                       \
      case TUNNEL_MODE_##n:                           \
        out = TUNNEL_API_MODE_##n;                    \
        break;
      foreach_tunnel_mode
#undef _
    }

  return (out);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
