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
#include <vnet/ip/ip_types_api.h>
#include <vnet/fib/fib_table.h>

#include <vnet/tunnel/tunnel_types.api_enum.h>
#include <vnet/tunnel/tunnel_types.api_types.h>


STATIC_ASSERT (sizeof (vl_api_tunnel_encap_decap_flags_t) ==
	       sizeof (tunnel_encap_decap_flags_t),
	       "tunnel API and internal flags enum size differ");
STATIC_ASSERT (sizeof (vl_api_tunnel_flags_t) == sizeof (tunnel_flags_t),
	       "tunnel API and internal flags enum size differ");

int
tunnel_encap_decap_flags_decode (vl_api_tunnel_encap_decap_flags_t f,
				 tunnel_encap_decap_flags_t * o)
{
  if (f & ~TUNNEL_ENCAP_DECAP_FLAG_MASK)
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
tunnel_flags_decode (vl_api_tunnel_flags_t f, tunnel_flags_t *o)
{
  if (f & ~TUNNEL_FLAG_MASK)
    /* unknown flags set */
    return (VNET_API_ERROR_INVALID_VALUE_2);

  *o = (tunnel_flags_t) f;
  return (0);
}

vl_api_tunnel_flags_t
tunnel_flags_encode (tunnel_flags_t f)
{
  return ((vl_api_tunnel_flags_t) f);
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

int
tunnel_decode (const vl_api_tunnel_t *in, tunnel_t *out)
{
  int rv;

  ip_address_decode2 (&in->src, &out->t_src);
  ip_address_decode2 (&in->dst, &out->t_dst);

  if (ip_addr_version (&out->t_src) != ip_addr_version (&out->t_dst))
    return (VNET_API_ERROR_INVALID_PROTOCOL);

  if (0 == ip_address_cmp (&out->t_src, &out->t_dst))
    return (VNET_API_ERROR_SAME_SRC_DST);

  rv = tunnel_encap_decap_flags_decode (in->encap_decap_flags,
					&out->t_encap_decap_flags);

  if (rv)
    return (rv);

  rv = tunnel_mode_decode (in->mode, &out->t_mode);

  if (rv)
    return (rv);

  rv = tunnel_flags_decode (in->flags, &out->t_flags);

  if (rv)
    return (rv);

  out->t_table_id = clib_net_to_host_u32 (in->table_id);
  out->t_fib_index = fib_table_find (
    ip_address_family_to_fib_proto (ip_addr_version (&out->t_dst)),
    out->t_table_id);

  if (~0 == out->t_fib_index)
    return (VNET_API_ERROR_NO_SUCH_FIB);

  out->t_dscp = ip_dscp_decode (in->dscp);
  out->t_hop_limit = in->hop_limit;

  return (0);
}

void
tunnel_encode (const tunnel_t *in, vl_api_tunnel_t *out)
{
  ip_address_encode2 (&in->t_src, &out->src);
  ip_address_encode2 (&in->t_dst, &out->dst);

  out->encap_decap_flags =
    tunnel_encap_decap_flags_encode (in->t_encap_decap_flags);
  out->mode = tunnel_mode_encode (in->t_mode);
  out->flags = tunnel_flags_encode (in->t_flags);
  out->table_id = clib_host_to_net_u32 (in->t_table_id);
  out->dscp = ip_dscp_encode (in->t_dscp);
  out->hop_limit = in->t_hop_limit;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
