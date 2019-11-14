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


#include <vnet/ipsec/ipsec_types_api.h>
#include <vlibapi/api_types.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

int
ipsec_proto_decode (vl_api_ipsec_proto_t in, ipsec_protocol_t * out)
{
  in = clib_net_to_host_u32 (in);

  switch (in)
    {
    case IPSEC_API_PROTO_ESP:
      *out = IPSEC_PROTOCOL_ESP;
      return (0);
    case IPSEC_API_PROTO_AH:
      *out = IPSEC_PROTOCOL_AH;
      return (0);
    }
  return (VNET_API_ERROR_INVALID_PROTOCOL);
}

vl_api_ipsec_proto_t
ipsec_proto_encode (ipsec_protocol_t p)
{
  switch (p)
    {
    case IPSEC_PROTOCOL_ESP:
      return clib_host_to_net_u32 (IPSEC_API_PROTO_ESP);
    case IPSEC_PROTOCOL_AH:
      return clib_host_to_net_u32 (IPSEC_API_PROTO_AH);
    }
  return (VNET_API_ERROR_UNIMPLEMENTED);
}

int
ipsec_crypto_algo_decode (vl_api_ipsec_crypto_alg_t in,
			  ipsec_crypto_alg_t * out)
{
  in = clib_net_to_host_u32 (in);

  switch (in)
    {
#define _(v,f,s) case IPSEC_API_CRYPTO_ALG_##f: \
      *out = IPSEC_CRYPTO_ALG_##f;              \
      return (0);
      foreach_ipsec_crypto_alg
#undef _
    }
  return (VNET_API_ERROR_INVALID_ALGORITHM);
}

vl_api_ipsec_crypto_alg_t
ipsec_crypto_algo_encode (ipsec_crypto_alg_t c)
{
  switch (c)
    {
#define _(v,f,s) case IPSEC_CRYPTO_ALG_##f:                     \
      return clib_host_to_net_u32(IPSEC_API_CRYPTO_ALG_##f);
      foreach_ipsec_crypto_alg
#undef _
    case IPSEC_CRYPTO_N_ALG:
      break;
    }
  ASSERT (0);
  return (VNET_API_ERROR_UNIMPLEMENTED);
}

int
ipsec_integ_algo_decode (vl_api_ipsec_integ_alg_t in, ipsec_integ_alg_t * out)
{
  in = clib_net_to_host_u32 (in);

  switch (in)
    {
#define _(v,f,s) case IPSEC_API_INTEG_ALG_##f:  \
      *out = IPSEC_INTEG_ALG_##f;               \
      return (0);
      foreach_ipsec_integ_alg
#undef _
    }
  return (VNET_API_ERROR_INVALID_ALGORITHM);
}

vl_api_ipsec_integ_alg_t
ipsec_integ_algo_encode (ipsec_integ_alg_t i)
{
  switch (i)
    {
#define _(v,f,s) case IPSEC_INTEG_ALG_##f:                      \
      return (clib_host_to_net_u32(IPSEC_API_INTEG_ALG_##f));
      foreach_ipsec_integ_alg
#undef _
    case IPSEC_INTEG_N_ALG:
      break;
    }
  ASSERT (0);
  return (VNET_API_ERROR_UNIMPLEMENTED);
}

void
ipsec_key_decode (const vl_api_key_t * key, ipsec_key_t * out)
{
  ipsec_mk_key (out, key->data, key->length);
}

void
ipsec_key_encode (const ipsec_key_t * in, vl_api_key_t * out)
{
  out->length = in->len;
  clib_memcpy (out->data, in->data, out->length);
}

ipsec_sa_flags_t
ipsec_sa_flags_decode (vl_api_ipsec_sad_flags_t in)
{
  ipsec_sa_flags_t flags = IPSEC_SA_FLAG_NONE;
  in = clib_net_to_host_u32 (in);

  if (in & IPSEC_API_SAD_FLAG_USE_ESN)
    flags |= IPSEC_SA_FLAG_USE_ESN;
  if (in & IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY)
    flags |= IPSEC_SA_FLAG_USE_ANTI_REPLAY;
  if (in & IPSEC_API_SAD_FLAG_IS_TUNNEL)
    flags |= IPSEC_SA_FLAG_IS_TUNNEL;
  if (in & IPSEC_API_SAD_FLAG_IS_TUNNEL_V6)
    flags |= IPSEC_SA_FLAG_IS_TUNNEL_V6;
  if (in & IPSEC_API_SAD_FLAG_UDP_ENCAP)
    flags |= IPSEC_SA_FLAG_UDP_ENCAP;

  return (flags);
}

vl_api_ipsec_sad_flags_t
ipsec_sad_flags_encode (const ipsec_sa_t * sa)
{
  vl_api_ipsec_sad_flags_t flags = IPSEC_API_SAD_FLAG_NONE;

  if (ipsec_sa_is_set_USE_ESN (sa))
    flags |= IPSEC_API_SAD_FLAG_USE_ESN;
  if (ipsec_sa_is_set_USE_ANTI_REPLAY (sa))
    flags |= IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY;
  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL;
  if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
    flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL_V6;
  if (ipsec_sa_is_set_UDP_ENCAP (sa))
    flags |= IPSEC_API_SAD_FLAG_UDP_ENCAP;

  return clib_host_to_net_u32 (flags);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
