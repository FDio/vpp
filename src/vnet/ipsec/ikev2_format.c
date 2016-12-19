/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ikev2.h>
#include <vnet/ipsec/ikev2_priv.h>

u8 *
format_ikev2_sa_transform (u8 * s, va_list * args)
{
  ikev2_sa_transform_t *tr = va_arg (*args, ikev2_sa_transform_t *);

  if (!tr)
    return s;

  if (tr->type >= IKEV2_TRANSFORM_NUM_TYPES)
    return s;

  s = format (s, "%U:", format_ikev2_transform_type, tr->type);

  switch (tr->type)
    {
    case IKEV2_TRANSFORM_TYPE_ENCR:
      s = format (s, "%U", format_ikev2_transform_encr_type, tr->encr_type);
      break;
    case IKEV2_TRANSFORM_TYPE_PRF:
      s = format (s, "%U", format_ikev2_transform_prf_type, tr->prf_type);
      break;
    case IKEV2_TRANSFORM_TYPE_INTEG:
      s = format (s, "%U", format_ikev2_transform_integ_type, tr->integ_type);
      break;
    case IKEV2_TRANSFORM_TYPE_DH:
      s = format (s, "%U", format_ikev2_transform_dh_type, tr->dh_type);
      break;
    case IKEV2_TRANSFORM_TYPE_ESN:
      s = format (s, "%U", format_ikev2_transform_esn_type, tr->esn_type);
      break;
    default:
      break;
    }

  if (tr->type == IKEV2_TRANSFORM_TYPE_ENCR &&
      tr->encr_type == IKEV2_TRANSFORM_ENCR_TYPE_AES_CBC && tr->key_len)
    s = format (s, "-%u", tr->key_len * 8);
  else if (vec_len (tr->attrs) == 4 && tr->attrs[0] == 0x80
	   && tr->attrs[1] == 0x0e)
    s = format (s, "-%u", tr->attrs[2] * 256 + tr->attrs[3]);
  else if (vec_len (tr->attrs))
    s = format (s, "(unknown attr %U)", format_hex_bytes,
		tr->attrs, vec_len (tr->attrs));

  return s;
}

#define MACRO_FORMAT(lc)                                \
u8 * format_ikev2_##lc (u8 * s, va_list * args)         \
{                                                       \
  u32 i = va_arg (*args, u32);                          \
  char * t = 0;                                         \
  switch (i) {                                          \
        foreach_ikev2_##lc                              \
      default:                                          \
        return format (s, "unknown (%u)", i);           \
    }                                                   \
  s = format (s, "%s", t);                              \
  return s;                                             \
}

#define MACRO_UNFORMAT(lc)                              \
uword                                                   \
unformat_ikev2_##lc (unformat_input_t * input,          \
                     va_list * args)                    \
{                                                       \
  u32 * r = va_arg (*args, u32 *);                      \
  if (0) ;                                              \
  foreach_ikev2_##lc                                    \
  else                                                  \
    return 0;                                           \
  return 1;                                             \
}

#define _(v,f,str) case IKEV2_AUTH_METHOD_##f: t = str; break;
MACRO_FORMAT (auth_method)
#undef _
#define _(v,f,str) else if (unformat (input, str)) *r = IKEV2_AUTH_METHOD_##f;
  MACRO_UNFORMAT (auth_method)
#undef _
#define _(v,f,str) case IKEV2_TRANSFORM_TYPE_##f: t = str; break;
  MACRO_FORMAT (transform_type)
#undef _
#define _(v,f,str) else if (unformat (input, str)) *r = IKEV2_TRANSFORM_TYPE_##f;
  MACRO_UNFORMAT (transform_type)
#undef _
#define _(v,f) case IKEV2_NOTIFY_MSG_##f: t = #f; break;
  MACRO_FORMAT (notify_msg_type)
#undef _
#define _(v,f,str) case IKEV2_ID_TYPE_##f: t = str; break;
  MACRO_FORMAT (id_type)
#undef _
#define _(v,f,str) else if (unformat (input, str)) *r = IKEV2_ID_TYPE_##f;
  MACRO_UNFORMAT (id_type)
#undef _
#define _(v,f,str) case IKEV2_TRANSFORM_ENCR_TYPE_##f: t = str; break;
  MACRO_FORMAT (transform_encr_type)
#undef _
#define _(v,f,str) else if (unformat (input, str)) *r = IKEV2_TRANSFORM_ENCR_TYPE_##f;
  MACRO_UNFORMAT (transform_encr_type)
#undef _
#define _(v,f,str) case IKEV2_TRANSFORM_PRF_TYPE_##f: t = str; break;
  MACRO_FORMAT (transform_prf_type)
#undef _
#define _(v,f,str) else if (unformat (input, str)) *r = IKEV2_TRANSFORM_PRF_TYPE_##f;
  MACRO_UNFORMAT (transform_prf_type)
#undef _
#define _(v,f,str) case IKEV2_TRANSFORM_INTEG_TYPE_##f: t = str; break;
  MACRO_FORMAT (transform_integ_type)
#undef _
#define _(v,f,str) else if (unformat (input, str)) *r = IKEV2_TRANSFORM_INTEG_TYPE_##f;
  MACRO_UNFORMAT (transform_integ_type)
#undef _
#define _(v,f,str) case IKEV2_TRANSFORM_DH_TYPE_##f: t = str; break;
  MACRO_FORMAT (transform_dh_type)
#undef _
#define _(v,f,str) else if (unformat (input, str)) *r = IKEV2_TRANSFORM_DH_TYPE_##f;
  MACRO_UNFORMAT (transform_dh_type)
#undef _
#define _(v,f,str) case IKEV2_TRANSFORM_ESN_TYPE_##f: t = str; break;
  MACRO_FORMAT (transform_esn_type)
#undef _
#define _(v,f,str) else if (unformat (input, str)) *r = IKEV2_TRANSFORM_ESN_TYPE_##f;
  MACRO_UNFORMAT (transform_esn_type)
#undef _
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
