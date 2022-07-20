/*
 * Copyright (c) 2022 Rubicon Communications, LLC.
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

/*
 * chacha-merged.c version 20080118
 * D. J. Bernstein
 * Public domain.
 */

#ifndef __included_wg_hchacha20_h__
#define __included_wg_hchacha20_h__

#include <vlib/vlib.h>

/* clang-format off */
#define U32C(v) (v##U)
#define U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);
/* clang-format on */

static const char sigma[16] = "expand 32-byte k";

static inline void
hchacha20 (u32 derived_key[8], const u8 nonce[16], const u8 key[32])
{
  int i;
  u32 x[] = { U8TO32_LITTLE (sigma + 0), U8TO32_LITTLE (sigma + 4),
	      U8TO32_LITTLE (sigma + 8), U8TO32_LITTLE (sigma + 12),
	      U8TO32_LITTLE (key + 0),	 U8TO32_LITTLE (key + 4),
	      U8TO32_LITTLE (key + 8),	 U8TO32_LITTLE (key + 12),
	      U8TO32_LITTLE (key + 16),	 U8TO32_LITTLE (key + 20),
	      U8TO32_LITTLE (key + 24),	 U8TO32_LITTLE (key + 28),
	      U8TO32_LITTLE (nonce + 0), U8TO32_LITTLE (nonce + 4),
	      U8TO32_LITTLE (nonce + 8), U8TO32_LITTLE (nonce + 12) };

  for (i = 20; i > 0; i -= 2)
    {
      QUARTERROUND (x[0], x[4], x[8], x[12])
      QUARTERROUND (x[1], x[5], x[9], x[13])
      QUARTERROUND (x[2], x[6], x[10], x[14])
      QUARTERROUND (x[3], x[7], x[11], x[15])
      QUARTERROUND (x[0], x[5], x[10], x[15])
      QUARTERROUND (x[1], x[6], x[11], x[12])
      QUARTERROUND (x[2], x[7], x[8], x[13])
      QUARTERROUND (x[3], x[4], x[9], x[14])
    }

  clib_memcpy (derived_key + 0, x + 0, sizeof (u32) * 4);
  clib_memcpy (derived_key + 4, x + 12, sizeof (u32) * 4);
}

#endif /* __included_wg_hchacha20_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
