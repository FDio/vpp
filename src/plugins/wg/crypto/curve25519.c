/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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
  *  More information can be found at https://cr.yp.to/ecdh.html
  */

#include <string.h>

#include <wg/crypto/include/curve25519.h>
#include <wg/crypto/random.h>
#include "curve25519-donna.c"

bool
curve25519_gen_shared (u8 public_key[CURVE25519_KEY_SIZE],
		       const u8 secret_key[CURVE25519_KEY_SIZE],
		       const u8 basepoint[CURVE25519_KEY_SIZE])
{
  static const u8 zero[CURVE25519_KEY_SIZE] = { 0 };

  curve25519_donna (public_key, secret_key, basepoint);
  return memcmp (public_key, zero, CURVE25519_KEY_SIZE);
}

bool
curve25519_gen_public (u8 public_key[CURVE25519_KEY_SIZE],
		       const u8 secret_key[CURVE25519_KEY_SIZE])
{
  static const u8 basepoint[CURVE25519_KEY_SIZE] = { 9 };
  return curve25519_gen_shared (public_key, secret_key, basepoint);
}

void
curve25519_gen_secret (u8 secret_key[CURVE25519_KEY_SIZE])
{
  for (int i = 0; i < CURVE25519_KEY_SIZE; ++i)
    {
      secret_key[i] = get_random_u32 ();
    }
  curve25519_clamp_secret (secret_key);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
