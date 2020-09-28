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

#ifndef __included_wg_convert_h__
#define __included_wg_convert_h__

#include <stdbool.h>
#include <vlib/vlib.h>

enum curve25519_lengths
{
  CURVE25519_KEY_SIZE = 32
};

bool curve25519_gen_shared (u8 shared_key[CURVE25519_KEY_SIZE],
			    const u8 secret_key[CURVE25519_KEY_SIZE],
			    const u8 basepoint[CURVE25519_KEY_SIZE]);
bool curve25519_gen_secret (u8 secret[CURVE25519_KEY_SIZE]);
bool curve25519_gen_public (u8 public_key[CURVE25519_KEY_SIZE],
			    const u8 secret_key[CURVE25519_KEY_SIZE]);

bool key_to_base64 (const u8 * src, size_t src_len, u8 * out);
bool key_from_base64 (const u8 * src, size_t src_len, u8 * out);

#endif /* __included_wg_convert_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
