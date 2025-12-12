/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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
