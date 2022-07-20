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

#ifndef __included_wg_chachapoly_h__
#define __included_wg_chachapoly_h__

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>

#define XCHACHA20POLY1305_NONCE_SIZE 24
#define CHACHA20POLY1305_KEY_SIZE    32

bool wg_chacha20poly1305_calc (vlib_main_t *vm, u8 *src, u32 src_len, u8 *dst,
			       u8 *aad, u32 aad_len, u64 nonce,
			       vnet_crypto_op_id_t op_id,
			       vnet_crypto_key_index_t key_index);

void wg_xchacha20poly1305_encrypt (vlib_main_t *vm, u8 *src, u32 src_len,
				   u8 *dst, u8 *aad, u32 aad_len,
				   u8 nonce[XCHACHA20POLY1305_NONCE_SIZE],
				   u8 key[CHACHA20POLY1305_KEY_SIZE]);

bool wg_xchacha20poly1305_decrypt (vlib_main_t *vm, u8 *src, u32 src_len,
				   u8 *dst, u8 *aad, u32 aad_len,
				   u8 nonce[XCHACHA20POLY1305_NONCE_SIZE],
				   u8 key[CHACHA20POLY1305_KEY_SIZE]);

#endif /* __included_wg_chachapoly_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
