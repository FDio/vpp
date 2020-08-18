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
* More information can be found at https://cr.yp.to/mac.html
*/

#ifndef __included_crypto_poly1305_h__
#define __included_crypto_poly1305_h__

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vlib/vlib.h>


enum poly1305_constant
{
  POLY1305_KEY_LEN = 32,
  POLY1305_MAC_LEN = 16,
  POLY1305_BLOCK_SIZE = 16
};

typedef struct poly1305_ctx
{
  uint32_t r[5];
  uint32_t h[5];
  uint32_t pad[4];
  size_t leftover;
  unsigned char buffer[POLY1305_BLOCK_SIZE];
  unsigned char final;
} poly1305_ctx_t;

void poly1305_init (poly1305_ctx_t * ctx, const unsigned char key[32]);
void poly1305_update (poly1305_ctx_t * ctx, const unsigned char *m,
		      size_t bytes);
void poly1305_finish (poly1305_ctx_t * ctx, unsigned char mac[16]);

#endif /* __included_crypto_poly1305_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
