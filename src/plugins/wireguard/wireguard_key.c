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

#include <wireguard/wireguard_key.h>
#include <openssl/evp.h>

bool
curve25519_gen_shared (u8 shared_key[CURVE25519_KEY_SIZE],
		       const u8 secret_key[CURVE25519_KEY_SIZE],
		       const u8 basepoint[CURVE25519_KEY_SIZE])
{

  bool ret;
  EVP_PKEY_CTX *ctx;
  size_t key_len;

  EVP_PKEY *peerkey = NULL;
  EVP_PKEY *pkey =
    EVP_PKEY_new_raw_private_key (EVP_PKEY_X25519, NULL, secret_key,
				  CURVE25519_KEY_SIZE);

  ret = true;

  ctx = EVP_PKEY_CTX_new (pkey, NULL);
  if (EVP_PKEY_derive_init (ctx) <= 0)
    {
      ret = false;
      goto out;
    }

  peerkey =
    EVP_PKEY_new_raw_public_key (EVP_PKEY_X25519, NULL, basepoint,
				 CURVE25519_KEY_SIZE);
  if (EVP_PKEY_derive_set_peer (ctx, peerkey) <= 0)
    {
      ret = false;
      goto out;
    }

  key_len = CURVE25519_KEY_SIZE;
  if (EVP_PKEY_derive (ctx, shared_key, &key_len) <= 0)
    {
      ret = false;
    }

out:
  EVP_PKEY_CTX_free (ctx);
  EVP_PKEY_free (pkey);
  EVP_PKEY_free (peerkey);
  return ret;
}

bool
curve25519_gen_public (u8 public_key[CURVE25519_KEY_SIZE],
		       const u8 secret_key[CURVE25519_KEY_SIZE])
{
  size_t pub_len;
  EVP_PKEY *pkey =
    EVP_PKEY_new_raw_private_key (EVP_PKEY_X25519, NULL, secret_key,
				  CURVE25519_KEY_SIZE);
  pub_len = CURVE25519_KEY_SIZE;
  if (!EVP_PKEY_get_raw_public_key (pkey, public_key, &pub_len))
    {
      EVP_PKEY_free (pkey);
      return false;
    }
  EVP_PKEY_free (pkey);
  return true;
}

bool
curve25519_gen_secret (u8 secret_key[CURVE25519_KEY_SIZE])
{
  size_t secret_len;
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id (EVP_PKEY_X25519, NULL);
  EVP_PKEY_keygen_init (pctx);
  EVP_PKEY_keygen (pctx, &pkey);
  EVP_PKEY_CTX_free (pctx);

  secret_len = CURVE25519_KEY_SIZE;
  if (!EVP_PKEY_get_raw_private_key (pkey, secret_key, &secret_len))
    {
      EVP_PKEY_free (pkey);
      return false;
    }
  EVP_PKEY_free (pkey);
  return true;
}

bool
key_to_base64 (const u8 * src, size_t src_len, u8 * out)
{
  if (!EVP_EncodeBlock (out, src, src_len))
    return false;
  return true;
}

bool
key_from_base64 (const u8 * src, size_t src_len, u8 * out)
{
  if (EVP_DecodeBlock (out, src, src_len - 1) <= 0)
    return false;
  return true;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
