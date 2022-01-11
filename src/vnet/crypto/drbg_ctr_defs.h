/* Copyright (c) 2022 Cisco and/or its affiliates.
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
 * limitations under the License. */

#ifndef included_vnet_crypto_drbg_defs_h
#define included_vnet_crypto_drbg_defs_h

/* NIST SP800-90 section 10.2.1 table 3 for AES-128 with 128-bits strength */
#define VNET_CRYPTO_DRBG_CTR_AES_BITS  128
#define VNET_CRYPTO_DRBG_CTR_STRENGTH  VNET_CRYPTO_DRBG_CTR_AES_BITS
#define VNET_CRYPTO_DRBG_CTR_BLOCK_LEN (VNET_CRYPTO_DRBG_CTR_AES_BITS / 8)
#define VNET_CRYPTO_DRBG_CTR_KEY_LEN   VNET_CRYPTO_DRBG_CTR_BLOCK_LEN
#define VNET_CRYPTO_DRBG_CTR_V_LEN     VNET_CRYPTO_DRBG_CTR_BLOCK_LEN
#define VNET_CRYPTO_DRBG_CTR_SEED_LEN                                         \
  (VNET_CRYPTO_DRBG_CTR_BLOCK_LEN + VNET_CRYPTO_DRBG_CTR_KEY_LEN)
#define VNET_CRYPTO_DRBG_CTR_ENTROPY_LEN     VNET_CRYPTO_DRBG_CTR_SEED_LEN
#define VNET_CRYPTO_DRBG_CTR_RESEED_INTERVAL ((u64) 1 << 48)
#define VNET_CRYPTO_DRBG_CTR_MAX_REQ_LEN     (((u32) 1 << 19) / 8)

/* 256-vector worth of AES-CBC IV */
#define VNET_CRYPTO_DRBG_CTR_BUFSZ (256*16)

typedef union
{
  u8 as_u8[VNET_CRYPTO_DRBG_CTR_SEED_LEN];
  u64 as_u64[4];
} vnet_crypto_drbg_ctr_seed_t;

typedef union
{
  struct
  {
    u8 key[VNET_CRYPTO_DRBG_CTR_KEY_LEN];
    union
    {
      u8 v[VNET_CRYPTO_DRBG_CTR_V_LEN];
      struct
      {
	u64 salt;
	u64 cntr_be;
      };
    };
  };
  vnet_crypto_drbg_ctr_seed_t _;
} vnet_crypto_drbg_ctr_kv_t;
STATIC_ASSERT_SIZEOF_ELT (vnet_crypto_drbg_ctr_kv_t, key, 16);
STATIC_ASSERT_SIZEOF_ELT (vnet_crypto_drbg_ctr_kv_t, v, 16);
STATIC_ASSERT_SIZEOF_ELT (vnet_crypto_drbg_ctr_kv_t, _, 32);

typedef struct
{
  vnet_crypto_drbg_ctr_kv_t kv;
  u64 reseed_counter;
  u32 key_index;
  u32 bufsz;
  u8 buf[VNET_CRYPTO_DRBG_CTR_BUFSZ];
} vnet_crypto_drbg_ctr_t;

clib_error_t *
vnet_crypto_drbg_ctr_reseed (vlib_main_t *vm, vnet_crypto_drbg_ctr_t *drbg,
			     const vnet_crypto_drbg_ctr_seed_t *seed);
clib_error_t *
vnet_crypto_drbg_ctr_init (vlib_main_t *vm, vnet_crypto_drbg_ctr_t *drbg,
			   const vnet_crypto_drbg_ctr_seed_t *seed);
void vnet_crypto_drbg_ctr_cleanup (vlib_main_t *vm,
				   vnet_crypto_drbg_ctr_t *drbg);

#endif /* included_vnet_crypto_drbg_defs_h */
