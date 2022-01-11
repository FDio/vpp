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

#include <sys/random.h>
#include "drbg_ctr.h"

/* NIST SP800-90Ar1 section 10.2.1.4.1 without derivation function
 * No additional data supported */
clib_error_t *
vnet_crypto_drbg_ctr_reseed (vlib_main_t *vm, vnet_crypto_drbg_ctr_t *drbg,
			     const vnet_crypto_drbg_ctr_seed_t *seed)
{
  vnet_crypto_drbg_ctr_seed_t seed_;
  if (!seed)
    {
      if (getrandom (&seed_, sizeof (seed_), 0) != sizeof (seed_))
	return clib_error_return_unix (0, "getrandom() failed");
      seed = &seed_;
    }

  clib_error_t *err = vnet_crypto_drbg_ctr_update (vm, drbg, seed);
  if (PREDICT_FALSE (err != 0))
    return err;
  drbg->reseed_counter = 1;
  return 0;
}

/* NIST SP800-90Ar1 section 10.2.1.3.1 without derivation function
 * No personalization string supported */
clib_error_t *
vnet_crypto_drbg_ctr_init (vlib_main_t *vm, vnet_crypto_drbg_ctr_t *drbg,
			   const vnet_crypto_drbg_ctr_seed_t *seed)
{
  clib_memset (drbg, 0, sizeof (*drbg));
  drbg->key_index = vnet_crypto_key_add (vm, VNET_CRYPTO_ALG_AES_128_CTR,
					 drbg->kv.key, sizeof (drbg->kv.key));
  return vnet_crypto_drbg_ctr_reseed (vm, drbg, seed);
}

void
vnet_crypto_drbg_ctr_cleanup (vlib_main_t *vm, vnet_crypto_drbg_ctr_t *drbg)
{
  vnet_crypto_key_del (vm, drbg->key_index);
  clib_memset (drbg, 0xff, sizeof (*drbg));
}

static clib_error_t *
vnet_crypto_drbg_ctr_module_init (vlib_main_t *vm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct;
  clib_error_t *err;
  vec_foreach (ct, cm->threads)
    {
      err = vnet_crypto_drbg_ctr_init (vm, &ct->drbg, 0);
      if (err)
	return err;
    }
  return 0;
}

VLIB_INIT_FUNCTION (vnet_crypto_drbg_ctr_module_init) = {
  .runs_after = VLIB_INITS ("vnet_crypto_init"),
};
