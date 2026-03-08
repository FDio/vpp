/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024-2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <vnet/crypto/engine.h>
#include <native/crypto_native.h>

static char *
crypto_native_init (vnet_crypto_engine_registration_t *r)
{
  return 0;
}

VNET_CRYPTO_REGISTER_ENGINE () = {
  .name = "native",
  .desc = "Native ISA Optimized Crypto",
  .prio = 100,
  .init_fn = crypto_native_init,
};
