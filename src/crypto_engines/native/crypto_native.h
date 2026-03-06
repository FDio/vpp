/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#ifndef __crypto_native_h__
#define __crypto_native_h__

#include <vnet/crypto/engine.h>

typedef int (crypto_native_variant_probe_t) ();
extern vnet_crypto_engine_registration_t __vnet_crypto_engine;
#endif /* __crypto_native_h__ */
