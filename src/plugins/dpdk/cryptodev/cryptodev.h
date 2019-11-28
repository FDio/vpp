/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */
#ifndef included_cryptodev_h
#define included_cryptodev_h

#include <vnet/crypto/crypto.h>
#include <dpdk/ipsec/ipsec.h>

#define CRYPTODEV_BURST_SIZE    32
#define CRYPTODEV_NB_CRYPTO_OPS DPDK_CRYPTO_N_QUEUE_DESC
#define CRYPTODEV_NB_SESSION    DPDK_CRYPTO_NB_SESS_OBJS
#define CRYPTODEV_MAX_TIMER     CRYPTODEV_BURST_SIZE
#define CRYPTODEV_MAX_INFLIGHT  CRYPTODEV_BURST_SIZE
#define CRYPTODEV_DEFAULT_VDEV  crypto_aesni_mb

clib_error_t *
dpdk_cryptodev_init (vlib_main_t * vm);

#endif
