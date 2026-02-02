/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#ifndef included_vnet_crypto_engine_h
#define included_vnet_crypto_engine_h

#ifndef included_clib_types_h
typedef unsigned int u32;
#endif

typedef struct
{
  vnet_crypto_op_id_t opt;
  vnet_crypto_simple_op_fn_t *fn;
  vnet_crypto_chained_op_fn_t *cfn;
} vnet_crypto_engine_op_handlers_t;

struct vnet_crypto_engine_registration;

typedef char *(
  vnet_crypto_engine_init_fn_t) (struct vnet_crypto_engine_registration *);

typedef struct vnet_crypto_engine_registration
{
  char name[32];  /* backend name */
  char desc[128]; /* backend name */
  int prio;
  u32 version;
  u16 key_data_sz[VNET_CRYPTO_N_ALGS];
  u32 per_thread_data_sz;
  u32 num_threads;
  void *per_thread_data;
  vnet_crypto_engine_init_fn_t *init_fn;
  vnet_crypto_key_fn_t *key_handler;
  vnet_crypto_engine_op_handlers_t *op_handlers;
} vnet_crypto_engine_registration_t;

#define VNET_CRYPTO_ENGINE_REGISTRATION()                                     \
  __clib_export vnet_crypto_engine_registration_t __vnet_crypto_engine

#endif
