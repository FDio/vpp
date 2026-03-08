/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024-2026 Cisco Systems, Inc.
 */

#ifndef included_vnet_crypto_engine_h
#define included_vnet_crypto_engine_h

#ifndef included_clib_types_h
typedef unsigned int u32;
#endif

typedef int (vnet_crypto_is_supported_fn_t) (void);
struct vnet_crypto_engine_registration;
struct vnet_crypto_reg_alg_group;

typedef union
{
  struct
  {
    vnet_crypto_simple_op_fn_t *enc_fn;
    vnet_crypto_simple_op_fn_t *dec_fn;
    vnet_crypto_simple_op_fn_t *hmac_fn;
    vnet_crypto_simple_op_fn_t *hash_fn;
  };
  vnet_crypto_simple_op_fn_t *fn[VNET_CRYPTO_OP_N_TYPES];
} vnet_crypto_reg_alg_simple_t;

typedef union
{
  struct
  {
    vnet_crypto_chained_op_fn_t *enc_fn;
    vnet_crypto_chained_op_fn_t *dec_fn;
    vnet_crypto_chained_op_fn_t *hmac_fn;
    vnet_crypto_chained_op_fn_t *hash_fn;
  };
  vnet_crypto_chained_op_fn_t *fn[VNET_CRYPTO_OP_N_TYPES];
} vnet_crypto_reg_alg_chained_t;

typedef struct vnet_crypto_reg_alg
{
  struct vnet_crypto_reg_alg *next;
  struct vnet_crypto_reg_alg_group *group;
  vnet_crypto_alg_t alg_id;
  vnet_crypto_reg_alg_simple_t simple;
  vnet_crypto_reg_alg_chained_t chained;
} vnet_crypto_reg_alg_t;

typedef struct vnet_crypto_reg_alg_group
{
  struct vnet_crypto_reg_alg_group *next;
  const char *name;
  vnet_crypto_is_supported_fn_t *probe_fn;
  int priority;
  u16 max_key_data_sz;
  u8 key_data_per_thread;
  vnet_crypto_key_change_fn_t *key_change_fn;
  vnet_crypto_reg_alg_t *algs;
} vnet_crypto_reg_alg_group_t;

typedef char *(
  vnet_crypto_engine_init_fn_t) (struct vnet_crypto_engine_registration *);

typedef struct vnet_crypto_engine_registration
{
  struct vnet_crypto_engine_registration *next;
  char name[32];  /* backend name */
  char desc[128]; /* backend name */
  int prio;
  u32 version;
  u32 num_threads;
  void *per_thread_data;
  u8 is_registered;
  vnet_crypto_engine_init_fn_t *init_fn;
  vnet_crypto_reg_alg_group_t *reg_op_groups;
} vnet_crypto_engine_registration_t;

void vnet_crypto_register_engine_registration (vnet_crypto_engine_registration_t *r);

extern __clib_export vnet_crypto_engine_registration_t __vnet_crypto_engine;

#define VNET_CRYPTO_REG_ENGINE()                                                                   \
  __clib_export vnet_crypto_engine_registration_t __vnet_crypto_engine;                            \
  static void __clib_constructor __vnet_crypto_engine_ctor (void)                                  \
  {                                                                                                \
    vnet_crypto_register_engine_registration (&__vnet_crypto_engine);                              \
  }                                                                                                \
  __clib_export vnet_crypto_engine_registration_t __vnet_crypto_engine

#define VNET_CRYPTO_REG_ALG_GROUP(x)                                                               \
  static vnet_crypto_reg_alg_group_t x;                                                            \
  static void __clib_constructor __vnet_crypto_reg_alg_group_ctor_##x (void)                       \
  {                                                                                                \
    if (x.name == 0)                                                                               \
      x.name = #x;                                                                                 \
    x.next = __vnet_crypto_engine.reg_op_groups;                                                   \
    __vnet_crypto_engine.reg_op_groups = &x;                                                       \
  }                                                                                                \
  static vnet_crypto_reg_alg_group_t x

#define VNET_CRYPTO_REG_ALG(x)                                                                     \
  static vnet_crypto_reg_alg_t x;                                                                  \
  static void __clib_constructor __vnet_crypto_reg_alg_ctor_##x (void)                             \
  {                                                                                                \
    if (x.group == 0)                                                                              \
      return;                                                                                      \
    x.next = x.group->algs;                                                                        \
    x.group->algs = &x;                                                                            \
  }                                                                                                \
  static vnet_crypto_reg_alg_t x

#endif
