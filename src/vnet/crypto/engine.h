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
struct vnet_crypto_reg_op_group;

typedef struct vnet_crypto_reg_op
{
  struct vnet_crypto_reg_op *next;
  struct vnet_crypto_reg_op_group *group;
  vnet_crypto_op_id_t op_id;
  vnet_crypto_simple_op_fn_t *fn;
  vnet_crypto_chained_op_fn_t *cfn;
} vnet_crypto_reg_op_t;

typedef struct vnet_crypto_reg_op_group
{
  struct vnet_crypto_reg_op_group *next;
  const char *name;
  vnet_crypto_is_supported_fn_t *probe_fn;
  int priority;
  u16 max_key_data_sz;
  u8 key_data_per_thread;
  vnet_crypto_key_data_fn_t *key_add_fn;
  vnet_crypto_key_data_fn_t *key_del_fn;
  vnet_crypto_reg_op_t *ops;
} vnet_crypto_reg_op_group_t;

typedef char *(
  vnet_crypto_engine_init_fn_t) (struct vnet_crypto_engine_registration *);

typedef struct vnet_crypto_engine_registration
{
  char name[32];  /* backend name */
  char desc[128]; /* backend name */
  int prio;
  u32 version;
  u32 num_threads;
  void *per_thread_data;
  vnet_crypto_engine_init_fn_t *init_fn;
  vnet_crypto_reg_op_group_t *reg_op_groups;
} vnet_crypto_engine_registration_t;

extern __clib_export vnet_crypto_engine_registration_t __vnet_crypto_engine;

#define VNET_CRYPTO_REG_ENGINE()                                                                   \
  __clib_export vnet_crypto_engine_registration_t __vnet_crypto_engine

#define VNET_CRYPTO_REG_OP_GROUP(x)                                                                \
  static vnet_crypto_reg_op_group_t x;                                                             \
  static void __clib_constructor __vnet_crypto_reg_op_group_ctor_##x (void)                        \
  {                                                                                                \
    if (x.name == 0)                                                                               \
      x.name = #x;                                                                                 \
    x.next = __vnet_crypto_engine.reg_op_groups;                                                   \
    __vnet_crypto_engine.reg_op_groups = &x;                                                       \
  }                                                                                                \
  static vnet_crypto_reg_op_group_t x

#define VNET_CRYPTO_REG_OP(x)                                                                      \
  static vnet_crypto_reg_op_t x;                                                                   \
  static void __clib_constructor __vnet_crypto_reg_op_ctor_##x (void)                              \
  {                                                                                                \
    if (x.group == 0)                                                                              \
      return;                                                                                      \
    x.next = x.group->ops;                                                                         \
    x.group->ops = &x;                                                                             \
  }                                                                                                \
  static vnet_crypto_reg_op_t x

#endif
