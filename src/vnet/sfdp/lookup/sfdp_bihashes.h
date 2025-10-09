/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_lookup_sfdp_bihashes_h__
#define __included_lookup_sfdp_bihashes_h__
#include <vnet/sfdp/lookup/parser.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_32_8.h>
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/bihash_56_8.h>
#define foreach_clib_bihash_kv                                                \
  _ (24, 8)                                                                   \
  _ (32, 8)                                                                   \
  _ (40, 8)                                                                   \
  _ (48, 8)                                                                   \
  _ (56, 8)

__attribute__ ((__unused__)) static const sfdp_parser_bihash_registration_t
  sfdp_parser_bihash_regs[SFDP_PARSER_MAX_KEY_SIZE] = {
#define _(k, v)                                                               \
  [k] = {                                                                     \
    .table_size = sizeof (clib_bihash_##k##_##v##_t),                         \
    .sfdp_parser_bihash_add_del_fn = (void *) clib_bihash_add_del_##k##_##v,  \
    .sfdp_parser_bihash_hash_fn = (void *) clib_bihash_hash_##k##_##v,        \
    .sfdp_parser_bihash_init_fn = (void *) clib_bihash_init_##k##_##v,        \
    .sfdp_parser_bihash_prefetch_bucket_fn =                                  \
      (void *) clib_bihash_prefetch_bucket_##k##_##v,                         \
    .sfdp_parser_bihash_search_with_hash_fn =                                 \
      (void *) clib_bihash_search_inline_with_hash_##k##_##v,                 \
  },

    foreach_clib_bihash_kv
#undef _
  };

#define SFDP_PARSER_BIHASH_CALL_FN(x, fn, args...)                            \
  sfdp_parser_bihash_regs[(x)->key_size].fn (args)
#endif