/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#ifndef included_unittest_crypto_crypto_h
#define included_unittest_crypto_crypto_h

typedef struct
{
  u32 length;
  u8 *data;
} unittest_crypto_test_data_t;

typedef struct unittest_crypto_test_registration
{
  char *name;
  vnet_crypto_alg_t alg;
  unittest_crypto_test_data_t iv, key, hash, digest, plaintext, ciphertext, aad, tag;
  u32 plaintext_incremental;

  /* next */
  struct unittest_crypto_test_registration *next;
} unittest_crypto_test_registration_t;


typedef struct
{
  int verbose;
  int quiet;
  u8 *engine;
  u8 *inc_data;
  u8 async;
  u8 has_alg_filter;

  /* perf */
  vnet_crypto_alg_t alg;
  u32 warmup_rounds;
  u32 rounds;
  u32 buffer_size;
  u32 n_buffers;
  u32 elts_per_frame;

  unittest_crypto_test_registration_t *test_registrations;
} crypto_test_main_t;

extern crypto_test_main_t crypto_test_main;

clib_error_t *test_crypto_async (vlib_main_t *vm, crypto_test_main_t *tm);

#define TEST_DATA(n) { .data = (u8 *) n, .length = sizeof (n)}
#define TEST_DATA_STR(n)                                                      \
  {                                                                           \
    .data = (u8 *) n, .length = sizeof (n) - 1                                \
  }
#define TEST_DATA_CHUNK(s,off,n) { .data = (u8 *) s + off, .length = n}

#define UNITTEST_REGISTER_CRYPTO_TEST(x)                                     \
  unittest_crypto_test_registration_t __unittest_crypto_test_##x;            \
static void __clib_constructor                                               \
__unittest_crypto_test_registration_##x (void)                               \
{                                                                            \
  crypto_test_main_t * cm = &crypto_test_main;                               \
  __unittest_crypto_test_##x.next = cm->test_registrations;                  \
    cm->test_registrations = & __unittest_crypto_test_##x;                   \
}                                                                            \
unittest_crypto_test_registration_t __unittest_crypto_test_##x

#endif
