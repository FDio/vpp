/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 */


#ifndef included_unittest_crypto_crypto_h
#define included_unittest_crypto_crypto_h

#define CRYPTO_TEST_MAX_OP_CHUNKS 8

typedef struct
{
  u32 length;
  u8 *data;
} unittest_crypto_test_data_t;

typedef struct unittest_crypto_test_registration
{
  char *name;
  vnet_crypto_alg_t alg;
  unittest_crypto_test_data_t iv, key, digest, plaintext, ciphertext, aad,
    tag;
  u32 plaintext_incremental;
  u8 is_chained;

  /* plaintext and cipher text data used for testing chained buffers */
  unittest_crypto_test_data_t pt_chunks[CRYPTO_TEST_MAX_OP_CHUNKS + 1];
  unittest_crypto_test_data_t ct_chunks[CRYPTO_TEST_MAX_OP_CHUNKS + 1];

  /* next */
  struct unittest_crypto_test_registration *next;
} unittest_crypto_test_registration_t;


typedef struct
{
  int verbose;
  u8 *inc_data;

  /* perf */
  vnet_crypto_alg_t alg;
  u32 warmup_rounds;
  u32 rounds;
  u32 buffer_size;
  u32 n_buffers;

  unittest_crypto_test_registration_t *test_registrations;
} crypto_test_main_t;

extern crypto_test_main_t crypto_test_main;

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
