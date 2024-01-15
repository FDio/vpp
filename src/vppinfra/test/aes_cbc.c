/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#if defined(__AES__) || defined(__ARM_FEATURE_CRYPTO)
#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/crypto/aes_cbc.h>

static const u8 iv[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

static const u8 plaintext[] = {
  0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73,
  0x93, 0x17, 0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7,
  0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4,
  0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45,
  0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10,
};

static const u8 key128[] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
			     0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };

static const u8 key192[24] = {
  0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B,
  0x80, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B,
};

static const u8 ciphertext128[] = {
  0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12,
  0xE9, 0x19, 0x7D, 0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB,
  0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2, 0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74,
  0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16, 0x3F, 0xF1, 0xCA, 0xA1,
  0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30, 0x75, 0x86, 0xE1, 0xA7,
};

static const u8 ciphertext192[64] = {
  0x4F, 0x02, 0x1D, 0xB2, 0x43, 0xBC, 0x63, 0x3D, 0x71, 0x78, 0x18, 0x3A, 0x9F,
  0xA0, 0x71, 0xE8, 0xB4, 0xD9, 0xAD, 0xA9, 0xAD, 0x7D, 0xED, 0xF4, 0xE5, 0xE7,
  0x38, 0x76, 0x3F, 0x69, 0x14, 0x5A, 0x57, 0x1B, 0x24, 0x20, 0x12, 0xFB, 0x7A,
  0xE0, 0x7F, 0xA9, 0xBA, 0xAC, 0x3D, 0xF1, 0x02, 0xE0, 0x08, 0xB0, 0xE2, 0x79,
  0x88, 0x59, 0x88, 0x81, 0xD9, 0x20, 0xA9, 0xE6, 0x4F, 0x56, 0x15, 0xCD,
};

static const u8 key256[32] = {
  0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE,
  0xF0, 0x85, 0x7D, 0x77, 0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61,
  0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4,
};

static const u8 ciphertext256[64] = {
  0xF5, 0x8C, 0x4C, 0x04, 0xD6, 0xE5, 0xF1, 0xBA, 0x77, 0x9E, 0xAB, 0xFB, 0x5F,
  0x7B, 0xFB, 0xD6, 0x9C, 0xFC, 0x4E, 0x96, 0x7E, 0xDB, 0x80, 0x8D, 0x67, 0x9F,
  0x77, 0x7B, 0xC6, 0x70, 0x2C, 0x7D, 0x39, 0xF2, 0x33, 0x69, 0xA9, 0xD9, 0xBA,
  0xCF, 0xA5, 0x30, 0xE2, 0x63, 0x04, 0x23, 0x14, 0x61, 0xB2, 0xEB, 0x05, 0xE2,
  0xC3, 0x9B, 0xE9, 0xFC, 0xDA, 0x6C, 0x19, 0x07, 0x8C, 0x6A, 0x9D, 0x1B,
};

#define _(b)                                                                  \
  static clib_error_t *test_clib_aes##b##_cbc_encrypt (clib_error_t *err)     \
  {                                                                           \
    aes_cbc_key_data_t k;                                                     \
    u8 data[512];                                                             \
    clib_aes##b##_cbc_key_expand (&k, key##b);                                \
    clib_aes##b##_cbc_encrypt (&k, plaintext, sizeof (plaintext), iv, data);  \
    if (memcmp (ciphertext##b, data, sizeof (ciphertext##b)) != 0)            \
      err =                                                                   \
	clib_error_return (err, "encrypted data doesn't match plaintext");    \
    return err;                                                               \
  }                                                                           \
  void __test_perf_fn perftest_aes##b##_enc_var_sz (test_perf_t *tp)          \
  {                                                                           \
    u32 n = tp->n_ops;                                                        \
    aes_cbc_key_data_t *kd = test_mem_alloc (sizeof (*kd));                   \
    u8 *dst = test_mem_alloc (n + 16);                                        \
    u8 *src = test_mem_alloc_and_fill_inc_u8 (n + 16, 0, 0);                  \
    clib_aes##b##_cbc_key_expand (kd, key##b);                                \
                                                                              \
    test_perf_event_enable (tp);                                              \
    clib_aes##b##_cbc_encrypt (kd, src, n, iv, dst);                          \
    test_perf_event_disable (tp);                                             \
  }
_ (128)
_ (192)
_ (256)
#undef _

REGISTER_TEST (clib_aes128_cbc_encrypt) = {
  .name = "clib_aes128_cbc_encrypt",
  .fn = test_clib_aes128_cbc_encrypt,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes128_enc_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 9008,
			      .fn = perftest_aes128_enc_var_sz }),
};

REGISTER_TEST (clib_aes192_cbc_encrypt) = {
  .name = "clib_aes192_cbc_encrypt",
  .fn = test_clib_aes192_cbc_encrypt,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes192_enc_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 9008,
			      .fn = perftest_aes192_enc_var_sz }),
};

REGISTER_TEST (clib_aes256_cbc_encrypt) = {
  .name = "clib_aes256_cbc_encrypt",
  .fn = test_clib_aes256_cbc_encrypt,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes256_enc_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 9008,
			      .fn = perftest_aes256_enc_var_sz }),
};

#define _(b)                                                                  \
  static clib_error_t *test_clib_aes##b##_cbc_decrypt (clib_error_t *err)     \
  {                                                                           \
    aes_cbc_key_data_t k;                                                     \
    u8 data[512];                                                             \
    clib_aes##b##_cbc_key_expand (&k, key##b);                                \
    clib_aes##b##_cbc_decrypt (&k, ciphertext##b, sizeof (ciphertext##b), iv, \
			       data);                                         \
    if (memcmp (plaintext, data, sizeof (plaintext)) != 0)                    \
      err =                                                                   \
	clib_error_return (err, "decrypted data doesn't match plaintext");    \
    return err;                                                               \
  }                                                                           \
  void __test_perf_fn perftest_aes##b##_dec_var_sz (test_perf_t *tp)          \
  {                                                                           \
    u32 n = tp->n_ops;                                                        \
    aes_cbc_key_data_t *kd = test_mem_alloc (sizeof (*kd));                   \
    u8 *dst = test_mem_alloc (n + 16);                                        \
    u8 *src = test_mem_alloc_and_fill_inc_u8 (n + 16, 0, 0);                  \
    clib_aes##b##_cbc_key_expand (kd, key##b);                                \
                                                                              \
    test_perf_event_enable (tp);                                              \
    clib_aes##b##_cbc_decrypt (kd, src, n, iv, dst);                          \
    test_perf_event_disable (tp);                                             \
  }

_ (128)
_ (192)
_ (256)
#undef _

REGISTER_TEST (clib_aes128_cbc_decrypt) = {
  .name = "clib_aes128_cbc_decrypt",
  .fn = test_clib_aes128_cbc_decrypt,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes128_dec_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 9008,
			      .fn = perftest_aes128_dec_var_sz }),
};

REGISTER_TEST (clib_aes192_cbc_decrypt) = {
  .name = "clib_aes192_cbc_decrypt",
  .fn = test_clib_aes192_cbc_decrypt,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes192_dec_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 9008,
			      .fn = perftest_aes192_dec_var_sz }),
};

REGISTER_TEST (clib_aes256_cbc_decrypt) = {
  .name = "clib_aes256_cbc_decrypt",
  .fn = test_clib_aes256_cbc_decrypt,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes256_dec_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 9008,
			      .fn = perftest_aes256_dec_var_sz }),
};

#endif
