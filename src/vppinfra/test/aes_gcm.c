/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#if defined(__AES__) && defined(__PCLMUL__)
#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/crypto/aes_gcm.h>

static const u8 tc3_key128[] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65,
				 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
				 0x67, 0x30, 0x83, 0x08 };

static const u8 tc3_key256[] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73,
				 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
				 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86,
				 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
				 0x67, 0x30, 0x83, 0x08 };

static const u8 tc3_iv[] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
			     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };

static const u8 tc4_plaintext[] = {
  0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
  0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
  0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95,
  0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
  0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
};

static const u8 tc4_aad[] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
			      0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
			      0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2 };

static const u8 tc4_ciphertext128[] = {
  0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7,
  0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
  0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2,
  0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
  0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91
};

static const u8 tc4_tag128[] = { 0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21,
				 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a,
				 0xe7, 0x12, 0x1a, 0x47 };

static const u8 tc4_ciphertext256[] = {
  0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3,
  0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
  0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48,
  0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
  0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62
};

static const u8 tc4_tag256[] = { 0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e,
				 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53,
				 0xbb, 0x2d, 0x55, 0x1b };

#define perftest_aesXXX_YYY_var_sz(a, b)                                      \
  void __test_perf_fn perftest_aes##a##_##b##_var_sz (test_perf_t *tp)        \
  {                                                                           \
    u32 n = tp->n_ops;                                                        \
    aes_gcm_key_data_t *kd = test_mem_alloc (sizeof (*kd));                   \
    u8 *dst = test_mem_alloc (n + 16);                                        \
    u8 *src = test_mem_alloc_and_fill_inc_u8 (n + 16, 0, 0);                  \
    u8 *tag = test_mem_alloc (16);                                            \
    u8 *key = test_mem_alloc_and_fill_inc_u8 (32, 192, 0);                    \
    u8 *iv = test_mem_alloc_and_fill_inc_u8 (16, 128, 0);                     \
                                                                              \
    clib_aes_gcm_key_expand (kd, key, AES_KEY_##a);                           \
                                                                              \
    test_perf_event_enable (tp);                                              \
    clib_aes##a##_gcm_##b (kd, src, dst, n, 0, 0, iv, tag, 16);               \
    test_perf_event_disable (tp);                                             \
                                                                              \
    test_mem_free (tag);                                                      \
    test_mem_free (dst);                                                      \
    test_mem_free (src);                                                      \
    test_mem_free (key);                                                      \
    test_mem_free (iv);                                                       \
    test_mem_free (kd);                                                       \
  }

static clib_error_t *
test_clib_aes128_gcm_enc (clib_error_t *err)
{
  aes_gcm_key_data_t kd;
  u8 data[512];
  u8 tag[16];
  clib_aes_gcm_key_expand (&kd, tc3_key128, AES_KEY_128);
  clib_aes128_gcm_enc (&kd, tc4_plaintext, data, sizeof (tc4_plaintext),
		       tc4_aad, sizeof (tc4_aad), tc3_iv, tag, sizeof (tag));

  if (memcmp (tc4_tag128, tag, sizeof (tc4_tag128)) != 0)
    return clib_error_return (err, "invalid tag");

  if (memcmp (tc4_ciphertext128, data, sizeof (tc4_ciphertext128)) != 0)
    return clib_error_return (err, "invalid ciphertext");

  return err;
}
perftest_aesXXX_YYY_var_sz (128, enc);

REGISTER_TEST (clib_aes128_gcm_enc) = {
  .name = "clib_aes128_gcm_enc",
  .fn = test_clib_aes128_gcm_enc,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes128_enc_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 1 << 20,
			      .fn = perftest_aes128_enc_var_sz }),
};

static clib_error_t *
test_clib_aes256_gcm_enc (clib_error_t *err)
{
  aes_gcm_key_data_t kd;
  u8 data[512];
  u8 tag[16];
  clib_aes_gcm_key_expand (&kd, tc3_key256, AES_KEY_256);
  clib_aes256_gcm_enc (&kd, tc4_plaintext, data, sizeof (tc4_plaintext),
		       tc4_aad, sizeof (tc4_aad), tc3_iv, tag, sizeof (tag));

  if (memcmp (tc4_tag256, tag, sizeof (tc4_tag256)) != 0)
    return clib_error_return (err, "invalid tag");

  if (memcmp (tc4_ciphertext256, data, sizeof (tc4_ciphertext256)) != 0)
    return clib_error_return (err, "invalid ciphertext");

  return err;
}

perftest_aesXXX_YYY_var_sz (256, enc);
REGISTER_TEST (clib_aes256_gcm_enc) = {
  .name = "clib_aes256_gcm_enc",
  .fn = test_clib_aes256_gcm_enc,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes256_enc_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 1 << 20,
			      .fn = perftest_aes256_enc_var_sz }),
};

static clib_error_t *
test_clib_aes128_gcm_dec (clib_error_t *err)
{
  aes_gcm_key_data_t kd;
  u8 data[512];
  int rv;
  clib_aes_gcm_key_expand (&kd, tc3_key128, AES_KEY_128);
  rv = clib_aes128_gcm_dec (
    &kd, tc4_ciphertext128, data, sizeof (tc4_ciphertext128), tc4_aad,
    sizeof (tc4_aad), tc3_iv, tc4_tag128, sizeof (tc4_tag128));

  if (!rv)
    return clib_error_return (err, "invalid tag");

  if (memcmp (tc4_plaintext, data, sizeof (tc4_plaintext)) != 0)
    return clib_error_return (err, "invalid ciphertext");

  return err;
}

perftest_aesXXX_YYY_var_sz (128, dec);

REGISTER_TEST (clib_aes128_gcm_dec) = {
  .name = "clib_aes128_gcm_dec",
  .fn = test_clib_aes128_gcm_dec,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes128_dec_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 1 << 20,
			      .fn = perftest_aes128_dec_var_sz }),
};

static clib_error_t *
test_clib_aes256_gcm_dec (clib_error_t *err)
{
  aes_gcm_key_data_t kd;
  u8 data[512];
  int rv;
  clib_aes_gcm_key_expand (&kd, tc3_key256, AES_KEY_256);
  rv = clib_aes256_gcm_dec (
    &kd, tc4_ciphertext256, data, sizeof (tc4_ciphertext256), tc4_aad,
    sizeof (tc4_aad), tc3_iv, tc4_tag256, sizeof (tc4_tag256));

  if (!rv)
    return clib_error_return (err, "invalid tag");

  if (memcmp (tc4_plaintext, data, sizeof (tc4_plaintext)) != 0)
    return clib_error_return (err, "invalid ciphertext");

  return err;
}

perftest_aesXXX_YYY_var_sz (256, dec);
REGISTER_TEST (clib_aes256_gcm_dec) = {
  .name = "clib_aes256_gcm_dec",
  .fn = test_clib_aes256_gcm_dec,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_aes256_dec_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 1 << 20,
			      .fn = perftest_aes256_dec_var_sz }),
};
#endif
