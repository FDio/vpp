/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#if defined(__AES__) && defined(__PCLMUL__)
#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/crypto/aes_gcm.h>

static const u8 tc1_key128[16] = {
  0,
};

static const u8 tc1_iv[12] = {
  0,
};

static const u8 tc1_tag128[] = { 0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e,
				 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57,
				 0xa4, 0xe7, 0x45, 0x5a };
static const u8 tc1_key256[32] = {
  0,
};

static const u8 tc1_tag256[] = {
  0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
  0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
};

static const u8 tc2_ciphertext256[] = { 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60,
					0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3,
					0xba, 0xf3, 0x9d, 0x18 };

static const u8 tc2_tag256[] = { 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99,
				 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5,
				 0xd4, 0x8a, 0xb9, 0x19 };

static const u8 tc2_plaintext[16] = {
  0,
};

static const u8 tc2_tag128[] = { 0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec,
				 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2,
				 0x12, 0x57, 0xbd, 0xdf };

static const u8 tc2_ciphertext128[] = { 0x03, 0x88, 0xda, 0xce, 0x60, 0xb6,
					0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9,
					0x71, 0xb2, 0xfe, 0x78 };

static const u8 tc3_key128[] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65,
				 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
				 0x67, 0x30, 0x83, 0x08 };

static const u8 tc3_iv[] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
			     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };

static const u8 tc3_plaintext[] = {
  0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf,
  0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c,
  0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09,
  0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5,
  0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55
};

static const u8 tc3_ciphertext128[] = {
  0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84,
  0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1,
  0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93,
  0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39,
  0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85
};

static const u8 tc3_tag128[] = { 0x4d, 0x5c, 0x2a, 0xf3, 0x27, 0xcd,
				 0x64, 0xa6, 0x2c, 0xf3, 0x5a, 0xbd,
				 0x2b, 0xa6, 0xfa, 0xb4 };

static const u8 tc3_key256[] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73,
				 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
				 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86,
				 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
				 0x67, 0x30, 0x83, 0x08 };

static const u8 tc3_ciphertext256[] = {
  0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a,
  0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98,
  0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb,
  0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63,
  0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad
};

static const u8 tc3_tag256[] = { 0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34,
				 0x71, 0xbd, 0xec, 0x1a, 0x50, 0x22,
				 0x70, 0xe3, 0xcc, 0x6c };

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

static const struct
{
  char *name;
  const u8 *pt, *key128, *key256, *ct128, *ct256, *tag128, *tag256, *aad, *iv;
  u32 data_len, tag128_len, tag256_len, aad_len;
} test_cases[] = {
  /* test cases */
  {
    .name = "GCM Spec. TC1",
    .iv = tc1_iv,
    .key128 = tc1_key128,
    .key256 = tc1_key256,
    .tag128 = tc1_tag128,
    .tag128_len = sizeof (tc1_tag128),
    .tag256 = tc1_tag256,
    .tag256_len = sizeof (tc1_tag256),
  },
  {
    .name = "GCM Spec. TC2",
    .pt = tc2_plaintext,
    .data_len = sizeof (tc2_plaintext),
    .iv = tc1_iv,
    .key128 = tc1_key128,
    .key256 = tc1_key256,
    .ct128 = tc2_ciphertext128,
    .ct256 = tc2_ciphertext256,
    .tag128 = tc2_tag128,
    .tag128_len = sizeof (tc2_tag128),
    .tag256 = tc2_tag256,
    .tag256_len = sizeof (tc2_tag256),
  },
  {
    .name = "GCM Spec. TC3",
    .pt = tc3_plaintext,
    .data_len = sizeof (tc3_plaintext),
    .iv = tc3_iv,
    .key128 = tc3_key128,
    .key256 = tc3_key256,
    .ct128 = tc3_ciphertext128,
    .ct256 = tc3_ciphertext256,
    .tag128 = tc3_tag128,
    .tag128_len = sizeof (tc3_tag128),
    .tag256 = tc3_tag256,
    .tag256_len = sizeof (tc3_tag256),
  },
  {
    .name = "GCM Spec. TC4",
    .pt = tc4_plaintext,
    .data_len = sizeof (tc4_plaintext),
    .aad = tc4_aad,
    .aad_len = sizeof (tc4_aad),
    .iv = tc3_iv,
    .key128 = tc3_key128,
    .key256 = tc3_key256,
    .ct128 = tc4_ciphertext128,
    .ct256 = tc4_ciphertext256,
    .tag128 = tc4_tag128,
    .tag128_len = sizeof (tc4_tag128),
    .tag256 = tc4_tag256,
    .tag256_len = sizeof (tc4_tag256),
  }
};

#define perftest_aesXXX_enc_var_sz(a)                                         \
  void __test_perf_fn perftest_aes##a##_enc_var_sz (test_perf_t *tp)          \
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
    clib_aes##a##_gcm_enc (kd, src, n, 0, 0, iv, 16, dst, tag);               \
    test_perf_event_disable (tp);                                             \
                                                                              \
    test_mem_free (tag);                                                      \
    test_mem_free (dst);                                                      \
    test_mem_free (src);                                                      \
    test_mem_free (key);                                                      \
    test_mem_free (iv);                                                       \
    test_mem_free (kd);                                                       \
  }

#define perftest_aesXXX_dec_var_sz(a)                                         \
  void __test_perf_fn perftest_aes##a##_dec_var_sz (test_perf_t *tp)          \
  {                                                                           \
    u32 n = tp->n_ops;                                                        \
    aes_gcm_key_data_t *kd = test_mem_alloc (sizeof (*kd));                   \
    u8 *dst = test_mem_alloc (n + 16);                                        \
    u8 *src = test_mem_alloc_and_fill_inc_u8 (n + 16, 0, 0);                  \
    u8 *tag = test_mem_alloc (16);                                            \
    u8 *key = test_mem_alloc_and_fill_inc_u8 (32, 192, 0);                    \
    u8 *iv = test_mem_alloc_and_fill_inc_u8 (16, 128, 0);                     \
    int *rv = test_mem_alloc (16);                                            \
                                                                              \
    clib_aes_gcm_key_expand (kd, key, AES_KEY_##a);                           \
                                                                              \
    test_perf_event_enable (tp);                                              \
    rv[0] = clib_aes##a##_gcm_dec (kd, src, n, 0, 0, iv, tag, 16, dst);       \
    test_perf_event_disable (tp);                                             \
                                                                              \
    test_mem_free (tag);                                                      \
    test_mem_free (dst);                                                      \
    test_mem_free (src);                                                      \
    test_mem_free (key);                                                      \
    test_mem_free (iv);                                                       \
    test_mem_free (kd);                                                       \
    test_mem_free (rv);                                                       \
  }

static clib_error_t *
test_clib_aes128_gcm_enc (clib_error_t *err)
{
  aes_gcm_key_data_t kd;
  u8 data[512];
  u8 tag[16];

  FOREACH_ARRAY_ELT (tc, test_cases)
    {
      clib_aes_gcm_key_expand (&kd, tc->key128, AES_KEY_128);
      clib_aes128_gcm_enc (&kd, tc->pt, tc->data_len, tc->aad, tc->aad_len,
			   tc->iv, tc->tag128_len, data, tag);

      if (memcmp (tc->tag128, tag, tc->tag128_len) != 0)
	return clib_error_return (err, "%s: invalid tag", tc->name);

      if (tc->data_len && memcmp (tc->ct128, data, tc->data_len) != 0)
	return clib_error_return (err, "%s: invalid ciphertext", tc->name);
    }

  return err;
}

perftest_aesXXX_enc_var_sz (128);

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

  FOREACH_ARRAY_ELT (tc, test_cases)
    {
      clib_aes_gcm_key_expand (&kd, tc->key256, AES_KEY_256);
      clib_aes256_gcm_enc (&kd, tc->pt, tc->data_len, tc->aad, tc->aad_len,
			   tc->iv, tc->tag256_len, data, tag);

      if (memcmp (tc->tag256, tag, tc->tag256_len) != 0)
	return clib_error_return (err, "%s: invalid tag", tc->name);

      if (tc->data_len && memcmp (tc->ct256, data, tc->data_len) != 0)
	return clib_error_return (err, "%s: invalid ciphertext", tc->name);
    }

  return err;
}

perftest_aesXXX_enc_var_sz (256);
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

  FOREACH_ARRAY_ELT (tc, test_cases)
    {
      clib_aes_gcm_key_expand (&kd, tc->key128, AES_KEY_128);
      rv = clib_aes128_gcm_dec (&kd, tc->ct128, tc->data_len, tc->aad,
				tc->aad_len, tc->iv, tc->tag128,
				tc->tag128_len, data);

      if (!rv)
	return clib_error_return (err, "%s: invalid tag", tc->name);

      if (tc->data_len && memcmp (tc->pt, data, tc->data_len) != 0)
	return clib_error_return (err, "%s: invalid ciphertext", tc->name);
    }

  return err;
}

perftest_aesXXX_dec_var_sz (128);

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

  FOREACH_ARRAY_ELT (tc, test_cases)
    {
      clib_aes_gcm_key_expand (&kd, tc->key256, AES_KEY_256);
      rv = clib_aes256_gcm_dec (&kd, tc->ct256, tc->data_len, tc->aad,
				tc->aad_len, tc->iv, tc->tag256,
				tc->tag256_len, data);

      if (!rv)
	return clib_error_return (err, "%s: invalid tag", tc->name);

      if (tc->data_len && memcmp (tc->pt, data, tc->data_len) != 0)
	return clib_error_return (err, "%s: invalid ciphertext", tc->name);
    }

  return err;
}

perftest_aesXXX_dec_var_sz (256);
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
