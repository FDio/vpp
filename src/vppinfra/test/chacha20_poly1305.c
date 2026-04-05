/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/test/test.h>

#if defined(CLIB_HAVE_VEC512) || defined(CLIB_HAVE_VEC256) || defined(CLIB_HAVE_VEC128)

#include <vppinfra/crypto/chacha20_poly1305.h>

static const u8 tc1_key[] = {
  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
};

static const u8 tc1_iv[] = {
  0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
};

static const u8 tc1_aad[] = {
  0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

static const u8 tc1_tag[] = {
  0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
};

static const u8 tc1_plaintext[] = {
  0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74,
  0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
  0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20,
  0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
  0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70,
  0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65,
  0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75,
  0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69, 0x74, 0x2e,
};

static const u8 tc1_ciphertext[] = {
  0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
  0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
  0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
  0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
  0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
  0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
  0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
  0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
};

static const u8 tc2_key[] = {
  0x2d, 0xb0, 0x5d, 0x40, 0xc8, 0xed, 0x44, 0x88, 0x34, 0xd1, 0x13, 0xaf, 0x57, 0xa1, 0xeb, 0x3a,
  0x2a, 0x80, 0x51, 0x36, 0xec, 0x5b, 0xbc, 0x08, 0x93, 0x84, 0x21, 0xb5, 0x13, 0x88, 0x3c, 0x0d,
};

static const u8 tc2_iv[] = {
  0x00, 0x00, 0x00, 0x00, 0x3d, 0x86, 0xb5, 0x6b, 0xc8, 0xa3, 0x1f, 0x1d,
};

static const u8 tc2_aad[] = {
  0x33, 0x10, 0x41, 0x12, 0x1f, 0xf3, 0xd2, 0x6b,
};

static const u8 tc2_tag[] = {
  0xdd, 0x6b, 0x3b, 0x82, 0xce, 0x5a, 0xbd, 0xd6, 0xa9, 0x35, 0x83, 0xd8, 0x8c, 0x3d, 0x85, 0x77,
};

static const u8 tc3_key[] = {
  0x4c, 0xf5, 0x96, 0x83, 0x38, 0xe6, 0xae, 0x7f, 0x2d, 0x29, 0x25, 0x76, 0xd5, 0x75, 0x27, 0x86,
  0x91, 0x9a, 0x27, 0x7a, 0xfb, 0x46, 0xc5, 0xef, 0x94, 0x81, 0x79, 0x57, 0x14, 0x59, 0x40, 0x68,
};

static const u8 tc3_iv[] = {
  0x00, 0x00, 0x00, 0x00, 0xca, 0xbf, 0x33, 0x71, 0x32, 0x45, 0x77, 0x8e,
};

static const u8 tc3_tag[] = {
  0xea, 0xe0, 0x1e, 0x9e, 0x2c, 0x91, 0xaa, 0xe1, 0xdb, 0x5d, 0x99, 0x3f, 0x8a, 0xf7, 0x69, 0x92,
};

typedef struct
{
  const char *name;
  const u8 *key;
  const u8 *iv;
  const u8 *aad;
  const u8 *tag;
  const u8 *plaintext;
  const u8 *ciphertext;
  u32 aad_len;
  u32 data_len;
} chacha20_poly1305_test_t;

static const chacha20_poly1305_test_t test_cases[] = {
  {
    .name = "RFC8439 TC1",
    .key = tc1_key,
    .iv = tc1_iv,
    .aad = tc1_aad,
    .tag = tc1_tag,
    .plaintext = tc1_plaintext,
    .ciphertext = tc1_ciphertext,
    .aad_len = sizeof (tc1_aad),
    .data_len = sizeof (tc1_plaintext),
  },
  {
    .name = "RFC8439 TC1 [aad12]",
    .key = tc1_key,
    .iv = tc1_iv,
    .aad = tc1_aad,
    .tag = tc1_tag,
    .plaintext = tc1_plaintext,
    .ciphertext = tc1_ciphertext,
    .aad_len = sizeof (tc1_aad),
    .data_len = sizeof (tc1_plaintext),
  },
  {
    .name = "RFC8439 TC2",
    .key = tc2_key,
    .iv = tc2_iv,
    .aad = tc2_aad,
    .tag = tc2_tag,
    .plaintext = 0,
    .ciphertext = 0,
    .aad_len = sizeof (tc2_aad),
    .data_len = 0,
  },
  {
    .name = "RFC8439 TC2 [aad8]",
    .key = tc2_key,
    .iv = tc2_iv,
    .aad = tc2_aad,
    .tag = tc2_tag,
    .plaintext = 0,
    .ciphertext = 0,
    .aad_len = sizeof (tc2_aad),
    .data_len = 0,
  },
  {
    .name = "RFC8439 TC3",
    .key = tc3_key,
    .iv = tc3_iv,
    .aad = 0,
    .tag = tc3_tag,
    .plaintext = 0,
    .ciphertext = 0,
    .aad_len = 0,
    .data_len = 0,
  },
  {
    .name = "RFC8439 TC3 [aad0]",
    .key = tc3_key,
    .iv = tc3_iv,
    .aad = 0,
    .tag = tc3_tag,
    .plaintext = 0,
    .ciphertext = 0,
    .aad_len = 0,
    .data_len = 0,
  },
};

static clib_error_t *
test_clib_poly1305_aead (clib_error_t *err)
{
  u8 tag[16];
  u8 otk[64] = {};
  u64u lengths[2];

  FOREACH_ARRAY_ELT (tc, test_cases)
    {
      clib_poly1305_ctx_t poly_ctx = {};
      clib_poly1305_init_data_t poly_kd = {};

      clib_memset (tag, 0, sizeof (tag));
      clib_memset (otk, 0, sizeof (otk));

      clib_chacha20 (otk, otk, sizeof (otk), tc->key, tc->iv, 0);
      clib_poly1305_precompute (&poly_kd, otk);
      clib_poly1305_init (&poly_ctx, &poly_kd);

      clib_chacha20_poly1305_update_padded (&poly_ctx, tc->aad, tc->aad_len);
      clib_chacha20_poly1305_update_padded (&poly_ctx, tc->ciphertext, tc->data_len);

      lengths[0] = tc->aad_len;
      lengths[1] = tc->data_len;
      clib_poly1305_update (&poly_ctx, (u8 *) lengths, sizeof (lengths));
      clib_poly1305_final (&poly_ctx, tag);

      if (memcmp (tag, tc->tag, sizeof (tag)) != 0)
	return clib_error_return (err, "%s poly1305 tag mismatch\nexp: %U\ncalc: %U\n", tc->name,
				  format_hexdump, tc->tag, sizeof (tag), format_hexdump, tag,
				  sizeof (tag));
    }

  return err;
}

static clib_error_t *
test_clib_chacha20_poly1305 (clib_error_t *err)
{
  u8 ct[sizeof (tc1_ciphertext)] = {};
  u8 pt[sizeof (tc1_plaintext)] = {};
  u8 tag[16];
  u8 bad_tag[16];

  FOREACH_ARRAY_ELT (tc, test_cases)
    {
      clib_memset (ct, 0, sizeof (ct));
      clib_memset (pt, 0, sizeof (pt));
      clib_memset (tag, 0, sizeof (tag));

      if (!clib_chacha20_poly1305_enc (tc->plaintext, ct, tc->aad, tc->iv, tag, tc->data_len,
				       tc->aad_len, tc->key))
	return clib_error_return (err, "encrypt failed: %s", tc->name);

      if (memcmp (tag, tc->tag, sizeof (tag)) != 0)
	return clib_error_return (err, "%s tag mismatch\nexp: %U\ncalc: %U\n", tc->name,
				  format_hexdump, tc->tag, sizeof (tag), format_hexdump, tag,
				  sizeof (tag));

      if (tc->data_len && memcmp (ct, tc->ciphertext, tc->data_len) != 0)
	return clib_error_return (err, "%s ciphertext mismatch\nexp: %U\ncalc: %U\n", tc->name,
				  format_hexdump, tc->ciphertext, tc->data_len, format_hexdump, ct,
				  tc->data_len);

      if (!clib_chacha20_poly1305_dec (tc->ciphertext, pt, tc->aad, tc->iv, tag, tc->data_len,
				       tc->aad_len, tc->key))
	return clib_error_return (err, "decrypt failed: %s", tc->name);

      if (tc->data_len && memcmp (pt, tc->plaintext, tc->data_len) != 0)
	return clib_error_return (err, "%s plaintext mismatch\nexp: %U\ncalc: %U\n", tc->name,
				  format_hexdump, tc->plaintext, tc->data_len, format_hexdump, pt,
				  tc->data_len);

      clib_memcpy_fast (bad_tag, tc->tag, sizeof (bad_tag));
      bad_tag[0] ^= 1;
      if (clib_chacha20_poly1305_dec (tc->ciphertext, pt, tc->aad, tc->iv, bad_tag, tc->data_len,
				      tc->aad_len, tc->key))
	return clib_error_return (err, "bad tag accepted: %s", tc->name);
    }

  return err;
}

static clib_error_t *
test_clib_chacha20 (clib_error_t *err)
{
  u8 ct[sizeof (tc1_ciphertext)] = {};

  FOREACH_ARRAY_ELT (tc, test_cases)
    {
      if (tc->data_len == 0)
	continue;

      clib_memset (ct, 0, sizeof (ct));
      clib_chacha20 (ct, (u8 *) tc->plaintext, tc->data_len, (u8 *) tc->key, (u8 *) tc->iv, 1);

      if (memcmp (ct, tc->ciphertext, tc->data_len) != 0)
	return clib_error_return (err, "%s chacha20 ciphertext mismatch\nexp: %U\ncalc: %U\n",
				  tc->name, format_hexdump, tc->ciphertext, tc->data_len,
				  format_hexdump, ct, tc->data_len);
    }

  return err;
}

void __test_perf_fn
perftest_clib_chacha20_var_sz (test_perf_t *tp)
{
  uword n = tp->n_ops;
  u8 *src = test_mem_alloc_and_fill_inc_u8 (n + 16, 0, 0);
  u8 *dst = test_mem_alloc (n + 16);
  u8 *iv = test_mem_alloc_and_fill_inc_u8 (12, 128, 0);

  test_perf_event_enable (tp);
  clib_chacha20 (dst, src, n, (u8 *) tc1_key, iv, 1);
  test_perf_event_disable (tp);
}

void __test_perf_fn
perftest_clib_chacha20_poly1305_var_sz (test_perf_t *tp)
{
  uword n = tp->n_ops;
  u8 *src = test_mem_alloc_and_fill_inc_u8 (n + 16, 0, 0);
  u8 *dst = test_mem_alloc (n + 16);
  u8 *iv = test_mem_alloc_and_fill_inc_u8 (12, 128, 0);
  u8 *tag = test_mem_alloc (16);

  test_perf_event_enable (tp);
  clib_chacha20_poly1305_enc (src, dst, tc1_aad, iv, tag, n, sizeof (tc1_aad), (u8 *) tc1_key);
  test_perf_event_disable (tp);
}

REGISTER_TEST (clib_chacha20) = {
  .name = "clib_chacha20",
  .fn = test_clib_chacha20,
  .perf_tests = PERF_TESTS (
    { .name = "variable size (per byte)", .n_ops = 1424, .fn = perftest_clib_chacha20_var_sz },
    { .name = "variable size (per byte)", .n_ops = 1048576, .fn = perftest_clib_chacha20_var_sz }),
};

REGISTER_TEST (clib_poly1305_aead) = {
  .name = "clib_poly1305_aead",
  .fn = test_clib_poly1305_aead,
};

REGISTER_TEST (clib_chacha20_poly1305) = {
  .name = "clib_chacha20_poly1305",
  .fn = test_clib_chacha20_poly1305,
  .perf_tests = PERF_TESTS ({ .name = "variable size (per byte)",
			      .n_ops = 1424,
			      .fn = perftest_clib_chacha20_poly1305_var_sz },
			    { .name = "variable size (per byte)",
			      .n_ops = 1048576,
			      .fn = perftest_clib_chacha20_poly1305_var_sz }),
};

#endif
