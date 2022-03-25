/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/vector/test/test.h>

static u64 const PRIME64_1 = 0x9E3779B185EBCA87ULL;
static u64 const PRIME64_2 = 0xC2B2AE3D27D4EB4FULL;
static u64 const PRIME64_3 = 0x165667B19E3779F9ULL;
static u64 const PRIME64_4 = 0x85EBCA77C2B2AE63ULL;
static u64 const PRIME64_5 = 0x27D4EB2F165667C5ULL;

/* Mixes input into acc, this is mostly used in the first loop. */
static_always_inline u64
xxh64_round (u64 acc, u64 const input)
{
  acc += input * PRIME64_2;
  acc = rotate_left (acc, 31);
  return acc * PRIME64_1;
}

#ifdef CLIB_HAVE_VEC256
static_always_inline u64x4
xxh64_round_x4 (u64x4 acc, u64x4 input)
{
  acc += input * u64x4_splat (PRIME64_2);
  acc = (acc << 31) | acc >> (64 - 31);
  return acc * u64x4_splat (PRIME64_1);
}
#endif

/* Merges acc into hash to finalize */
static_always_inline u64
xxh64_merge (u64 hash, u64 const acc)
{
  return (hash ^ acc) * PRIME64_1 + PRIME64_4;
}

#ifdef CLIB_HAVE_VEC256
static_always_inline u64x4
u64x4_rotate_left (u64x4 v, u64x4 n_bits)
{
  return (v << n_bits | v >> (u64x4_splat (64) - n_bits));
}
#endif

static_always_inline u64
xxh64 (void const *const input, size_t const length, u64 const seed)
{
  u8 *data = (u8 *) input;
  u64 hash = seed + PRIME64_5;
  uword n_left = length;

  if (input == NULL)
    goto done;

  if (n_left >= 32)
    {
#ifdef CLIB_HAVE_VEC256
      u64x4 a4 = { PRIME64_1 + PRIME64_2, PRIME64_2, 0, -PRIME64_1 };
      u64x4u *d = (u64x4u *) input;

      a4 += u64x4_splat (seed);
      while (n_left >= 256)
	{
	  a4 = xxh64_round_x4 (a4, d[0]);
	  a4 = xxh64_round_x4 (a4, d[1]);
	  a4 = xxh64_round_x4 (a4, d[2]);
	  a4 = xxh64_round_x4 (a4, d[3]);
	  a4 = xxh64_round_x4 (a4, d[4]);
	  a4 = xxh64_round_x4 (a4, d[5]);
	  a4 = xxh64_round_x4 (a4, d[6]);
	  a4 = xxh64_round_x4 (a4, d[7]);
	  d += 8;
	  n_left -= 256;
	}

      while (n_left >= 32)
	{
	  a4 = xxh64_round_x4 (a4, d[0]);
	  d += 1;
	  n_left -= 32;
	}

      u64x4 r4 = u64x4_rotate_left (a4, (u64x4){ 1, 7, 12, 18 });
      u64x2 r2 = u64x4_extract_lo (r4) + u64x4_extract_hi (r4);
      r2 += (u64x2) u8x16_align_right (r2, r2, 8);
      hash = r2[0];

      a4 = xxh64_round_x4 ((u64x4){}, a4);
      hash = xxh64_merge (hash, a4[0]);
      hash = xxh64_merge (hash, a4[1]);
      hash = xxh64_merge (hash, a4[2]);
      hash = xxh64_merge (hash, a4[3]);
      data = (u8 *) d;
#else
      /* Initialize our accumulators */
      u64 acc1 = seed + PRIME64_1 + PRIME64_2;
      u64 acc2 = seed + PRIME64_2;
      u64 acc3 = seed + 0;
      u64 acc4 = seed - PRIME64_1;
      u64u *d = (u64u *) input;

      while (n_left >= 32)
	{
	  acc1 = xxh64_round (acc1, d[0]);
	  acc2 = xxh64_round (acc2, d[1]);
	  acc3 = xxh64_round (acc3, d[2]);
	  acc4 = xxh64_round (acc4, d[3]);
	  d += 4;
	  n_left -= 32;
	}

      hash = rotate_left (acc1, 1) + rotate_left (acc2, 7) +
	     rotate_left (acc3, 12) + rotate_left (acc4, 18);

      acc1 = xxh64_round (0, acc1);
      acc2 = xxh64_round (0, acc2);
      acc3 = xxh64_round (0, acc3);
      acc4 = xxh64_round (0, acc4);

      hash = xxh64_merge (hash, acc1);
      hash = xxh64_merge (hash, acc2);
      hash = xxh64_merge (hash, acc3);
      hash = xxh64_merge (hash, acc4);
      data = (u8 *) d;
#endif
    }

  hash += (u64) length;

  /* Process the n_left data. */
  while (n_left >= 8)
    {
      hash ^= xxh64_round (0, *(u64u *) data);
      hash = rotate_left (hash, 27);
      hash *= PRIME64_1;
      hash += PRIME64_4;
      data += 8;
      n_left -= 8;
    }

  if (n_left >= 4)
    {
      hash ^= (u64) (*(u32u *) data) * PRIME64_1;
      hash = rotate_left (hash, 23);
      hash *= PRIME64_2;
      hash += PRIME64_3;
      data += 4;
      n_left -= 4;
    }

  while (n_left != 0)
    {
      hash ^= (u64) data[0] * PRIME64_5;
      hash = rotate_left (hash, 11);
      hash *= PRIME64_1;
      data++;
      n_left--;
    }

done:
  /* avalanche - mixes all bits to finalize the hash */
  hash ^= hash >> 33;
  hash *= PRIME64_2;
  hash ^= hash >> 29;
  hash *= PRIME64_3;
  hash ^= hash >> 32;
  return hash;
}

static const char str1[44] = "The quick brown fox jumps over the lazy dog.";

static struct
{
  void *data;
  u64 len;
  u64 seed;
  u64 hash;
  int replicate;
} xxh64_tests[] = {
  { .data = 0, .len = 0, .hash = 0xef46db3751d8e999 },
  { .data = (void *) str1, .len = 1, .hash = 0x5b4d6af247a3cf7b },
  { .data = (void *) str1, .len = 2, .hash = 0x4d9dd5b2d0613c90 },
  { .data = (void *) str1, .len = 3, .hash = 0x4108f90b5de14d15 },
  { .data = (void *) str1, .len = 4, .hash = 0xcdf13a49d263200f },
  { .data = (void *) str1, .len = 5, .hash = 0xf0d7a3adcfa8c683 },
  { .data = (void *) str1, .len = 6, .hash = 0x645e5d666ac3e66d },
  { .data = (void *) str1, .len = 7, .hash = 0xc6fce9d72e310949 },
  { .data = (void *) str1, .len = 8, .hash = 0xd07b38a78a153b0b },
  { .data = (void *) str1, .len = 9, .hash = 0x9d1214db001dfc69 },
  { .data = (void *) str1, .len = 10, .hash = 0xdb3919475ab1cf22 },
  { .data = (void *) str1, .len = 11, .hash = 0x61cbdf23c67af875 },
  { .data = (void *) str1, .len = 12, .hash = 0xb2ed38017844f789 },
  { .data = (void *) str1, .len = 13, .hash = 0xed6dc8c5841a51e4 },
  { .data = (void *) str1, .len = 14, .hash = 0x5e5ddb1fae229e50 },
  { .data = (void *) str1, .len = 15, .hash = 0x59bf1a33358c7d98 },
  { .data = (void *) str1, .len = 16, .hash = 0x0f7e67014943a311 },
  { .data = (void *) str1, .len = 17, .hash = 0x6bf87c8b1fd9ed1a },
  { .data = (void *) str1, .len = 18, .hash = 0xa2d31bb8d44b0557 },
  { .data = (void *) str1, .len = 19, .hash = 0xc9b4e7b3c328d9e0 },
  { .data = (void *) str1, .len = 20, .hash = 0x457cd2650fe6aa94 },
  { .data = (void *) str1, .len = 21, .hash = 0x3c5831248b534326 },
  { .data = (void *) str1, .len = 22, .hash = 0x645c543cb504efad },
  { .data = (void *) str1, .len = 23, .hash = 0xb91f8b1617c11212 },
  { .data = (void *) str1, .len = 24, .hash = 0xe5bcc54f9811d5de },
  { .data = (void *) str1, .len = 25, .hash = 0x1eb61388311e1536 },
  { .data = (void *) str1, .len = 26, .hash = 0x54ad75ab2f5cbf06 },
  { .data = (void *) str1, .len = 27, .hash = 0x425f794b47c2bd48 },
  { .data = (void *) str1, .len = 28, .hash = 0x1dcd16dd15317465 },
  { .data = (void *) str1, .len = 29, .hash = 0x2fca2d55fcc6c2cf },
  { .data = (void *) str1, .len = 30, .hash = 0xcbd47a9c2bf5830b },
  { .data = (void *) str1, .len = 31, .hash = 0x3f8d95ab32c127d9 },
  { .data = (void *) str1, .len = 32, .hash = 0xe2bbc9136629a4ee },
  { .data = (void *) str1, .len = 33, .hash = 0x6d92fe2ebab7db31 },
  { .data = (void *) str1, .len = 34, .hash = 0x20c50c763d3e7180 },
  { .data = (void *) str1, .len = 35, .hash = 0x2d27cba0d24872de },
  { .data = (void *) str1, .len = 36, .hash = 0x9457ee2b0cace793 },
  { .data = (void *) str1, .len = 37, .hash = 0x675af3b6c6f51195 },
  { .data = (void *) str1, .len = 38, .hash = 0xb3e5ae9ec090534c },
  { .data = (void *) str1, .len = 39, .hash = 0xe01509ec7bdd4b5e },
  { .data = (void *) str1, .len = 40, .hash = 0x581a9e84f2ab44ef },
  { .data = (void *) str1, .len = 41, .hash = 0x9d60cef4bf4427b0 },
  { .data = (void *) str1, .len = 42, .hash = 0xab06bcadc103bf7d },
  { .data = (void *) str1, .len = 43, .hash = 0x0b242d361fda71bc },
  { .data = (void *) str1, .len = sizeof (str1), .hash = 0x44ad33705751ad73 },
  { .data = (void *) str1,
    .len = sizeof (str1),
    .replicate = 2,
    .hash = 0x0a416e44b37cdcc3 },
  { .data = (void *) str1,
    .len = sizeof (str1),
    .replicate = 5,
    .hash = 0xfc142335b3bb966d },
  { .data = (void *) str1,
    .len = sizeof (str1),
    .replicate = 12,
    .hash = 0xfd66e2e79c7788a2 },
  { .data = (void *) str1,
    .len = sizeof (str1),
    .seed = 0xfedcba9876543210,
    .hash = 0x272c0391adeb3cbd }
};

static clib_error_t *
test_clib_xxh64 (clib_error_t *err)
{
  u8 *tmp = 0;
  for (int i = 0; i < ARRAY_LEN (xxh64_tests); i++)
    {
      u64 h, len;
      void *data;
      if (xxh64_tests[i].replicate > 1)
	{
	  vec_reset_length (tmp);
	  for (int j = 0; j < xxh64_tests[i].replicate; j++)
	    tmp = format (tmp, "%44s", xxh64_tests[i].data);
	  data = tmp;
	  len = vec_len (tmp);
	}
      else
	{
	  data = xxh64_tests[i].data;
	  len = xxh64_tests[i].len;
	}

      h = xxh64 (data, len, xxh64_tests[i].seed);

      if (h != xxh64_tests[i].hash)
	{
	  err = clib_error_return (err,
				   "xxh64 test %u failed (expected "
				   "0x%lx calculated 0x%lx)",
				   i, xxh64_tests[i].hash, h);
	  goto done;
	}
    }
done:
  vec_free (tmp);
  return err;
}

void __test_perf_fn
perftest_variable_size (int fd, test_perf_t *tp)
{
  u32 n = tp->n_ops;
  u8 *d = test_mem_alloc_and_fill_inc_u8 (n, 0, 0);
  u64 *h = test_mem_alloc (8);

  test_perf_event_enable (fd);
  h[0] = xxh64 (d, n, 0);
  test_perf_event_disable (fd);

  test_mem_free (d);
  test_mem_free (h);
}

REGISTER_TEST (clib_xxh64) = {
  .name = "clib_xxh64",
  .fn = test_clib_xxh64,
  .perf_tests = PERF_TESTS ({ .name = "variable_size",
			      .op_name = "Byte",
			      .n_ops = 16384,
			      .fn = perftest_variable_size }),
};
