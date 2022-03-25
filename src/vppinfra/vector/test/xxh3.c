/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/vector/test/test.h>
#include <byteswap.h>

#define XXH3_SECRET_SIZE_MIN 136

static u64 xxh3_64_secret[] = {
  0xbe4ba423396cfeb8, 0x1cad21f72c81017c, 0xdb979083e96dd4de,
  0x1f67b3b7a4a44072, 0x78e5c0cc4ee679cb, 0x2172ffcc7dd05a82,
  0x8e2443f7744608b8, 0x4c263a81e69035e0, 0xcb00c391bb52283c,
  0xa32e531b8b65d088, 0x4ef90da297486471, 0xd8acdea946ef1938,
  0x3f349ce33f76faa8, 0x1d4f0bc7c7bbdcf9, 0x3159b4cd4be0518a,
  0x647378d9c97e9fc8, 0xc3ebd33483acc5ea, 0xeb6313faffa081c5,
  0x49daf0b751dd0d17, 0x9e68d429265516d3, 0xfca1477d58be162b,
  0xce31d07ad1b8f88f, 0x280416958f3acb45, 0x7e404bbbcafbd7af
};

#define XXH_PRIME64_1 0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3 0x165667B19E3779F9ULL
#define XXH_PRIME64_4 0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5 0x27D4EB2F165667C5ULL
#define XXH_PRIME32_1 0x9E3779B1U /*!< 0b10011110001101110111100110110001 */
#define XXH_PRIME32_2 0x85EBCA77U /*!< 0b10000101111010111100101001110111 */
#define XXH_PRIME32_3 0xC2B2AE3DU /*!< 0b11000010101100101010111000111101 */
#define XXH_PRIME32_4 0x27D4EB2FU /*!< 0b00100111110101001110101100101111 */
#define XXH_PRIME32_5 0x165667B1U /*!< 0b00010110010101100110011110110001 */

static u64
u64_loadu (void *ptr)
{
  u64 v = *(u64u *) ptr;
  return 1 ? v : bswap_64 (v);
}

static u32
u32_loadu (void *ptr)
{
  u32 v = *(u32u *) ptr;
  return 1 ? v : bswap_32 (v);
}

static u64
XXH_xorshift64 (u64 v64, int shift)
{
  return v64 ^ (v64 >> shift);
}

static void
XXH3_scalarScrambleRound (void *acc, void *secret, size_t lane)
{
  u64 *xacc = (u64 *) acc;
  u8 *xsecret = (u8 *) secret;
  u64 key64 = u64_loadu (xsecret + lane * 8);
  u64 acc64 = xacc[lane];
  acc64 = XXH_xorshift64 (acc64, 47);
  acc64 ^= key64;
  acc64 *= XXH_PRIME32_1;
  xacc[lane] = acc64;
}
static void
XXH3_scrambleAcc_scalar (void *acc, void *secret)
{
  size_t i;
  for (i = 0; i < (64 / sizeof (u64)); i++)
    XXH3_scalarScrambleRound (acc, secret, i);
}

static void
XXH3_scalarRound (void *acc, void *input, void *secret, size_t lane)
{
  u64 *xacc = (u64 *) acc;
  u8 *xinput = (u8 *) input;
  u8 *xsecret = (u8 *) secret;
  u64 data_val = u64_loadu (xinput + lane * 8);
  u64 data_key = data_val ^ u64_loadu (xsecret + lane * 8);
  xacc[lane ^ 1] += data_val;
  xacc[lane] +=
    ((u64) (u32) (data_key & 0xFFFFFFFF) * (u64) (u32) (data_key >> 32));
}

static void
XXH3_accumulate_512_scalar (void *acc, void *input, void *secret)
{
  for (int i = 0; i < 8; i++)
    XXH3_scalarRound (acc, input, secret, i);
}

static void
XXH3_accumulate (u64 *acc, u8 *input, u8 *secret, size_t nbStripes)
{
  for (size_t n = 0; n < nbStripes; n++)
    {
      u8 *in = input + n * 64;
      XXH3_accumulate_512_scalar (acc, in, secret + n * 8);
    }
}

static void
XXH3_hashLong_internal_loop (u64 *acc, u8 *input, size_t len, u8 *secret,
			     size_t secretSize)
{
  size_t nbStripesPerBlock = (secretSize - 64) / 8;
  size_t block_len = 64 * nbStripesPerBlock;
  size_t nb_blocks = (len - 1) / block_len;

  for (size_t n = 0; n < nb_blocks; n++)
    {
      XXH3_accumulate (acc, input + n * block_len, secret, nbStripesPerBlock);
      XXH3_scrambleAcc_scalar (acc, secret + secretSize - 64);
    }

  size_t nbStripes = ((len - 1) - (block_len * nb_blocks)) / 64;
  XXH3_accumulate (acc, input + nb_blocks * block_len, secret, nbStripes);
  u8 *p = input + len - 64;
  XXH3_accumulate_512_scalar (acc, p, secret + secretSize - 64 - 7);
}

static u64
XXH3_mul128_fold64 (u64 lhs, u64 rhs)
{
  __uint128_t product = (__uint128_t) lhs * (__uint128_t) rhs;
  return product ^ (product >> 64);
}

static u64
XXH3_mix2Accs (u64 *acc, u8 *secret)
{
  return XXH3_mul128_fold64 (acc[0] ^ u64_loadu (secret),
			     acc[1] ^ u64_loadu (secret + 8));
}

static u64
XXH3_avalanche (u64 h64)
{
  h64 = XXH_xorshift64 (h64, 37);
  h64 *= 0x165667919E3779F9ULL;
  h64 = XXH_xorshift64 (h64, 32);
  return h64;
}
static u64
XXH3_mergeAccs (u64 *acc, u8 *secret, u64 start)
{
  u64 result64 = start;
  size_t i = 0;
  for (i = 0; i < 4; i++)
    result64 += XXH3_mix2Accs (acc + 2 * i, secret + 16 * i);
  return XXH3_avalanche (result64);
}

static u64
XXH3_mix16B2 (u64u *i, u64u *secret, u64 seed)
{
  u64 input_lo = i[0];
  u64 input_hi = i[1];
  return XXH3_mul128_fold64 (input_lo ^ (secret[0] + seed),
			     input_hi ^ (secret[1] - seed));
}

static u64
XXH3_64bits_internal (u8 *input, size_t len, u64 seed)
{
  u64 *secret = xxh3_64_secret;
  u64 hash;

  if (len <= 16)
    {
      if (len > 8)
	{
	  u64 bitflip1 = (secret[3] ^ secret[4]) + seed;
	  u64 bitflip2 = (secret[5] ^ secret[6]) - seed;

	  u64 input_lo = u64_loadu (input) ^ bitflip1;
	  u64 input_hi = u64_loadu (input + len - 8) ^ bitflip2;

	  u64 acc = len + bswap_64 (input_lo) + input_hi +
		    XXH3_mul128_fold64 (input_lo, input_hi);
	  return XXH3_avalanche (acc);
	}
      if (len >= 4)
	{
	  u64 bitflip = (secret[1] ^ secret[2]) - seed;
	  seed ^= (u64) bswap_32 ((u32) seed) << 32;
	  u32 input1 = u32_loadu (input);
	  u32 input2 = u32_loadu (input + len - 4);
	  u64 input64 = input2 + (((u64) input1) << 32);
	  hash = input64 ^ bitflip;

	  /* rrmxmx mix */
	  u64 mix_constant = 0x9FB21C651E98DF25;
	  hash ^= rotate_left (hash, 49) ^ rotate_left (hash, 24);
	  hash *= mix_constant;
	  hash ^= (hash >> 35) + len;
	  hash *= mix_constant;
	  return XXH_xorshift64 (hash, 28);
	}
      if (len)
	{
	  u32 c1, c2, c3, bitflip;
	  bitflip = (secret[0] ^ (secret[0] >> 32)) + seed;

	  c1 = input[0] << 16;
	  c2 = input[len >> 1] << 24;
	  c3 = input[len - 1];

	  hash = (c1 | c2 | c3 | (len << 8)) ^ bitflip;
	}
      else
	hash = seed ^ (secret[7] ^ secret[8]);

      /* XXH64 avalanche */
      hash ^= hash >> 33;
      hash *= XXH_PRIME64_2;
      hash ^= hash >> 29;
      hash *= XXH_PRIME64_3;
      hash ^= hash >> 32;
      return hash;
    }
  if (len <= 128)
    {
      u64 acc = len * XXH_PRIME64_1;
      u64 *s64 = secret;
      u64u *left = (u64u *) input;
      u64u *right = (u64u *) (input + len);
      if (len > 32)
	{
	  if (len > 64)
	    {
	      if (len > 96)
		{
		  acc += XXH3_mix16B2 (left + 6, s64 + 12, seed);
		  acc += XXH3_mix16B2 (right - 8, s64 + 14, seed);
		}
	      acc += XXH3_mix16B2 (left + 4, s64 + 8, seed);
	      acc += XXH3_mix16B2 (right - 6, s64 + 10, seed);
	    }
	  acc += XXH3_mix16B2 (left + 2, s64 + 4, seed);
	  acc += XXH3_mix16B2 (right - 4, s64 + 6, seed);
	}
      acc += XXH3_mix16B2 (left, s64 + 0, seed);
      acc += XXH3_mix16B2 (right - 2, s64 + 2, seed);
      return XXH3_avalanche (acc);
    }

  if (len <= 240)
    {
      u64 acc = len * XXH_PRIME64_1;
      int nbRounds = (int) len / 16;
      u64u *left = (u64u *) input;
      u64u *right = (u64u *) (input + len);
      u64 *s64 = secret;
      for (int i = 0; i < 16; i+=2)
	acc += XXH3_mix16B2 (left + i, s64 + i, seed);

      acc = XXH3_avalanche (acc);
      for (int i = 8; i < nbRounds; i++)
	acc += XXH3_mix16B2 (left + (2 * i), (u64u *)
			    ((u8 *) secret + (16 * (i - 8)) + 3), seed);

      acc += XXH3_mix16B2 (right- 2, (u64u *) ((u8 *) secret + 136 - 17), seed);
      return XXH3_avalanche (acc);
    }

  u64 acc[] = { XXH_PRIME32_3, XXH_PRIME64_1, XXH_PRIME64_2, XXH_PRIME64_3,
		XXH_PRIME64_4, XXH_PRIME32_2, XXH_PRIME64_5, XXH_PRIME32_1 };
  XXH3_hashLong_internal_loop (acc, (u8 *) input, len, (u8 *) secret,
			       sizeof (xxh3_64_secret));
  return XXH3_mergeAccs (acc, (u8 *) secret + 11, (u64) len * XXH_PRIME64_1);
}

static u64
xxh3 (void *input, uword length, u64 const seed)
{
  return XXH3_64bits_internal (input, length, seed);
}

static const char str1[44] = "The quick brown fox jumps over the lazy dog.";

static struct
{
  void *data;
  u64 len;
  u64 seed;
  u64 hash;
  int replicate;
} xxh3_tests[] = {
  { .data = 0, .len = 0, .hash = 0x2d06800538d394c2 },
  { .data = (void *) str1, .len = 1, .hash = 0x20948828081ddcb4 },
  { .data = (void *) str1, .len = 2, .hash = 0x9f7d14ddaec31723 },
  { .data = (void *) str1, .len = 3, .hash = 0x178e97a55c30304f },
  { .data = (void *) str1, .len = 4, .hash = 0x3094195fbd46ee2a },
  { .data = (void *) str1, .len = 5, .hash = 0x4fb0dc0b9f6e5c96 },
  { .data = (void *) str1, .len = 6, .hash = 0xc1e0fef54f256f2a },
  { .data = (void *) str1, .len = 7, .hash = 0x8706dee3383094a1 },
  { .data = (void *) str1, .len = 8, .hash = 0x4fdd94d918ebefb3 },
  { .data = (void *) str1, .len = 9, .hash = 0xfef27d9106f45256 },
  { .data = (void *) str1, .len = 10, .hash = 0xf4bd9b9eeb1219f7 },
  { .data = (void *) str1, .len = 11, .hash = 0x13d1fe37b490c61f },
  { .data = (void *) str1, .len = 12, .hash = 0x3981236174cea0c9 },
  { .data = (void *) str1, .len = 13, .hash = 0xebfec07ff674510f },
  { .data = (void *) str1, .len = 14, .hash = 0x6e36452dbcebbe5d },
  { .data = (void *) str1, .len = 15, .hash = 0x3a289a3801e80314 },
  { .data = (void *) str1, .len = 16, .hash = 0x4246951ded1f9054 },
  { .data = (void *) str1, .len = 17, .hash = 0xa429a74ff039e59b },
  { .data = (void *) str1, .len = 18, .hash = 0x612ca8010786294c },
  { .data = (void *) str1, .len = 19, .hash = 0xf8b92649fd8122b4 },
  { .data = (void *) str1, .len = 20, .hash = 0xbca2f897b4602f95 },
  { .data = (void *) str1, .len = 21, .hash = 0x4989751ccb9787aa },
  { .data = (void *) str1, .len = 22, .hash = 0x863ea19c82d21e0f },
  { .data = (void *) str1, .len = 23, .hash = 0xe7e470588755ed4a },
  { .data = (void *) str1, .len = 24, .hash = 0xc617afad6216f691 },
  { .data = (void *) str1, .len = 25, .hash = 0xa1751582273f0091 },
  { .data = (void *) str1, .len = 26, .hash = 0xa516240cb2f9ad0d },
  { .data = (void *) str1, .len = 27, .hash = 0x6effab781357c8fd },
  { .data = (void *) str1, .len = 28, .hash = 0x1c152c0138d746fc },
  { .data = (void *) str1, .len = 29, .hash = 0x9458cc98859cda39 },
  { .data = (void *) str1, .len = 30, .hash = 0x8581bc781295a97a },
  { .data = (void *) str1, .len = 31, .hash = 0x4a912de556acb067 },
  { .data = (void *) str1, .len = 32, .hash = 0x7faa8dfb9e729c7b },
  { .data = (void *) str1, .len = 33, .hash = 0x96bcb2b6ca494c3e },
  { .data = (void *) str1, .len = 34, .hash = 0xe3bdc983e9dc7666 },
  { .data = (void *) str1, .len = 35, .hash = 0x22a5effc87a94e2a },
  { .data = (void *) str1, .len = 36, .hash = 0xab50bd7ecd4392d7 },
  { .data = (void *) str1, .len = 37, .hash = 0xcf2b2daeeb2c44c1 },
  { .data = (void *) str1, .len = 38, .hash = 0x8075492d70ef20c7 },
  { .data = (void *) str1, .len = 39, .hash = 0x3c739e24919bc7aa },
  { .data = (void *) str1, .len = 40, .hash = 0x0e5f7580b8546f51 },
  { .data = (void *) str1, .len = 41, .hash = 0xa2bbdd36c7cee0fd },
  { .data = (void *) str1, .len = 42, .hash = 0xd75d8ceb870b5a73 },
  { .data = (void *) str1, .len = 43, .hash = 0xce7d19a5418fb365 },
  { .data = (void *) str1, .len = 44, .hash = 0xb614e0225d51db19 },
  { .data = (void *) str1,
    .len = sizeof (str1),
    .replicate = 2,
    .hash = 0x512061cb72c666fd },
  { .data = (void *) str1,
    .len = sizeof (str1),
    .replicate = 5,
    .hash = 0x76b324388b1f9864 },
  { .data = (void *) str1,
    .len = sizeof (str1),
    .replicate = 12,
    .hash = 0xb808618ceb3b2f54 }
};

static clib_error_t *
test_clib_xxh3 (clib_error_t *err)
{
  u8 *tmp = 0;

  for (int i = 0; i < ARRAY_LEN (xxh3_tests); i++)
    {
      u64 h, len;
      void *data;
      if (xxh3_tests[i].replicate > 1)
	{
	  vec_reset_length (tmp);
	  for (int j = 0; j < xxh3_tests[i].replicate; j++)
	    tmp = format (tmp, "%44s", xxh3_tests[i].data);
	  data = tmp;
	  len = vec_len (tmp);
	}
      else
	{
	  data = xxh3_tests[i].data;
	  len = xxh3_tests[i].len;
	}

      h = xxh3 (data, len, xxh3_tests[i].seed);

      if (h != xxh3_tests[i].hash)
	{
	  err = clib_error_return (err,
				   "xxh3 test %u failed (expected "
				   "0x%lx calculated 0x%lx)",
				   i, xxh3_tests[i].hash, h);
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
  h[0] = xxh3 (d, n, 0);
  test_perf_event_disable (fd);

  test_mem_free (d);
  test_mem_free (h);
}

REGISTER_TEST (clib_xxh3) = {
  .name = "clib_xxh3",
  .fn = test_clib_xxh3,
  .perf_tests = PERF_TESTS ({ .name = "variable_size",
			      .op_name = "Byte",
			      .n_ops = 16384,
			      .fn = perftest_variable_size }),
};
