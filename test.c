#if 0
cc \
  -g \
  -Wall -Werror \
  -march=native \
  -O3 \
  -Isrc \
  -Llib/x86_64-linux-gnu \
  -Wl,-rpath ./lib/x86_64-linux-gnu \
  "$0" \
  -lvppinfra \
  && exec ./a.out "$@"
exit
#endif

#define _GNU_SOURCE
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/pool.h>
#include <stdint.h>

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

typedef struct
{
  u64 low64;
  u64 high64;
} XXH128_hash_t;

_Alignas(64) static u8 XXH3_kSecret[192] = {
  0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7,
  0x21, 0xad, 0x1c, 0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40,
  0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f, 0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5,
  0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21, 0xb8, 0x08, 0x46, 0x74,
  0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c, 0x3c,
  0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53,
  0x2e, 0xa3, 0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef,
  0x46, 0xa9, 0xde, 0xac, 0xd8, 0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f,
  0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d, 0x8a, 0x51, 0xe0, 0x4b, 0xcd,
  0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64, 0xea, 0xc5,
  0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63,
  0xeb, 0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26,
  0x29, 0xd4, 0x68, 0x9e, 0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f,
  0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce, 0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16,
  0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
};

static u64
u64_loadu (void *ptr)
{
  u64 v = *(u64u *) ptr;
  return 1 ? v : __builtin_bswap64 (v);
}

static u32
u32_loadu (void *ptr)
{
  u32 v = *(u32u *) ptr;
  return 1 ? v : __builtin_bswap32 (v);
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
  {
    u64 data_val = u64_loadu (xinput + lane * 8);
    u64 data_key = data_val ^ u64_loadu (xsecret + lane * 8);
    xacc[lane ^ 1] += data_val;
    xacc[lane] +=
      ((u64) (u32) (data_key & 0xFFFFFFFF) * (u64) (u32) (data_key >> 32));
  }
}

static void
XXH3_accumulate_512_scalar (void *acc, void *input, void *secret)
{
  size_t i;
  for (i = 0; i < (64 / sizeof (u64)); i++)
    XXH3_scalarRound (acc, input, secret, i);
}

static void
XXH3_accumulate (u64 *acc, u8 *input, u8 *secret, size_t nbStripes)
{
  size_t n;
  for (n = 0; n < nbStripes; n++)
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
XXH3_hashLong_64b_internal (void *input, size_t len, void *secret,
			    size_t secretSize)
{
  _Alignas(8) u64 acc[(64 / sizeof (u64))] = { XXH_PRIME32_3, XXH_PRIME64_1,
					       XXH_PRIME64_2, XXH_PRIME64_3,
					       XXH_PRIME64_4, XXH_PRIME32_2,
					       XXH_PRIME64_5, XXH_PRIME32_1 };
  XXH3_hashLong_internal_loop (acc, (u8 *) input, len, (u8 *) secret,
			       secretSize);
  return XXH3_mergeAccs (acc, (u8 *) secret + 11, (u64) len * XXH_PRIME64_1);
}

static u64
XXH3_hashLong_64b_default (void *input, size_t len, u64 seed64, u8 *secret,
			   size_t secretLen)
{
  return XXH3_hashLong_64b_internal (input, len, XXH3_kSecret,
				     sizeof (XXH3_kSecret));
}

static u64
XXH3_len_9to16_64b (u8 *input, size_t len, u8 *secret, u64 seed)
{
  u64 bitflip1 = (u64_loadu (secret + 24) ^ u64_loadu (secret + 32)) + seed;
  u64 bitflip2 = (u64_loadu (secret + 40) ^ u64_loadu (secret + 48)) - seed;
  u64 input_lo = u64_loadu (input) ^ bitflip1;
  u64 input_hi = u64_loadu (input + len - 8) ^ bitflip2;
  u64 acc = len + __builtin_bswap64 (input_lo) + input_hi +
	    XXH3_mul128_fold64 (input_lo, input_hi);
  return XXH3_avalanche (acc);
}
static u64
XXH3_rrmxmx (u64 h64, u64 len)
{
  h64 ^= (((h64) << (49)) | ((h64) >> (64 - (49)))) ^
	 (((h64) << (24)) | ((h64) >> (64 - (24))));
  h64 *= 0x9FB21C651E98DF25ULL;
  h64 ^= (h64 >> 35) + len;
  h64 *= 0x9FB21C651E98DF25ULL;
  return XXH_xorshift64 (h64, 28);
}
static u64
XXH3_len_4to8_64b (u8 *input, size_t len, u8 *secret, u64 seed)
{
  seed ^= (u64) __builtin_bswap32 ((u32) seed) << 32;
  u32 input1 = u32_loadu (input);
  u32 input2 = u32_loadu (input + len - 4);
  u64 bitflip = (u64_loadu (secret + 8) ^ u64_loadu (secret + 16)) - seed;
  u64 input64 = input2 + (((u64) input1) << 32);
  u64 keyed = input64 ^ bitflip;
  return XXH3_rrmxmx (keyed, len);
}

static u64
XXH64_avalanche (u64 hash)
{
  hash ^= hash >> 33;
  hash *= XXH_PRIME64_2;
  hash ^= hash >> 29;
  hash *= XXH_PRIME64_3;
  hash ^= hash >> 32;
  return hash;
}

static u64
XXH3_len_1to3_64b (u8 *input, size_t len, u8 *secret, u64 seed)
{
  u8 c1 = input[0];
  u8 c2 = input[len >> 1];
  u8 c3 = input[len - 1];
  u32 combined =
    ((u32) c1 << 16) | ((u32) c2 << 24) | ((u32) c3 << 0) | ((u32) len << 8);
  u64 bitflip = (u32_loadu (secret) ^ u32_loadu (secret + 4)) + seed;
  u64 keyed = (u64) combined ^ bitflip;
  return XXH64_avalanche (keyed);
}
static u64
XXH3_len_0to16_64b (u8 *input, size_t len, u8 *secret, u64 seed)
{
  if (len > 8)
    return XXH3_len_9to16_64b (input, len, secret, seed);
  if (len >= 4)
    return XXH3_len_4to8_64b (input, len, secret, seed);
  if (len)
    return XXH3_len_1to3_64b (input, len, secret, seed);
  return XXH64_avalanche (seed ^
			  (u64_loadu (secret + 56) ^ u64_loadu (secret + 64)));
}
static u64
XXH3_mix16B (u8 *input, u8 *secret, u64 seed64)
{
  u64 input_lo = u64_loadu (input);
  u64 input_hi = u64_loadu (input + 8);
  return XXH3_mul128_fold64 (input_lo ^ (u64_loadu (secret) + seed64),
			     input_hi ^ (u64_loadu (secret + 8) - seed64));
}
static u64
XXH3_len_17to128_64b (u8 *input, size_t len, u8 *secret, size_t secretSize,
		      u64 seed)
{
  u64 acc = len * XXH_PRIME64_1;
  if (len > 32)
    {
      if (len > 64)
	{
	  if (len > 96)
	    {
	      acc += XXH3_mix16B (input + 48, secret + 96, seed);
	      acc += XXH3_mix16B (input + len - 64, secret + 112, seed);
	    }
	  acc += XXH3_mix16B (input + 32, secret + 64, seed);
	  acc += XXH3_mix16B (input + len - 48, secret + 80, seed);
	}
      acc += XXH3_mix16B (input + 16, secret + 32, seed);
      acc += XXH3_mix16B (input + len - 32, secret + 48, seed);
    }
  acc += XXH3_mix16B (input + 0, secret + 0, seed);
  acc += XXH3_mix16B (input + len - 16, secret + 16, seed);
  return XXH3_avalanche (acc);
}
static u64
XXH3_len_129to240_64b (u8 *input, size_t len, u8 *secret, size_t secretSize,
		       u64 seed)
{
  u64 acc = len * XXH_PRIME64_1;
  int nbRounds = (int) len / 16;
  int i;
  for (i = 0; i < 8; i++)
    acc += XXH3_mix16B (input + (16 * i), secret + (16 * i), seed);

  acc = XXH3_avalanche (acc);
  for (i = 8; i < nbRounds; i++)
    acc += XXH3_mix16B (input + (16 * i), secret + (16 * (i - 8)) + 3, seed);

  acc += XXH3_mix16B (input + len - 16, secret + 136 - 17, seed);
  return XXH3_avalanche (acc);
}

static u64
XXH3_64bits_internal (void *input, size_t len, u64 seed64, void *secret,
		      size_t secretLen)
{
  ((void) 0);
  if (len <= 16)
    return XXH3_len_0to16_64b ((u8 *) input, len, (u8 *) secret, seed64);
  if (len <= 128)
    return XXH3_len_17to128_64b ((u8 *) input, len, (u8 *) secret, secretLen,
				 seed64);
  if (len <= 240)
    return XXH3_len_129to240_64b ((u8 *) input, len, (u8 *) secret, secretLen,
				  seed64);
  return XXH3_hashLong_64b_default (input, len, seed64, (u8 *) secret,
				    secretLen);
}

static u64
XXH3_64bits (void *input, size_t length)
{
  return XXH3_64bits_internal (input, length, 0, XXH3_kSecret,
			       sizeof (XXH3_kSecret));
}

int
main ()
{
  clib_mem_init (0, 32 << 20);
  char t1[7] = "test123";
  char t2[41] = "A quick brown fox jumps over the lazy dog";
  u64 h1 = 0x736b19652f9d0a53;
  u64 h2 = 0x3b884470dd895df6;
  u64 h;

  h = XXH3_64bits (t1, sizeof (t1));
  fformat (stderr, "hash %lx %s\n", h, h == h1 ? "OK" : "FAIL");
  h = XXH3_64bits (t2, sizeof (t2));
  fformat (stderr, "hash %lx %s\n", h, h == h2 ? "OK" : "FAIL");
}
