/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/* MD5C.C - RSA Data Security, Inc., MD5 message-digest algorithm */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#include <vppinfra/string.h>	/* for memset */
#include <vppinfra/byte_order.h>
#include <vppinfra/md5.h>

/* F, G, H and I are basic MD5 functions. */
#define F(b, c, d) (d ^ (b & (c ^ d)))
#define G(b, c, d) F (d, b, c)
#define H(b, c, d) (b ^ c ^ d)
#define I(b, c, d) (c ^ (b | ~d))

/* ROTATE_LEFT rotates x left n bits. */
#define ROTATE_LEFT(x,n) \
  (((x) << (n)) | ((x) >> (32 - (n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
   Rotation is separate from addition to prevent recomputation. */
#define FF(a,b,c,d,x,s,ac)			\
do {						\
  a += F (b, c, d) + x + ac;			\
  a = ROTATE_LEFT (a, s);			\
  a += b;					\
} while (0)

#define GG(a,b,c,d,x,s,ac)			\
do {						\
  a += G (b, c, d) + x + ac;			\
  a = ROTATE_LEFT (a, s);			\
  a += b;					\
} while (0)

#define HH(a,b,c,d,x,s,ac)			\
do {						\
  a += H (b, c, d) + x + ac;			\
  a = ROTATE_LEFT (a, s);			\
  a += b;					\
} while (0)

#define II(a,b,c,d,x,s,ac)			\
do {						\
  a += I (b, c, d) + x + ac;			\
  a = ROTATE_LEFT (a, s);			\
  a += b;					\
} while (0)

#undef _

/* MD5 basic transformation. Transforms state based on block. */
static void
md5_transform (md5_context_t * m, u32 * data, u32 * result, int zero_buffer)
{
  u32 a = m->state[0], b = m->state[1], c = m->state[2], d = m->state[3];
  u32 *x = data;

/* Constants for MD5Transform routine. */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

  /* Round 1 */
  FF (a, b, c, d, clib_host_to_little_u32 (x[0]), S11, 0xd76aa478);	/* 1 */
  FF (d, a, b, c, clib_host_to_little_u32 (x[1]), S12, 0xe8c7b756);	/* 2 */
  FF (c, d, a, b, clib_host_to_little_u32 (x[2]), S13, 0x242070db);	/* 3 */
  FF (b, c, d, a, clib_host_to_little_u32 (x[3]), S14, 0xc1bdceee);	/* 4 */
  FF (a, b, c, d, clib_host_to_little_u32 (x[4]), S11, 0xf57c0faf);	/* 5 */
  FF (d, a, b, c, clib_host_to_little_u32 (x[5]), S12, 0x4787c62a);	/* 6 */
  FF (c, d, a, b, clib_host_to_little_u32 (x[6]), S13, 0xa8304613);	/* 7 */
  FF (b, c, d, a, clib_host_to_little_u32 (x[7]), S14, 0xfd469501);	/* 8 */
  FF (a, b, c, d, clib_host_to_little_u32 (x[8]), S11, 0x698098d8);	/* 9 */
  FF (d, a, b, c, clib_host_to_little_u32 (x[9]), S12, 0x8b44f7af);	/* 10 */
  FF (c, d, a, b, clib_host_to_little_u32 (x[10]), S13, 0xffff5bb1);	/* 11 */
  FF (b, c, d, a, clib_host_to_little_u32 (x[11]), S14, 0x895cd7be);	/* 12 */
  FF (a, b, c, d, clib_host_to_little_u32 (x[12]), S11, 0x6b901122);	/* 13 */
  FF (d, a, b, c, clib_host_to_little_u32 (x[13]), S12, 0xfd987193);	/* 14 */
  FF (c, d, a, b, clib_host_to_little_u32 (x[14]), S13, 0xa679438e);	/* 15 */
  FF (b, c, d, a, clib_host_to_little_u32 (x[15]), S14, 0x49b40821);	/* 16 */

  /* Round 2 */
  GG (a, b, c, d, x[1], S21, 0xf61e2562);	/* 17 */
  GG (d, a, b, c, x[6], S22, 0xc040b340);	/* 18 */
  GG (c, d, a, b, x[11], S23, 0x265e5a51);	/* 19 */
  GG (b, c, d, a, x[0], S24, 0xe9b6c7aa);	/* 20 */
  GG (a, b, c, d, x[5], S21, 0xd62f105d);	/* 21 */
  GG (d, a, b, c, x[10], S22, 0x02441453);	/* 22 */
  GG (c, d, a, b, x[15], S23, 0xd8a1e681);	/* 23 */
  GG (b, c, d, a, x[4], S24, 0xe7d3fbc8);	/* 24 */
  GG (a, b, c, d, x[9], S21, 0x21e1cde6);	/* 25 */
  GG (d, a, b, c, x[14], S22, 0xc33707d6);	/* 26 */
  GG (c, d, a, b, x[3], S23, 0xf4d50d87);	/* 27 */
  GG (b, c, d, a, x[8], S24, 0x455a14ed);	/* 28 */
  GG (a, b, c, d, x[13], S21, 0xa9e3e905);	/* 29 */
  GG (d, a, b, c, x[2], S22, 0xfcefa3f8);	/* 30 */
  GG (c, d, a, b, x[7], S23, 0x676f02d9);	/* 31 */
  GG (b, c, d, a, x[12], S24, 0x8d2a4c8a);	/* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[5], S31, 0xfffa3942);	/* 33 */
  HH (d, a, b, c, x[8], S32, 0x8771f681);	/* 34 */
  HH (c, d, a, b, x[11], S33, 0x6d9d6122);	/* 35 */
  HH (b, c, d, a, x[14], S34, 0xfde5380c);	/* 36 */
  HH (a, b, c, d, x[1], S31, 0xa4beea44);	/* 37 */
  HH (d, a, b, c, x[4], S32, 0x4bdecfa9);	/* 38 */
  HH (c, d, a, b, x[7], S33, 0xf6bb4b60);	/* 39 */
  HH (b, c, d, a, x[10], S34, 0xbebfbc70);	/* 40 */
  HH (a, b, c, d, x[13], S31, 0x289b7ec6);	/* 41 */
  HH (d, a, b, c, x[0], S32, 0xeaa127fa);	/* 42 */
  HH (c, d, a, b, x[3], S33, 0xd4ef3085);	/* 43 */
  HH (b, c, d, a, x[6], S34, 0x04881d05);	/* 44 */
  HH (a, b, c, d, x[9], S31, 0xd9d4d039);	/* 45 */
  HH (d, a, b, c, x[12], S32, 0xe6db99e5);	/* 46 */
  HH (c, d, a, b, x[15], S33, 0x1fa27cf8);	/* 47 */
  HH (b, c, d, a, x[2], S34, 0xc4ac5665);	/* 48 */

  /* Round 4 */
  II (a, b, c, d, x[0], S41, 0xf4292244);	/* 49 */
  II (d, a, b, c, x[7], S42, 0x432aff97);	/* 50 */
  II (c, d, a, b, x[14], S43, 0xab9423a7);	/* 51 */
  II (b, c, d, a, x[5], S44, 0xfc93a039);	/* 52 */
  II (a, b, c, d, x[12], S41, 0x655b59c3);	/* 53 */
  II (d, a, b, c, x[3], S42, 0x8f0ccc92);	/* 54 */
  II (c, d, a, b, x[10], S43, 0xffeff47d);	/* 55 */
  II (b, c, d, a, x[1], S44, 0x85845dd1);	/* 56 */
  II (a, b, c, d, x[8], S41, 0x6fa87e4f);	/* 57 */
  II (d, a, b, c, x[15], S42, 0xfe2ce6e0);	/* 58 */
  II (c, d, a, b, x[6], S43, 0xa3014314);	/* 59 */
  II (b, c, d, a, x[13], S44, 0x4e0811a1);	/* 60 */
  II (a, b, c, d, x[4], S41, 0xf7537e82);	/* 61 */
  II (d, a, b, c, x[11], S42, 0xbd3af235);	/* 62 */
  II (c, d, a, b, x[2], S43, 0x2ad7d2bb);	/* 63 */
  II (b, c, d, a, x[9], S44, 0xeb86d391);	/* 64 */

  a += m->state[0];
  b += m->state[1];
  c += m->state[2];
  d += m->state[3];

  if (result)
    {
      result[0] = clib_host_to_little_u32 (a);
      result[1] = clib_host_to_little_u32 (b);
      result[2] = clib_host_to_little_u32 (c);
      result[3] = clib_host_to_little_u32 (d);
    }
  else
    {
      m->state[0] = a;
      m->state[1] = b;
      m->state[2] = c;
      m->state[3] = d;
    }

  /* Zero sensitive information. */
  if (result)
    memset (m, ~0, sizeof (m[0]));
  else if (zero_buffer)
    memset (m->input_buffer.b8, 0, sizeof (m->input_buffer));
}

/* MD5 initialization. Begins an MD5 operation, writing a new context. */
void
md5_init (md5_context_t * c)
{
  memset (c, 0, sizeof (c[0]));

  /* Load magic initialization constants. */
  c->state[0] = 0x67452301;
  c->state[1] = 0xefcdab89;
  c->state[2] = 0x98badcfe;
  c->state[3] = 0x10325476;
}

always_inline void __attribute__ ((unused))
md5_fill_buffer_aligned (md5_context_t * c, u32 * d32)
{
  int i;
  for (i = 0; i < ARRAY_LEN (c->input_buffer.b32); i++)
    c->input_buffer.b32[i] = d32[i];
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
void
md5_add (md5_context_t * c, void *data, int data_bytes)
{
  u32 data_bytes_left;
  void *d;

  if (data_bytes == 0)
    return;

  d = data;
  data_bytes_left = data_bytes;

  if ((pointer_to_uword (d) % sizeof (u32)) == 0
      && (c->n_bits % BITS (c->input_buffer)) == 0
      && data_bytes >= sizeof (c->input_buffer))
    {
      int is_last_iteration;
      /* Fast aligned version. */
      do
	{
	  data_bytes_left -= sizeof (c->input_buffer);
	  is_last_iteration = data_bytes_left < sizeof (c->input_buffer);
	  md5_transform (c, d, /* result */ 0,	/* zero_buffer */
			 is_last_iteration);
	  d += sizeof (c->input_buffer);
	}
      while (!is_last_iteration);
    }

  /* Slow unaligned version. */
  {
    int bi;
    u8 *d8 = d;

    bi = (c->n_bits / BITS (u8)) % ARRAY_LEN (c->input_buffer.b8);

    while (data_bytes_left > 0)
      {
	c->input_buffer.b8[bi] = d8[0];
	data_bytes_left -= 1;
	d8++;
	bi++;
	if (bi == ARRAY_LEN (c->input_buffer.b8))
	  {
	    bi = 0;
	    md5_transform (c, c->input_buffer.b32,
			   /* result */ 0,
			   /* zero_buffer */ 1);
	  }
      }
  }

  c->n_bits += data_bytes * BITS (u8);
}

void
md5_finish (md5_context_t * c, u8 * digest)
{
  u64 n_bits_save;
  int bi, n_pad;
  static u8 padding[sizeof (c->input_buffer)] = { 0x80, 0, };

  n_bits_save = c->n_bits;
  bi = (n_bits_save / BITS (u8)) % ARRAY_LEN (c->input_buffer.b8);

  n_pad = sizeof (c->input_buffer) - (bi + sizeof (u64));
  if (n_pad <= 0)
    n_pad += sizeof (c->input_buffer);
  md5_add (c, padding, n_pad);

  c->input_buffer.b64[ARRAY_LEN (c->input_buffer.b64) - 1]
    = clib_host_to_little_u64 (n_bits_save);

  md5_transform (c, c->input_buffer.b32, (u32 *) digest,
		 /* zero_buffer */ 1);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
