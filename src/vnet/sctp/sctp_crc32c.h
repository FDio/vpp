/* crc32c.c -- compute CRC-32C using the Intel crc32 instruction
 * Copyright (C) 2013 Mark Adler
 * Version 1.1  1 Aug 2013  Mark Adler
 */

/*
  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Mark Adler
  madler@alumni.caltech.edu
 */

/* Use hardware CRC instruction on Intel SSE 4.2 processors.  This computes a
   CRC-32C, *not* the CRC-32 used by Ethernet and zip, gzip, etc.  A software
   version is provided as a fall-back, as well as for speed comparisons. */

/* Version history:
   1.0  10 Feb 2013  First version
   1.1   1 Aug 2013  Correct comments on why three crc instructions in parallel
 */
#ifndef included_vnet_sctp_crc32_h
#define included_vnet_sctp_crc32_h

const static u64 POLY = 0x11EDC6F41;

/* Table for a quadword-at-a-time software crc. */
static pthread_once_t crc32c_once_sw = PTHREAD_ONCE_INIT;
static u32 crc32c_table[8][256];

/* Construct table for software CRC-32C calculation. */
static void
crc32c_init_sw (void)
{
  u32 n, crc, k;

  for (n = 0; n < 256; n++)
    {
      crc = n;
      crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
      crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
      crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
      crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
      crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
      crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
      crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
      crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
      crc32c_table[0][n] = crc;
    }
  for (n = 0; n < 256; n++)
    {
      crc = crc32c_table[0][n];
      for (k = 1; k < 8; k++)
	{
	  crc = crc32c_table[0][crc & 0xff] ^ (crc >> 8);
	  crc32c_table[k][n] = crc;
	}
    }
}

/* Table-driven software version as a fall-back.  This is about 15 times slower
   than using the hardware instructions.  This assumes little-endian integers,
   as is the case on Intel processors that the assembler code here is for. */
static u32
crc32c_sw (u32 crci, const void *buf, size_t len)
{
  const unsigned char *next = buf;
  u64 crc;

  pthread_once (&crc32c_once_sw, crc32c_init_sw);
  crc = crci ^ 0xffffffff;
  while (len && ((uintptr_t) next & 7) != 0)
    {
      crc = crc32c_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
      len--;
    }
  while (len >= 8)
    {
      crc ^= *(u64 *) next;
      crc = crc32c_table[7][crc & 0xff] ^
	crc32c_table[6][(crc >> 8) & 0xff] ^
	crc32c_table[5][(crc >> 16) & 0xff] ^
	crc32c_table[4][(crc >> 24) & 0xff] ^
	crc32c_table[3][(crc >> 32) & 0xff] ^
	crc32c_table[2][(crc >> 40) & 0xff] ^
	crc32c_table[1][(crc >> 48) & 0xff] ^ crc32c_table[0][crc >> 56];
      next += 8;
      len -= 8;
    }
  while (len)
    {
      crc = crc32c_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
      len--;
    }
  return (u32) crc ^ 0xffffffff;
}

/* Multiply a matrix times a vector over the Galois field of two elements,
   GF(2).  Each element is a bit in an unsigned integer.  mat must have at
   least as many entries as the power of two for most significant one bit in
   vec. */
static inline u32
gf2_matrix_times (u32 * mat, u32 vec)
{
  u32 sum;

  sum = 0;
  while (vec)
    {
      if (vec & 1)
	sum ^= *mat;
      vec >>= 1;
      mat++;
    }
  return sum;
}

/* Multiply a matrix by itself over GF(2).  Both mat and square must have 32
   rows. */
static inline void
gf2_matrix_square (u32 * square, u32 * mat)
{
  int n;

  for (n = 0; n < 32; n++)
    square[n] = gf2_matrix_times (mat, mat[n]);
}

/* Construct an operator to apply len zeros to a crc.  len must be a power of
   two.  If len is not a power of two, then the result is the same as for the
   largest power of two less than len.  The result for len == 0 is the same as
   for len == 1.  A version of this routine could be easily written for any
   len, but that is not needed for this application. */
static void
crc32c_zeros_op (u32 * even, size_t len)
{
  int n;
  u32 row;
  u32 odd[32];			/* odd-power-of-two zeros operator */

  /* put operator for one zero bit in odd */
  odd[0] = POLY;		/* CRC-32C polynomial */
  row = 1;
  for (n = 1; n < 32; n++)
    {
      odd[n] = row;
      row <<= 1;
    }

  /* put operator for two zero bits in even */
  gf2_matrix_square (even, odd);

  /* put operator for four zero bits in odd */
  gf2_matrix_square (odd, even);

  /* first square will put the operator for one zero byte (eight zero bits),
     in even -- next square puts operator for two zero bytes in odd, and so
     on, until len has been rotated down to zero */
  do
    {
      gf2_matrix_square (even, odd);
      len >>= 1;
      if (len == 0)
	return;
      gf2_matrix_square (odd, even);
      len >>= 1;
    }
  while (len);

  /* answer ended up in odd -- copy to even */
  for (n = 0; n < 32; n++)
    even[n] = odd[n];
}

/* Take a length and build four lookup tables for applying the zeros operator
   for that length, byte-by-byte on the operand. */
static void
crc32c_zeros (u32 zeros[][256], size_t len)
{
  u32 n;
  u32 op[32];

  crc32c_zeros_op (op, len);
  for (n = 0; n < 256; n++)
    {
      zeros[0][n] = gf2_matrix_times (op, n);
      zeros[1][n] = gf2_matrix_times (op, n << 8);
      zeros[2][n] = gf2_matrix_times (op, n << 16);
      zeros[3][n] = gf2_matrix_times (op, n << 24);
    }
}

/* Apply the zeros operator table to crc. */
static inline u32
crc32c_shift (u32 zeros[][256], u32 crc)
{
  return zeros[0][crc & 0xff] ^ zeros[1][(crc >> 8) & 0xff] ^
    zeros[2][(crc >> 16) & 0xff] ^ zeros[3][crc >> 24];
}

/* Block sizes for three-way parallel crc computation.  LONG and SHORT must
   both be powers of two.  The associated string constants must be set
   accordingly, for use in constructing the assembler instructions. */
#define LONG 8192
#define LONGx1 "8192"
#define LONGx2 "16384"
#define SHORT 256
#define SHORTx1 "256"
#define SHORTx2 "512"

/* Tables for hardware crc that shift a crc by LONG and SHORT zeros. */
static pthread_once_t crc32c_once_hw = PTHREAD_ONCE_INIT;
static u32 crc32c_long[4][256];
static u32 crc32c_short[4][256];

/* Initialize tables for shifting crcs. */
static void
crc32c_init_hw (void)
{
  crc32c_zeros (crc32c_long, LONG);
  crc32c_zeros (crc32c_short, SHORT);
}

/* Compute CRC-32C using the Intel hardware instruction. */
static u32
crc32c_hw (u32 crc, const void *buf, size_t len)
{
  const unsigned char *next = buf;
  const unsigned char *end;
  u64 crc0, crc1, crc2;		/* need to be 64 bits for crc32q */

  /* populate shift tables the first time through */
  pthread_once (&crc32c_once_hw, crc32c_init_hw);

  /* pre-process the crc */
  crc0 = crc ^ 0xffffffff;

  /* compute the crc for up to seven leading bytes to bring the data pointer
     to an eight-byte boundary */
  while (len && ((uintptr_t) next & 7) != 0)
    {
    __asm__ ("crc32b\t" "(%1), %0": "=r" (crc0):"r" (next),
	       "0" (crc0));
      next++;
      len--;
    }

  /* compute the crc on sets of LONG*3 bytes, executing three independent crc
     instructions, each on LONG bytes -- this is optimized for the Nehalem,
     Westmere, Sandy Bridge, and Ivy Bridge architectures, which have a
     throughput of one crc per cycle, but a latency of three cycles */
  while (len >= LONG * 3)
    {
      crc1 = 0;
      crc2 = 0;
      end = next + LONG;
      do
	{
	__asm__ ("crc32q\t" "(%3), %0\n\t" "crc32q\t" LONGx1 "(%3), %1\n\t" "crc32q\t" LONGx2 "(%3), %2": "=r" (crc0), "=r" (crc1), "=r" (crc2):"r" (next), "0" (crc0), "1" (crc1),
		   "2"
		   (crc2));
	  next += 8;
	}
      while (next < end);
      crc0 = crc32c_shift (crc32c_long, crc0) ^ crc1;
      crc0 = crc32c_shift (crc32c_long, crc0) ^ crc2;
      next += LONG * 2;
      len -= LONG * 3;
    }

  /* do the same thing, but now on SHORT*3 blocks for the remaining data less
     than a LONG*3 block */
  while (len >= SHORT * 3)
    {
      crc1 = 0;
      crc2 = 0;
      end = next + SHORT;
      do
	{
	__asm__ ("crc32q\t" "(%3), %0\n\t" "crc32q\t" SHORTx1 "(%3), %1\n\t" "crc32q\t" SHORTx2 "(%3), %2": "=r" (crc0), "=r" (crc1), "=r" (crc2):"r" (next), "0" (crc0), "1" (crc1),
		   "2"
		   (crc2));
	  next += 8;
	}
      while (next < end);
      crc0 = crc32c_shift (crc32c_short, crc0) ^ crc1;
      crc0 = crc32c_shift (crc32c_short, crc0) ^ crc2;
      next += SHORT * 2;
      len -= SHORT * 3;
    }

  /* compute the crc on the remaining eight-byte units less than a SHORT*3
     block */
  end = next + (len - (len & 7));
  while (next < end)
    {
    __asm__ ("crc32q\t" "(%1), %0": "=r" (crc0):"r" (next),
	       "0" (crc0));
      next += 8;
    }
  len &= 7;

  /* compute the crc for up to seven trailing bytes */
  while (len)
    {
    __asm__ ("crc32b\t" "(%1), %0": "=r" (crc0):"r" (next),
	       "0" (crc0));
      next++;
      len--;
    }

  /* return a post-processed crc */
  return (u32) crc0 ^ 0xffffffff;
}

/* Check for SSE 4.2.  SSE 4.2 was first supported in Nehalem processors
   introduced in November, 2008.  This does not check for the existence of the
   cpuid instruction itself, which was introduced on the 486SL in 1992, so this
   will fail on earlier x86 processors.  cpuid works on all Pentium and later
   processors. */
#define SSE42(have) \
    do { \
        u32 eax, ecx; \
        eax = 1; \
        __asm__("cpuid" \
                : "=c"(ecx) \
                : "a"(eax) \
                : "%ebx", "%edx"); \
        (have) = (ecx >> 20) & 1; \
    } while (0)

/* Compute a CRC-32C.  If the crc32 instruction is available, use the hardware
   version.  Otherwise, use the software version. */
u32
crc32c (u32 crc, const void *buf, size_t len)
{
  int sse42;

  SSE42 (sse42);
  return sse42 ? crc32c_hw (crc, buf, len) : crc32c_sw (crc, buf, len);
}

#endif /* included_vnet_sctp_crc32_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
