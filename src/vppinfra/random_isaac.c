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
/*
  ------------------------------------------------------------------------------
  By Bob Jenkins, 1996, Public Domain
  MODIFIED:
  960327: Creation (addition of randinit, really)
  970719: use context, not global variables, for internal state
  980324: renamed seed to flag
  980605: recommend ISAAC_LOG2_SIZE=4 for noncryptography.
  010626: note this is public domain
  ------------------------------------------------------------------------------

  Modified for CLIB by Eliot Dresselhaus.
  Dear Bob, Thanks for all the great work. - Eliot

  modifications copyright (c) 2003 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/* ISAAC is Bob Jenkins' random number generator.
   http://burtleburtle.net/bob/rand/isaacafa.html */

#include <vppinfra/random_isaac.h>

#if uword_bits != 32 && uword_bits != 64
#error "isaac only works for 32 or 64 bit words"
#endif

#if uword_bits == 32

#define ind32(mm,x)  (*(u32 *)((u8 *)(mm) + ((x) & ((ISAAC_SIZE-1)<<2))))
#define rngstep32(mix,a,b,mm,m,m2,r,x,y)		\
{							\
  x = *m;						\
  a = (a^(mix)) + *(m2++);				\
  *(m++) = y = ind32(mm,x) + a + b;			\
  *(r++) = b = ind32(mm,y>>ISAAC_LOG2_SIZE) + x;	\
}

void
isaac (isaac_t * ctx, uword * results)
{
  u32 a, b, c, x, y, *m, *mm, *m2, *r, *mend;

  mm = ctx->memory;
  r = results;
  a = ctx->a;
  b = ctx->b;
  c = ctx->c;

  b += ++c;
  mend = m2 = mm + ARRAY_LEN (ctx->memory) / 2;
  m = mm;
  while (m < mend)
    {
      rngstep32 (a << 13, a, b, mm, m, m2, r, x, y);
      rngstep32 (a >> 6, a, b, mm, m, m2, r, x, y);
      rngstep32 (a << 2, a, b, mm, m, m2, r, x, y);
      rngstep32 (a >> 16, a, b, mm, m, m2, r, x, y);
    }

  m2 = mm;
  while (m2 < mend)
    {
      rngstep32 (a << 13, a, b, mm, m, m2, r, x, y);
      rngstep32 (a >> 6, a, b, mm, m, m2, r, x, y);
      rngstep32 (a << 2, a, b, mm, m, m2, r, x, y);
      rngstep32 (a >> 16, a, b, mm, m, m2, r, x, y);
    }

  ctx->a = a;
  ctx->b = b;
  ctx->c = c;
}

/* Perform 2 isaac runs with different contexts simultaneously. */
void
isaac2 (isaac_t * ctx, uword * results)
{
#define _(n) \
  u32 a##n, b##n, c##n, x##n, y##n, * m##n, * mm##n, * m2##n, * r##n, * mend##n

  _(0);
  _(1);
  (void) mend1;			/* "set but unused variable" error on mend1 with gcc 4.9  */
#undef _

#define _(n)							\
do {								\
  mm##n = ctx[(n)].memory;					\
  r##n = results + (n) * ISAAC_SIZE;				\
  a##n = ctx[(n)].a;						\
  b##n = ctx[(n)].b;						\
  c##n = ctx[(n)].c;						\
  b##n += ++c##n;						\
  mend##n = m2##n = mm##n + ARRAY_LEN (ctx[(n)].memory) / 2;	\
  m##n = mm##n;							\
} while (0)

  _(0);
  _(1);

#undef _

  while (m0 < mend0)
    {
      rngstep32 (a0 << 13, a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep32 (a1 << 13, a1, b1, mm1, m1, m21, r1, x1, y1);
      rngstep32 (a0 >> 6, a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep32 (a1 >> 6, a1, b1, mm1, m1, m21, r1, x1, y1);
      rngstep32 (a0 << 2, a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep32 (a1 << 2, a1, b1, mm1, m1, m21, r1, x1, y1);
      rngstep32 (a0 >> 16, a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep32 (a1 >> 16, a1, b1, mm1, m1, m21, r1, x1, y1);
    }

  m20 = mm0;
  m21 = mm1;
  while (m20 < mend0)
    {
      rngstep32 (a0 << 13, a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep32 (a1 << 13, a1, b1, mm1, m1, m21, r1, x1, y1);
      rngstep32 (a0 >> 6, a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep32 (a1 >> 6, a1, b1, mm1, m1, m21, r1, x1, y1);
      rngstep32 (a0 << 2, a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep32 (a1 << 2, a1, b1, mm1, m1, m21, r1, x1, y1);
      rngstep32 (a0 >> 16, a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep32 (a1 >> 16, a1, b1, mm1, m1, m21, r1, x1, y1);
    }

  ctx[0].a = a0;
  ctx[0].b = b0;
  ctx[0].c = c0;
  ctx[1].a = a1;
  ctx[1].b = b1;
  ctx[1].c = c1;
}

#define mix32(a,b,c,d,e,f,g,h)			\
{						\
   a^=b<<11; d+=a; b+=c;			\
   b^=c>>2;  e+=b; c+=d;			\
   c^=d<<8;  f+=c; d+=e;			\
   d^=e>>16; g+=d; e+=f;			\
   e^=f<<10; h+=e; f+=g;			\
   f^=g>>4;  a+=f; g+=h;			\
   g^=h<<8;  b+=g; h+=a;			\
   h^=a>>9;  c+=h; a+=b;			\
}

void
isaac_init (isaac_t * ctx, uword * seeds)
{
  word i;
  u32 a, b, c, d, e, f, g, h, *m, *r;

  ctx->a = ctx->b = ctx->c = 0;
  m = ctx->memory;
  r = seeds;

  a = b = c = d = e = f = g = h = 0x9e3779b9;	/* the golden ratio */

  for (i = 0; i < 4; ++i)	/* scramble it */
    mix32 (a, b, c, d, e, f, g, h);

  /* initialize using the contents of r[] as the seed */
  for (i = 0; i < ISAAC_SIZE; i += 8)
    {
      a += r[i];
      b += r[i + 1];
      c += r[i + 2];
      d += r[i + 3];
      e += r[i + 4];
      f += r[i + 5];
      g += r[i + 6];
      h += r[i + 7];
      mix32 (a, b, c, d, e, f, g, h);
      m[i] = a;
      m[i + 1] = b;
      m[i + 2] = c;
      m[i + 3] = d;
      m[i + 4] = e;
      m[i + 5] = f;
      m[i + 6] = g;
      m[i + 7] = h;
    }

  /* do a second pass to make all of the seed affect all of m */
  for (i = 0; i < ISAAC_SIZE; i += 8)
    {
      a += m[i];
      b += m[i + 1];
      c += m[i + 2];
      d += m[i + 3];
      e += m[i + 4];
      f += m[i + 5];
      g += m[i + 6];
      h += m[i + 7];
      mix32 (a, b, c, d, e, f, g, h);
      m[i] = a;
      m[i + 1] = b;
      m[i + 2] = c;
      m[i + 3] = d;
      m[i + 4] = e;
      m[i + 5] = f;
      m[i + 6] = g;
      m[i + 7] = h;
    }
}
#endif /* uword_bits == 32 */

#if uword_bits == 64

#define ind64(mm,x)  (*(u64 *)((u8 *)(mm) + ((x) & ((ISAAC_SIZE-1)<<3))))
#define rngstep64(mix,a,b,mm,m,m2,r,x,y)		\
{							\
  x = *m;						\
  a = (mix) + *(m2++);					\
  *(m++) = y = ind64(mm,x) + a + b;			\
  *(r++) = b = ind64(mm,y>>ISAAC_LOG2_SIZE) + x;	\
}

void
isaac (isaac_t * ctx, uword * results)
{
  u64 a, b, c, x, y, *m, *mm, *m2, *r, *mend;

  mm = ctx->memory;
  r = results;
  a = ctx->a;
  b = ctx->b;
  c = ctx->c;

  b += ++c;
  mend = m2 = mm + ARRAY_LEN (ctx->memory) / 2;
  m = mm;
  while (m < mend)
    {
      rngstep64 (~(a ^ (a << 21)), a, b, mm, m, m2, r, x, y);
      rngstep64 (a ^ (a >> 5), a, b, mm, m, m2, r, x, y);
      rngstep64 (a ^ (a << 12), a, b, mm, m, m2, r, x, y);
      rngstep64 (a ^ (a >> 33), a, b, mm, m, m2, r, x, y);
    }

  m2 = mm;
  while (m2 < mend)
    {
      rngstep64 (~(a ^ (a << 21)), a, b, mm, m, m2, r, x, y);
      rngstep64 (a ^ (a >> 5), a, b, mm, m, m2, r, x, y);
      rngstep64 (a ^ (a << 12), a, b, mm, m, m2, r, x, y);
      rngstep64 (a ^ (a >> 33), a, b, mm, m, m2, r, x, y);
    }

  ctx->a = a;
  ctx->b = b;
  ctx->c = c;
}

/* Perform 2 isaac runs with different contexts simultaneously. */
void
isaac2 (isaac_t * ctx, uword * results)
{
#define _(n) \
  u64 a##n, b##n, c##n, x##n, y##n, * m##n, * mm##n, * m2##n, * r##n, * mend##n

  _(0);
  _(1);

#undef _

#define _(n)							\
do {								\
  mm##n = ctx[(n)].memory;					\
  r##n = results + (n) * ISAAC_SIZE;				\
  a##n = ctx[(n)].a;						\
  b##n = ctx[(n)].b;						\
  c##n = ctx[(n)].c;						\
  b##n += ++c##n;						\
  mend##n = m2##n = mm##n + ARRAY_LEN (ctx[(n)].memory) / 2;	\
  m##n = mm##n;							\
} while (0)

  _(0);
  _(1);

#undef _

  (void) mend1;			/* compiler warning */

  while (m0 < mend0)
    {
      rngstep64 (~(a0 ^ (a0 << 21)), a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep64 (~(a1 ^ (a1 << 21)), a1, b1, mm1, m1, m21, r1, x1, y1);
      rngstep64 (a0 ^ (a0 >> 5), a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep64 (a1 ^ (a1 >> 5), a1, b1, mm1, m1, m21, r1, x1, y1);
      rngstep64 (a0 ^ (a0 << 12), a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep64 (a1 ^ (a1 << 12), a1, b1, mm1, m1, m21, r1, x1, y1);
      rngstep64 (a0 ^ (a0 >> 33), a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep64 (a1 ^ (a1 >> 33), a1, b1, mm1, m1, m21, r1, x1, y1);
    }

  m20 = mm0;
  m21 = mm1;
  while (m20 < mend0)
    {
      rngstep64 (~(a0 ^ (a0 << 21)), a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep64 (~(a1 ^ (a1 << 21)), a1, b1, mm1, m1, m21, r1, x1, y1);
      rngstep64 (a0 ^ (a0 >> 5), a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep64 (a1 ^ (a1 >> 5), a1, b1, mm1, m1, m21, r1, x1, y1);
      rngstep64 (a0 ^ (a0 << 12), a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep64 (a1 ^ (a1 << 12), a1, b1, mm1, m1, m21, r1, x1, y1);
      rngstep64 (a0 ^ (a0 >> 33), a0, b0, mm0, m0, m20, r0, x0, y0);
      rngstep64 (a1 ^ (a1 >> 33), a1, b1, mm1, m1, m21, r1, x1, y1);
    }

  ctx[0].a = a0;
  ctx[0].b = b0;
  ctx[0].c = c0;
  ctx[1].a = a1;
  ctx[1].b = b1;
  ctx[1].c = c1;
}

#define mix64(a,b,c,d,e,f,g,h)			\
{						\
   a-=e; f^=h>>9;  h+=a;			\
   b-=f; g^=a<<9;  a+=b;			\
   c-=g; h^=b>>23; b+=c;			\
   d-=h; a^=c<<15; c+=d;			\
   e-=a; b^=d>>14; d+=e;			\
   f-=b; c^=e<<20; e+=f;			\
   g-=c; d^=f>>17; f+=g;			\
   h-=d; e^=g<<14; g+=h;			\
}

void
isaac_init (isaac_t * ctx, uword * seeds)
{
  word i;
  u64 a, b, c, d, e, f, g, h, *m, *r;

  ctx->a = ctx->b = ctx->c = 0;
  m = ctx->memory;
  r = seeds;

  a = b = c = d = e = f = g = h = 0x9e3779b97f4a7c13LL;	/* the golden ratio */

  for (i = 0; i < 4; ++i)	/* scramble it */
    mix64 (a, b, c, d, e, f, g, h);

  for (i = 0; i < ISAAC_SIZE; i += 8)	/* fill in mm[] with messy stuff */
    {
      a += r[i];
      b += r[i + 1];
      c += r[i + 2];
      d += r[i + 3];
      e += r[i + 4];
      f += r[i + 5];
      g += r[i + 6];
      h += r[i + 7];
      mix64 (a, b, c, d, e, f, g, h);
      m[i] = a;
      m[i + 1] = b;
      m[i + 2] = c;
      m[i + 3] = d;
      m[i + 4] = e;
      m[i + 5] = f;
      m[i + 6] = g;
      m[i + 7] = h;
    }

  /* do a second pass to make all of the seed affect all of mm */
  for (i = 0; i < ISAAC_SIZE; i += 8)
    {
      a += m[i];
      b += m[i + 1];
      c += m[i + 2];
      d += m[i + 3];
      e += m[i + 4];
      f += m[i + 5];
      g += m[i + 6];
      h += m[i + 7];
      mix64 (a, b, c, d, e, f, g, h);
      m[i] = a;
      m[i + 1] = b;
      m[i + 2] = c;
      m[i + 3] = d;
      m[i + 4] = e;
      m[i + 5] = f;
      m[i + 6] = g;
      m[i + 7] = h;
    }
}
#endif /* uword_bits == 64 */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
