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
 * pg_input.c: buffer generator input
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

  /*
   * To be honest, the packet generator needs an extreme
   * makeover. Two key assumptions which drove the current implementation
   * are no longer true. First, buffer managers implement a
   * post-TX recycle list. Second, that packet generator performance
   * is first-order important.
   */

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/devices/devices.h>

static int
validate_buffer_data2 (vlib_buffer_t * b, pg_stream_t * s,
		       u32 data_offset, u32 n_bytes)
{
  u8 *bd, *pd, *pm;
  u32 i;

  bd = b->data;
  pd = s->fixed_packet_data + data_offset;
  pm = s->fixed_packet_data_mask + data_offset;

  if (pd + n_bytes >= vec_end (s->fixed_packet_data))
    n_bytes = (pd < vec_end (s->fixed_packet_data)
	       ? vec_end (s->fixed_packet_data) - pd : 0);

  for (i = 0; i < n_bytes; i++)
    if ((bd[i] & pm[i]) != pd[i])
      break;

  if (i >= n_bytes)
    return 1;

  clib_warning ("buffer %U", format_vnet_buffer, b);
  clib_warning ("differ at index %d", i);
  clib_warning ("is     %U", format_hex_bytes, bd, n_bytes);
  clib_warning ("mask   %U", format_hex_bytes, pm, n_bytes);
  clib_warning ("expect %U", format_hex_bytes, pd, n_bytes);
  return 0;
}

static int
validate_buffer_data (vlib_buffer_t * b, pg_stream_t * s)
{
  return validate_buffer_data2 (b, s, 0, s->buffer_bytes);
}

always_inline void
set_1 (void *a0,
       u64 v0, u64 v_min, u64 v_max, u32 n_bits, u32 is_net_byte_order)
{
  ASSERT (v0 >= v_min && v0 <= v_max);
  if (n_bits == BITS (u8))
    {
      ((u8 *) a0)[0] = v0;
    }
  else if (n_bits == BITS (u16))
    {
      if (is_net_byte_order)
	v0 = clib_host_to_net_u16 (v0);
      clib_mem_unaligned (a0, u16) = v0;
    }
  else if (n_bits == BITS (u32))
    {
      if (is_net_byte_order)
	v0 = clib_host_to_net_u32 (v0);
      clib_mem_unaligned (a0, u32) = v0;
    }
  else if (n_bits == BITS (u64))
    {
      if (is_net_byte_order)
	v0 = clib_host_to_net_u64 (v0);
      clib_mem_unaligned (a0, u64) = v0;
    }
}

always_inline void
set_2 (void *a0, void *a1,
       u64 v0, u64 v1,
       u64 v_min, u64 v_max,
       u32 n_bits, u32 is_net_byte_order, u32 is_increment)
{
  ASSERT (v0 >= v_min && v0 <= v_max);
  ASSERT (v1 >= v_min && v1 <= (v_max + is_increment));
  if (n_bits == BITS (u8))
    {
      ((u8 *) a0)[0] = v0;
      ((u8 *) a1)[0] = v1;
    }
  else if (n_bits == BITS (u16))
    {
      if (is_net_byte_order)
	{
	  v0 = clib_host_to_net_u16 (v0);
	  v1 = clib_host_to_net_u16 (v1);
	}
      clib_mem_unaligned (a0, u16) = v0;
      clib_mem_unaligned (a1, u16) = v1;
    }
  else if (n_bits == BITS (u32))
    {
      if (is_net_byte_order)
	{
	  v0 = clib_host_to_net_u32 (v0);
	  v1 = clib_host_to_net_u32 (v1);
	}
      clib_mem_unaligned (a0, u32) = v0;
      clib_mem_unaligned (a1, u32) = v1;
    }
  else if (n_bits == BITS (u64))
    {
      if (is_net_byte_order)
	{
	  v0 = clib_host_to_net_u64 (v0);
	  v1 = clib_host_to_net_u64 (v1);
	}
      clib_mem_unaligned (a0, u64) = v0;
      clib_mem_unaligned (a1, u64) = v1;
    }
}

static_always_inline void
do_set_fixed (pg_main_t * pg,
	      pg_stream_t * s,
	      u32 * buffers,
	      u32 n_buffers,
	      u32 n_bits,
	      u32 byte_offset, u32 is_net_byte_order, u64 v_min, u64 v_max)
{
  vlib_main_t *vm = vlib_get_main ();

  while (n_buffers >= 4)
    {
      vlib_buffer_t *b0, *b1, *b2, *b3;
      void *a0, *a1;

      b0 = vlib_get_buffer (vm, buffers[0]);
      b1 = vlib_get_buffer (vm, buffers[1]);
      b2 = vlib_get_buffer (vm, buffers[2]);
      b3 = vlib_get_buffer (vm, buffers[3]);
      buffers += 2;
      n_buffers -= 2;

      a0 = (void *) b0 + byte_offset;
      a1 = (void *) b1 + byte_offset;
      CLIB_PREFETCH ((void *) b2 + byte_offset, sizeof (v_min), WRITE);
      CLIB_PREFETCH ((void *) b3 + byte_offset, sizeof (v_min), WRITE);

      set_2 (a0, a1, v_min, v_min, v_min, v_max, n_bits, is_net_byte_order,
	     /* is_increment */ 0);

      ASSERT (validate_buffer_data (b0, s));
      ASSERT (validate_buffer_data (b1, s));
    }

  while (n_buffers > 0)
    {
      vlib_buffer_t *b0;
      void *a0;

      b0 = vlib_get_buffer (vm, buffers[0]);
      buffers += 1;
      n_buffers -= 1;

      a0 = (void *) b0 + byte_offset;

      set_1 (a0, v_min, v_min, v_max, n_bits, is_net_byte_order);

      ASSERT (validate_buffer_data (b0, s));
    }
}

static_always_inline u64
do_set_increment (pg_main_t * pg,
		  pg_stream_t * s,
		  u32 * buffers,
		  u32 n_buffers,
		  u32 n_bits,
		  u32 byte_offset,
		  u32 is_net_byte_order,
		  u32 want_sum, u64 * sum_result, u64 v_min, u64 v_max, u64 v)
{
  vlib_main_t *vm = vlib_get_main ();
  u64 sum = 0;

  ASSERT (v >= v_min && v <= v_max);

  while (n_buffers >= 4)
    {
      vlib_buffer_t *b0, *b1, *b2, *b3;
      void *a0, *a1;
      u64 v_old;

      b0 = vlib_get_buffer (vm, buffers[0]);
      b1 = vlib_get_buffer (vm, buffers[1]);
      b2 = vlib_get_buffer (vm, buffers[2]);
      b3 = vlib_get_buffer (vm, buffers[3]);
      buffers += 2;
      n_buffers -= 2;

      a0 = (void *) b0 + byte_offset;
      a1 = (void *) b1 + byte_offset;
      CLIB_PREFETCH ((void *) b2 + byte_offset, sizeof (v_min), WRITE);
      CLIB_PREFETCH ((void *) b3 + byte_offset, sizeof (v_min), WRITE);

      v_old = v;
      v = v_old + 2;
      v = v > v_max ? v_min : v;
      set_2 (a0, a1,
	     v_old + 0, v_old + 1, v_min, v_max, n_bits, is_net_byte_order,
	     /* is_increment */ 1);

      if (want_sum)
	sum += 2 * v_old + 1;

      if (PREDICT_FALSE (v_old + 1 > v_max))
	{
	  if (want_sum)
	    sum -= 2 * v_old + 1;

	  v = v_old;
	  set_1 (a0, v + 0, v_min, v_max, n_bits, is_net_byte_order);
	  if (want_sum)
	    sum += v;
	  v += 1;

	  v = v > v_max ? v_min : v;
	  set_1 (a1, v + 0, v_min, v_max, n_bits, is_net_byte_order);
	  if (want_sum)
	    sum += v;
	  v += 1;
	}

      ASSERT (validate_buffer_data (b0, s));
      ASSERT (validate_buffer_data (b1, s));
    }

  while (n_buffers > 0)
    {
      vlib_buffer_t *b0;
      void *a0;
      u64 v_old;

      b0 = vlib_get_buffer (vm, buffers[0]);
      buffers += 1;
      n_buffers -= 1;

      a0 = (void *) b0 + byte_offset;

      v_old = v;
      if (want_sum)
	sum += v_old;
      v += 1;
      v = v > v_max ? v_min : v;

      ASSERT (v_old >= v_min && v_old <= v_max);
      set_1 (a0, v_old, v_min, v_max, n_bits, is_net_byte_order);

      ASSERT (validate_buffer_data (b0, s));
    }

  if (want_sum)
    *sum_result = sum;

  return v;
}

static_always_inline void
do_set_random (pg_main_t * pg,
	       pg_stream_t * s,
	       u32 * buffers,
	       u32 n_buffers,
	       u32 n_bits,
	       u32 byte_offset,
	       u32 is_net_byte_order,
	       u32 want_sum, u64 * sum_result, u64 v_min, u64 v_max)
{
  vlib_main_t *vm = vlib_get_main ();
  u64 v_diff = v_max - v_min + 1;
  u64 r_mask = max_pow2 (v_diff) - 1;
  u64 v0, v1;
  u64 sum = 0;
  void *random_data;

  random_data = clib_random_buffer_get_data
    (&vm->random_buffer, n_buffers * n_bits / BITS (u8));

  v0 = v1 = v_min;

  while (n_buffers >= 4)
    {
      vlib_buffer_t *b0, *b1, *b2, *b3;
      void *a0, *a1;
      u64 r0 = 0, r1 = 0;	/* warnings be gone */

      b0 = vlib_get_buffer (vm, buffers[0]);
      b1 = vlib_get_buffer (vm, buffers[1]);
      b2 = vlib_get_buffer (vm, buffers[2]);
      b3 = vlib_get_buffer (vm, buffers[3]);
      buffers += 2;
      n_buffers -= 2;

      a0 = (void *) b0 + byte_offset;
      a1 = (void *) b1 + byte_offset;
      CLIB_PREFETCH ((void *) b2 + byte_offset, sizeof (v_min), WRITE);
      CLIB_PREFETCH ((void *) b3 + byte_offset, sizeof (v_min), WRITE);

      switch (n_bits)
	{
#define _(n)					\
	  case BITS (u##n):			\
	    {					\
	      u##n * r = random_data;		\
	      r0 = r[0];			\
	      r1 = r[1];			\
	      random_data = r + 2;		\
	    }					\
	  break;

	  _(8);
	  _(16);
	  _(32);
	  _(64);

#undef _
	}

      /* Add power of 2 sized random number which may be out of range. */
      v0 += r0 & r_mask;
      v1 += r1 & r_mask;

      /* Twice should be enough to reduce to v_min .. v_max range. */
      v0 = v0 > v_max ? v0 - v_diff : v0;
      v1 = v1 > v_max ? v1 - v_diff : v1;
      v0 = v0 > v_max ? v0 - v_diff : v0;
      v1 = v1 > v_max ? v1 - v_diff : v1;

      if (want_sum)
	sum += v0 + v1;

      set_2 (a0, a1, v0, v1, v_min, v_max, n_bits, is_net_byte_order,
	     /* is_increment */ 0);

      ASSERT (validate_buffer_data (b0, s));
      ASSERT (validate_buffer_data (b1, s));
    }

  while (n_buffers > 0)
    {
      vlib_buffer_t *b0;
      void *a0;
      u64 r0 = 0;		/* warnings be gone */

      b0 = vlib_get_buffer (vm, buffers[0]);
      buffers += 1;
      n_buffers -= 1;

      a0 = (void *) b0 + byte_offset;

      switch (n_bits)
	{
#define _(n)					\
	  case BITS (u##n):			\
	    {					\
	      u##n * r = random_data;		\
	      r0 = r[0];			\
	      random_data = r + 1;		\
	    }					\
	  break;

	  _(8);
	  _(16);
	  _(32);
	  _(64);

#undef _
	}

      /* Add power of 2 sized random number which may be out of range. */
      v0 += r0 & r_mask;

      /* Twice should be enough to reduce to v_min .. v_max range. */
      v0 = v0 > v_max ? v0 - v_diff : v0;
      v0 = v0 > v_max ? v0 - v_diff : v0;

      if (want_sum)
	sum += v0;

      set_1 (a0, v0, v_min, v_max, n_bits, is_net_byte_order);

      ASSERT (validate_buffer_data (b0, s));
    }

  if (want_sum)
    *sum_result = sum;
}

#define _(i,t)							\
  clib_mem_unaligned (a##i, t) =				\
    clib_host_to_net_##t ((clib_net_to_host_mem_##t (a##i) &~ mask)	\
			  | (v##i << shift))

always_inline void
setbits_1 (void *a0,
	   u64 v0,
	   u64 v_min, u64 v_max,
	   u32 max_bits, u32 n_bits, u64 mask, u32 shift)
{
  ASSERT (v0 >= v_min && v0 <= v_max);
  if (max_bits == BITS (u8))
    ((u8 *) a0)[0] = (((u8 *) a0)[0] & ~mask) | (v0 << shift);

  else if (max_bits == BITS (u16))
    {
      _(0, u16);
    }
  else if (max_bits == BITS (u32))
    {
      _(0, u32);
    }
  else if (max_bits == BITS (u64))
    {
      _(0, u64);
    }
}

always_inline void
setbits_2 (void *a0, void *a1,
	   u64 v0, u64 v1,
	   u64 v_min, u64 v_max,
	   u32 max_bits, u32 n_bits, u64 mask, u32 shift, u32 is_increment)
{
  ASSERT (v0 >= v_min && v0 <= v_max);
  ASSERT (v1 >= v_min && v1 <= v_max + is_increment);
  if (max_bits == BITS (u8))
    {
      ((u8 *) a0)[0] = (((u8 *) a0)[0] & ~mask) | (v0 << shift);
      ((u8 *) a1)[0] = (((u8 *) a1)[0] & ~mask) | (v1 << shift);
    }

  else if (max_bits == BITS (u16))
    {
      _(0, u16);
      _(1, u16);
    }
  else if (max_bits == BITS (u32))
    {
      _(0, u32);
      _(1, u32);
    }
  else if (max_bits == BITS (u64))
    {
      _(0, u64);
      _(1, u64);
    }
}

#undef _

static_always_inline void
do_setbits_fixed (pg_main_t * pg,
		  pg_stream_t * s,
		  u32 * buffers,
		  u32 n_buffers,
		  u32 max_bits,
		  u32 n_bits,
		  u32 byte_offset, u64 v_min, u64 v_max, u64 mask, u32 shift)
{
  vlib_main_t *vm = vlib_get_main ();

  while (n_buffers >= 4)
    {
      vlib_buffer_t *b0, *b1, *b2, *b3;
      void *a0, *a1;

      b0 = vlib_get_buffer (vm, buffers[0]);
      b1 = vlib_get_buffer (vm, buffers[1]);
      b2 = vlib_get_buffer (vm, buffers[2]);
      b3 = vlib_get_buffer (vm, buffers[3]);
      buffers += 2;
      n_buffers -= 2;

      a0 = (void *) b0 + byte_offset;
      a1 = (void *) b1 + byte_offset;
      CLIB_PREFETCH ((void *) b2 + byte_offset, sizeof (v_min), WRITE);
      CLIB_PREFETCH ((void *) b3 + byte_offset, sizeof (v_min), WRITE);

      setbits_2 (a0, a1,
		 v_min, v_min, v_min, v_max, max_bits, n_bits, mask, shift,
		 /* is_increment */ 0);

      ASSERT (validate_buffer_data (b0, s));
      ASSERT (validate_buffer_data (b1, s));
    }

  while (n_buffers > 0)
    {
      vlib_buffer_t *b0;
      void *a0;

      b0 = vlib_get_buffer (vm, buffers[0]);
      buffers += 1;
      n_buffers -= 1;

      a0 = (void *) b0 + byte_offset;

      setbits_1 (a0, v_min, v_min, v_max, max_bits, n_bits, mask, shift);
      ASSERT (validate_buffer_data (b0, s));
    }
}

static_always_inline u64
do_setbits_increment (pg_main_t * pg,
		      pg_stream_t * s,
		      u32 * buffers,
		      u32 n_buffers,
		      u32 max_bits,
		      u32 n_bits,
		      u32 byte_offset,
		      u64 v_min, u64 v_max, u64 v, u64 mask, u32 shift)
{
  vlib_main_t *vm = vlib_get_main ();

  ASSERT (v >= v_min && v <= v_max);

  while (n_buffers >= 4)
    {
      vlib_buffer_t *b0, *b1, *b2, *b3;
      void *a0, *a1;
      u64 v_old;

      b0 = vlib_get_buffer (vm, buffers[0]);
      b1 = vlib_get_buffer (vm, buffers[1]);
      b2 = vlib_get_buffer (vm, buffers[2]);
      b3 = vlib_get_buffer (vm, buffers[3]);
      buffers += 2;
      n_buffers -= 2;

      a0 = (void *) b0 + byte_offset;
      a1 = (void *) b1 + byte_offset;
      CLIB_PREFETCH ((void *) b2 + byte_offset, sizeof (v_min), WRITE);
      CLIB_PREFETCH ((void *) b3 + byte_offset, sizeof (v_min), WRITE);

      v_old = v;
      v = v_old + 2;
      v = v > v_max ? v_min : v;
      setbits_2 (a0, a1,
		 v_old + 0, v_old + 1,
		 v_min, v_max, max_bits, n_bits, mask, shift,
		 /* is_increment */ 1);

      if (PREDICT_FALSE (v_old + 1 > v_max))
	{
	  v = v_old;
	  setbits_1 (a0, v + 0, v_min, v_max, max_bits, n_bits, mask, shift);
	  v += 1;

	  v = v > v_max ? v_min : v;
	  setbits_1 (a1, v + 0, v_min, v_max, max_bits, n_bits, mask, shift);
	  v += 1;
	}
      ASSERT (validate_buffer_data (b0, s));
      ASSERT (validate_buffer_data (b1, s));
    }

  while (n_buffers > 0)
    {
      vlib_buffer_t *b0;
      void *a0;
      u64 v_old;

      b0 = vlib_get_buffer (vm, buffers[0]);
      buffers += 1;
      n_buffers -= 1;

      a0 = (void *) b0 + byte_offset;

      v_old = v;
      v = v_old + 1;
      v = v > v_max ? v_min : v;

      ASSERT (v_old >= v_min && v_old <= v_max);
      setbits_1 (a0, v_old, v_min, v_max, max_bits, n_bits, mask, shift);

      ASSERT (validate_buffer_data (b0, s));
    }

  return v;
}

static_always_inline void
do_setbits_random (pg_main_t * pg,
		   pg_stream_t * s,
		   u32 * buffers,
		   u32 n_buffers,
		   u32 max_bits,
		   u32 n_bits,
		   u32 byte_offset, u64 v_min, u64 v_max, u64 mask, u32 shift)
{
  vlib_main_t *vm = vlib_get_main ();
  u64 v_diff = v_max - v_min + 1;
  u64 r_mask = max_pow2 (v_diff) - 1;
  u64 v0, v1;
  void *random_data;

  random_data = clib_random_buffer_get_data
    (&vm->random_buffer, n_buffers * max_bits / BITS (u8));
  v0 = v1 = v_min;

  while (n_buffers >= 4)
    {
      vlib_buffer_t *b0, *b1, *b2, *b3;
      void *a0, *a1;
      u64 r0 = 0, r1 = 0;	/* warnings be gone */

      b0 = vlib_get_buffer (vm, buffers[0]);
      b1 = vlib_get_buffer (vm, buffers[1]);
      b2 = vlib_get_buffer (vm, buffers[2]);
      b3 = vlib_get_buffer (vm, buffers[3]);
      buffers += 2;
      n_buffers -= 2;

      a0 = (void *) b0 + byte_offset;
      a1 = (void *) b1 + byte_offset;
      CLIB_PREFETCH ((void *) b2 + byte_offset, sizeof (v_min), WRITE);
      CLIB_PREFETCH ((void *) b3 + byte_offset, sizeof (v_min), WRITE);

      switch (max_bits)
	{
#define _(n)					\
	  case BITS (u##n):			\
	    {					\
	      u##n * r = random_data;		\
	      r0 = r[0];			\
	      r1 = r[1];			\
	      random_data = r + 2;		\
	    }					\
	  break;

	  _(8);
	  _(16);
	  _(32);
	  _(64);

#undef _
	}

      /* Add power of 2 sized random number which may be out of range. */
      v0 += r0 & r_mask;
      v1 += r1 & r_mask;

      /* Twice should be enough to reduce to v_min .. v_max range. */
      v0 = v0 > v_max ? v0 - v_diff : v0;
      v1 = v1 > v_max ? v1 - v_diff : v1;
      v0 = v0 > v_max ? v0 - v_diff : v0;
      v1 = v1 > v_max ? v1 - v_diff : v1;

      setbits_2 (a0, a1, v0, v1, v_min, v_max, max_bits, n_bits, mask, shift,
		 /* is_increment */ 0);

      ASSERT (validate_buffer_data (b0, s));
      ASSERT (validate_buffer_data (b1, s));
    }

  while (n_buffers > 0)
    {
      vlib_buffer_t *b0;
      void *a0;
      u64 r0 = 0;		/* warnings be gone */

      b0 = vlib_get_buffer (vm, buffers[0]);
      buffers += 1;
      n_buffers -= 1;

      a0 = (void *) b0 + byte_offset;

      switch (max_bits)
	{
#define _(n)					\
	  case BITS (u##n):			\
	    {					\
	      u##n * r = random_data;		\
	      r0 = r[0];			\
	      random_data = r + 1;		\
	    }					\
	  break;

	  _(8);
	  _(16);
	  _(32);
	  _(64);

#undef _
	}

      /* Add power of 2 sized random number which may be out of range. */
      v0 += r0 & r_mask;

      /* Twice should be enough to reduce to v_min .. v_max range. */
      v0 = v0 > v_max ? v0 - v_diff : v0;
      v0 = v0 > v_max ? v0 - v_diff : v0;

      setbits_1 (a0, v0, v_min, v_max, max_bits, n_bits, mask, shift);

      ASSERT (validate_buffer_data (b0, s));
    }
}

static u64
do_it (pg_main_t * pg,
       pg_stream_t * s,
       u32 * buffers,
       u32 n_buffers,
       u32 lo_bit, u32 hi_bit,
       u64 v_min, u64 v_max, u64 v, pg_edit_type_t edit_type)
{
  u32 max_bits, l0, l1, h1, start_bit;

  if (v_min == v_max)
    edit_type = PG_EDIT_FIXED;

  l0 = lo_bit / BITS (u8);
  l1 = lo_bit % BITS (u8);
  h1 = hi_bit % BITS (u8);

  start_bit = l0 * BITS (u8);

  max_bits = hi_bit - start_bit;
  ASSERT (max_bits <= 64);

#define _(n)						\
  case (n):						\
    if (edit_type == PG_EDIT_INCREMENT)			\
      v = do_set_increment (pg, s, buffers, n_buffers,	\
			    BITS (u##n),		\
			    l0,				\
			    /* is_net_byte_order */ 1,	\
			    /* want sum */ 0, 0,	\
			    v_min, v_max,		\
			    v);				\
    else if (edit_type == PG_EDIT_RANDOM)		\
      do_set_random (pg, s, buffers, n_buffers,		\
		     BITS (u##n),			\
		     l0,				\
		     /* is_net_byte_order */ 1,		\
		     /* want sum */ 0, 0,		\
		     v_min, v_max);			\
    else /* edit_type == PG_EDIT_FIXED */		\
      do_set_fixed (pg, s, buffers, n_buffers,		\
		    BITS (u##n),			\
		    l0,					\
		    /* is_net_byte_order */ 1,		\
		    v_min, v_max);			\
  goto done;

  if (l1 == 0 && h1 == 0)
    {
      switch (max_bits)
	{
	  _(8);
	  _(16);
	  _(32);
	  _(64);
	}
    }

#undef _

  {
    u64 mask;
    u32 shift = l1;
    u32 n_bits = max_bits;

    max_bits = clib_max (max_pow2 (n_bits), 8);

    mask = ((u64) 1 << (u64) n_bits) - 1;
    mask &= ~(((u64) 1 << (u64) shift) - 1);

    mask <<= max_bits - n_bits;
    shift += max_bits - n_bits;

    switch (max_bits)
      {
#define _(n)								\
	case (n):							\
	  if (edit_type == PG_EDIT_INCREMENT)				\
	    v = do_setbits_increment (pg, s, buffers, n_buffers,	\
				      BITS (u##n), n_bits,		\
				      l0, v_min, v_max, v,		\
				      mask, shift);			\
	  else if (edit_type == PG_EDIT_RANDOM)				\
	    do_setbits_random (pg, s, buffers, n_buffers,		\
			       BITS (u##n), n_bits,			\
			       l0, v_min, v_max,			\
			       mask, shift);				\
	  else /* edit_type == PG_EDIT_FIXED */				\
	    do_setbits_fixed (pg, s, buffers, n_buffers,		\
			      BITS (u##n), n_bits,			\
			      l0, v_min, v_max,				\
			      mask, shift);				\
	goto done;

	_(8);
	_(16);
	_(32);
	_(64);

#undef _
      }
  }

done:
  return v;
}

static void
pg_generate_set_lengths (pg_main_t * pg,
			 pg_stream_t * s, u32 * buffers, u32 n_buffers)
{
  u64 v_min, v_max, length_sum;
  pg_edit_type_t edit_type;

  v_min = s->min_packet_bytes;
  v_max = s->max_packet_bytes;
  edit_type = s->packet_size_edit_type;

  if (edit_type == PG_EDIT_INCREMENT)
    s->last_increment_packet_size
      = do_set_increment (pg, s, buffers, n_buffers,
			  8 * STRUCT_SIZE_OF (vlib_buffer_t, current_length),
			  STRUCT_OFFSET_OF (vlib_buffer_t, current_length),
			  /* is_net_byte_order */ 0,
			  /* want sum */ 1, &length_sum,
			  v_min, v_max, s->last_increment_packet_size);

  else if (edit_type == PG_EDIT_RANDOM)
    do_set_random (pg, s, buffers, n_buffers,
		   8 * STRUCT_SIZE_OF (vlib_buffer_t, current_length),
		   STRUCT_OFFSET_OF (vlib_buffer_t, current_length),
		   /* is_net_byte_order */ 0,
		   /* want sum */ 1, &length_sum,
		   v_min, v_max);

  else				/* edit_type == PG_EDIT_FIXED */
    {
      do_set_fixed (pg, s, buffers, n_buffers,
		    8 * STRUCT_SIZE_OF (vlib_buffer_t, current_length),
		    STRUCT_OFFSET_OF (vlib_buffer_t, current_length),
		    /* is_net_byte_order */ 0,
		    v_min, v_max);
      length_sum = v_min * n_buffers;
    }

  {
    vnet_main_t *vnm = vnet_get_main ();
    vnet_interface_main_t *im = &vnm->interface_main;
    vnet_sw_interface_t *si =
      vnet_get_sw_interface (vnm, s->sw_if_index[VLIB_RX]);

    vlib_increment_combined_counter (im->combined_sw_if_counters
				     + VNET_INTERFACE_COUNTER_RX,
				     vlib_get_thread_index (),
				     si->sw_if_index, n_buffers, length_sum);
  }

}

static void
pg_generate_fix_multi_buffer_lengths (pg_main_t * pg,
				      pg_stream_t * s,
				      u32 * buffers, u32 n_buffers)
{
  vlib_main_t *vm = vlib_get_main ();
  pg_buffer_index_t *pbi;
  uword n_bytes_left;
  static u32 *unused_buffers = 0;

  while (n_buffers > 0)
    {
      vlib_buffer_t *b;
      u32 bi;

      bi = buffers[0];
      b = vlib_get_buffer (vm, bi);

      /* Current length here is length of whole packet. */
      n_bytes_left = b->current_length;

      pbi = s->buffer_indices;
      while (1)
	{
	  uword n = clib_min (n_bytes_left, s->buffer_bytes);

	  b->current_length = n;
	  n_bytes_left -= n;
	  if (n_bytes_left > 0)
	    b->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  else
	    b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;

	  /* Return unused buffers to fifos. */
	  if (n == 0)
	    vec_add1 (unused_buffers, bi);

	  pbi++;
	  if (pbi >= vec_end (s->buffer_indices))
	    break;

	  bi = b->next_buffer;
	  b = vlib_get_buffer (vm, bi);
	}
      ASSERT (n_bytes_left == 0);

      buffers += 1;
      n_buffers -= 1;
    }

  if (vec_len (unused_buffers) > 0)
    {
      vlib_buffer_free_no_next (vm, unused_buffers, vec_len (unused_buffers));
      _vec_len (unused_buffers) = 0;
    }
}

static void
pg_generate_edit (pg_main_t * pg,
		  pg_stream_t * s, u32 * buffers, u32 n_buffers)
{
  pg_edit_t *e;

  vec_foreach (e, s->non_fixed_edits)
  {
    switch (e->type)
      {
      case PG_EDIT_RANDOM:
      case PG_EDIT_INCREMENT:
	{
	  u32 lo_bit, hi_bit;
	  u64 v_min, v_max;

	  v_min = pg_edit_get_value (e, PG_EDIT_LO);
	  v_max = pg_edit_get_value (e, PG_EDIT_HI);

	  hi_bit = (BITS (u8) * STRUCT_OFFSET_OF (vlib_buffer_t, data)
		    + BITS (u8) + e->lsb_bit_offset);
	  lo_bit = hi_bit - e->n_bits;

	  e->last_increment_value
	    = do_it (pg, s, buffers, n_buffers, lo_bit, hi_bit, v_min, v_max,
		     e->last_increment_value, e->type);
	}
	break;

      case PG_EDIT_UNSPECIFIED:
	break;

      default:
	/* Should not be any fixed edits left. */
	ASSERT (0);
	break;
      }
  }

  /* Call any edit functions to e.g. completely IP lengths, checksums, ... */
  {
    int i;
    for (i = vec_len (s->edit_groups) - 1; i >= 0; i--)
      {
	pg_edit_group_t *g = s->edit_groups + i;
	if (g->edit_function)
	  g->edit_function (pg, s, g, buffers, n_buffers);
      }
  }
}

static void
pg_set_next_buffer_pointers (pg_main_t * pg,
			     pg_stream_t * s,
			     u32 * buffers, u32 * next_buffers, u32 n_buffers)
{
  vlib_main_t *vm = vlib_get_main ();

  while (n_buffers >= 4)
    {
      u32 ni0, ni1;
      vlib_buffer_t *b0, *b1;

      b0 = vlib_get_buffer (vm, buffers[0]);
      b1 = vlib_get_buffer (vm, buffers[1]);
      ni0 = next_buffers[0];
      ni1 = next_buffers[1];

      vlib_prefetch_buffer_with_index (vm, buffers[2], WRITE);
      vlib_prefetch_buffer_with_index (vm, buffers[3], WRITE);

      b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b1->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b0->next_buffer = ni0;
      b1->next_buffer = ni1;

      buffers += 2;
      next_buffers += 2;
      n_buffers -= 2;
    }

  while (n_buffers > 0)
    {
      u32 ni0;
      vlib_buffer_t *b0;

      b0 = vlib_get_buffer (vm, buffers[0]);
      ni0 = next_buffers[0];
      buffers += 1;
      next_buffers += 1;
      n_buffers -= 1;

      b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b0->next_buffer = ni0;
    }
}

static_always_inline void
init_buffers_inline (vlib_main_t * vm,
		     pg_stream_t * s,
		     u32 * buffers,
		     u32 n_buffers, u32 data_offset, u32 n_data, u32 set_data)
{
  u32 n_left, *b;
  u8 *data, *mask;

  ASSERT (s->replay_packet_templates == 0);

  data = s->fixed_packet_data + data_offset;
  mask = s->fixed_packet_data_mask + data_offset;
  if (data + n_data >= vec_end (s->fixed_packet_data))
    n_data = (data < vec_end (s->fixed_packet_data)
	      ? vec_end (s->fixed_packet_data) - data : 0);
  if (n_data > 0)
    {
      ASSERT (data + n_data <= vec_end (s->fixed_packet_data));
      ASSERT (mask + n_data <= vec_end (s->fixed_packet_data_mask));
    }

  n_left = n_buffers;
  b = buffers;

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, b[2], STORE);
      vlib_prefetch_buffer_with_index (vm, b[3], STORE);

      bi0 = b[0];
      bi1 = b[1];
      b += 2;
      n_left -= 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	vnet_buffer (b1)->sw_if_index[VLIB_RX] = s->sw_if_index[VLIB_RX];

      vnet_buffer (b0)->sw_if_index[VLIB_TX] =
	vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;

      if (set_data)
	{
	  clib_memcpy_fast (b0->data, data, n_data);
	  clib_memcpy_fast (b1->data, data, n_data);
	}
      else
	{
	  ASSERT (validate_buffer_data2 (b0, s, data_offset, n_data));
	  ASSERT (validate_buffer_data2 (b1, s, data_offset, n_data));
	}
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;

      bi0 = b[0];
      b += 1;
      n_left -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = s->sw_if_index[VLIB_RX];
      /* s->sw_if_index[VLIB_TX]; */
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

      if (set_data)
	clib_memcpy_fast (b0->data, data, n_data);
      else
	ASSERT (validate_buffer_data2 (b0, s, data_offset, n_data));
    }
}

static u32
pg_stream_fill_helper (pg_main_t * pg,
		       pg_stream_t * s,
		       pg_buffer_index_t * bi,
		       u32 * buffers, u32 * next_buffers, u32 n_alloc)
{
  vlib_main_t *vm = vlib_get_main ();
  uword is_start_of_packet = bi == s->buffer_indices;
  u32 n_allocated;

  ASSERT (vec_len (s->replay_packet_templates) == 0);

  n_allocated = vlib_buffer_alloc (vm, buffers, n_alloc);
  if (n_allocated == 0)
    return 0;

  /*
   * We can't assume we got all the buffers we asked for...
   * This never worked until recently.
   */
  n_alloc = n_allocated;

  /* Reinitialize buffers */
  init_buffers_inline
    (vm, s,
     buffers,
     n_alloc, (bi - s->buffer_indices) * s->buffer_bytes /* data offset */ ,
     s->buffer_bytes,
     /* set_data */ 1);

  if (next_buffers)
    pg_set_next_buffer_pointers (pg, s, buffers, next_buffers, n_alloc);

  if (is_start_of_packet)
    {
      pg_generate_set_lengths (pg, s, buffers, n_alloc);
      if (vec_len (s->buffer_indices) > 1)
	pg_generate_fix_multi_buffer_lengths (pg, s, buffers, n_alloc);

      pg_generate_edit (pg, s, buffers, n_alloc);
    }

  return n_alloc;
}

static u32
pg_stream_fill_replay (pg_main_t * pg, pg_stream_t * s, u32 n_alloc)
{
  pg_buffer_index_t *bi;
  u32 n_left, i, l;
  u32 buffer_alloc_request = 0;
  u32 buffer_alloc_result;
  u32 current_buffer_index;
  u32 *buffers;
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *si;

  buffers = pg->replay_buffers_by_thread[vm->thread_index];
  vec_reset_length (buffers);
  bi = s->buffer_indices;

  n_left = n_alloc;
  i = s->current_replay_packet_index;
  l = vec_len (s->replay_packet_templates);

  /* Figure out how many buffers we need */
  while (n_left > 0)
    {
      u8 *d0;

      d0 = vec_elt (s->replay_packet_templates, i);
      buffer_alloc_request += (vec_len (d0) + (VLIB_BUFFER_DATA_SIZE - 1))
	/ VLIB_BUFFER_DATA_SIZE;

      i = ((i + 1) == l) ? 0 : i + 1;
      n_left--;
    }

  ASSERT (buffer_alloc_request > 0);
  vec_validate (buffers, buffer_alloc_request - 1);

  /* Allocate that many buffers */
  buffer_alloc_result = vlib_buffer_alloc (vm, buffers, buffer_alloc_request);
  if (buffer_alloc_result < buffer_alloc_request)
    {
      clib_warning ("alloc failure, got %d not %d", buffer_alloc_result,
		    buffer_alloc_request);
      vlib_buffer_free_no_next (vm, buffers, buffer_alloc_result);
      pg->replay_buffers_by_thread[vm->thread_index] = buffers;
      return 0;
    }

  /* Now go generate the buffers, and add them to the FIFO */
  n_left = n_alloc;

  current_buffer_index = 0;
  i = s->current_replay_packet_index;
  l = vec_len (s->replay_packet_templates);
  while (n_left > 0)
    {
      u8 *d0;
      int not_last;
      u32 data_offset;
      u32 bytes_to_copy, bytes_this_chunk;
      vlib_buffer_t *b;

      d0 = vec_elt (s->replay_packet_templates, i);
      data_offset = 0;
      bytes_to_copy = vec_len (d0);

      /* Add head chunk to pg fifo */
      clib_fifo_add1 (bi->buffer_fifo, buffers[current_buffer_index]);

      /* Copy the data */
      while (bytes_to_copy)
	{
	  bytes_this_chunk = clib_min (bytes_to_copy, VLIB_BUFFER_DATA_SIZE);
	  ASSERT (current_buffer_index < vec_len (buffers));
	  b = vlib_get_buffer (vm, buffers[current_buffer_index]);
	  clib_memcpy_fast (b->data, d0 + data_offset, bytes_this_chunk);
	  vnet_buffer (b)->sw_if_index[VLIB_RX] = s->sw_if_index[VLIB_RX];
	  vnet_buffer (b)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  b->flags = 0;
	  b->next_buffer = 0;
	  b->current_data = 0;
	  b->current_length = bytes_this_chunk;

	  not_last = bytes_this_chunk < bytes_to_copy;
	  if (not_last)
	    {
	      ASSERT (current_buffer_index < (vec_len (buffers) - 1));
	      b->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      b->next_buffer = buffers[current_buffer_index + 1];
	    }
	  bytes_to_copy -= bytes_this_chunk;
	  data_offset += bytes_this_chunk;
	  current_buffer_index++;
	}

      i = ((i + 1) == l) ? 0 : i + 1;
      n_left--;
    }

  /* Update the interface counters */
  si = vnet_get_sw_interface (vnm, s->sw_if_index[VLIB_RX]);
  l = 0;
  for (i = 0; i < n_alloc; i++)
    l += vlib_buffer_index_length_in_chain (vm, buffers[i]);
  vlib_increment_combined_counter (im->combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX,
				   vlib_get_thread_index (),
				   si->sw_if_index, n_alloc, l);

  s->current_replay_packet_index += n_alloc;
  s->current_replay_packet_index %= vec_len (s->replay_packet_templates);

  pg->replay_buffers_by_thread[vm->thread_index] = buffers;
  return n_alloc;
}


static u32
pg_stream_fill (pg_main_t * pg, pg_stream_t * s, u32 n_buffers)
{
  pg_buffer_index_t *bi;
  word i, n_in_fifo, n_alloc, n_free, n_added;
  u32 *tail, *start, *end, *last_tail, *last_start;

  bi = s->buffer_indices;

  n_in_fifo = clib_fifo_elts (bi->buffer_fifo);
  if (n_in_fifo >= n_buffers)
    return n_in_fifo;

  n_alloc = n_buffers - n_in_fifo;

  /* Round up, but never generate more than limit. */
  n_alloc = clib_max (VLIB_FRAME_SIZE, n_alloc);

  if (s->n_packets_limit > 0
      && s->n_packets_generated + n_in_fifo + n_alloc >= s->n_packets_limit)
    {
      n_alloc = s->n_packets_limit - s->n_packets_generated - n_in_fifo;
      if (n_alloc < 0)
	n_alloc = 0;
    }

  /*
   * Handle pcap replay directly
   */
  if (s->replay_packet_templates)
    return pg_stream_fill_replay (pg, s, n_alloc);

  /* All buffer fifos should have the same size. */
  if (CLIB_DEBUG > 0)
    {
      uword l = ~0, e;
      vec_foreach (bi, s->buffer_indices)
      {
	e = clib_fifo_elts (bi->buffer_fifo);
	if (bi == s->buffer_indices)
	  l = e;
	ASSERT (l == e);
      }
    }

  last_tail = last_start = 0;
  n_added = n_alloc;

  for (i = vec_len (s->buffer_indices) - 1; i >= 0; i--)
    {
      bi = vec_elt_at_index (s->buffer_indices, i);

      n_free = clib_fifo_free_elts (bi->buffer_fifo);
      if (n_free < n_alloc)
	clib_fifo_resize (bi->buffer_fifo, n_alloc - n_free);

      tail = clib_fifo_advance_tail (bi->buffer_fifo, n_alloc);
      start = bi->buffer_fifo;
      end = clib_fifo_end (bi->buffer_fifo);

      if (tail + n_alloc <= end)
	{
	  n_added =
	    pg_stream_fill_helper (pg, s, bi, tail, last_tail, n_alloc);
	}
      else
	{
	  u32 n = clib_min (end - tail, n_alloc);
	  n_added = pg_stream_fill_helper (pg, s, bi, tail, last_tail, n);

	  if (n_added == n && n_alloc > n_added)
	    {
	      n_added += pg_stream_fill_helper
		(pg, s, bi, start, last_start, n_alloc - n_added);
	    }
	}

      if (PREDICT_FALSE (n_added < n_alloc))
	tail = clib_fifo_advance_tail (bi->buffer_fifo, n_added - n_alloc);

      last_tail = tail;
      last_start = start;

      /* Verify that pkts in the fifo are properly allocated */
    }

  return n_in_fifo + n_added;
}

typedef struct
{
  u32 stream_index;

  u32 packet_length;
  u32 sw_if_index;

  /* Use pre data for packet data. */
  vlib_buffer_t buffer;
} pg_input_trace_t;

static u8 *
format_pg_input_trace (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  pg_input_trace_t *t = va_arg (*va, pg_input_trace_t *);
  pg_main_t *pg = &pg_main;
  pg_stream_t *stream;
  vlib_node_t *n;
  u32 indent = format_get_indent (s);

  stream = 0;
  if (!pool_is_free_index (pg->streams, t->stream_index))
    stream = pool_elt_at_index (pg->streams, t->stream_index);

  if (stream)
    s = format (s, "stream %v", pg->streams[t->stream_index].name);
  else
    s = format (s, "stream %d", t->stream_index);

  s = format (s, ", %d bytes", t->packet_length);
  s = format (s, ", %d sw_if_index", t->sw_if_index);

  s = format (s, "\n%U%U",
	      format_white_space, indent, format_vnet_buffer, &t->buffer);

  s = format (s, "\n%U", format_white_space, indent);

  n = 0;
  if (stream)
    n = vlib_get_node (vm, stream->node_index);

  if (n && n->format_buffer)
    s = format (s, "%U", n->format_buffer,
		t->buffer.pre_data, sizeof (t->buffer.pre_data));
  else
    s = format (s, "%U",
		format_hex_bytes, t->buffer.pre_data,
		ARRAY_LEN (t->buffer.pre_data));
  return s;
}

static void
pg_input_trace (pg_main_t * pg,
		vlib_node_runtime_t * node,
		pg_stream_t * s, u32 * buffers, u32 n_buffers)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 *b, n_left, stream_index, next_index;

  n_left = n_buffers;
  b = buffers;
  stream_index = s - pg->streams;
  next_index = s->next_index;

  while (n_left >= 2)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      pg_input_trace_t *t0, *t1;

      bi0 = b[0];
      bi1 = b[1];
      b += 2;
      n_left -= 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      vlib_trace_buffer (vm, node, next_index, b0, /* follow_chain */ 1);
      vlib_trace_buffer (vm, node, next_index, b1, /* follow_chain */ 1);

      t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
      t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));

      t0->stream_index = stream_index;
      t1->stream_index = stream_index;

      t0->packet_length = vlib_buffer_length_in_chain (vm, b0);
      t1->packet_length = vlib_buffer_length_in_chain (vm, b1);

      t0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      t1->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];

      clib_memcpy_fast (&t0->buffer, b0,
			sizeof (b0[0]) - sizeof (b0->pre_data));
      clib_memcpy_fast (&t1->buffer, b1,
			sizeof (b1[0]) - sizeof (b1->pre_data));

      clib_memcpy_fast (t0->buffer.pre_data, b0->data,
			sizeof (t0->buffer.pre_data));
      clib_memcpy_fast (t1->buffer.pre_data, b1->data,
			sizeof (t1->buffer.pre_data));
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      pg_input_trace_t *t0;

      bi0 = b[0];
      b += 1;
      n_left -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      vlib_trace_buffer (vm, node, next_index, b0, /* follow_chain */ 1);
      t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));

      t0->stream_index = stream_index;
      t0->packet_length = vlib_buffer_length_in_chain (vm, b0);
      t0->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      clib_memcpy_fast (&t0->buffer, b0,
			sizeof (b0[0]) - sizeof (b0->pre_data));
      clib_memcpy_fast (t0->buffer.pre_data, b0->data,
			sizeof (t0->buffer.pre_data));
    }
}

static uword
pg_generate_packets (vlib_node_runtime_t * node,
		     pg_main_t * pg,
		     pg_stream_t * s, uword n_packets_to_generate)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 *to_next, n_this_frame, n_left, n_trace, n_packets_in_fifo;
  uword n_packets_generated;
  pg_buffer_index_t *bi, *bi0;
  u32 next_index = s->next_index;
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  u8 feature_arc_index = fm->device_input_feature_arc_index;
  cm = &fm->feature_config_mains[feature_arc_index];
  u32 current_config_index = ~(u32) 0;
  int i;

  bi0 = s->buffer_indices;

  n_packets_in_fifo = pg_stream_fill (pg, s, n_packets_to_generate);
  n_packets_to_generate = clib_min (n_packets_in_fifo, n_packets_to_generate);
  n_packets_generated = 0;

  if (PREDICT_FALSE
      (vnet_have_features (feature_arc_index, s->sw_if_index[VLIB_RX])))
    {
      current_config_index =
	vec_elt (cm->config_index_by_sw_if_index, s->sw_if_index[VLIB_RX]);
      vnet_get_config_data (&cm->config_main, &current_config_index,
			    &next_index, 0);
    }

  while (n_packets_to_generate > 0)
    {
      u32 *head, *start, *end;

      if (PREDICT_TRUE (next_index == VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT))
	{
	  vlib_next_frame_t *nf;
	  vlib_frame_t *f;
	  ethernet_input_frame_t *ef;
	  pg_interface_t *pi;
	  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left);
	  nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
	  f = vlib_get_frame (vm, nf->frame_index);
	  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

	  ef = vlib_frame_scalar_args (f);
	  pi = pool_elt_at_index (pg->interfaces, s->pg_if_index);
	  ef->sw_if_index = pi->sw_if_index;
	  ef->hw_if_index = pi->hw_if_index;
	}
      else
	vlib_get_next_frame (vm, node, next_index, to_next, n_left);

      n_this_frame = n_packets_to_generate;
      if (n_this_frame > n_left)
	n_this_frame = n_left;

      start = bi0->buffer_fifo;
      end = clib_fifo_end (bi0->buffer_fifo);
      head = clib_fifo_head (bi0->buffer_fifo);

      if (head + n_this_frame <= end)
	clib_memcpy_fast (to_next, head, n_this_frame * sizeof (u32));
      else
	{
	  u32 n = end - head;
	  clib_memcpy_fast (to_next + 0, head, n * sizeof (u32));
	  clib_memcpy_fast (to_next + n, start,
			    (n_this_frame - n) * sizeof (u32));
	}

      if (s->replay_packet_templates == 0)
	{
	  vec_foreach (bi, s->buffer_indices)
	    clib_fifo_advance_head (bi->buffer_fifo, n_this_frame);
	}
      else
	{
	  clib_fifo_advance_head (bi0->buffer_fifo, n_this_frame);
	}

      if (current_config_index != ~(u32) 0)
	for (i = 0; i < n_this_frame; i++)
	  {
	    vlib_buffer_t *b;
	    b = vlib_get_buffer (vm, to_next[i]);
	    b->current_config_index = current_config_index;
	    vnet_buffer (b)->feature_arc_index = feature_arc_index;
	  }

      n_trace = vlib_get_trace_count (vm, node);
      if (n_trace > 0)
	{
	  u32 n = clib_min (n_trace, n_this_frame);
	  pg_input_trace (pg, node, s, to_next, n);
	  vlib_set_trace_count (vm, node, n_trace - n);
	}

      n_packets_to_generate -= n_this_frame;
      n_packets_generated += n_this_frame;
      n_left -= n_this_frame;
      if (CLIB_DEBUG > 0)
	{
	  int i;
	  vlib_buffer_t *b;

	  for (i = 0; i < VLIB_FRAME_SIZE - n_left; i++)
	    {
	      b = vlib_get_buffer (vm, to_next[i]);
	      ASSERT ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0 ||
		      b->current_length >= VLIB_BUFFER_MIN_CHAIN_SEG_SIZE);
	    }
	}

      int jj;
      for (jj = 0; jj < n_this_frame; ++jj)
	{
	  u32 bi = *(head + jj);
	  printf ("#%03d buflen: %llu\n", bi,
		  (long long unsigned) vlib_buffer_index_length_in_chain (vm,
									  bi));
	  fflush (stdout);
	}
      vlib_put_next_frame (vm, node, next_index, n_left);
    }

  return n_packets_generated;
}

static uword
pg_input_stream (vlib_node_runtime_t * node, pg_main_t * pg, pg_stream_t * s)
{
  vlib_main_t *vm = vlib_get_main ();
  uword n_packets;
  f64 time_now, dt;

  if (s->n_packets_limit > 0 && s->n_packets_generated >= s->n_packets_limit)
    {
      pg_stream_enable_disable (pg, s, /* want_enabled */ 0);
      return 0;
    }

  /* Apply rate limit. */
  time_now = vlib_time_now (vm);
  if (s->time_last_generate == 0)
    s->time_last_generate = time_now;

  dt = time_now - s->time_last_generate;
  s->time_last_generate = time_now;

  n_packets = VLIB_FRAME_SIZE;
  if (s->rate_packets_per_second > 0)
    {
      s->packet_accumulator += dt * s->rate_packets_per_second;
      n_packets = s->packet_accumulator;

      /* Never allow accumulator to grow if we get behind. */
      s->packet_accumulator -= n_packets;
    }

  /* Apply fixed limit. */
  if (s->n_packets_limit > 0
      && s->n_packets_generated + n_packets > s->n_packets_limit)
    n_packets = s->n_packets_limit - s->n_packets_generated;

  /* Generate up to one frame's worth of packets. */
  if (n_packets > VLIB_FRAME_SIZE)
    n_packets = VLIB_FRAME_SIZE;

  if (n_packets > 0)
    n_packets = pg_generate_packets (node, pg, s, n_packets);

  s->n_packets_generated += n_packets;

  return n_packets;
}

uword
pg_input (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  uword i;
  pg_main_t *pg = &pg_main;
  uword n_packets = 0;
  u32 worker_index = 0;

  if (vlib_num_workers ())
    worker_index = vlib_get_current_worker_index ();

  /* *INDENT-OFF* */
  clib_bitmap_foreach (i, pg->enabled_streams[worker_index], ({
    pg_stream_t *s = vec_elt_at_index (pg->streams, i);
    n_packets += pg_input_stream (node, pg, s);
  }));
  /* *INDENT-ON* */

  return n_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (pg_input_node) = {
  .function = pg_input,
  .name = "pg-input",
  .sibling_of = "device-input",
  .type = VLIB_NODE_TYPE_INPUT,

  .format_trace = format_pg_input_trace,

  /* Input node will be left disabled until a stream is active. */
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
