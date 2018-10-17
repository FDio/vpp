/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef PLUGINS_IOAM_PLUGIN_IOAM_LIB_E2E_IOAM_SEQNO_LIB_H_
#define PLUGINS_IOAM_PLUGIN_IOAM_LIB_E2E_IOAM_SEQNO_LIB_H_

#include <vppinfra/types.h>

#define SEQ_CHECK_VALUE 0x80000000	/* for seq number wraparound detection */

#define SEQNO_WINDOW_SIZE 2048
#define SEQNO_WINDOW_ARRAY_SIZE 64

typedef struct seqno_bitmap_
{
  u32 window_size;
  u32 array_size;
  u32 mask;
  u32 pad;
  u64 highest;
  u64 array[SEQNO_WINDOW_ARRAY_SIZE];	/* Will be alloc to array_size */
} seqno_bitmap;

typedef struct seqno_rx_info_
{
  u64 rx_packets;
  u64 lost_packets;
  u64 reordered_packets;
  u64 dup_packets;
  seqno_bitmap bitmap;
} seqno_rx_info;

/* This structure is 64-byte aligned */
typedef struct ioam_seqno_data_
{
  union
  {
    u32 seq_num;		/* Useful only for encap node */
    seqno_rx_info seqno_rx;
  };
} ioam_seqno_data;

static inline void
BIT_SET (u64 * p, u32 n)
{
  p[n >> 5] |= (1 << (n & 31));
}

static inline int
BIT_TEST (u64 * p, u32 n)
{
  return p[n >> 5] & (1 << (n & 31));
}

static void
BIT_CLEAR (u64 * p, u64 start, int num_bits, u32 mask)
{
  int n, t;
  int start_index = (start >> 5);
  int mask_index = (mask >> 5);

  start_index &= mask_index;
  if (start & 0x1f)
    {
      int start_bit = (start & 0x1f);

      n = (1 << start_bit) - 1;
      t = start_bit + num_bits;
      if (t < 32)
	{
	  n |= ~((1 << t) - 1);
	  p[start_index] &= n;
	  return;
	}
      p[start_index] &= n;
      start_index = (start_index + 1) & mask_index;
      num_bits -= (32 - start_bit);
    }
  while (num_bits >= 32)
    {
      p[start_index] = 0;
      start_index = (start_index + 1) & mask_index;
      num_bits -= 32;
    }
  n = ~((1 << num_bits) - 1);
  p[start_index] &= n;
}

static inline u8
seqno_check_wraparound (u32 a, u32 b)
{
  if ((a != b) && (a > b) && ((a - b) > SEQ_CHECK_VALUE))
    {
      return 1;
    }
  return 0;
}

/*
 * Function to analyze the PPC value recevied.
 *     - Updates the bitmap with received sequence number
 *     - counts the received/lost/duplicate/reordered packets
 */
inline static void
ioam_analyze_seqno (seqno_rx_info * seqno_rx, u64 seqno)
{
  int diff;
  static int peer_dead_count;
  seqno_bitmap *bitmap = &seqno_rx->bitmap;

  seqno_rx->rx_packets++;

  if (seqno > bitmap->highest)
    {				/* new larger sequence number */
      peer_dead_count = 0;
      diff = seqno - bitmap->highest;
      if (diff < bitmap->window_size)
	{
	  if (diff > 1)
	    {			/* diff==1 is *such* a common case it's a win to optimize it */
	      BIT_CLEAR (bitmap->array, bitmap->highest + 1, diff - 1,
			 bitmap->mask);
	      seqno_rx->lost_packets += diff - 1;
	    }
	}
      else
	{
	  seqno_rx->lost_packets += diff - 1;
	  clib_memset (bitmap->array, 0, bitmap->array_size * sizeof (u64));
	}
      BIT_SET (bitmap->array, seqno & bitmap->mask);
      bitmap->highest = seqno;
      return;
    }

  /* we've seen a bigger seq number before */
  diff = bitmap->highest - seqno;
  if (diff >= bitmap->window_size)
    {
      if (seqno_check_wraparound (bitmap->highest, seqno))
	{
	  clib_memset (bitmap->array, 0, bitmap->array_size * sizeof (u64));
	  BIT_SET (bitmap->array, seqno & bitmap->mask);
	  bitmap->highest = seqno;
	  return;
	}
      else
	{
	  peer_dead_count++;
	  if (peer_dead_count > 25)
	    {
	      peer_dead_count = 0;
	      clib_memset (bitmap->array, 0,
			   bitmap->array_size * sizeof (u64));
	      BIT_SET (bitmap->array, seqno & bitmap->mask);
	      bitmap->highest = seqno;
	    }
	  //ppc_rx->reordered_packets++;
	}
      return;
    }

  if (BIT_TEST (bitmap->array, seqno & bitmap->mask))
    {
      seqno_rx->dup_packets++;
      return;			/* Already seen */
    }
  seqno_rx->reordered_packets++;
  seqno_rx->lost_packets--;
  BIT_SET (bitmap->array, seqno & bitmap->mask);
  return;
}

u8 *show_ioam_seqno_analyse_data_fn (u8 * s, seqno_rx_info * rx);

u8 *show_ioam_seqno_cmd_fn (u8 * s, ioam_seqno_data * seqno_data, u8 enc);

void ioam_seqno_init_data (ioam_seqno_data * data);

void ioam_seqno_init_rx_info (seqno_rx_info * data);

#endif /* PLUGINS_IOAM_PLUGIN_IOAM_LIB_E2E_IOAM_SEQNO_LIB_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
