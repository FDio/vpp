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
 * counter.h: simple and packet/byte counters
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

#ifndef included_vlib_counter_h
#define included_vlib_counter_h

/* 
 * Annoyingly enough, counters are created long before
 * the CPU configuration is available, so we have to
 * preallocate the mini-counter per-cpu vectors
 */

typedef struct {
  /* Compact counters that (rarely) can overflow. */
  u16 ** minis;

  /* Counters to hold overflow. */
  u64 * maxi;

  /* Counter values as of last clear. */
  u64 * value_at_last_clear;

  /* Values as of last serialize. */
  u64 * value_at_last_serialize;

  /* Last counter index serialized incrementally. */
  u32 last_incremental_serialize_index;

  /* Counter name. */
  char * name;
} vlib_simple_counter_main_t;

always_inline void
vlib_increment_simple_counter (vlib_simple_counter_main_t * cm,
                               u32 cpu_index,
			       u32 index,
			       u32 increment)
{
  u16 * my_minis;
  u16 * mini;
  u32 old, new;

  my_minis = cm->minis[cpu_index];
  mini = vec_elt_at_index (my_minis, index);
  old = mini[0];
  new = old + increment;
  mini[0] = new;

  if (PREDICT_FALSE (mini[0] != new))
    {
      __sync_fetch_and_add (&cm->maxi[index], new);
      my_minis[index] = 0;
    }
}

always_inline u64
vlib_get_simple_counter (vlib_simple_counter_main_t * cm, u32 index)
{
  u16 *my_minis, *mini;
  u64 v;
  int i;

  ASSERT (index < vec_len (cm->maxi));

  v = 0;

  for (i = 0; i < vec_len(cm->minis); i++)
    {
      my_minis = cm->minis[i];
      mini = vec_elt_at_index (my_minis, index);
      v += mini[0];
    }

  v += cm->maxi[index];

  if (index < vec_len (cm->value_at_last_clear))
    {
      ASSERT (v >= cm->value_at_last_clear[index]);
      v -= cm->value_at_last_clear[index];
    }

  return v;
}

always_inline void
vlib_zero_simple_counter (vlib_simple_counter_main_t * cm, u32 index)
{
  u16 * my_minis;
  int i;

  ASSERT (index < vec_len (cm->maxi));

  for (i = 0; i < vec_len(cm->minis); i++)
    {
      my_minis = cm->minis[i];
      my_minis[index] = 0;
    }

  cm->maxi[index] = 0;

  if (index < vec_len (cm->value_at_last_clear))
    cm->value_at_last_clear[index] = 0;
}

/* Combined counters hold both packets and byte differences. */
/* Maxi-packet/byte counter. */
typedef struct {
  u64 packets, bytes;
} vlib_counter_t;

always_inline void
vlib_counter_add (vlib_counter_t * a, vlib_counter_t * b)
{
  a->packets += b->packets;
  a->bytes += b->bytes;
}

always_inline void
vlib_counter_sub (vlib_counter_t * a, vlib_counter_t * b)
{
  ASSERT (a->packets >= b->packets);
  ASSERT (a->bytes >= b->bytes);
  a->packets -= b->packets;
  a->bytes -= b->bytes;
}

always_inline void
vlib_counter_zero (vlib_counter_t * a)
{ a->packets = a->bytes = 0; }

/* Micro-counter: 16 bits of packets and 16 bits of byte difference. */
typedef struct {
  /* Packet count. */
  u16 packets;

  /* The average packet size hack doesn't work in a multi-core config */
  i16 bytes;
} vlib_mini_counter_t;

typedef struct {
  /* Compact counters that (rarely) can overflow. */
  vlib_mini_counter_t ** minis;

  /* Counters to hold overflow. */
  vlib_counter_t * maxi;

  /* Debug counters for testing. */
  vlib_counter_t * debug;

  /* Counter values as of last clear. */
  vlib_counter_t * value_at_last_clear;

  /* Counter values as of last serialize. */
  vlib_counter_t * value_at_last_serialize;

  /* Last counter index serialized incrementally. */
  u32 last_incremental_serialize_index;

  /* Average packet sizes used in mini-counter byte differences. */
  u32 ave_packet_size;

  /* Current summed packets and bytes for average computation. */
  u32 ave_packets, ave_bytes;

  /* Counter name. */
  char * name;

} vlib_combined_counter_main_t;

void vlib_clear_simple_counters (vlib_simple_counter_main_t * cm);
void vlib_clear_combined_counters (vlib_combined_counter_main_t * cm);

always_inline void
vlib_increment_combined_counter (vlib_combined_counter_main_t * cm,
                                 u32 cpu_index,
				 u32 index,
				 u32 packet_increment,
				 u32 byte_increment)
{
  vlib_mini_counter_t * my_minis, * mini;
  u32 old_packets, new_packets;
  i32 old_bytes, new_bytes;

  /* Use this CPU's mini counter array */
  my_minis = cm->minis[cpu_index];

  mini = vec_elt_at_index (my_minis, index);
  old_packets = mini->packets;
  old_bytes = mini->bytes;

  new_packets = old_packets + packet_increment;
  new_bytes = old_bytes + byte_increment;

  mini->packets = new_packets;
  mini->bytes = new_bytes;

  /* Bytes always overflow before packets.. */
  if (PREDICT_FALSE (mini->bytes != new_bytes))
    {
      vlib_counter_t * maxi = vec_elt_at_index (cm->maxi, index);

      __sync_fetch_and_add (&maxi->packets, new_packets);
      __sync_fetch_and_add (&maxi->bytes, new_bytes);

      mini->packets = 0;
      mini->bytes = 0;
    }
}

/* This is never done in the speed path */
static inline void
vlib_get_combined_counter (vlib_combined_counter_main_t * cm,
			   u32 index,
			   vlib_counter_t * result)
{
  vlib_mini_counter_t * my_minis, * mini;
  vlib_counter_t * maxi;
  int i;

  result->packets = 0;
  result->bytes = 0;

  for (i = 0; i < vec_len(cm->minis); i++)
    {
      my_minis = cm->minis[i];

      mini = vec_elt_at_index (my_minis, index);
      result->packets += mini->packets;
      result->bytes += mini->bytes;
    }

  maxi = vec_elt_at_index (cm->maxi, index);
  result->packets += maxi->packets;
  result->bytes += maxi->bytes;

  if (index < vec_len (cm->value_at_last_clear))
    vlib_counter_sub (result, &cm->value_at_last_clear[index]);
}

always_inline void
vlib_zero_combined_counter (vlib_combined_counter_main_t * cm,
			    u32 index)
{
  vlib_mini_counter_t * mini, * my_minis;
  int i;

  for (i = 0; i < vec_len(cm->minis); i++)
    {
      my_minis = cm->minis[i];

      mini = vec_elt_at_index (my_minis, index);
      mini->packets = 0;
      mini->bytes = 0;
    }

  vlib_counter_zero (&cm->maxi[index]);
  if (index < vec_len (cm->value_at_last_clear))
    vlib_counter_zero (&cm->value_at_last_clear[index]);
}

void vlib_validate_simple_counter (vlib_simple_counter_main_t *cm, u32 index);
void vlib_validate_combined_counter (vlib_combined_counter_main_t *cm, u32 index);

/* Number of simple/combined counters allocated. */
#define vlib_counter_len(cm) vec_len((cm)->maxi)

serialize_function_t serialize_vlib_simple_counter_main, unserialize_vlib_simple_counter_main;
serialize_function_t serialize_vlib_combined_counter_main, unserialize_vlib_combined_counter_main;

#endif /* included_vlib_counter_h */
