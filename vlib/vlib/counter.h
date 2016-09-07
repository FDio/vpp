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

/** \file

    Optimized thread-safe counters.

    Each vlib_[simple|combined]_counter_main_t consists of a single
    vector of thread-safe / atomically-updated u64 counters [the
    "maxi" vector], and a (u16 **) per-thread vector [the "minis"
    vector] of narrow, per-thread counters.

    The idea is to drastically reduce the number of atomic operations.
    In the case of packet counts, we divide the number of atomic ops
    by 2**16, etc.
*/

/** A collection of simple counters */

typedef struct
{
  u16 **minis;	 /**< Per-thread u16 non-atomic counters */
  u64 *maxi;	 /**< Shared wide counters */
  u64 *value_at_last_clear; /**< Counter values as of last clear. */
  u64 *value_at_last_serialize;	/**< Values as of last serialize. */
  u32 last_incremental_serialize_index;	/**< Last counter index
                                           serialized incrementally. */

  char *name;			/**< The counter collection's name. */
} vlib_simple_counter_main_t;

/** Increment a simple counter
    @param cm - (vlib_simple_counter_main_t *) simple counter main pointer
    @param cpu_index - (u32) the current cpu index
    @param index - (u32) index of the counter to increment
    @param increment - (u32) quantitiy to add to the counter
*/
always_inline void
vlib_increment_simple_counter (vlib_simple_counter_main_t * cm,
			       u32 cpu_index, u32 index, u32 increment)
{
  u16 *my_minis;
  u16 *mini;
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

/** Get the value of a simple counter
    Scrapes the entire set of mini counters. Innacurate unless
    worker threads which might increment the counter are
    barrier-synchronized

    @param cm - (vlib_simple_counter_main_t *) simple counter main pointer
    @param index - (u32) index of the counter to fetch
    @returns - (u64) current counter value
*/
always_inline u64
vlib_get_simple_counter (vlib_simple_counter_main_t * cm, u32 index)
{
  u16 *my_minis, *mini;
  u64 v;
  int i;

  ASSERT (index < vec_len (cm->maxi));

  v = 0;

  for (i = 0; i < vec_len (cm->minis); i++)
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

/** Clear a simple counter
    Clears the set of per-thread u16 counters, and the u64 counter

    @param cm - (vlib_simple_counter_main_t *) simple counter main pointer
    @param index - (u32) index of the counter to clear
*/
always_inline void
vlib_zero_simple_counter (vlib_simple_counter_main_t * cm, u32 index)
{
  u16 *my_minis;
  int i;

  ASSERT (index < vec_len (cm->maxi));

  for (i = 0; i < vec_len (cm->minis); i++)
    {
      my_minis = cm->minis[i];
      my_minis[index] = 0;
    }

  cm->maxi[index] = 0;

  if (index < vec_len (cm->value_at_last_clear))
    cm->value_at_last_clear[index] = 0;
}

/** Combined counter to hold both packets and byte differences.
 */
typedef struct
{
  u64 packets;			/**< packet counter */
  u64 bytes;			/**< byte counter  */
} vlib_counter_t;

/** Add two combined counters, results in the first counter
    @param [in,out] a - (vlib_counter_t *) dst counter
    @param b - (vlib_counter_t *) src counter
*/

always_inline void
vlib_counter_add (vlib_counter_t * a, vlib_counter_t * b)
{
  a->packets += b->packets;
  a->bytes += b->bytes;
}

/** Subtract combined counters, results in the first counter
    @param [in,out] a - (vlib_counter_t *) dst counter
    @param b - (vlib_counter_t *) src counter
*/
always_inline void
vlib_counter_sub (vlib_counter_t * a, vlib_counter_t * b)
{
  ASSERT (a->packets >= b->packets);
  ASSERT (a->bytes >= b->bytes);
  a->packets -= b->packets;
  a->bytes -= b->bytes;
}

/** Clear a combined counter
    @param a - (vlib_counter_t *) counter to clear
*/
always_inline void
vlib_counter_zero (vlib_counter_t * a)
{
  a->packets = a->bytes = 0;
}

/** Mini combined counter */
typedef struct
{
  u16 packets;			/**< Packet count */
  i16 bytes;			/**< Byte count */
} vlib_mini_counter_t;

/** A collection of combined counters */
typedef struct
{
  vlib_mini_counter_t **minis;	/**< Per-thread u16 non-atomic counter pairs */
  vlib_counter_t *maxi;		/**< Shared wide counter pairs */
  vlib_counter_t *value_at_last_clear;	/**< Counter values as of last clear. */
  vlib_counter_t *value_at_last_serialize; /**< Counter values as of last serialize. */
  u32 last_incremental_serialize_index;	/**< Last counter index serialized incrementally. */
  char *name; /**< The counter collection's name. */
} vlib_combined_counter_main_t;

/** Clear a collection of simple counters
    @param cm - (vlib_simple_counter_main_t *) collection to clear
*/
void vlib_clear_simple_counters (vlib_simple_counter_main_t * cm);

/** Clear a collection of combined counters
    @param cm - (vlib_combined_counter_main_t *) collection to clear
*/
void vlib_clear_combined_counters (vlib_combined_counter_main_t * cm);

/** Increment a combined counter
    @param cm - (vlib_combined_counter_main_t *) comined counter main pointer
    @param cpu_index - (u32) the current cpu index
    @param index - (u32) index of the counter to increment
    @param packet_increment - (u32) number of packets to add to the counter
    @param byte_increment - (u32) number of bytes to add to the counter
*/

always_inline void
vlib_increment_combined_counter (vlib_combined_counter_main_t * cm,
				 u32 cpu_index,
				 u32 index,
				 u32 packet_increment, u32 byte_increment)
{
  vlib_mini_counter_t *my_minis, *mini;
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
      vlib_counter_t *maxi = vec_elt_at_index (cm->maxi, index);

      __sync_fetch_and_add (&maxi->packets, new_packets);
      __sync_fetch_and_add (&maxi->bytes, new_bytes);

      mini->packets = 0;
      mini->bytes = 0;
    }
}

/** Get the value of a combined counter, never called in the speed path
    Scrapes the entire set of mini counters. Innacurate unless
    worker threads which might increment the counter are
    barrier-synchronized

    @param cm - (vlib_combined_counter_main_t *) combined counter main pointer
    @param index - (u32) index of the combined counter to fetch
    @param result [out] - (vlib_counter_t *) result stored here
*/

static inline void
vlib_get_combined_counter (vlib_combined_counter_main_t * cm,
			   u32 index, vlib_counter_t * result)
{
  vlib_mini_counter_t *my_minis, *mini;
  vlib_counter_t *maxi;
  int i;

  result->packets = 0;
  result->bytes = 0;

  for (i = 0; i < vec_len (cm->minis); i++)
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

/** Clear a combined counter
    Clears the set of per-thread u16 counters, and the shared vlib_counter_t

    @param cm - (vlib_combined_counter_main_t *) combined counter main pointer
    @param index - (u32) index of the counter to clear
*/
always_inline void
vlib_zero_combined_counter (vlib_combined_counter_main_t * cm, u32 index)
{
  vlib_mini_counter_t *mini, *my_minis;
  int i;

  for (i = 0; i < vec_len (cm->minis); i++)
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

/** validate a simple counter
    @param cm - (vlib_simple_counter_main_t *) pointer to the counter collection
    @param index - (u32) index of the counter to validate
*/

void vlib_validate_simple_counter (vlib_simple_counter_main_t * cm,
				   u32 index);
/** validate a combined counter
    @param cm - (vlib_combined_counter_main_t *) pointer to the counter
    collection
    @param index - (u32) index of the counter to validate
*/

void vlib_validate_combined_counter (vlib_combined_counter_main_t * cm,
				     u32 index);

/** Obtain the number of simple or combined counters allocated.
    A macro which reduces to to vec_len(cm->maxi), the answer in either
    case.

    @param cm - (vlib_simple_counter_main_t) or
    (vlib_combined_counter_main_t) the counter collection to interrogate
    @returns vec_len(cm->maxi)
*/
#define vlib_counter_len(cm) vec_len((cm)->maxi)

serialize_function_t serialize_vlib_simple_counter_main,
  unserialize_vlib_simple_counter_main;
serialize_function_t serialize_vlib_combined_counter_main,
  unserialize_vlib_combined_counter_main;

#endif /* included_vlib_counter_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
