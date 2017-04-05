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

    Each vlib_[simple|combined]_counter_main_t consists of a per-thread
    vector of per-object counters.

    The idea is to drastically eliminate atomic operations.
*/

/** 64bit counters */
typedef u64 counter_t;

/** A collection of simple counters */

typedef struct
{
  counter_t **counters;	 /**< Per-thread u64 non-atomic counters */
  counter_t *value_at_last_serialize;	/**< Values as of last serialize. */
  u32 last_incremental_serialize_index;	/**< Last counter index
                                           serialized incrementally. */

  char *name;			/**< The counter collection's name. */
} vlib_simple_counter_main_t;

/** The number of counters (not the number of per-thread counters) */
u32 vlib_simple_counter_n_counters (const vlib_simple_counter_main_t * cm);

/** Increment a simple counter
    @param cm - (vlib_simple_counter_main_t *) simple counter main pointer
    @param thread_index - (u32) the current cpu index
    @param index - (u32) index of the counter to increment
    @param increment - (u64) quantitiy to add to the counter
*/
always_inline void
vlib_increment_simple_counter (vlib_simple_counter_main_t * cm,
			       u32 thread_index, u32 index, u64 increment)
{
  counter_t *my_counters;

  my_counters = cm->counters[thread_index];
  my_counters[index] += increment;
}

/** Get the value of a simple counter
    Scrapes the entire set of per-thread counters. Innacurate unless
    worker threads which might increment the counter are
    barrier-synchronized

    @param cm - (vlib_simple_counter_main_t *) simple counter main pointer
    @param index - (u32) index of the counter to fetch
    @returns - (u64) current counter value
*/
always_inline counter_t
vlib_get_simple_counter (vlib_simple_counter_main_t * cm, u32 index)
{
  counter_t *my_counters;
  counter_t v;
  int i;

  ASSERT (index < vlib_simple_counter_n_counters (cm));

  v = 0;

  for (i = 0; i < vec_len (cm->counters); i++)
    {
      my_counters = cm->counters[i];
      v += my_counters[index];
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
  counter_t *my_counters;
  int i;

  ASSERT (index < vlib_simple_counter_n_counters (cm));

  for (i = 0; i < vec_len (cm->counters); i++)
    {
      my_counters = cm->counters[i];
      my_counters[index] = 0;
    }
}

/** Combined counter to hold both packets and byte differences.
 */
typedef struct
{
  counter_t packets;			/**< packet counter */
  counter_t bytes;			/**< byte counter  */
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

/** A collection of combined counters */
typedef struct
{
  vlib_counter_t **counters;	/**< Per-thread u64 non-atomic counter pairs */
  vlib_counter_t *value_at_last_serialize; /**< Counter values as of last serialize. */
  u32 last_incremental_serialize_index;	/**< Last counter index serialized incrementally. */
  char *name; /**< The counter collection's name. */
} vlib_combined_counter_main_t;

/** The number of counters (not the number of per-thread counters) */
u32 vlib_combined_counter_n_counters (const vlib_combined_counter_main_t *
				      cm);

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
    @param thread_index - (u32) the current cpu index
    @param index - (u32) index of the counter to increment
    @param packet_increment - (u64) number of packets to add to the counter
    @param byte_increment - (u64) number of bytes to add to the counter
*/

always_inline void
vlib_increment_combined_counter (vlib_combined_counter_main_t * cm,
				 u32 thread_index,
				 u32 index, u64 n_packets, u64 n_bytes)
{
  vlib_counter_t *my_counters;

  /* Use this CPU's counter array */
  my_counters = cm->counters[thread_index];

  my_counters[index].packets += n_packets;
  my_counters[index].bytes += n_bytes;
}

/** Pre-fetch a per-thread combined counter for the given object index */
always_inline void
vlib_prefetch_combined_counter (const vlib_combined_counter_main_t * cm,
				u32 thread_index, u32 index)
{
  vlib_counter_t *cpu_counters;

  /*
   * This CPU's index is assumed to already be in cache
   */
  cpu_counters = cm->counters[thread_index];
  CLIB_PREFETCH (cpu_counters + index, CLIB_CACHE_LINE_BYTES, STORE);
}


/** Get the value of a combined counter, never called in the speed path
    Scrapes the entire set of per-thread counters. Innacurate unless
    worker threads which might increment the counter are
    barrier-synchronized

    @param cm - (vlib_combined_counter_main_t *) combined counter main pointer
    @param index - (u32) index of the combined counter to fetch
    @param result [out] - (vlib_counter_t *) result stored here
*/

static inline void
vlib_get_combined_counter (const vlib_combined_counter_main_t * cm,
			   u32 index, vlib_counter_t * result)
{
  vlib_counter_t *my_counters, *counter;
  int i;

  result->packets = 0;
  result->bytes = 0;

  for (i = 0; i < vec_len (cm->counters); i++)
    {
      my_counters = cm->counters[i];

      counter = vec_elt_at_index (my_counters, index);
      result->packets += counter->packets;
      result->bytes += counter->bytes;
    }
}

/** Clear a combined counter
    Clears the set of per-thread counters.

    @param cm - (vlib_combined_counter_main_t *) combined counter main pointer
    @param index - (u32) index of the counter to clear
*/
always_inline void
vlib_zero_combined_counter (vlib_combined_counter_main_t * cm, u32 index)
{
  vlib_counter_t *my_counters, *counter;
  int i;

  for (i = 0; i < vec_len (cm->counters); i++)
    {
      my_counters = cm->counters[i];

      counter = vec_elt_at_index (my_counters, index);
      counter->packets = 0;
      counter->bytes = 0;
    }
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
