/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* counter.h: simple and packet/byte counters */

#ifndef included_vlib_counter_h
#define included_vlib_counter_h

#include <vlib/counter_types.h>
#include <vppinfra/clib.h>

/** \file

    Optimized thread-safe counters.

    Each vlib_[simple|combined]_counter_main_t consists of a per-thread
    vector of per-object counters.

    The idea is to drastically eliminate atomic operations.
*/

/** A collection of simple counters */

typedef struct
{
  counter_t **counters;	   /**< Per-thread u64 non-atomic counters */
  char *name;		   /**< The counter collection's name. */
  char *stat_segment_name; /**< Name in stat segment directory */
  u32 stats_entry_index;
} vlib_simple_counter_main_t;

/** The number of counters (not the number of per-thread counters) */
u32 vlib_simple_counter_n_counters (const vlib_simple_counter_main_t *cm);

/** Pre-fetch a per-thread simple counter for the given object index */
always_inline void
vlib_prefetch_simple_counter (const vlib_simple_counter_main_t *cm,
			      clib_thread_index_t thread_index, u32 index)
{
  counter_t *my_counters;

  /*
   * This CPU's index is assumed to already be in cache
   */
  my_counters = cm->counters[thread_index];
  clib_prefetch_store (my_counters + index);
}

/** Increment a simple counter
    @param cm - (vlib_simple_counter_main_t *) simple counter main pointer
    @param thread_index - (u32) the current cpu index
    @param index - (u32) index of the counter to increment
    @param increment - (u64) quantitiy to add to the counter
*/
always_inline void
vlib_increment_simple_counter (vlib_simple_counter_main_t *cm,
			       clib_thread_index_t thread_index, u32 index,
			       u64 increment)
{
  counter_t *my_counters;

  my_counters = cm->counters[thread_index];
  my_counters[index] += increment;
}

/** Decrement a simple counter
    @param cm - (vlib_simple_counter_main_t *) simple counter main pointer
    @param thread_index - (u32) the current cpu index
    @param index - (u32) index of the counter to increment
    @param increment - (u64) quantitiy remove from the counter value
*/
always_inline void
vlib_decrement_simple_counter (vlib_simple_counter_main_t *cm,
			       clib_thread_index_t thread_index, u32 index,
			       u64 decrement)
{
  counter_t *my_counters;

  my_counters = cm->counters[thread_index];

  ASSERT (my_counters[index] >= decrement);

  my_counters[index] -= decrement;
}

/** Set a simple counter
    @param cm - (vlib_simple_counter_main_t *) simple counter main pointer
    @param thread_index - (u32) the current cpu index
    @param index - (u32) index of the counter to increment
    @param value - (u64) quantitiy to set to the counter
*/
always_inline void
vlib_set_simple_counter (vlib_simple_counter_main_t *cm,
			 clib_thread_index_t thread_index, u32 index,
			 u64 value)
{
  counter_t *my_counters;

  my_counters = cm->counters[thread_index];
  my_counters[index] = value;
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
vlib_get_simple_counter (vlib_simple_counter_main_t *cm, u32 index)
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
vlib_zero_simple_counter (vlib_simple_counter_main_t *cm, u32 index)
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

/** Add two combined counters, results in the first counter
    @param [in,out] a - (vlib_counter_t *) dst counter
    @param b - (vlib_counter_t *) src counter
*/

always_inline void
vlib_counter_add (vlib_counter_t *a, vlib_counter_t *b)
{
  a->packets += b->packets;
  a->bytes += b->bytes;
}

/** Subtract combined counters, results in the first counter
    @param [in,out] a - (vlib_counter_t *) dst counter
    @param b - (vlib_counter_t *) src counter
*/
always_inline void
vlib_counter_sub (vlib_counter_t *a, vlib_counter_t *b)
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
vlib_counter_zero (vlib_counter_t *a)
{
  a->packets = a->bytes = 0;
}

/** A collection of combined counters */
typedef struct
{
  vlib_counter_t **counters; /**< Per-thread u64 non-atomic counter pairs */
  char *name;		     /**< The counter collection's name. */
  char *stat_segment_name;   /**< Name in stat segment directory */
  u32 stats_entry_index;
} vlib_combined_counter_main_t;

/** The number of counters (not the number of per-thread counters) */
u32 vlib_combined_counter_n_counters (const vlib_combined_counter_main_t *cm);

/** Clear a collection of simple counters
    @param cm - (vlib_simple_counter_main_t *) collection to clear
*/
void vlib_clear_simple_counters (vlib_simple_counter_main_t *cm);

/** Clear a collection of combined counters
    @param cm - (vlib_combined_counter_main_t *) collection to clear
*/
void vlib_clear_combined_counters (vlib_combined_counter_main_t *cm);

/** Increment a combined counter
    @param cm - (vlib_combined_counter_main_t *) comined counter main pointer
    @param thread_index - (u32) the current cpu index
    @param index - (u32) index of the counter to increment
    @param packet_increment - (u64) number of packets to add to the counter
    @param byte_increment - (u64) number of bytes to add to the counter
*/

always_inline void
vlib_increment_combined_counter (vlib_combined_counter_main_t *cm,
				 clib_thread_index_t thread_index, u32 index,
				 u64 n_packets, u64 n_bytes)
{
  vlib_counter_t *my_counters;

  /* Use this CPU's counter array */
  my_counters = cm->counters[thread_index];

  my_counters[index].packets += n_packets;
  my_counters[index].bytes += n_bytes;
}

/** Pre-fetch a per-thread combined counter for the given object index */
always_inline void
vlib_prefetch_combined_counter (const vlib_combined_counter_main_t *cm,
				clib_thread_index_t thread_index, u32 index)
{
  vlib_counter_t *cpu_counters;

  /*
   * This CPU's index is assumed to already be in cache
   */
  cpu_counters = cm->counters[thread_index];
  clib_prefetch_store (cpu_counters + index);
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
vlib_get_combined_counter (const vlib_combined_counter_main_t *cm, u32 index,
			   vlib_counter_t *result)
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
vlib_zero_combined_counter (vlib_combined_counter_main_t *cm, u32 index)
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
    @param cm - (vlib_simple_counter_main_t *) pointer to the counter
   collection
    @param index - (u32) index of the counter to validate
*/

void vlib_validate_simple_counter (vlib_simple_counter_main_t *cm, u32 index);
void vlib_free_simple_counter (vlib_simple_counter_main_t *cm);

/** validate a combined counter
    @param cm - (vlib_combined_counter_main_t *) pointer to the counter
    collection
    @param index - (u32) index of the counter to validate
*/

void vlib_validate_combined_counter (vlib_combined_counter_main_t *cm,
				     u32 index);
int
vlib_validate_combined_counter_will_expand (vlib_combined_counter_main_t *cm,
					    u32 index);

void vlib_free_combined_counter (vlib_combined_counter_main_t *cm);

/** Obtain the number of simple or combined counters allocated.
    A macro which reduces to to vec_len(cm->maxi), the answer in either
    case.

    @param cm - (vlib_simple_counter_main_t) or
    (vlib_combined_counter_main_t) the counter collection to interrogate
    @returns vec_len(cm->maxi)
*/
#define vlib_counter_len(cm) vec_len ((cm)->maxi)

typedef struct
{
  counter_t **bins;	   /**< Per-thread u64 non-atomic histogram bins */
  u32 min_exp;		   /**< log2 bin minimum exponent */
  char *name;		   /**< The histogram collection's name. */
  char *stat_segment_name; /**< Name in stat segment directory */
  u32 stats_entry_index;
} vlib_log2_histogram_main_t;

void vlib_validate_log2_histogram (vlib_log2_histogram_main_t *hm,
				   u32 num_bins);

static_always_inline u8
vlib_log2_histogram_bin_index (const vlib_log2_histogram_main_t *hm, u32 value)
{
  if (value == 0)
    return 0;
  u8 log2_val = min_log2 (value);
  int min_exp = hm->min_exp;
  int n_bins = vec_len (hm->bins[0]);
  int bin = log2_val - min_exp;
  if (bin < 0)
    bin = 0;
  if (bin >= n_bins)
    bin = n_bins - 1;
  return (u8) bin;
}

always_inline void
vlib_increment_log2_histogram_bin (vlib_log2_histogram_main_t *hm,
				   clib_thread_index_t thread_index, u8 bin,
				   u64 increment)
{
  uint64_t *my_bins = hm->bins[thread_index];
  my_bins[bin + 1] += increment;
}

#endif /* included_vlib_counter_h */
