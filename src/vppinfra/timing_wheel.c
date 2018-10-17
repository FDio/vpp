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
#include <vppinfra/bitmap.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/timing_wheel.h>

void
timing_wheel_init (timing_wheel_t * w, u64 current_cpu_time,
		   f64 cpu_clocks_per_second)
{
  if (w->max_sched_time <= w->min_sched_time)
    {
      w->min_sched_time = 1e-6;
      w->max_sched_time = 1e-3;
    }

  w->cpu_clocks_per_second = cpu_clocks_per_second;
  w->log2_clocks_per_bin =
    max_log2 (w->cpu_clocks_per_second * w->min_sched_time);
  w->log2_bins_per_wheel =
    max_log2 (w->cpu_clocks_per_second * w->max_sched_time);
  w->log2_bins_per_wheel -= w->log2_clocks_per_bin;
  w->log2_clocks_per_wheel = w->log2_bins_per_wheel + w->log2_clocks_per_bin;
  w->bins_per_wheel = 1 << w->log2_bins_per_wheel;
  w->bins_per_wheel_mask = w->bins_per_wheel - 1;

  w->current_time_index = current_cpu_time >> w->log2_clocks_per_bin;

  if (w->n_wheel_elt_time_bits <= 0 ||
      w->n_wheel_elt_time_bits >= STRUCT_BITS_OF (timing_wheel_elt_t,
						  cpu_time_relative_to_base))
    w->n_wheel_elt_time_bits =
      STRUCT_BITS_OF (timing_wheel_elt_t, cpu_time_relative_to_base) - 1;

  w->cpu_time_base = current_cpu_time;
  w->time_index_next_cpu_time_base_update
    =
    w->current_time_index +
    ((u64) 1 << (w->n_wheel_elt_time_bits - w->log2_clocks_per_bin));
}

always_inline uword
get_level_and_relative_time (timing_wheel_t * w, u64 cpu_time,
			     uword * rtime_result)
{
  u64 dt, rtime;
  uword level_index;

  dt = (cpu_time >> w->log2_clocks_per_bin);

  /* Time should always move forward. */
  ASSERT (dt >= w->current_time_index);

  dt -= w->current_time_index;

  /* Find level and offset within level.  Level i has bins of size 2^((i+1)*M) */
  rtime = dt;
  for (level_index = 0; (rtime >> w->log2_bins_per_wheel) != 0; level_index++)
    rtime = (rtime >> w->log2_bins_per_wheel) - 1;

  /* Return offset within level and level index. */
  ASSERT (rtime < w->bins_per_wheel);
  *rtime_result = rtime;
  return level_index;
}

always_inline uword
time_index_to_wheel_index (timing_wheel_t * w, uword level_index, u64 ti)
{
  return (ti >> (level_index * w->log2_bins_per_wheel)) &
    w->bins_per_wheel_mask;
}

/* Find current time on this level. */
always_inline uword
current_time_wheel_index (timing_wheel_t * w, uword level_index)
{
  return time_index_to_wheel_index (w, level_index, w->current_time_index);
}

/* Circular wheel indexing. */
always_inline uword
wheel_add (timing_wheel_t * w, word x)
{
  return x & w->bins_per_wheel_mask;
}

always_inline uword
rtime_to_wheel_index (timing_wheel_t * w, uword level_index, uword rtime)
{
  uword t = current_time_wheel_index (w, level_index);
  return wheel_add (w, t + rtime);
}

static clib_error_t *
validate_level (timing_wheel_t * w, uword level_index, uword * n_elts)
{
  timing_wheel_level_t *level;
  timing_wheel_elt_t *e;
  uword wi;
  clib_error_t *error = 0;

#define _(x)					\
  do {						\
    error = CLIB_ERROR_ASSERT (x);		\
    ASSERT (! error);				\
    if (error) return error;			\
  } while (0)

  level = vec_elt_at_index (w->levels, level_index);
  for (wi = 0; wi < vec_len (level->elts); wi++)
    {
      /* Validate occupancy bitmap. */
      _(clib_bitmap_get_no_check (level->occupancy_bitmap, wi) ==
	(vec_len (level->elts[wi]) > 0));

      *n_elts += vec_len (level->elts[wi]);

      vec_foreach (e, level->elts[wi])
      {
	/* Validate time bin and level. */
	u64 e_time;
	uword e_ti, e_li, e_wi;

	e_time = e->cpu_time_relative_to_base + w->cpu_time_base;
	e_li = get_level_and_relative_time (w, e_time, &e_ti);
	e_wi = rtime_to_wheel_index (w, level_index, e_ti);

	if (e_li == level_index - 1)
	  /* If this element was scheduled on the previous level
	     it must be wrapped. */
	  _(e_ti + current_time_wheel_index (w, level_index - 1)
	    >= w->bins_per_wheel);
	else
	  {
	    _(e_li == level_index);
	    if (e_li == 0)
	      _(e_wi == wi);
	    else
	      _(e_wi == wi || e_wi + 1 == wi || e_wi - 1 == wi);
	  }
      }
    }

#undef _

  return error;
}

void
timing_wheel_validate (timing_wheel_t * w)
{
  uword l;
  clib_error_t *error = 0;
  uword n_elts;

  if (!w->validate)
    return;

  n_elts = pool_elts (w->overflow_pool);
  for (l = 0; l < vec_len (w->levels); l++)
    {
      error = validate_level (w, l, &n_elts);
      if (error)
	clib_error_report (error);
    }
}

always_inline void
free_elt_vector (timing_wheel_t * w, timing_wheel_elt_t * ev)
{
  /* Poison free elements so we never use them by mistake. */
  if (CLIB_DEBUG > 0)
    clib_memset (ev, ~0, vec_len (ev) * sizeof (ev[0]));
  _vec_len (ev) = 0;
  vec_add1 (w->free_elt_vectors, ev);
}

static timing_wheel_elt_t *
insert_helper (timing_wheel_t * w, uword level_index, uword rtime)
{
  timing_wheel_level_t *level;
  timing_wheel_elt_t *e;
  uword wheel_index;

  /* Circular buffer. */
  vec_validate (w->levels, level_index);
  level = vec_elt_at_index (w->levels, level_index);

  if (PREDICT_FALSE (!level->elts))
    {
      uword max = w->bins_per_wheel - 1;
      clib_bitmap_validate (level->occupancy_bitmap, max);
      vec_validate (level->elts, max);
    }

  wheel_index = rtime_to_wheel_index (w, level_index, rtime);

  level->occupancy_bitmap =
    clib_bitmap_ori (level->occupancy_bitmap, wheel_index);

  /* Allocate an elt vector from free list if there is one. */
  if (!level->elts[wheel_index] && vec_len (w->free_elt_vectors))
    level->elts[wheel_index] = vec_pop (w->free_elt_vectors);

  /* Add element to vector for this time bin. */
  vec_add2 (level->elts[wheel_index], e, 1);

  return e;
}

/* Insert user data on wheel at given CPU time stamp. */
static void
timing_wheel_insert_helper (timing_wheel_t * w, u64 insert_cpu_time,
			    u32 user_data)
{
  timing_wheel_elt_t *e;
  u64 dt;
  uword rtime, level_index;

  level_index = get_level_and_relative_time (w, insert_cpu_time, &rtime);

  dt = insert_cpu_time - w->cpu_time_base;
  if (PREDICT_TRUE (0 == (dt >> BITS (e->cpu_time_relative_to_base))))
    {
      e = insert_helper (w, level_index, rtime);
      e->user_data = user_data;
      e->cpu_time_relative_to_base = dt;
      if (insert_cpu_time < w->cached_min_cpu_time_on_wheel)
	w->cached_min_cpu_time_on_wheel = insert_cpu_time;
    }
  else
    {
      /* Time too far in the future: add to overflow vector. */
      timing_wheel_overflow_elt_t *oe;
      pool_get (w->overflow_pool, oe);
      oe->user_data = user_data;
      oe->cpu_time = insert_cpu_time;
    }
}

always_inline uword
elt_is_deleted (timing_wheel_t * w, u32 user_data)
{
  return (hash_elts (w->deleted_user_data_hash) > 0
	  && hash_get (w->deleted_user_data_hash, user_data));
}

static timing_wheel_elt_t *
delete_user_data (timing_wheel_elt_t * elts, u32 user_data)
{
  uword found_match;
  timing_wheel_elt_t *e, *new_elts;

  /* Quickly scan to see if there are any elements to delete
     in this bucket. */
  found_match = 0;
  vec_foreach (e, elts)
  {
    found_match = e->user_data == user_data;
    if (found_match)
      break;
  }
  if (!found_match)
    return elts;

  /* Re-scan to build vector of new elts with matching user_data deleted. */
  new_elts = 0;
  vec_foreach (e, elts)
  {
    if (e->user_data != user_data)
      vec_add1 (new_elts, e[0]);
  }

  vec_free (elts);
  return new_elts;
}

/* Insert user data on wheel at given CPU time stamp. */
void
timing_wheel_insert (timing_wheel_t * w, u64 insert_cpu_time, u32 user_data)
{
  /* Remove previously deleted elements. */
  if (elt_is_deleted (w, user_data))
    {
      timing_wheel_level_t *l;
      uword wi;

      /* Delete elts with given user data so that stale events don't expire. */
      vec_foreach (l, w->levels)
      {
	  /* *INDENT-OFF* */
	  clib_bitmap_foreach (wi, l->occupancy_bitmap, ({
	    l->elts[wi] = delete_user_data (l->elts[wi], user_data);
	    if (vec_len (l->elts[wi]) == 0)
	      l->occupancy_bitmap = clib_bitmap_andnoti (l->occupancy_bitmap, wi);
	  }));
	  /* *INDENT-ON* */
      }

      {
	timing_wheel_overflow_elt_t *oe;
	/* *INDENT-OFF* */
	pool_foreach (oe, w->overflow_pool, ({
	  if (oe->user_data == user_data)
	    pool_put (w->overflow_pool, oe);
	}));
	/* *INDENT-ON* */
      }

      hash_unset (w->deleted_user_data_hash, user_data);
    }

  timing_wheel_insert_helper (w, insert_cpu_time, user_data);
}

void
timing_wheel_delete (timing_wheel_t * w, u32 user_data)
{
  if (!w->deleted_user_data_hash)
    w->deleted_user_data_hash =
      hash_create ( /* capacity */ 0, /* value bytes */ 0);

  hash_set1 (w->deleted_user_data_hash, user_data);
}

/* Returns time of next expiring element. */
u64
timing_wheel_next_expiring_elt_time (timing_wheel_t * w)
{
  timing_wheel_level_t *l;
  timing_wheel_elt_t *e;
  uword li, wi, wi0;
  u32 min_dt;
  u64 min_t;
  uword wrapped = 0;

  min_dt = ~0;
  min_t = ~0ULL;
  vec_foreach (l, w->levels)
  {
    if (!l->occupancy_bitmap)
      continue;

    li = l - w->levels;
    wi0 = wi = current_time_wheel_index (w, li);
    wrapped = 0;
    while (1)
      {
	if (clib_bitmap_get_no_check (l->occupancy_bitmap, wi))
	  {
	    vec_foreach (e, l->elts[wi])
	      min_dt = clib_min (min_dt, e->cpu_time_relative_to_base);

	    if (wrapped && li + 1 < vec_len (w->levels))
	      {
		uword wi1 = current_time_wheel_index (w, li + 1);
		if (l[1].occupancy_bitmap
		    && clib_bitmap_get_no_check (l[1].occupancy_bitmap, wi1))
		  {
		    vec_foreach (e, l[1].elts[wi1])
		    {
		      min_dt =
			clib_min (min_dt, e->cpu_time_relative_to_base);
		    }
		  }
	      }

	    min_t = w->cpu_time_base + min_dt;
	    goto done;
	  }

	wi = wheel_add (w, wi + 1);
	if (wi == wi0)
	  break;

	wrapped = wi != wi + 1;
      }
  }

  {
    timing_wheel_overflow_elt_t *oe;

    if (min_dt != ~0)
      min_t = w->cpu_time_base + min_dt;

    /* *INDENT-OFF* */
    pool_foreach (oe, w->overflow_pool,
		  ({ min_t = clib_min (min_t, oe->cpu_time); }));
    /* *INDENT-ON* */

  done:
    return min_t;
  }
}

static inline void
insert_elt (timing_wheel_t * w, timing_wheel_elt_t * e)
{
  u64 t = w->cpu_time_base + e->cpu_time_relative_to_base;
  timing_wheel_insert_helper (w, t, e->user_data);
}

always_inline u64
elt_cpu_time (timing_wheel_t * w, timing_wheel_elt_t * e)
{
  return w->cpu_time_base + e->cpu_time_relative_to_base;
}

always_inline void
validate_expired_elt (timing_wheel_t * w, timing_wheel_elt_t * e,
		      u64 current_cpu_time)
{
  if (CLIB_DEBUG > 0)
    {
      u64 e_time = elt_cpu_time (w, e);

      /* Verify that element is actually expired. */
      ASSERT ((e_time >> w->log2_clocks_per_bin)
	      <= (current_cpu_time >> w->log2_clocks_per_bin));
    }
}

static u32 *
expire_bin (timing_wheel_t * w,
	    uword level_index,
	    uword wheel_index, u64 advance_cpu_time, u32 * expired_user_data)
{
  timing_wheel_level_t *level = vec_elt_at_index (w->levels, level_index);
  timing_wheel_elt_t *e;
  u32 *x;
  uword i, j, e_len;

  e = vec_elt (level->elts, wheel_index);
  e_len = vec_len (e);

  vec_add2 (expired_user_data, x, e_len);
  for (i = j = 0; i < e_len; i++)
    {
      validate_expired_elt (w, &e[i], advance_cpu_time);
      x[j] = e[i].user_data;

      /* Only advance if elt is not to be deleted. */
      j += !elt_is_deleted (w, e[i].user_data);
    }

  /* Adjust for deleted elts. */
  if (j < e_len)
    _vec_len (expired_user_data) -= e_len - j;

  free_elt_vector (w, e);

  level->elts[wheel_index] = 0;
  clib_bitmap_set_no_check (level->occupancy_bitmap, wheel_index, 0);

  return expired_user_data;
}

/* Called rarely. 32 bit times should only overflow every 4 seconds or so on a fast machine. */
static u32 *
advance_cpu_time_base (timing_wheel_t * w, u32 * expired_user_data)
{
  timing_wheel_level_t *l;
  timing_wheel_elt_t *e;
  u64 delta;

  w->stats.cpu_time_base_advances++;
  delta = ((u64) 1 << w->n_wheel_elt_time_bits);
  w->cpu_time_base += delta;
  w->time_index_next_cpu_time_base_update += delta >> w->log2_clocks_per_bin;

  vec_foreach (l, w->levels)
  {
    uword wi;
      /* *INDENT-OFF* */
      clib_bitmap_foreach (wi, l->occupancy_bitmap, ({
	vec_foreach (e, l->elts[wi])
	  {
	    /* This should always be true since otherwise we would have already expired
	       this element. Note that in the second half of this function we need
               to take care not to place the expired elements ourselves. */
	    ASSERT (e->cpu_time_relative_to_base >= delta);
	    e->cpu_time_relative_to_base -= delta;
	  }
      }));
      /* *INDENT-ON* */
  }

  /* See which overflow elements fit now. */
  {
    timing_wheel_overflow_elt_t *oe;
    /* *INDENT-OFF* */
    pool_foreach (oe, w->overflow_pool, ({
      /* It fits now into 32 bits. */
      if (0 == ((oe->cpu_time - w->cpu_time_base) >> BITS (e->cpu_time_relative_to_base)))
	{
	  u64 ti = oe->cpu_time >> w->log2_clocks_per_bin;
	  if (ti <= w->current_time_index)
	    {
	      /* This can happen when timing wheel is not advanced for a long time
		 (for example when at a gdb breakpoint for a while). */
              /* Note: the ti == w->current_time_index means it is also an expired timer */
	      if (! elt_is_deleted (w, oe->user_data))
		vec_add1 (expired_user_data, oe->user_data);
	    }
	  else
	    timing_wheel_insert_helper (w, oe->cpu_time, oe->user_data);
	  pool_put (w->overflow_pool, oe);
	}
    }));
    /* *INDENT-ON* */
  }
  return expired_user_data;
}

static u32 *
refill_level (timing_wheel_t * w,
	      uword level_index,
	      u64 advance_cpu_time,
	      uword from_wheel_index,
	      uword to_wheel_index, u32 * expired_user_data)
{
  timing_wheel_level_t *level;
  timing_wheel_elt_t *to_insert = w->unexpired_elts_pending_insert;
  u64 advance_time_index = advance_cpu_time >> w->log2_clocks_per_bin;

  vec_validate (w->stats.refills, level_index);
  w->stats.refills[level_index] += 1;

  if (level_index + 1 >= vec_len (w->levels))
    goto done;

  level = vec_elt_at_index (w->levels, level_index + 1);
  if (!level->occupancy_bitmap)
    goto done;

  while (1)
    {
      timing_wheel_elt_t *e, *es;

      if (clib_bitmap_get_no_check
	  (level->occupancy_bitmap, from_wheel_index))
	{
	  es = level->elts[from_wheel_index];
	  level->elts[from_wheel_index] = 0;
	  clib_bitmap_set_no_check (level->occupancy_bitmap, from_wheel_index,
				    0);

	  vec_foreach (e, es)
	  {
	    u64 e_time = elt_cpu_time (w, e);
	    u64 ti = e_time >> w->log2_clocks_per_bin;
	    if (ti <= advance_time_index)
	      {
		validate_expired_elt (w, e, advance_cpu_time);
		if (!elt_is_deleted (w, e->user_data))
		  vec_add1 (expired_user_data, e->user_data);
	      }
	    else
	      vec_add1 (to_insert, e[0]);
	  }
	  free_elt_vector (w, es);
	}

      if (from_wheel_index == to_wheel_index)
	break;

      from_wheel_index = wheel_add (w, from_wheel_index + 1);
    }

  timing_wheel_validate (w);
done:
  w->unexpired_elts_pending_insert = to_insert;
  return expired_user_data;
}

/* Advance wheel and return any expired user data in vector. */
u32 *
timing_wheel_advance (timing_wheel_t * w, u64 advance_cpu_time,
		      u32 * expired_user_data,
		      u64 * next_expiring_element_cpu_time)
{
  timing_wheel_level_t *level;
  uword level_index, advance_rtime, advance_level_index, advance_wheel_index;
  uword n_expired_user_data_before;
  u64 current_time_index, advance_time_index;

  n_expired_user_data_before = vec_len (expired_user_data);

  /* Re-fill lower levels when time wraps. */
  current_time_index = w->current_time_index;
  advance_time_index = advance_cpu_time >> w->log2_clocks_per_bin;

  {
    u64 current_ti, advance_ti;

    current_ti = current_time_index >> w->log2_bins_per_wheel;
    advance_ti = advance_time_index >> w->log2_bins_per_wheel;

    if (PREDICT_FALSE (current_ti != advance_ti))
      {
	if (w->unexpired_elts_pending_insert)
	  _vec_len (w->unexpired_elts_pending_insert) = 0;

	level_index = 0;
	while (current_ti != advance_ti)
	  {
	    uword c, a;
	    c = current_ti & (w->bins_per_wheel - 1);
	    a = advance_ti & (w->bins_per_wheel - 1);
	    if (c != a)
	      expired_user_data = refill_level (w,
						level_index,
						advance_cpu_time,
						c, a, expired_user_data);
	    current_ti >>= w->log2_bins_per_wheel;
	    advance_ti >>= w->log2_bins_per_wheel;
	    level_index++;
	  }
      }
  }

  advance_level_index =
    get_level_and_relative_time (w, advance_cpu_time, &advance_rtime);
  advance_wheel_index =
    rtime_to_wheel_index (w, advance_level_index, advance_rtime);

  /* Empty all occupied bins for entire levels that we advance past. */
  for (level_index = 0; level_index < advance_level_index; level_index++)
    {
      uword wi;

      if (level_index >= vec_len (w->levels))
	break;

      level = vec_elt_at_index (w->levels, level_index);
      /* *INDENT-OFF* */
      clib_bitmap_foreach (wi, level->occupancy_bitmap, ({
        expired_user_data = expire_bin (w, level_index, wi, advance_cpu_time,
					expired_user_data);
      }));
      /* *INDENT-ON* */
    }

  if (PREDICT_TRUE (level_index < vec_len (w->levels)))
    {
      uword wi;
      level = vec_elt_at_index (w->levels, level_index);
      wi = current_time_wheel_index (w, level_index);
      if (level->occupancy_bitmap)
	while (1)
	  {
	    if (clib_bitmap_get_no_check (level->occupancy_bitmap, wi))
	      expired_user_data =
		expire_bin (w, advance_level_index, wi, advance_cpu_time,
			    expired_user_data);

	    /* When we jump out, we have already just expired the bin,
	       corresponding to advance_wheel_index */
	    if (wi == advance_wheel_index)
	      break;

	    wi = wheel_add (w, wi + 1);
	  }
    }

  /* Advance current time index. */
  w->current_time_index = advance_time_index;

  if (vec_len (w->unexpired_elts_pending_insert) > 0)
    {
      timing_wheel_elt_t *e;
      vec_foreach (e, w->unexpired_elts_pending_insert) insert_elt (w, e);
      _vec_len (w->unexpired_elts_pending_insert) = 0;
    }

  /* Don't advance until necessary. */
  /* However, if the timing_wheel_advance() hasn't been called for some time,
     the while() loop will ensure multiple calls to advance_cpu_time_base()
     in a row until the w->cpu_time_base is fresh enough. */
  while (PREDICT_FALSE
	 (advance_time_index >= w->time_index_next_cpu_time_base_update))
    expired_user_data = advance_cpu_time_base (w, expired_user_data);

  if (next_expiring_element_cpu_time)
    {
      u64 min_t;

      /* Anything expired?  If so we need to recompute next expiring elt time. */
      if (vec_len (expired_user_data) == n_expired_user_data_before
	  && w->cached_min_cpu_time_on_wheel != 0ULL)
	min_t = w->cached_min_cpu_time_on_wheel;
      else
	{
	  min_t = timing_wheel_next_expiring_elt_time (w);
	  w->cached_min_cpu_time_on_wheel = min_t;
	}

      *next_expiring_element_cpu_time = min_t;
    }

  return expired_user_data;
}

u8 *
format_timing_wheel (u8 * s, va_list * va)
{
  timing_wheel_t *w = va_arg (*va, timing_wheel_t *);
  int verbose = va_arg (*va, int);
  u32 indent = format_get_indent (s);

  s = format (s, "level 0: %.4e - %.4e secs, 2^%d - 2^%d clocks",
	      (f64) (1 << w->log2_clocks_per_bin) / w->cpu_clocks_per_second,
	      (f64) (1 << w->log2_clocks_per_wheel) /
	      w->cpu_clocks_per_second, w->log2_clocks_per_bin,
	      w->log2_clocks_per_wheel);

  if (verbose)
    {
      int l;

      s = format (s, "\n%Utime base advances %Ld, every %.4e secs",
		  format_white_space, indent + 2,
		  w->stats.cpu_time_base_advances,
		  (f64) ((u64) 1 << w->n_wheel_elt_time_bits) /
		  w->cpu_clocks_per_second);

      for (l = 0; l < vec_len (w->levels); l++)
	s = format (s, "\n%Ulevel %d: refills %Ld",
		    format_white_space, indent + 2,
		    l,
		    l <
		    vec_len (w->stats.refills) ? w->stats.
		    refills[l] : (u64) 0);
    }

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
