/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vppinfra/histogram.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>

static inline size_t
clib_hgram_inst_size(u32 type_flags)
{
  switch (CLIB_HGRAM_FLD_GET (CLIB_HGRAM_TYPE_FLAGS_LAYOUT, type_flags))
    {
#define F(e, v, t, s) \
    case e: \
      { \
        t* junk = NULL; \
        u32 buckets = CLIB_HGRAM_FLD_GET (CLIB_HGRAM_TYPE_FLAGS_BUCKETS, type_flags); \
        buckets += CLIB_HGRAM_MIN_BUCKETS; \
        return sizeof(*junk) + sizeof(junk->bucket[0]) * buckets; \
      }
foreach_clib_hgram_layout (F)
#undef F

    default:
        ASSERT(0);
        return 0;
    }
}

void
clib_hgram_main_init (clib_hgram_main_t* hm, u32 thread_index)
{
  memset (hm, 0, sizeof (*hm));

  clib_spinlock_init (&hm->lock);
  hm->inst = NULL;
  hm->thread_index = thread_index;
}

static void*
clib_hgram_inst_new_impl_tf (clib_hgram_main_t* hm,
                             const clib_hgram_dataset_desc_t* dataset_desc,
                             u32 type_flags,
                             u32 instance)
{
  ASSERT(hm);
  size_t sz = clib_hgram_inst_size(type_flags);
  clib_hgram_inst_t* hi = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES); \
  memset (hi, 0, sz);

  hi->hdr.type_flags = type_flags;
  hi->hdr.instance = instance;
  hi->hdr.thread_index = hm->thread_index;
  hi->hdr.dataset_desc = dataset_desc;

  clib_hgram_main_lock (hm);
  hi->hdr.hgram_index = vec_len (hm->inst);
  vec_add1 (hm->inst, hi);
  clib_hgram_main_unlock (hm);

  return hi;
}

void*
clib_hgram_inst_new_impl (clib_hgram_main_t* hm,
                          const clib_hgram_dataset_desc_t* dataset_desc,
                          clib_hgram_layout_t layout,
                          u32 instance)
{
  ASSERT(hm);
  ASSERT(dataset_desc);
  ASSERT(layout > 0);
  ASSERT(layout < CLIB_HGRAM_LAYOUT_last);
  ASSERT(dataset_desc->shift >= 0);
  ASSERT(dataset_desc->shift < CLIB_HGRAM_SHIFT_last);
  ASSERT(dataset_desc->scale >= 0);
  ASSERT(dataset_desc->scale < CLIB_HGRAM_SCALE_last);
  ASSERT(dataset_desc->buckets >= CLIB_HGRAM_MIN_BUCKETS);
  ASSERT(dataset_desc->buckets <= CLIB_HGRAM_MAX_BUCKETS);
  u32 last_bucket = dataset_desc->buckets - 1;
  u32 buckets = dataset_desc->buckets - CLIB_HGRAM_MIN_BUCKETS;
  ASSERT(buckets <= CLIB_HGRAM_FLD_MAX(CLIB_HGRAM_TYPE_FLAGS_BUCKETS));

  u32 type_flags =
      CLIB_HGRAM_FLD_RAW (CLIB_HGRAM_TYPE_FLAGS_BUCKETS, buckets)
    | CLIB_HGRAM_FLD_RAW (CLIB_HGRAM_TYPE_FLAGS_ENABLE, 1)
    | CLIB_HGRAM_FLD_RAW (CLIB_HGRAM_TYPE_FLAGS_KEEP0, (dataset_desc->keep0 ? 1 : 0))
    | CLIB_HGRAM_FLD_RAW (CLIB_HGRAM_TYPE_FLAGS_LAYOUT, layout)
    | CLIB_HGRAM_FLD_RAW (CLIB_HGRAM_TYPE_FLAGS_SCALE, dataset_desc->scale)
    | CLIB_HGRAM_FLD_RAW (CLIB_HGRAM_TYPE_FLAGS_SHIFT, dataset_desc->shift);

  u32 msb = clib_hgram_bucket_to_smallest_msb (type_flags, last_bucket);
  ASSERT(msb && msb < 64);

  return clib_hgram_inst_new_impl_tf (hm, dataset_desc, type_flags, instance);
}

void*
clib_hgram_inst_clone (clib_hgram_main_t* hm, clib_hgram_inst_hdr_t* hi)
{
  ASSERT(hm);
  ASSERT(hi);

  if (hi->thread_index == hm->thread_index)
    return hi;

  u32 type_flags = hi->type_flags & (
      CLIB_HGRAM_TYPE_FLAGS_BUCKETS
    | CLIB_HGRAM_TYPE_FLAGS_ENABLE
    | CLIB_HGRAM_TYPE_FLAGS_KEEP0
    | CLIB_HGRAM_TYPE_FLAGS_LAYOUT
    | CLIB_HGRAM_TYPE_FLAGS_SCALE
    | CLIB_HGRAM_TYPE_FLAGS_SHIFT );

  return clib_hgram_inst_new_impl_tf (hm, hi->dataset_desc, type_flags, hi->instance);
}

clib_hgram_inst_t*
clib_hgram_inst_dup_atomic (clib_hgram_inst_t* hi)
{
  ASSERT(hi);
  size_t sz = clib_hgram_inst_size(hi->hdr.type_flags);
  clib_hgram_inst_t* dup_hi = clib_mem_alloc(sz);
  uword try = 0;

  while(1)
    {
      u32 type_flags;
      while (1)
        {
          type_flags = hi->hdr.type_flags;
          CLIB_MEMORY_BARRIER ();
          if (CLIB_HGRAM_FLD_GET (CLIB_HGRAM_TYPE_FLAGS_UPDATING, type_flags) & 1)
            continue;
          break;
        }

      memcpy(dup_hi, hi, sz);
      CLIB_MEMORY_BARRIER ();
      if (type_flags == hi->hdr.type_flags)
        break;
      ++try;
      if (try > 3)
        {
          /* Make sure it is marked as updating. */
          dup_hi->hdr.type_flags
            = CLIB_HGRAM_FLD_CHANGE (CLIB_HGRAM_TYPE_FLAGS_UPDATING,
                                     dup_hi->hdr.type_flags, 1);
          break;
        }
    }
  return dup_hi;
}


#define CLIB_HGRAM_start_update \
  u32 type_flags = hi->hdr.type_flags; \
  while (1) \
    { \
      u32 update = 1 + CLIB_HGRAM_FLD_GET (CLIB_HGRAM_TYPE_FLAGS_UPDATING, type_flags); \
      ASSERT (update&1); \
      u32 new_type_flags \
        = CLIB_HGRAM_FLD_CHANGE (CLIB_HGRAM_TYPE_FLAGS_UPDATING, type_flags, update); \
      if (__sync_bool_compare_and_swap (&hi->hdr.type_flags, type_flags, new_type_flags )) \
        { \
          type_flags = new_type_flags; \
          break; \
        } \
      type_flags = hi->hdr.type_flags; \
    }

#define CLIB_HGRAM_maybe_clear \
  if (PREDICT_FALSE (type_flags & CLIB_HGRAM_TYPE_FLAGS_CLEAR)) \
    { \
      memset((char*)hi + sizeof(clib_hgram_inst_hdr_t), 0, \
             clib_hgram_inst_size(type_flags) - sizeof(clib_hgram_inst_hdr_t)); \
      type_flags \
        = __sync_fetch_and_and (&hi->hdr.type_flags, ~CLIB_HGRAM_TYPE_FLAGS_CLEAR); \
    }

#define CLIB_HGRAM_update_minmax_v(var, hi_v, sample_v) \
  if (PREDICT_FALSE(   (var) <= hi->hi_v.min.sample_v \
                    || hi->hi_v.min.cpu_time == 0)) \
    { \
      hi->hi_v.min.sample_v = (var); \
      hi->hi_v.min.cpu_time = cpu_time; \
    } \
  if (PREDICT_FALSE(   (var) >= hi->hi_v.max.sample_v \
                    || hi->hi_v.max.cpu_time == 0)) \
    { \
      hi->hi_v.max.sample_v = (var); \
      hi->hi_v.max.cpu_time = cpu_time; \
    }

#define CLIB_HGRAM_calculate_bucket(var) \
  uword bucket_i = clib_hgram_bucket_from_value (type_flags, (var));

#define CLIB_HGRAM_update_bucket_sample_v(var) \
  hi->bucket[bucket_i].count++; \
  hi->bucket[bucket_i].total_v += (var); \
  hi->bucket[bucket_i].sample.v = (var); \
  hi->bucket[bucket_i].sample.cpu_time = cpu_time;

#define CLIB_HGRAM_update_bucket_sample \
  hi->bucket[bucket_i].count++; \
  hi->bucket[bucket_i].sample.cpu_time = cpu_time;

#define CLIB_HGRAM_complete_update \
  while (1) \
    { \
      u32 update = 1 + CLIB_HGRAM_FLD_GET (CLIB_HGRAM_TYPE_FLAGS_UPDATING, type_flags); \
      ASSERT (0 == (update&1)); \
      u32 new_type_flags \
        = CLIB_HGRAM_FLD_CHANGE (CLIB_HGRAM_TYPE_FLAGS_UPDATING, type_flags, update); \
      if (__sync_bool_compare_and_swap (&hi->hdr.type_flags, type_flags, new_type_flags )) \
        { \
          break; \
        } \
      type_flags = hi->hdr.type_flags; \
    }


void
clib_hgram_dispatch_sample_impl (clib_hgram_inst_dispatch_t* hi,
                                 u64 cpu_time, u64 deltat, u64 v)
{
  ASSERT (hi);

  CLIB_HGRAM_start_update
  CLIB_HGRAM_maybe_clear

  hi->total_deltat += deltat;
  hi->total_v += v;

  CLIB_HGRAM_update_minmax_v(deltat, minmax_deltat, v);
  CLIB_HGRAM_update_minmax_v(v, minmax_v, v);

  CLIB_HGRAM_calculate_bucket(deltat);
  CLIB_HGRAM_update_bucket_sample_v(v);

  CLIB_HGRAM_complete_update
}

void
clib_hgram_interval_end_impl (clib_hgram_inst_interval_t* hi,
                              u64 cpu_time)
{
  ASSERT (hi);
  u64 deltat = cpu_time - hi->start_cpu_time;

  CLIB_HGRAM_start_update
  CLIB_HGRAM_maybe_clear

  hi->total_deltat += deltat;

  CLIB_HGRAM_update_minmax_v(deltat, minmax_deltat, v);

  CLIB_HGRAM_calculate_bucket(deltat);
  CLIB_HGRAM_update_bucket_sample

  CLIB_HGRAM_complete_update
}

u8*
clib_hgram_format_name_thread (u8* s,
                               struct vlib_main_t* vm,
                               clib_hgram_inst_hdr_t* hi)
{
  ASSERT(hi);

  /* instance not used */
  return format (s, "%s-%u",
                 hi->dataset_desc->name,
                 hi->thread_index);
}
