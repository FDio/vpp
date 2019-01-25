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

#ifndef included_clib_histogram_h
#define included_clib_histogram_h

#include <vppinfra/types.h>
#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/lock.h>

struct vlib_main_t;
struct clib_hgram_inst_hdr_t;

/* Histogram sample, time u64 */
typedef struct
{
  /* Sample time, in clocks. */
  u64 cpu_time;

  /* Associated sample value. */
  u64 v;
} clib_hgram_sample_dt64_t;


/* Histogram sample, time */
typedef struct
{
  /* Sample time, in clocks. */
  u64 cpu_time;
} clib_hgram_sample_dt_t;


/* Min-max pair, time u64 */
typedef struct
{
  clib_hgram_sample_dt64_t min;
  clib_hgram_sample_dt64_t max;
} clib_hgram_minmax_dt64_t;


/* Histogram bucket for deltat+v, plus previous sample */
typedef struct
{
  /* Total number of samples in the bucket. */
  u64 count;

  /* Sum of all v over all samples. */
  u64 total_v;

  /* Last sample. */
  clib_hgram_sample_dt64_t sample;
} clib_hgram_bucket_dt64s_t;


/* Histogram bucket for deltat, plus previous sample */
typedef struct
{
  /* Total number of samples in the bucket. */
  u64 count;

  /* Last sample. */
  clib_hgram_sample_dt_t sample;
} clib_hgram_bucket_dts_t;


/* Histogram layouts.  These define the histogram instance struct. */
#define foreach_clib_hgram_layout(F) \
  F (CLIB_HGRAM_LAYOUT_DISPATCH, 1, clib_hgram_inst_dispatch_t, "node dispatch time delta plus packets") \
  F (CLIB_HGRAM_LAYOUT_INTERVAL, 2, clib_hgram_inst_interval_t, "time interval only") \
  /**/

typedef enum
{
  CLIB_HGRAM_LAYOUT_NONE = 0,
#define F(e, v, t, s) e = v,
  foreach_clib_hgram_layout (F)
#undef F
  CLIB_HGRAM_LAYOUT_last
} clib_hgram_layout_t;


/*
 * Histogram value shifts.  These define how far to right-shift a
 * value before calculating the bucket.  This allows coarse control
 * over bucket ranges.  The sequence formula is (3<<n)-3
 */
#define foreach_clib_hgram_shift(F) \
  F (CLIB_HGRAM_SHIFT_0,  0,  0) \
  F (CLIB_HGRAM_SHIFT_3,  1,  3) \
  F (CLIB_HGRAM_SHIFT_9,  2,  9) \
  F (CLIB_HGRAM_SHIFT_21, 3, 21) \
  /**/

typedef enum
{
#define F(e, v, a) e = v,
  foreach_clib_hgram_shift (F)
#undef F
  CLIB_HGRAM_SHIFT_last
} clib_hgram_shift_t;


/*
 * Histogram value scales.  These define how the buckets are scaled:
 * log2, log4, log8, and log16.  Scaling allows a smaller number of
 * buckets to bin a larger range of values.
 */
#define foreach_clib_hgram_scale(F) \
  F (CLIB_HGRAM_SCALE_LOG2,  0, 2) \
  F (CLIB_HGRAM_SCALE_LOG4,  1, 4) \
  F (CLIB_HGRAM_SCALE_LOG8,  2, 8) \
  F (CLIB_HGRAM_SCALE_LOG16, 3, 16) \
  /**/

typedef enum
{
#define F(e, v, l) e = v,
  foreach_clib_hgram_scale (F)
#undef F
  CLIB_HGRAM_SCALE_last
} clib_hgram_scale_t;

/*
 * Histogram dataset descriptor.  Defined statically where the dataset
 * is defined.  Allows datasets to be defined by plugins or in higher
 * layers of VPP.
 */
typedef struct clib_hgram_dataset_desc_t
{
  /* The name of the dataset. */
  const char* name;

  /* Description of the dataset. */
  const char* description;

  /* Sample shift. */
  clib_hgram_shift_t shift;

  /* Sample scale. */
  clib_hgram_scale_t scale;

  /* Number of sample buckets. */
  u32 buckets;

  /* When a sample is exactly 0 (pre-shift), should it be kept or not? */
  u8 keep0;

  /*
   * Function to format the histogram instance name.
   */
  u8* (*format_name_fp)(
      u8* s,
      struct vlib_main_t* vm,
      struct clib_hgram_inst_hdr_t* hi);
} clib_hgram_dataset_desc_t;


/* Common histogram instance header.  */
typedef struct clib_hgram_inst_hdr_t
{
  /*
   * The type of histogram and SMP control flags.
   * See CLIB_HGRAM_TYPE_FLAGS*
   */
  u32 type_flags;

  /* The index of the histogram within hgram_main. */
  u32 hgram_index;

  /* The thread that owns the histogram. */
  u32 thread_index;

  /* The specific histogram instance, depends on type. */
  u32 instance;

  /* Dataset descriptor. */
  const clib_hgram_dataset_desc_t* dataset_desc;

} clib_hgram_inst_hdr_t;


#define CLIB_HGRAM_shift(m) \
  ( (((m) & 0x00000001) ?  0 : \
    (((m) & 0x00000002) ?  1 : \
    (((m) & 0x00000004) ?  2 : \
    (((m) & 0x00000008) ?  3 : \
    (((m) & 0x00000010) ?  4 : \
    (((m) & 0x00000020) ?  5 : \
    (((m) & 0x00000040) ?  6 : \
    (((m) & 0x00000080) ?  7 : \
    (((m) & 0x00000100) ?  8 : \
    (((m) & 0x00000200) ?  9 : \
    (((m) & 0x00000400) ? 10 : \
    (((m) & 0x00000800) ? 11 : \
    (((m) & 0x00001000) ? 12 : \
    (((m) & 0x00002000) ? 13 : \
    (((m) & 0x00004000) ? 14 : \
    (((m) & 0x00008000) ? 15 : \
    (((m) & 0x00010000) ? 16 : \
    (((m) & 0x00020000) ? 17 : \
    (((m) & 0x00040000) ? 18 : \
    (((m) & 0x00080000) ? 19 : \
    (((m) & 0x00100000) ? 20 : \
    (((m) & 0x00200000) ? 21 : \
    (((m) & 0x00400000) ? 22 : \
    (((m) & 0x00800000) ? 23 : \
    (((m) & 0x01000000) ? 24 : \
    (((m) & 0x02000000) ? 25 : \
    (((m) & 0x04000000) ? 26 : \
    (((m) & 0x08000000) ? 27 : \
    (((m) & 0x10000000) ? 28 : \
    (((m) & 0x20000000) ? 29 : \
    (((m) & 0x40000000) ? 30 : 31 ))))))))))))))))))))))))))))))))

/*
 * Determine the maximum value of a bitfield.
 *   m - The mask value.
 */
#define CLIB_HGRAM_FLD_MAX(m) \
  (m >> CLIB_HGRAM_shift(m))

/*
 * Extract a field from an integer.
 *   m - The mask value.
 *   i - The integer to extract from.
 *   Evaluates to the normalized value.
 */
#define CLIB_HGRAM_FLD_GET(m, i) \
  (((i)&m) >> CLIB_HGRAM_shift(m))

/*
 * Get a raw field value.
 *   m - The mask value.
 *   v - The value to set for the field.
 *   Evaluates to the new raw integer value for the field.
 */
#define CLIB_HGRAM_FLD_RAW(m, v) \
  ((((u32)v) << CLIB_HGRAM_shift(m)) & m)

/*
 * Change a value in a field.
 *   m - The mask value.
 *   i - The integer to change.
 *   v - The value to set for the field.
 *   Evaluates to the new integer value.
 */
#define CLIB_HGRAM_FLD_CHANGE(m, i, v) \
  (   ((u32)(i) & ~m) \
    | CLIB_HGRAM_FLD_RAW(m, v) )

#define CLIB_HGRAM_TYPE_FLAGS_KEEP0      0x00000001
#define CLIB_HGRAM_TYPE_FLAGS_CLEAR      0x00000002
#define CLIB_HGRAM_TYPE_FLAGS_ENABLE     0x00000004
#define CLIB_HGRAM_TYPE_FLAGS_unused3    0x00000008
#define CLIB_HGRAM_TYPE_FLAGS_SHIFT      0x00000030
#define CLIB_HGRAM_TYPE_FLAGS_SCALE      0x000000C0
#define CLIB_HGRAM_TYPE_FLAGS_UPDATING   0x00000F00
#define CLIB_HGRAM_TYPE_FLAGS_unused12   0x00FFF000
#define CLIB_HGRAM_TYPE_FLAGS_BUCKETS    0x0F000000
#define CLIB_HGRAM_TYPE_FLAGS_LAYOUT     0xF0000000

#define CLIB_HGRAM_MIN_BUCKETS 7
#define CLIB_HGRAM_MAX_BUCKETS \
  (CLIB_HGRAM_MIN_BUCKETS + CLIB_HGRAM_FLD_MAX(CLIB_HGRAM_TYPE_FLAGS_BUCKETS))

/*
 * Determine the actual number of buckets from type flags.
 *   tf - type flags
 */
#define CLIB_HGRAM_ACTUAL_BUCKETS( tf ) \
  ( \
     CLIB_HGRAM_FLD_GET (CLIB_HGRAM_TYPE_FLAGS_BUCKETS, (tf)) \
   + CLIB_HGRAM_MIN_BUCKETS \
  )

/*
 * The buckets are sized according to SHIFT and SCALE.  To bucket a
 * value, first a right-shift is applied to the value.  The first
 * bucket is reserved for values are zero after this shift (underflow).
 * If the value is not zero, then the log2 of the value is calculated
 * to produce the bucket log2.  This bucket is then scaled according to
 * SCALE, resulting in effective bucket bins of log2, log4, log8 and
 * log16.
 *
 *   shift scale   Bucket smallest MSB
 *   ----- -----   ----------------------------
 *       0     0   =0,  0,  1,  2,  3,  4,  5, ...
 *       0     1   =0,  0,  2,  4,  6,  8, 10, ...
 *       0     2   =0,  0,  3,  6,  9, 12, 15, ...
 *       0     3   =0,  0,  4,  8, 12, 16, 20, ...
 *       1     0   =0,  3,  4,  5,  6,  7,  8, ...
 *       1     1   =0,  3,  5,  7,  9, 11, 13, ...
 *       1     2   =0,  3,  6,  9, 12, 15, 18, ...
 *       1     3   =0,  3,  7, 11, 15, 19, 23, ...
 *       2     0   =0,  9, 10, 11, 12, 13, 14, ...
 *       2     1   =0,  9, 11, 13, 15, 17, 19, ...
 *       2     2   =0,  9, 12, 15, 18, 21, 24, ...
 *       2     3   =0,  9, 13, 17, 21, 25, 29, ...
 *       3     0   =0, 21, 22, 23, 24, 25, 26, ...
 *       3     1   =0, 21, 23, 25, 27, 29, 31, ...
 *       3     2   =0, 21, 24, 27, 30, 33, 36, ...
 *       3     3   =0, 21, 25, 29, 33, 37, 41, ...
*/
static_always_inline u32
clib_hgram_bucket_from_value (u32 type_flags, u64 v)
{
  u32 bucket = 0;
  u32 shift = 3 * (1 << CLIB_HGRAM_FLD_GET (CLIB_HGRAM_TYPE_FLAGS_SHIFT, type_flags)) - 3;
  /* shift is one of: 0, 3, 9, 21 */
  u64 bucket_v = v >> shift;
  if (PREDICT_TRUE (bucket_v))
    {
      bucket = 63 - __builtin_clzll(bucket_v);
      bucket /= (1+CLIB_HGRAM_FLD_GET (CLIB_HGRAM_TYPE_FLAGS_SCALE, type_flags));
      bucket += 1; /* +1 because bucket 0 is reserved for underflow/zero */
      u32 buckets = CLIB_HGRAM_ACTUAL_BUCKETS (type_flags);
      if (PREDICT_FALSE (bucket >= buckets))
        bucket = buckets - 1;
    }
  return bucket;
}

static_always_inline u32
clib_hgram_bucket_to_smallest_msb (u32 type_flags, u32 bucket)
{
  if (bucket == 0)
    return 0;

  u32 msb = (bucket-1) * (1+CLIB_HGRAM_FLD_GET (CLIB_HGRAM_TYPE_FLAGS_SCALE, type_flags));
  u32 shift = 3 * (1 << CLIB_HGRAM_FLD_GET (CLIB_HGRAM_TYPE_FLAGS_SHIFT, type_flags)) - 3;
  return msb + shift;
}

static_always_inline u64
clib_hgram_bucket_to_smallest_value (u32 type_flags, u32 bucket)
{
  if (bucket == 0)
    return 0ull;

  u32 msb = clib_hgram_bucket_to_smallest_msb (type_flags, bucket);
  if (msb > 63)
    msb = 63;

  return 1ull << msb;
}

/*
 * Node dispatch histogram, measuring packets per dispatch.  Buckets
 * per delta-t.
 */
typedef struct
{
  /* Histogram instance header. */
  clib_hgram_inst_hdr_t hdr;

  /* Summed delta-t of all samples. */
  u64 total_deltat;

  /* Summed v over all samples. */
  u64 total_v;

  /* (Most-recent) min-max delta-t. */
  clib_hgram_minmax_dt64_t minmax_deltat;

  /* (Most-recent) min-max v. */
  clib_hgram_minmax_dt64_t minmax_v;

  /* Buckets. */
  clib_hgram_bucket_dt64s_t bucket[0];

} clib_hgram_inst_dispatch_t;


/*
 * Pure interval histogram, measuring time windows only.  Bucket per
 * delta-t.
 */
typedef struct
{
  /* Histogram instance header. */
  clib_hgram_inst_hdr_t hdr;

  /* Summed delta-t of all samples. */
  u64 total_deltat;

  /* Start time of the current interval.  (Caller maintains this). */
  u64 start_cpu_time;

  /* (Most-recent) min-max delta-t. */
  clib_hgram_minmax_dt64_t minmax_deltat;

  /* Buckets. */
  clib_hgram_bucket_dts_t bucket[0];

} clib_hgram_inst_interval_t;


/* Union of all histogram types. */
typedef union
{
  clib_hgram_inst_hdr_t hdr;
  clib_hgram_inst_dispatch_t dispatch;
  clib_hgram_inst_interval_t interval;
} clib_hgram_inst_t;


/*
 * Histogram main.  One per vlib_main.
 */
typedef struct clib_hgram_main_t
{
  /*
   * Spinlock for adding instances in the owning thread, or for reading
   * the instances of one thread from the main thread.  Do not need to
   * take the lock to simply update an instance, or to index the vector
   * from the owning thread.
   */
  clib_spinlock_t lock;

  /* Vector of histogram instances */
  clib_hgram_inst_t** inst;

  /* Thread index of owning vlib_main. */
  u32 thread_index;

} clib_hgram_main_t;

/* Initilize a new histogram main. */
void
clib_hgram_main_init (clib_hgram_main_t* hm, u32 thread_index);

/*
 * Allocate and initialize a new histogram instance, and add it to the
 * histogram main.  The pointer may be memorized by the owner of the
 * instance.
 *
 * shift - Right-shift the sample by a number of bits before selecting
 *   a histogram bucket.
 * scale - Scale the buckets according to a power series.
 * buckets - The number of buckets in the histogram.
 * keep0 - If true, bucket samples with the value 0 (before shift).
 *   Otherwise, ignore those samples.
 */
void* clib_hgram_inst_new_impl (clib_hgram_main_t* hm,
                                const clib_hgram_dataset_desc_t* dataset_desc,
                                clib_hgram_layout_t layout,
                                u32 instance);

void* clib_hgram_inst_clone (clib_hgram_main_t* hm,
                             clib_hgram_inst_hdr_t* hi);

always_inline clib_hgram_inst_dispatch_t*
clib_hgram_inst_dispatch_new (clib_hgram_main_t* hm,
                              const clib_hgram_dataset_desc_t* dataset_desc,
                              u32 instance)
{
  if (PREDICT_TRUE (hm != NULL))
    {
      return clib_hgram_inst_new_impl (hm, dataset_desc,
                                       CLIB_HGRAM_LAYOUT_DISPATCH,
                                       instance);
    }
  return 0;
}

always_inline clib_hgram_inst_interval_t*
clib_hgram_inst_interval_new (clib_hgram_main_t* hm,
                              const clib_hgram_dataset_desc_t* dataset_desc,
                              u32 instance)
{
  if (PREDICT_TRUE (hm != NULL))
    {
      return clib_hgram_inst_new_impl (hm, dataset_desc,
                                       CLIB_HGRAM_LAYOUT_INTERVAL,
                                       instance);
    }
  return 0;
}

/* Add a sample to a dispatch histogram. */
void
clib_hgram_dispatch_sample_impl (clib_hgram_inst_dispatch_t* hi,
                                 u64 cpu_time, u64 deltat, u64 v);

always_inline void
clib_hgram_dispatch_sample (clib_hgram_inst_dispatch_t* hi,
                            u64 cpu_time, u64 deltat, u64 v)
{
  if (PREDICT_TRUE (hi != NULL && hi->hdr.type_flags & CLIB_HGRAM_TYPE_FLAGS_ENABLE))
    {
      if (   v
          || hi->hdr.type_flags & CLIB_HGRAM_TYPE_FLAGS_KEEP0)
        {
          clib_hgram_dispatch_sample_impl (hi, cpu_time, deltat, v);
        }
    }
}


/* Add a sample to a deltat histogram. */
void
clib_hgram_interval_end_impl (clib_hgram_inst_interval_t* hi,
                              u64 cpu_time);

always_inline void
clib_hgram_interval_end (clib_hgram_inst_interval_t* hi,
                         u64 cpu_time)
{
  if (PREDICT_TRUE (   hi != NULL
                    && hi->hdr.type_flags & CLIB_HGRAM_TYPE_FLAGS_ENABLE
                    && hi->start_cpu_time
                    && cpu_time))
    {
      if (   hi->start_cpu_time != cpu_time
          || hi->hdr.type_flags & CLIB_HGRAM_TYPE_FLAGS_KEEP0)
        {
          clib_hgram_interval_end_impl (hi, cpu_time);
        }
    }
}

/* Set start time on an interval histogram */
always_inline void
clib_hgram_interval_start (clib_hgram_inst_interval_t* hi,
                           u64 cpu_time)
{
  if (PREDICT_TRUE (hi != NULL))
    hi->start_cpu_time = cpu_time;
}

/*
 * Duplicate a histogram more or less atomically, in order to
 * display/send it.
 */
clib_hgram_inst_t*
clib_hgram_inst_dup_atomic (clib_hgram_inst_t* hi);

always_inline void
clib_hgram_main_lock (clib_hgram_main_t* hm)
{
  ASSERT(hm->lock);
  clib_spinlock_lock (&hm->lock);
}

always_inline void
clib_hgram_main_unlock (clib_hgram_main_t* hm)
{
  clib_spinlock_unlock (&hm->lock);
}

u8*
clib_hgram_format_name_thread (u8* s,
                               struct vlib_main_t* vm,
                               clib_hgram_inst_hdr_t* hi);


#endif /* ndef included_clib_histogram_h */
