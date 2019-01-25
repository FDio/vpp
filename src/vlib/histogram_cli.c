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

#include <ctype.h>

#include <vppinfra/mem.h>
#include <vppinfra/vec.h>
#include <vppinfra/histogram.h>

#include <vlib/vlib.h>

typedef struct
{
    u8* dataset;
    u32 thread_index;
    u8* name;
    u8* name_temp_;
} hgram_match_t;

typedef struct
{
    u64 since_cpu_time;
    u32 thread;
    u32 type_flags;
    u8 detail;
    u8 minmax;
    u8 sample;
    u8 empty;
    u8 cleared;
    u8 disabled;
} hgram_show_opts_t;

static u8
unformat_hgram_match (unformat_input_t* input,
                      hgram_match_t* match)
{
  u8 retval = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "dataset %v", &match->dataset))
        vec_terminate_c_string (match->dataset);
      else if (unformat (input, "thread %u", &match->thread_index))
        ;
      else if (unformat (input, "match %v", &match->name))
        vec_terminate_c_string (match->name);
      else
        break;
      retval = 1;
    }
  return retval;
}

static u8
unformat_hgram_show_opts (unformat_input_t* input,
                          hgram_show_opts_t* opts)
{
  u8 retval = 0;
  u32 recent;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "detail"))
        opts->detail = 1;
      else if (unformat (input, "verbose"))
        opts->detail = opts->minmax = opts->sample = 1;
      else if (unformat (input, "minmax"))
        opts->minmax = 1;
      else if (unformat (input, "recent %u", &recent))
        {
          vlib_main_t *vm = vlib_get_main ();
          if (recent == 0)
            recent = 1;
          if (recent > 60*60*24*365*10)
            recent = 60*60*24*365*10;

          f64 t = (f64)recent / vm->clib_time.seconds_per_clock;
          opts->since_cpu_time = vm->clib_time.last_cpu_time - (u64)t;
          if (opts->since_cpu_time > vm->clib_time.last_cpu_time)
            opts->since_cpu_time = 1;

          opts->sample = 1;
        }
      else if (unformat (input, "sample"))
        opts->sample = 1;
      else if (unformat (input, "empty"))
        opts->empty = 1;
      else if (unformat (input, "cleared"))
        opts->cleared = 1;
      else if (unformat (input, "disabled"))
        opts->disabled = 1;
      else
        break;
      retval = 1;
    }
  return retval;
}

static u8*
format_hgram_name (u8* s, va_list* args)
{
  vlib_main_t* vm = va_arg (*args, vlib_main_t*);
  clib_hgram_inst_hdr_t* hi = va_arg (*args, clib_hgram_inst_hdr_t*);

  ASSERT(hi);
  ASSERT(hi->dataset_desc);
  ASSERT(hi->dataset_desc->format_name_fp);
  return (hi->dataset_desc->format_name_fp) (s, vm, hi);
}

static u8
hgram_command_matches (clib_hgram_inst_t* hi,
                       vlib_main_t* vm,
                       hgram_match_t* match)
{
  ASSERT(hi);
  ASSERT(match);

  if (   vec_len (match->dataset)
      && 0 != strcmp ((char*)match->dataset, (char*)hi->hdr.dataset_desc->name))
    return 0;

  if (   match->thread_index != ~0
      && hi->hdr.thread_index != match->thread_index)
    return 0;

  if (vec_len (match->name))
    {
      vec_reset_length (match->name_temp_);
      match->name_temp_
        = format (match->name_temp_, "%U", format_hgram_name, vm, &hi->hdr);
      vec_terminate_c_string (match->name_temp_);

      if (NULL == strstr ((char*)match->name_temp_, (char*)match->name))
        return 0;
    }

  return 1;
}

static u8*
format_hgram_deltat (u8* s, va_list* args)
{
  u64 t = va_arg (*args, u64);
  if (!t)
    return format (s, "%10s", "-");

  vlib_main_t *vm = vlib_get_main ();
  f64 f = t * vm->clib_time.seconds_per_clock;
  if (f < 1e-8)
    return format (s, "%10llucl", t);
  if (f < 1e-6)
    return format (s, "   %5.1fns", f*1e9);
  if (f < 1e-3)
    return format (s, "%8.4fus", f*1e6);
  if (f < 1.0)
    return format (s, "%8.4fms", f*1e3);
  if (f < 60.0)
    return format (s, "%9.5fs", f);
  if (f < 60.0*60.0)
    return format (s, "%9.5fm", f/60.0);
  if (f < 24.0*60.0*60.0)
    return format (s, "%9.5fh", f/60.0/60.0);
  return format (s, "%9.4fd", f/60.0/60.0/24.0);
}

static u8*
format_hgram_timestamp (u8* s, va_list* args)
{
  u64 t = va_arg (*args, u64);
  if (!t)
    return format (s, "%20s", "-");
  vlib_main_t *vm = vlib_get_main ();
  f64 f = (t - vm->clib_time.init_cpu_time) * vm->clib_time.seconds_per_clock;
  return format (s, "%20U", format_time_interval, "d+h:m:s.u", f);
}

static u8*
format_hgram_bucket_dts (u8* s, va_list* args)
{
  clib_hgram_bucket_dts_t* bucket = va_arg (*args, clib_hgram_bucket_dts_t*);
  hgram_show_opts_t* opts = va_arg (*args, hgram_show_opts_t*);

  if (!bucket)
    {
      s = format (s, "%15s", "Samples");
      if (opts->sample)
        s = format (s, " %20s", "Last Sample Time");
      return s;
    }

  s = format (s, "%15llu", bucket->count);
  if (opts->sample)
    s = format (s, " %20U", format_hgram_timestamp, bucket->sample.cpu_time);
  return s;
}

static u8*
format_hgram_bucket_dt64s (u8* s, va_list* args)
{
  clib_hgram_bucket_dt64s_t* bucket = va_arg (*args, clib_hgram_bucket_dt64s_t*);
  hgram_show_opts_t* opts = va_arg (*args, hgram_show_opts_t*);

  if (!bucket)
    {
      s = format (s, "%15s", "Samples");
      if (opts->detail)
        s = format (s, " %20s %8s", "Total V", "V/Sample");
      if (opts->sample)
        s = format (s, " %20s %20s", "Last Sample Time", "Last Sample V");
      return s;
    }

  s = format (s, "%15llu", bucket->count);
  if (opts->detail)
    {
      if (bucket->count && bucket->total_v)
        s = format (s, " %20llu %8.4f", bucket->total_v, (f64)bucket->total_v/(f64)bucket->count);
      else
        s = format (s, " %20llu %8s", bucket->total_v, "-");
    }
  if (opts->sample)
    s = format (s, " %20U %20llu",
                format_hgram_timestamp, bucket->sample.cpu_time,
                bucket->sample.v );
  return s;
}

static u8*
format_hgram_bucket_label (u8* s, va_list* args)
{
  u32 bucket = va_arg (*args, u32);
  hgram_show_opts_t* opts = va_arg (*args, hgram_show_opts_t*);

  /*
   * ATTN: Should actually switch on layout/dataset to determine bucket
   * label type.  But right now, only deltat buckets exist.
   */
  if (bucket == ~0)
    return format (s, "%8s", "Bucket");

  char op = ' ';
  if (!(opts->type_flags & CLIB_HGRAM_TYPE_FLAGS_ENABLE))
    op = '$';
  if (opts->type_flags & CLIB_HGRAM_TYPE_FLAGS_CLEAR)
    op = '?';
  if (1 & CLIB_HGRAM_FLD_GET (CLIB_HGRAM_TYPE_FLAGS_UPDATING, opts->type_flags))
    op = '!';

  if (bucket == 0)
    {
      ++bucket;
      op = '<';
    }
  u64 t = clib_hgram_bucket_to_smallest_value (opts->type_flags, bucket);

  if (bucket == (CLIB_HGRAM_ACTUAL_BUCKETS(opts->type_flags)-1))
    op = '>';

  vlib_main_t *vm = vlib_get_main ();
  f64 f = t * vm->clib_time.seconds_per_clock;

  if (f < 1e-8)
    return format (s, "%c%5llucl", op, t);
  if (f < 1e-6)
    return format (s, "%c%5.1fns", op, f*1e9);
  if (f < 1e-3)
    return format (s, "%c%5.1fus", op, f*1e6);
  if (f < 1.0)
    return format (s, "%c%5.1fms", op, f*1e3);
  if (f < 60.0)
    return format (s, "%c%6.3fs", op, f);
  if (f < 60.0*60.0)
    return format (s, "%c%6.3fm", op, f/60.0);
  if (f < 24.0*60.0*60.0)
    return format (s, "%c%6.3fh", op, f/60.0/60.0);
  return format (s, "%c%6.1fd", op, f/60.0/60.0/24.0);
}

static u8*
format_hgram_inst_interval (u8* s, va_list* args)
{
  clib_hgram_inst_interval_t* hi = va_arg (*args, clib_hgram_inst_interval_t*);
  hgram_show_opts_t* opts = va_arg (*args, hgram_show_opts_t*);

  u8* hdr = format (NULL, "%U %U",
                    format_hgram_bucket_label, ~(u32)0, opts,
                    format_hgram_bucket_dts, NULL, opts);
  u32 bucket;
  for (bucket = 0; bucket < CLIB_HGRAM_ACTUAL_BUCKETS(opts->type_flags); ++bucket)
    {
      if (hi->bucket[bucket].count == 0 && !opts->empty)
        continue;
      if (hi->bucket[bucket].sample.cpu_time < opts->since_cpu_time)
        continue;

      s = format (s, "%v\n", hdr);
      vec_free (hdr);
      s = format (s, "%U %U",
                  format_hgram_bucket_label, bucket, opts,
                  format_hgram_bucket_dts, &hi->bucket[bucket], opts);
    }
  vec_free (hdr);
  if (!vec_len(s))
    return s;

  if (opts->detail && !opts->since_cpu_time)
    s = format (s, "\n%8s %15U", "Total dT",
                format_hgram_deltat, hi->total_deltat);

  if (   opts->minmax
      && hi->minmax_deltat.min.cpu_time >= opts->since_cpu_time)
    s = format (s, "\n%8s %15U %20U",
                "Min dT",
                format_hgram_deltat, hi->minmax_deltat.min.v,
                format_hgram_timestamp, hi->minmax_deltat.min.cpu_time);

  if (   opts->minmax
      && hi->minmax_deltat.max.cpu_time >= opts->since_cpu_time)
    s = format (s, "\n%8s %15U %20U",
                "Max dT",
                format_hgram_deltat, hi->minmax_deltat.max.v,
                format_hgram_timestamp, hi->minmax_deltat.max.cpu_time);
  return s;
}

static u8*
format_hgram_inst_dispatch (u8* s, va_list* args)
{
  clib_hgram_inst_dispatch_t* hi = va_arg (*args, clib_hgram_inst_dispatch_t*);
  hgram_show_opts_t* opts = va_arg (*args, hgram_show_opts_t*);

  u8* hdr = format (NULL, "%U %U",
                    format_hgram_bucket_label, ~(u32)0, opts,
                    format_hgram_bucket_dt64s, NULL, opts);
  u32 bucket;
  for (bucket = 0; bucket < CLIB_HGRAM_ACTUAL_BUCKETS(opts->type_flags); ++bucket)
    {
      if (hi->bucket[bucket].count == 0 && !opts->empty)
        continue;
      if (hi->bucket[bucket].sample.cpu_time < opts->since_cpu_time)
        continue;

      s = format (s, "%v\n", hdr);
      vec_free (hdr);
      s = format (s, "%U %U",
                  format_hgram_bucket_label, bucket, opts,
                  format_hgram_bucket_dt64s, &hi->bucket[bucket], opts);
    }
  vec_free (hdr);
  if (!vec_len(s))
    return s;

  if (opts->detail && !opts->since_cpu_time)
    s = format (s, "\n%8s %15U %20llu", "Tot dT,V",
                format_hgram_deltat, hi->total_deltat, hi->total_v);

  if (   opts->minmax
      && hi->minmax_deltat.min.cpu_time >= opts->since_cpu_time)
    s = format (s, "\n%8s %15U %20U",
                "Min dT",
                format_hgram_deltat, hi->minmax_deltat.min.v,
                format_hgram_timestamp, hi->minmax_deltat.min.cpu_time);

  if (   opts->minmax
      && hi->minmax_deltat.max.cpu_time >= opts->since_cpu_time)
    s = format (s, "\n%8s %15U %20U",
                "Max dT",
                format_hgram_deltat, hi->minmax_deltat.max.v,
                format_hgram_timestamp, hi->minmax_deltat.max.cpu_time);

  if (   opts->minmax
      && hi->minmax_v.min.cpu_time >= opts->since_cpu_time)
    s = format (s, "\n%8s %15llu %20U",
                "Min V",
                hi->minmax_v.min.v,
                format_hgram_timestamp, hi->minmax_v.min.cpu_time);

  if (   opts->minmax
      && hi->minmax_v.max.cpu_time >= opts->since_cpu_time)
    s = format (s, "\n%8s %15llu %20U",
                "Max V",
                hi->minmax_v.max.v,
                format_hgram_timestamp, hi->minmax_v.max.cpu_time);

  return s;
}

static u8*
format_hgram_inst (u8* s, va_list* args)
{
  clib_hgram_inst_t* hi = va_arg (*args, clib_hgram_inst_t*);
  hgram_show_opts_t* opts = va_arg (*args, hgram_show_opts_t*);

  clib_hgram_layout_t layout = CLIB_HGRAM_FLD_GET (CLIB_HGRAM_TYPE_FLAGS_LAYOUT, hi->hdr.type_flags);
  switch (layout)
    {
      case CLIB_HGRAM_LAYOUT_DISPATCH:
        return format (s, "%U", format_hgram_inst_dispatch, &hi->dispatch, opts);
      case CLIB_HGRAM_LAYOUT_INTERVAL:
        return format (s, "%U", format_hgram_inst_interval, &hi->interval, opts);
      default:
        break;
    }
  return format (s, "**UNKNOWN**");
}

static clib_error_t *
show_hgram_command_fn (vlib_main_t* vm, unformat_input_t* input,
                       vlib_cli_command_t* cmd)
{
  hgram_match_t match = {
    .thread_index = ~0,
    .name = 0,
    .name_temp_ = 0,
  };
  hgram_show_opts_t opts = {0};

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_hgram_match (input, &match))
        ;
      else if (unformat_hgram_show_opts (input, &opts))
        ;
      else
        return unformat_parse_error (input);
    }

  char* sep = "";
  uword vmi;
  for (vmi = 0; vmi < vec_len (vlib_mains); ++vmi)
    {
      opts.thread = vmi;
      vlib_main_t* chk_vm = vlib_mains[vmi];
      clib_hgram_main_t* hm = &chk_vm->hgram_main;

      // Duplicate the vector of instances within a critical section
      clib_hgram_main_lock (hm);
      clib_hgram_inst_t** dup_hist = vec_dup (hm->inst);
      clib_hgram_main_unlock (hm);

      /*
       * Search for and duplicate the instances that match the command.
       * The duplication freezes the values, allowing the print to
       * proceed on a consistent image.
       */
      uword hii;
      for (hii = 0; hii < vec_len (dup_hist); ++hii)
        {
          clib_hgram_inst_t* hi = dup_hist[hii];
          dup_hist[hii] = 0;
          if (!hi)
            continue;
          if (!opts.disabled && !(hi->hdr.type_flags & CLIB_HGRAM_TYPE_FLAGS_ENABLE))
            continue;
          if (!opts.cleared && (hi->hdr.type_flags & CLIB_HGRAM_TYPE_FLAGS_CLEAR))
            continue;
          if (!hgram_command_matches(hi, chk_vm, &match))
            continue;

          dup_hist[hii] = clib_hgram_inst_dup_atomic (hi);
        }

      for (hii = 0; hii < vec_len (dup_hist); ++hii)
        {
          clib_hgram_inst_t* hi = dup_hist[hii];
          if (!hi)
            continue;

          opts.type_flags = hi->hdr.type_flags;
          u8* s = format (NULL, "%U", format_hgram_inst, hi, &opts);
          if (vec_len(s))
            {
              vlib_cli_output (vm, "%s%U (index %u)%s%s\n%v",
                               sep, format_hgram_name, chk_vm, &hi->hdr, hii,
                               (opts.type_flags & CLIB_HGRAM_TYPE_FLAGS_CLEAR) ? " +CLR" : "",
                               (opts.type_flags & CLIB_HGRAM_TYPE_FLAGS_ENABLE) ? "" : " -ENA",
                               s );
              sep = "\n";
            }
          vec_free (s);
          clib_mem_free (hi);
          dup_hist[hii] = 0;
        }

      vec_free (dup_hist);
    }

  vec_free (match.name);
  vec_free (match.name_temp_);
  return NULL;
}

static clib_error_t *
clear_hgram_command_fn (vlib_main_t* vm, unformat_input_t* input,
                        vlib_cli_command_t* cmd)
{
  hgram_match_t match = {
      .thread_index = ~0,
      .name = 0,
      .name_temp_ = 0,
  };

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_hgram_match (input, &match))
        ;
      else
        return unformat_parse_error (input);
    }
  
  uword vmi;
  for (vmi = 0; vmi < vec_len (vlib_mains); ++vmi)
    {
      vlib_main_t* chk_vm = vlib_mains[vmi];
      clib_hgram_main_t* hm = &chk_vm->hgram_main;

      // Iterate the vector of instances within a critical section
      clib_hgram_main_lock (hm);

      uword hii;
      for (hii = 0; hii < vec_len (hm->inst); ++hii)
        {
          clib_hgram_inst_t* hi = hm->inst[hii];
          if (!hi)
            continue;
          if (hgram_command_matches(hi, vm, &match))
            __sync_fetch_and_or (&hi->hdr.type_flags, CLIB_HGRAM_TYPE_FLAGS_CLEAR);
        }
      clib_hgram_main_unlock (hm);
    }

  vec_free (match.name);
  vec_free (match.name_temp_);
  return NULL;
}

static clib_error_t *
set_hgram_command_fn (vlib_main_t* vm, unformat_input_t* input,
                      vlib_cli_command_t* cmd)
{
  hgram_match_t match = {
      .thread_index = ~0,
      .name = 0,
      .name_temp_ = 0,
  };

  u8 disable = 0;
  u8 enable = 0;
  u8 keep0 = 0;
  u8 discard0 = 0;
  u32 shift = CLIB_HGRAM_SHIFT_last;
  u32 scale = CLIB_HGRAM_SCALE_last;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_hgram_match (input, &match))
        ;
      else if (unformat (input, "disable"))
        disable = 1;
      else if (unformat (input, "enable"))
        enable = 1;
      else if (unformat (input, "keep-0"))
        keep0 = 1;
      else if (unformat (input, "discard-0"))
        discard0 = 1;

#define F(e, v, a) \
      else if (unformat (input, "shift " #a)) \
        shift = e;
      foreach_clib_hgram_shift (F)
#undef F

#define F(e, v, l) \
      else if (unformat (input, "log " #l)) \
        scale = e;
      foreach_clib_hgram_scale (F)
#undef F

      else
        return unformat_parse_error (input);
    }

  uword vmi;
  for (vmi = 0; vmi < vec_len (vlib_mains); ++vmi)
    {
      vlib_main_t* chk_vm = vlib_mains[vmi];
      clib_hgram_main_t* hm = &chk_vm->hgram_main;

      // Iterate the vector of instances within a critical section
      clib_hgram_main_lock (hm);

      uword hii;
      for (hii = 0; hii < vec_len (hm->inst); ++hii)
        {
          clib_hgram_inst_t* hi = hm->inst[hii];
          if (!hi)
            continue;
          if (!hgram_command_matches(hi, vm, &match))
            continue;

          uword try;
          for (try = 0; try < 3; ++try)
            {
              u32 type_flags = hi->hdr.type_flags;
              u32 new_type_flags = type_flags;

              if (enable)
                new_type_flags = CLIB_HGRAM_FLD_CHANGE (
                    CLIB_HGRAM_TYPE_FLAGS_ENABLE, new_type_flags, 1);
              else if (disable)
                new_type_flags = CLIB_HGRAM_FLD_CHANGE (
                    CLIB_HGRAM_TYPE_FLAGS_ENABLE, new_type_flags, 0);

              if (keep0)
                new_type_flags = CLIB_HGRAM_FLD_CHANGE (
                    CLIB_HGRAM_TYPE_FLAGS_KEEP0, new_type_flags, 1);
              else if (discard0)
                new_type_flags = CLIB_HGRAM_FLD_CHANGE (
                    CLIB_HGRAM_TYPE_FLAGS_KEEP0, new_type_flags, 0);

              if (shift != CLIB_HGRAM_SHIFT_last)
                {
                  new_type_flags = CLIB_HGRAM_FLD_CHANGE (
                      CLIB_HGRAM_TYPE_FLAGS_SHIFT, new_type_flags, shift);
                  new_type_flags = CLIB_HGRAM_FLD_CHANGE (
                      CLIB_HGRAM_TYPE_FLAGS_CLEAR, new_type_flags, 1);
                }
              if (scale != CLIB_HGRAM_SCALE_last)
                {
                  new_type_flags = CLIB_HGRAM_FLD_CHANGE (
                      CLIB_HGRAM_TYPE_FLAGS_SCALE, new_type_flags, scale);
                  new_type_flags = CLIB_HGRAM_FLD_CHANGE (
                      CLIB_HGRAM_TYPE_FLAGS_CLEAR, new_type_flags, 1);
                }

              if (__sync_bool_compare_and_swap (&hi->hdr.type_flags, type_flags, new_type_flags))
                break;
            }
        }
      clib_hgram_main_unlock (hm);
    }

  vec_free (match.name);
  vec_free (match.name_temp_);
  return NULL;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_histogram_command, static) = {
  .path = "show histogram",
  .short_help = "show histogram [dataset D] [thread T] [match NAME]"
                " [sample] [recent SEC] [verbose] [detail] [minmax] [empty] [cleared] [disabled]",
  .function = show_hgram_command_fn,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_histogram_command, static) = {
  .path = "clear histogram",
  .short_help = "clear histogram [dataset D] [thread T] [match NAME]",
  .function = clear_hgram_command_fn,
  .is_mp_safe = 1,
};

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_histogram_command, static) = {
  .path = "set histogram",
  .short_help = "set histogram [dataset D] [thread T] [match NAME]"
                " [enable|disable] [keep-0|discard-0] [shift 0|3|9|21] [log 2|4|8|16]",
  .function = set_hgram_command_fn,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

