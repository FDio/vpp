/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/error.h>

test_main_t test_main;

int
test_march_supported (clib_march_variant_type_t type)
{
#define _(s, n)                                                               \
  if (CLIB_MARCH_VARIANT_TYPE_##s == type)                                    \
    return clib_cpu_march_priority_##s ();
  foreach_march_variant
#undef _
    return 0;
}

clib_error_t *
test_funct (test_main_t *tm)
{
  for (int i = 0; i < CLIB_MARCH_TYPE_N_VARIANTS; i++)
    {
      test_registration_t *r = tm->registrations[i];

      if (r == 0 || test_march_supported (i) < 0)
	continue;

      fformat (stdout, "\nMultiarch Variant: %U\n", format_march_variant, i);
      fformat (stdout,
	       "-------------------------------------------------------\n");
      while (r)
	{
	  clib_error_t *err;
	  if (tm->filter && strstr (r->name, (char *) tm->filter) == 0)
	    goto next;
	  err = (r->fn) (0);
	  fformat (stdout, "%-50s %s\n", r->name, err ? "FAIL" : "PASS");
	  if (err)
	    {
	      clib_error_report (err);
	      fformat (stdout, "\n");
	    }
	next:
	  r = r->next;
	}
    }

  fformat (stdout, "\n");
  return 0;
}

#if 0
static u8 *
format_test_perf_bundle_core_power (u8 *s, va_list *args)
{
  test_perf_event_bundle_t __clib_unused *b =
    va_arg (*args, test_perf_event_bundle_t *);
  test_perf_t __clib_unused *tp = va_arg (*args, test_perf_t *);
  u64 *data = va_arg (*args, u64 *);

  if (data)
    s = format (s, "%7.1f %%", (f64) 100 * data[1] / data[0]);
  else
    s = format (s, "%9s", "Level 0");

  if (data)
    s = format (s, "%8.1f %%", (f64) 100 * data[2] / data[0]);
  else
    s = format (s, "%9s", "Level 1");

  if (data)
    s = format (s, "%7.1f %%", (f64) 100 * data[3] / data[0]);
  else
    s = format (s, "%9s", "Level 2");

  return s;
}

#ifdef __x86_64__
#define PERF_INTEL_CODE(event, umask) ((event) | (umask) << 8)
  ,
  {
    .name = "core-power",
    .desc =
      "Core cycles where the core was running under specific turbo schedule.",
    .type = PERF_TYPE_RAW,
    .config[0] = PERF_INTEL_CODE (0x3c, 0x00),
    .config[1] = PERF_INTEL_CODE (0x28, 0x07),
    .config[2] = PERF_INTEL_CODE (0x28, 0x18),
    .config[3] = PERF_INTEL_CODE (0x28, 0x20),
    .config[4] = PERF_INTEL_CODE (0x28, 0x40),
    .n_events = 5,
    .format_fn = format_test_perf_bundle_core_power,
  }
#endif
};
#endif

#ifdef __linux__
clib_error_t *
test_perf (test_main_t *tm)
{
  clib_error_t *err = 0;
  clib_perfmon_ctx_t _ctx, *ctx = &_ctx;

  if ((err = clib_perfmon_init_by_bundle_name (
	 ctx, "%s", tm->bundle ? (char *) tm->bundle : "default")))
    return err;

  fformat (stdout, "Warming up...\n");
  clib_perfmon_warmup (ctx);

  for (int i = 0; i < CLIB_MARCH_TYPE_N_VARIANTS; i++)
    {
      test_registration_t *r = tm->registrations[i];

      if (r == 0 || test_march_supported (i) < 0)
	continue;

      fformat (stdout, "\nMultiarch Variant: %U\n", format_march_variant, i);
      fformat (stdout,
	       "-------------------------------------------------------\n");
      while (r)
	{
	  if (r->perf_tests)
	    {
	      test_perf_t *pt = r->perf_tests;
	      if (tm->filter && strstr (r->name, (char *) tm->filter) == 0)
		goto next;

	      clib_perfmon_capture_group (ctx, "%s", r->name);
	      do
		{
		  for (int i = 0; i < tm->repeat; i++)
		    {
		      pt->fd = ctx->group_fd;
		      clib_perfmon_reset (ctx);
		      pt->fn (pt);
		      clib_perfmon_capture (ctx, pt->n_ops, "%0s", pt->name);
		    }
		}
	      while ((++pt)->fn);
	    }
	next:
	  r = r->next;
	}
      fformat (stdout, "%U\n", format_perfmon_bundle, ctx);
      clib_perfmon_clear (ctx);
    }

  clib_perfmon_free (ctx);
  return err;
}
#endif

int
main (int argc, char *argv[])
{
  test_main_t *tm = &test_main;
  unformat_input_t _i = {}, *i = &_i;
  clib_mem_init (0, 64ULL << 20);
  clib_error_t *err;
  int perf = 0;

  /* defaults */
  tm->repeat = 3;

  unformat_init_command_line (i, argv);

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "perf"))
	perf = 1;
      else if (unformat (i, "filter %s", &tm->filter))
	;
      else if (unformat (i, "bundle %s", &tm->bundle))
	;
      else if (unformat (i, "repeat %d", &tm->repeat))
	;
      else
	{
	  clib_warning ("unknown input '%U'", format_unformat_error, i);
	  exit (1);
	}
    }

  if (perf)
    err = test_perf (tm);
  else
    err = test_funct (tm);

  if (err)
    {
      clib_error_report (err);
      fformat (stderr, "\n");
      return 1;
    }
  return 0;
}

void *
test_mem_alloc (uword size)
{
  void *rv;
  size = round_pow2 (size, CLIB_CACHE_LINE_BYTES);
  rv = clib_mem_alloc_aligned (size, CLIB_CACHE_LINE_BYTES);
  clib_memset_u8 (rv, 0, size);
  return rv;
}

void *
test_mem_alloc_and_fill_inc_u8 (uword size, u8 start, u8 mask)
{
  u8 *rv;
  mask = mask ? mask : 0xff;
  size = round_pow2 (size, CLIB_CACHE_LINE_BYTES);
  rv = clib_mem_alloc_aligned (size, CLIB_CACHE_LINE_BYTES);
  for (uword i = 0; i < size; i++)
    rv[i] = ((u8) i + start) & mask;
  return rv;
}

void *
test_mem_alloc_and_splat (uword elt_size, uword n_elts, void *elt)
{
  u8 *rv, *e;
  uword data_size = elt_size * n_elts;
  uword alloc_size = round_pow2 (data_size, CLIB_CACHE_LINE_BYTES);
  e = rv = clib_mem_alloc_aligned (alloc_size, CLIB_CACHE_LINE_BYTES);
  while (e - rv < data_size)
    {
      clib_memcpy_fast (e, elt, elt_size);
      e += elt_size;
    }

  if (data_size < alloc_size)
    clib_memset_u8 (e, 0, alloc_size - data_size);
  return rv;
}

void
test_mem_free (void *p)
{
  clib_mem_free (p);
}
