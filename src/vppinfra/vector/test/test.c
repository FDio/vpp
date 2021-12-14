/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/vector/test/test.h>
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

#define TEST_PERF_MAX_EVENTS 7
typedef struct
{
  char *name;
  char *desc;
  u64 config[TEST_PERF_MAX_EVENTS];
  u32 type;
  u8 n_events;
  format_function_t *format_fn;
} test_perf_event_bundle_t;

static u8 *
format_test_perf_bundle_default (u8 *s, va_list *args)
{
  test_main_t *tm = &test_main;
  test_perf_event_bundle_t __clib_unused *b =
    va_arg (*args, test_perf_event_bundle_t *);
  test_perf_t *tp = va_arg (*args, test_perf_t *);
  u64 *data = va_arg (*args, u64 *);

  if (tm->ref_clock > 0)
    {
      if (data)
	s = format (s, "%8.1f", tm->ref_clock * data[0] / data[1] / 1e9);
      else
	s = format (s, "%8s", "Freq");
    }

  if (data)
    s = format (s, "%5.2f", (f64) data[2] / data[0]);
  else
    s = format (s, "%5s", "IPC");

  if (data)
    s = format (s, "%8.2f", (f64) data[0] / tp->n_ops);
  else
    s = format (s, "%8s", "Clks/Op");

  if (data)
    s = format (s, "%8.2f", (f64) data[2] / tp->n_ops);
  else
    s = format (s, "%8s", "Inst/Op");

  if (data)
    s = format (s, "%9.2f", (f64) data[3] / tp->n_ops);
  else
    s = format (s, "%9s", "Brnch/Op");

  if (data)
    s = format (s, "%10.2f", (f64) data[4] / tp->n_ops);
  else
    s = format (s, "%10s", "BrMiss/Op");
  return s;
}

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

test_perf_event_bundle_t perf_bundles[] = {
  {
    .name = "default",
    .desc = "IPC, Clocks/Operatiom, Instr/Operation, Branch Total & Miss",
    .type = PERF_TYPE_HARDWARE,
    .config[0] = PERF_COUNT_HW_CPU_CYCLES,
    .config[1] = PERF_COUNT_HW_REF_CPU_CYCLES,
    .config[2] = PERF_COUNT_HW_INSTRUCTIONS,
    .config[3] = PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
    .config[4] = PERF_COUNT_HW_BRANCH_MISSES,
    .n_events = 5,
    .format_fn = format_test_perf_bundle_default,
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

#ifdef __linux__
clib_error_t *
test_perf (test_main_t *tm)
{
  clib_error_t *err = 0;
  test_perf_event_bundle_t *b = 0;
  int group_fd = -1, fds[TEST_PERF_MAX_EVENTS];
  u64 count[TEST_PERF_MAX_EVENTS + 3] = {};
  struct perf_event_attr pe = {
    .size = sizeof (struct perf_event_attr),
    .disabled = 1,
    .exclude_kernel = 1,
    .exclude_hv = 1,
    .pinned = 1,
    .exclusive = 1,
    .read_format = (PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED |
		    PERF_FORMAT_TOTAL_TIME_RUNNING),
  };

  for (int i = 0; i < TEST_PERF_MAX_EVENTS; i++)
    fds[i] = -1;

  tm->ref_clock = os_cpu_clock_frequency ();

  if (tm->bundle)
    {
      for (int i = 0; i < ARRAY_LEN (perf_bundles); i++)
	if (strncmp ((char *) tm->bundle, perf_bundles[i].name,
		     vec_len (tm->bundle)) == 0)
	  {
	    b = perf_bundles + i;
	    break;
	  }
      if (b == 0)
	return clib_error_return (0, "Unknown bundle '%s'", tm->bundle);
    }
  else
    b = perf_bundles;

  for (int i = 0; i < b->n_events; i++)
    {
      pe.config = b->config[i];
      pe.type = b->type;
      int fd = syscall (__NR_perf_event_open, &pe, /* pid */ 0, /* cpu */ -1,
			/* group_fd */ group_fd, /* flags */ 0);
      if (fd < 0)
	{
	  err = clib_error_return_unix (0, "perf_event_open");
	  goto done;
	}

      if (group_fd == -1)
	{
	  group_fd = fd;
	  pe.pinned = 0;
	  pe.exclusive = 0;
	}
      fds[i] = fd;
    }
  fformat (stdout, "Warming up...\n");
  for (u64 i = 0; i < (u64) tm->ref_clock; i++)
    asm inline("" : : "r"(i * i) : "memory");

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
	      fformat (stdout, "%-22s%-12s%U\n", r->name, "OpType",
		       b->format_fn, b, pt, 0UL);
	      do
		{
		  u32 read_size = (b->n_events + 3) * sizeof (u64);
		  for (int i = 0; i < tm->repeat; i++)
		    {
		      test_perf_event_reset (group_fd);
		      pt->fn (group_fd, pt);
		      if ((read (group_fd, &count, read_size) != read_size))
			{
			  err = clib_error_return_unix (0, "read");
			  goto done;
			}
		      if (count[1] != count[2])
			clib_warning (
			  "perf counters were not running all the time."
#ifdef __x86_64__
			  "\nConsider turning NMI watchdog off ('sysctl -w "
			  "kernel.nmi_watchdog=0')."
#endif
			);
		      fformat (stdout, "  %-20s%-12s%U\n", pt->name,
			       pt->op_name ? pt->op_name : "", b->format_fn, b,
			       pt, count + 3);
		    }
		}
	      while ((++pt)->fn);
	    }
	next:
	  r = r->next;
	}
    }

done:
  for (int i = 0; i < TEST_PERF_MAX_EVENTS; i++)
    if (fds[i] != -1)
      close (fds[i]);
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
