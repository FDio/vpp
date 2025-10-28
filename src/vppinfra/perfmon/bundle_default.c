/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/perfmon/perfmon.h>

static u8 *
format_perfmon_bundle_default (u8 *s, va_list *args)
{
  clib_perfmon_ctx_t __clib_unused *ctx = va_arg (*args, clib_perfmon_ctx_t *);
  clib_perfmon_capture_t *c = va_arg (*args, clib_perfmon_capture_t *);
  u32 col = va_arg (*args, int);
  u64 *d = c->data;

  switch (col)
    {
    case 0:
      return format (s, "%5.2f", (f64) d[1] / d[0]);
    case 1:
      return format (s, "%8u", d[0]);
    case 2:
      return format (s, "%8.2f", (f64) d[0] / c->n_ops);
    case 3:
      return format (s, "%8u", d[1]);
    case 4:
      return format (s, "%8.2f", (f64) d[1] / c->n_ops);
    case 5:
      return format (s, "%9u", d[2]);
    case 6:
      return format (s, "%9.2f", (f64) d[2] / c->n_ops);
    case 7:
      return format (s, "%10u", d[3]);
    case 8:
      return format (s, "%10.2f", (f64) d[3] / c->n_ops);
#ifdef __x86_64__
    case 9:
      if (ctx->ref_clock > 0)
	return format (s, "%8.1f", (f64) d[0] / d[4] * (ctx->ref_clock / 1e9));
      else
	return s;
#endif
    default:
      return s;
    }
}

CLIB_PERFMON_BUNDLE (default) = {
  .name = "default",
  .desc = "IPC, Clocks/Operatiom, Instr/Operation, Branch Total & Miss",
  .type = PERF_TYPE_HARDWARE,
  .config[0] = PERF_COUNT_HW_CPU_CYCLES,
  .config[1] = PERF_COUNT_HW_INSTRUCTIONS,
  .config[2] = PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
  .config[3] = PERF_COUNT_HW_BRANCH_MISSES,
#ifdef __x86_64__
  .config[4] = PERF_COUNT_HW_REF_CPU_CYCLES,
  .n_events = 5,
#else
  .n_events = 4,
#endif
  .format_fn = format_perfmon_bundle_default,
  .column_headers = CLIB_STRING_ARRAY ("IPC", "Clks", "Clks/Op", "Inst",
				       "Inst/Op", "Brnch", "Brnch/Op",
				       "BrMiss", "BrMiss/Op"
#ifdef __x86_64__
				       ,
				       "Freq"
#endif
				       ),
};
