/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/perfmon/perfmon.h>

static u8 *
format_perfmon_bundle_default (u8 *s, va_list *args)
{
  clib_perfmon_ctx_t *ctx = va_arg (*args, clib_perfmon_ctx_t *);
  clib_perfmon_capture_t *c = va_arg (*args, clib_perfmon_capture_t *);
  u32 col = va_arg (*args, int);
  u64 *d = c->data;

  switch (col)
    {
    case 0:
      if (ctx->ref_clock > 0)
	return format (s, "%8.1f", (f64) d[0] / d[1] * (ctx->ref_clock / 1e9));
      else
	return s;
    case 1:
      return format (s, "%5.2f", (f64) d[2] / d[0]);
    case 2:
      return format (s, "%8u", d[0]);
    case 3:
      return format (s, "%8.2f", (f64) d[0] / c->n_ops);
    case 4:
      return format (s, "%8u", d[2]);
    case 5:
      return format (s, "%8.2f", (f64) d[2] / c->n_ops);
    case 6:
      return format (s, "%9u", d[3]);
    case 7:
      return format (s, "%9.2f", (f64) d[3] / c->n_ops);
    case 8:
      return format (s, "%10u", d[4]);
    case 9:
      return format (s, "%10.2f", (f64) d[4] / c->n_ops);
    default:
      return s;
    }
}

CLIB_PERFMON_BUNDLE (default) = {
  .name = "default",
  .desc = "IPC, Clocks/Operatiom, Instr/Operation, Branch Total & Miss",
  .type = PERF_TYPE_HARDWARE,
  .config[0] = PERF_COUNT_HW_CPU_CYCLES,
  .config[1] = PERF_COUNT_HW_REF_CPU_CYCLES,
  .config[2] = PERF_COUNT_HW_INSTRUCTIONS,
  .config[3] = PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
  .config[4] = PERF_COUNT_HW_BRANCH_MISSES,
  .n_events = 5,
  .format_fn = format_perfmon_bundle_default,
  .column_headers = CLIB_STRING_ARRAY ("Freq", "IPC", "Clks", "Clks/Op",
				       "Inst", "Inst/Op", "Brnch", "Brnch/Op",
				       "BrMiss", "BrMiss/Op"),
};
