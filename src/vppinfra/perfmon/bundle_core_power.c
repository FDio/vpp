/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#ifdef __x86_64__

#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/perfmon/perfmon.h>

static u8 *
format_perfmon_bundle_core_power (u8 *s, va_list *args)
{
  clib_perfmon_ctx_t __clib_unused *ctx = va_arg (*args, clib_perfmon_ctx_t *);
  clib_perfmon_capture_t *c = va_arg (*args, clib_perfmon_capture_t *);
  u32 col = va_arg (*args, int);
  u64 *d = c->data;

  switch (col)
    {
    case 0:
      return format (s, "%7.1f %%", (f64) 100 * d[1] / d[0]);
    case 1:
      return format (s, "%7.1f %%", (f64) 100 * d[2] / d[0]);
    case 2:
      return format (s, "%7.1f %%", (f64) 100 * d[3] / d[0]);
    default:
      return s;
    }
}

#define PERF_INTEL_CODE(event, umask) ((event) | (umask) << 8)

CLIB_PERFMON_BUNDLE (core_power) = {
  .name = "core-power",
  .desc =
    "Core cycles where the core was running under specific turbo schedule.",
  .type = PERF_TYPE_RAW,
  .config[0] = PERF_INTEL_CODE (0x3c, 0x00),
  .config[1] = PERF_INTEL_CODE (0x28, 0x07),
  .config[2] = PERF_INTEL_CODE (0x28, 0x18),
  .config[3] = PERF_INTEL_CODE (0x28, 0x20),
  .n_events = 4,
  .format_fn = format_perfmon_bundle_core_power,
  .column_headers = CLIB_STRING_ARRAY ("Level 0", "Level 1", "Level 2"),
};

#endif
