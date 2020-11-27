/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vppinfra/linux/sysfs.h>
#include <perfmon2/perfmon2.h>
#include <perfmon2/ia32_core/ia32_core.h>

/* *INDENT-OFF* */
VLIB_REGISTER_LOG_CLASS (if_ia32_uncore_log, static) = {
  .class_name = "perfmon2",
  .subclass_name = "ia32-uncore",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};
/* *INDENT-ON* */

#define log_debug(fmt,...) vlib_log_debug(if_ia32_uncore_log.class, fmt, __VA_ARGS__)
#define log_warn(fmt,...) vlib_log_warn(if_ia32_uncore_log.class, fmt, __VA_ARGS__)
#define log_err(fmt,...) vlib_log_err(if_ia32_uncore_log.class, fmt, __VA_ARGS__)

#define foreach_ia32_uncore_unit_type \
  _(IMC, "imc") \
  _(UPI, "upi") \

typedef enum
{
#define _(a,b) PERFMON2_IA32_UNCORE_UNIT_##a,
  foreach_ia32_uncore_unit_type
#undef _
} ia32_uncore_unit_type_t;

typedef struct
{
  u16 cpu_id;
  u8 numa;
  ia32_uncore_unit_type_t unit:8;
  u32 type;
} ia32_uncore_unit_t;

ia32_uncore_unit_t *ia32_uncore_units = 0;

static void
intel_ia32_uncore_add_unit (ia32_uncore_unit_type_t unit, char *name,
			    int *numa_by_cpu_id)
{
  static char *base_path = "/sys/bus/event_source/devices/uncore";
  clib_error_t *err;
  clib_bitmap_t *cpumask = 0;
  ia32_uncore_unit_t *u;
  u8 *s = 0;
  int i = 0, j;
  u32 perf_type;

  while (1)
    {
      s = format (s, "%s_%s_%u/type%c", base_path, name, i, 0);
      if ((err = clib_sysfs_read ((char *) s, "%u", &perf_type)))
	break;
      vec_reset_length (s);

      s = format (s, "%s_%s_%u/cpumask%c", base_path, name, i, 0);
      if ((err = clib_sysfs_read ((char *) s, "%U", unformat_bitmap_list,
				  &cpumask)))
	break;
      vec_reset_length (s);

      clib_bitmap_foreach (j, cpumask, ({
        vec_add2 (ia32_uncore_units, u, 1);
        u->type = perf_type;
        u->unit =  unit;
	u->cpu_id = j;
	u->numa = numa_by_cpu_id[j];
        log_debug ("controller %s_%u type %d cpu %u numa %u", name, i, perf_type, j, numa_by_cpu_id[j]);
	}));
      i++;
    };
  clib_error_free (err);
  clib_bitmap_free (cpumask);
  vec_free (s);
}

static clib_error_t *
intel_ia32_uncore_init (vlib_main_t * vm, perfmon2_source_t * b)
{
  clib_error_t *err = 0;
  clib_bitmap_t *node_bitmap = 0, *cpumask = 0;
  int *numa_by_cpu_id = 0;
  u32 i, j;
  u8 *s = 0;

  if ((err = clib_sysfs_read ("/sys/devices/system/node/has_cpu", "%U",
			      unformat_bitmap_list, &node_bitmap)))
    return clib_error_return (0, "failed to discover numa topology");

  clib_bitmap_foreach (i, node_bitmap, ({
    s = format (s, "/sys/devices/system/node/node%u/cpulist%c", i, 0);
    if ((err = clib_sysfs_read ((char *) s, "%U",
		unformat_bitmap_list, &cpumask)))
	 {
	   clib_error_free (err);
           err = clib_error_return (0, "failed to discover numa topology");
	   goto done;
	 }
    clib_bitmap_foreach (j, cpumask, ({
        vec_validate_init_empty (numa_by_cpu_id, j, -1);
	numa_by_cpu_id[j] = i;
      }));
    clib_bitmap_free (cpumask);
    vec_reset_length (s);
  }));

#define _(a,b) \
  intel_ia32_uncore_add_unit (PERFMON2_IA32_UNCORE_UNIT_##a, b, numa_by_cpu_id);
  foreach_ia32_uncore_unit_type;
#undef _

  if (vec_len (ia32_uncore_units) == 0)
    return clib_error_return (0, "no uncore units found");

done:
  vec_free (s);
  vec_free (cpumask);
  vec_free (node_bitmap);
  vec_free (numa_by_cpu_id);
  return err;
}

PERFMON2_REGISTER_SOURCE (intel_ia32_uncore) = {
  .name = "intel-ia32-uncore",
  .description = "intel IA-32 uncore events",
  .init_fn = intel_ia32_uncore_init,
};


static clib_error_t *
intel_ia32_uncore_imc_bw_init (vlib_main_t * vm, perfmon2_bundle_t * b)
{
  return 0;
}

PERFMON2_REGISTER_BUNDLE (intel_ia32_uncore_imc_bw) = {
  .name = "imc-bw",
  .description = "memory controller bandwidth",
  .source = "intel-ia32-uncore",
  .init_fn = intel_ia32_uncore_imc_bw_init,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
