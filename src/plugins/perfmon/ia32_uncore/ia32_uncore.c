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
#include <perfmon/perfmon.h>
#include <perfmon/ia32_core/ia32_core.h>

/* *INDENT-OFF* */
VLIB_REGISTER_LOG_CLASS (if_ia32_uncore_log, static) = {
  .class_name = "perfmon",
  .subclass_name = "ia32-uncore",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};
/* *INDENT-ON* */

#define log_debug(fmt,...) vlib_log_debug(if_ia32_uncore_log.class, fmt, __VA_ARGS__)
#define log_warn(fmt,...) vlib_log_warn(if_ia32_uncore_log.class, fmt, __VA_ARGS__)
#define log_err(fmt,...) vlib_log_err(if_ia32_uncore_log.class, fmt, __VA_ARGS__)

#define foreach_ia32_uncore_unit_type \
  _(IMC, "imc", "integrated Memory Controller (iMC)", "iMC socket %u channel %u") \
  _(UPI, "upi", "Intel Ultra Path Interconnect (UPI)", "UPI socket %u link %u") \

typedef enum
{
#define _(t,n,name,fmt) PERFMON_IA32_UNCORE_UNIT_##t,
  foreach_ia32_uncore_unit_type
#undef _
    PERFMON_IA32_UNCORE_N_UNITS,
} ia32_uncore_unit_type_t;


#define PERF_INTEL_CODE(event, umask, edge, any, inv, cmask) \
  ((event) | (umask) << 8 | (edge) << 18 | (any) << 21 | (inv) << 23 |  (cmask) << 24)

/* Type, EventCode, UMask, name, suffix, description */
#define foreach_perf_ia32_uncore_event \
  _(IMC, 0x04, 0x02, UNC_M_CAS_COUNT, RD, \
    "All DRAM Read CAS Commands issued (including underfills)") \
  _(IMC, 0x04, 0x02, UNC_M_CAS_COUNT, WR, \
    "All DRAM Write CAS commands issued") \
  _(IMC, 0x04, 0x0c, UNC_M_CAS_COUNT, ALL, \
    "All DRAM CAS commands issued") \

typedef enum
{
#define _(unit, event, umask, name, suffix, desc) \
    PERFMON_IA32_UNCORE_E_##unit##_##name##_##suffix,
  foreach_perf_ia32_uncore_event
#undef _
    PERFMON_IA32_UNCORE_N_EVENTS,
} perfmon_ia32_uncore_event_index_t;

static perfmon_event_t ia32_uncore_events[] = {
#define _(unit, event, umask, n, suffix, desc) \
  [PERFMON_IA32_UNCORE_E_##unit##_##n##_##suffix] = { \
    .config = (event) | (umask) << 8, \
    .name = #n "." #suffix, \
    .description = desc, \
    .type_from_instance = 1, \
    .instance_type = PERFMON_IA32_UNCORE_UNIT_##unit, \
  },

  foreach_perf_ia32_uncore_event
#undef _
};

static int
intel_ia32_uncore_instance_name_cmp (void *v1, void *v2)
{
  perfmon_instance_t *i1 = v1;
  perfmon_instance_t *i2 = v2;
  return strcmp (i1->name, i2->name);
}

static void
intel_ia32_uncore_add_unit (perfmon_source_t * src, ia32_uncore_unit_type_t u,
			    char *name, char *type_str, char *fmt, int *socket_by_cpu_id)
{
  static char *base_path = "/sys/bus/event_source/devices/uncore";
  clib_error_t *err;
  clib_bitmap_t *cpumask = 0;
  perfmon_instance_t *in;
  perfmon_instance_type_t *it;
  u8 *s = 0;
  int i = 0, j;
  u32 perf_type;

  vec_validate (src->instances_by_type, u);
  it = vec_elt_at_index (src->instances_by_type, u);
  it->name = type_str;

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

      /* *INDENT-OFF* */
      clib_bitmap_foreach (j, cpumask, ({
	  vec_add2 (it->instances, in, 1);
	  in->type = perf_type;
	  in->cpu = j;
	  in->pid = -1;
	  in->name = (char *) format (0, fmt, socket_by_cpu_id[j], i);
	  vec_terminate_c_string (in->name);
	  log_debug ("found %s %s", type_str, in->name);
	}));
      /* *INDENT-ON* */
      i++;
    };
  clib_error_free (err);
  clib_bitmap_free (cpumask);
  vec_free (s);
}

static clib_error_t *
intel_ia32_uncore_init (vlib_main_t * vm, perfmon_source_t * src)
{
  clib_error_t *err = 0;
  clib_bitmap_t *node_bitmap = 0, *cpumask = 0;
  int *numa_by_cpu_id = 0;
  u32 i, j;
  u8 *s = 0;

  if ((err = clib_sysfs_read ("/sys/devices/system/node/has_cpu", "%U",
			      unformat_bitmap_list, &node_bitmap)))
    {
      clib_error_free (err);
      return clib_error_return (0, "failed to discover numa topology");
    }

  /* *INDENT-OFF* */
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
  /* *INDENT-ON* */

#define _(t,n,name,fmt) \
  intel_ia32_uncore_add_unit (src, PERFMON_IA32_UNCORE_UNIT_##t, n, name, fmt,\
			      numa_by_cpu_id);
  foreach_ia32_uncore_unit_type;
#undef _

  for (i = 0, j = 0; i < vec_len (src->instances_by_type); i++)
    {
      perfmon_instance_type_t *it;

      it = vec_elt_at_index (src->instances_by_type, i);
      vec_sort_with_function (it->instances,
			      intel_ia32_uncore_instance_name_cmp);
      j += vec_len (it->instances);
    }

  if (j == 0)
    {
      vec_free (src->instances_by_type);
      return clib_error_return (0, "no uncore units found");
    }

done:
  vec_free (s);
  vec_free (cpumask);
  vec_free (node_bitmap);
  vec_free (numa_by_cpu_id);
  return err;
}

format_function_t format_ia32_core_config;

PERFMON_REGISTER_SOURCE (intel_ia32_uncore) = {
  .name = "intel-ia32-uncore",
  .description = "intel IA-32 uncore events",
  .events = ia32_uncore_events,
  .n_events = PERFMON_IA32_UNCORE_N_EVENTS,
  .init_fn = intel_ia32_uncore_init,
  .format_config = format_ia32_core_config,
};

PERFMON_REGISTER_BUNDLE (intel_ia32_uncore_imc_bw) = {
  .name = "imc-bw",
  .description = "memory controller bandwidth",
  .source = "intel-ia32-uncore",
  .events[0] = PERFMON_IA32_UNCORE_E_IMC_UNC_M_CAS_COUNT_RD,
  .events[1] = PERFMON_IA32_UNCORE_E_IMC_UNC_M_CAS_COUNT_WR,
  .n_events = 2,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
