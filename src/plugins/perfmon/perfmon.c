/*
 * perfmon.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vnet/plugin/plugin.h>
#include <perfmon/perfmon.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <linux/limits.h>

perfmon_main_t perfmon_main;

static char *perfmon_json_path = "/usr/share/vpp/plugins/perfmon";

typedef struct
{
  u8 model;
  u8 stepping;
  u8 has_stepping;
  char *filename;
} file_by_model_and_stepping_t;

/* Created by parsing mapfile.csv, see mapfile_tool.c */

static const file_by_model_and_stepping_t fms_table[] = {
  /* model, stepping, stepping valid, file */
  {0x2E, 0x0, 0, "NehalemEX_core_V2.json"},
  {0x1E, 0x0, 0, "NehalemEP_core_V2.json"},
  {0x1F, 0x0, 0, "NehalemEP_core_V2.json"},
  {0x1A, 0x0, 0, "NehalemEP_core_V2.json"},
  {0x2F, 0x0, 0, "WestmereEX_core_V2.json"},
  {0x25, 0x0, 0, "WestmereEP-SP_core_V2.json"},
  {0x2C, 0x0, 0, "WestmereEP-DP_core_V2.json"},
  {0x37, 0x0, 0, "Silvermont_core_V14.json"},
  {0x4D, 0x0, 0, "Silvermont_core_V14.json"},
  {0x4C, 0x0, 0, "Silvermont_core_V14.json"},
  {0x5C, 0x0, 0, "goldmont_core_v13.json"},
  {0x5F, 0x0, 0, "goldmont_core_v13.json"},
  {0x1C, 0x0, 0, "Bonnell_core_V4.json"},
  {0x26, 0x0, 0, "Bonnell_core_V4.json"},
  {0x27, 0x0, 0, "Bonnell_core_V4.json"},
  {0x36, 0x0, 0, "Bonnell_core_V4.json"},
  {0x35, 0x0, 0, "Bonnell_core_V4.json"},
  {0x2A, 0x0, 0, "sandybridge_core_v16.json"},
  {0x2D, 0x0, 0, "Jaketown_core_V20.json"},
  {0x3A, 0x0, 0, "ivybridge_core_v21.json"},
  {0x3E, 0x0, 0, "ivytown_core_v20.json"},
  {0x3C, 0x0, 0, "haswell_core_v28.json"},
  {0x45, 0x0, 0, "haswell_core_v28.json"},
  {0x46, 0x0, 0, "haswell_core_v28.json"},
  {0x3F, 0x0, 0, "haswellx_core_v20.json"},
  {0x3D, 0x0, 0, "broadwell_core_v23.json"},
  {0x47, 0x0, 0, "broadwell_core_v23.json"},
  {0x4F, 0x0, 0, "broadwellx_core_v14.json"},
  {0x56, 0x0, 0, "broadwellde_core_v7.json"},
  {0x4E, 0x0, 0, "skylake_core_v42.json"},
  {0x5E, 0x0, 0, "skylake_core_v42.json"},
  {0x8E, 0x0, 0, "skylake_core_v42.json"},
  {0x9E, 0x0, 0, "skylake_core_v42.json"},
  {0x57, 0x0, 0, "KnightsLanding_core_V9.json"},
  {0x85, 0x0, 0, "KnightsLanding_core_V9.json"},
  {0x55, 0x0, 1, "skylakex_core_v1.12.json"},
  {0x55, 0x1, 1, "skylakex_core_v1.12.json"},
  {0x55, 0x2, 1, "skylakex_core_v1.12.json"},
  {0x55, 0x3, 1, "skylakex_core_v1.12.json"},
  {0x55, 0x4, 1, "skylakex_core_v1.12.json"},
  {0x55, 0x5, 1, "cascadelakex_core_v1.00.json"},
  {0x55, 0x6, 1, "cascadelakex_core_v1.00.json"},
  {0x55, 0x7, 1, "cascadelakex_core_v1.00.json"},
  {0x55, 0x8, 1, "cascadelakex_core_v1.00.json"},
  {0x55, 0x9, 1, "cascadelakex_core_v1.00.json"},
  {0x55, 0xA, 1, "cascadelakex_core_v1.00.json"},
  {0x55, 0xB, 1, "cascadelakex_core_v1.00.json"},
  {0x55, 0xC, 1, "cascadelakex_core_v1.00.json"},
  {0x55, 0xD, 1, "cascadelakex_core_v1.00.json"},
  {0x55, 0xE, 1, "cascadelakex_core_v1.00.json"},
  {0x55, 0xF, 1, "cascadelakex_core_v1.00.json"},
  {0x7A, 0x0, 0, "goldmontplus_core_v1.01.json"},
};

static void
set_perfmon_json_path ()
{
  char *p, path[PATH_MAX];
  int rv;
  u8 *s;

  /* find executable path */
  if ((rv = readlink ("/proc/self/exe", path, PATH_MAX - 1)) == -1)
    return;

  /* readlink doesn't provide null termination */
  path[rv] = 0;

  /* strip filename */
  if ((p = strrchr (path, '/')) == 0)
    return;
  *p = 0;

  /* strip bin/ */
  if ((p = strrchr (path, '/')) == 0)
    return;
  *p = 0;

  /* cons up the .json file path */
  s = format (0, "%s/share/vpp/plugins/perfmon", path);
  vec_add1 (s, 0);
  perfmon_json_path = (char *) s;
}

static inline u32
get_cpuid (void)
{
#if defined(__x86_64__)
  u32 cpuid;
  asm volatile ("mov $1, %%eax; cpuid; mov %%eax, %0":"=r" (cpuid)::"%eax",
		"%edx", "%ecx", "%rbx");
  return cpuid;
#else
  return 0;
#endif
}

static clib_error_t *
perfmon_init (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;
  clib_error_t *error = 0;
  u32 cpuid;
  uword *ht;
  int found_a_table = 0;
  int i;
  u8 model, stepping;

  pm->vlib_main = vm;
  pm->vnet_main = vnet_get_main ();

  pm->capture_by_thread_and_node_name =
    hash_create_string (0, sizeof (uword));

  pm->log_class = vlib_log_register_class ("perfmon", 0);

  /* Default data collection interval */
  pm->timeout_interval = 3.0;
  vec_validate (pm->pm_fds, vec_len (vlib_mains) - 1);
  vec_validate (pm->perf_event_pages, vec_len (vlib_mains) - 1);
  vec_validate (pm->rdpmc_indices, vec_len (vlib_mains) - 1);
  pm->page_size = getpagesize ();

  pm->perfmon_generic_events = 0;

#define _(type,config,_name)                             \
  if(!perfmon_test_event(pm, _name,type,config)) { \
    perfmon_event_config_t c; \
    c.name=_name; c.pe_type=type; c.pe_config=config; \
    vec_add1(pm->perfmon_generic_events, c); \
  }
  foreach_perfmon_event;
#undef _

  ht = pm->perfmon_table = 0;

  set_perfmon_json_path ();

  cpuid = get_cpuid ();

  for (i = 0; i < ARRAY_LEN (fms_table); i++)
    {
      model = ((cpuid >> 12) & 0xf0) | ((cpuid >> 4) & 0xf);
      stepping = cpuid & 0xf;

      if (fms_table[i].model != model)
	continue;

      if (fms_table[i].has_stepping)
	{
	  if (fms_table[i].stepping != stepping)
	    continue;
	}

      found_a_table = 1;
      ht = perfmon_parse_table (pm, perfmon_json_path, fms_table[i].filename);
      break;
    }
  pm->perfmon_table = ht;

  if (found_a_table == 0 || pm->perfmon_table == 0 || hash_elts (ht) == 0)
    {
      vlib_log_err (pm->log_class, "No table for cpuid %x", cpuid);
      vlib_log_err (pm->log_class, "  model %x, stepping %x",
		    model, stepping);
    }

  return error;
}

VLIB_INIT_FUNCTION (perfmon_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Performance monitor plugin",
#if !defined(__x86_64__)
  .default_disabled = 1,
#endif
};
/* *INDENT-ON* */

static uword
atox (u8 * s)
{
  uword rv = 0;

  while (*s)
    {
      if (*s >= '0' && *s <= '9')
	rv = (rv << 4) | (*s - '0');
      else if (*s >= 'a' && *s <= 'f')
	rv = (rv << 4) | (*s - 'a' + 10);
      else if (*s >= 'A' && *s <= 'A')
	rv = (rv << 4) | (*s - 'A' + 10);
      else if (*s == 'x')
	;
      else
	break;
      s++;
    }
  return rv;
}

static uword
unformat_generic_event (unformat_input_t * input, va_list * args)
{
  perfmon_main_t *pm = va_arg (*args, perfmon_main_t *);
  perfmon_event_config_t *ep = va_arg (*args, perfmon_event_config_t *);
  u8 *s = 0;

  if (pm->perfmon_generic_events == 0)
    return 0;

  if (!unformat (input, "%s", &s))
    return 0;

  int found = 0;
  perfmon_event_config_t *c;
  vec_foreach (c, pm->perfmon_generic_events)
  {
    if (!strcmp (c->name, (char *) s))
      {
	ep->name = c->name;
	ep->pe_type = c->pe_type;
	ep->pe_config = c->pe_config;

	found = 1;
	break;
      }
  }

  vec_free (s);

  return found;
}

static uword
unformat_processor_event (unformat_input_t * input, va_list * args)
{
  perfmon_main_t *pm = va_arg (*args, perfmon_main_t *);
  perfmon_event_config_t *ep = va_arg (*args, perfmon_event_config_t *);
  u8 *s = 0;
  name_value_pair_t **nvps, *nvp;
  hash_pair_t *hp;
  int i;
  int set_values = 0;
  u32 pe_config = 0;

  if (pm->perfmon_table == 0)
    return 0;

  if (!unformat (input, "%s", &s))
    return 0;

  hp = hash_get_pair_mem (pm->perfmon_table, s);

  vec_free (s);

  if (hp == 0)
    return 0;

  nvps = (name_value_pair_t **) (hp->value[0]);

  for (i = 0; i < vec_len (nvps); i++)
    {
      nvp = nvps[i];
      if (!strncmp ((char *) nvp->name, "EventCode", 9))
	{
	  pe_config |= atox (nvp->value);
	  set_values++;
	}
      else if (!strncmp ((char *) nvp->name, "UMask", 5))
	{
	  pe_config |= (atox (nvp->value) << 8);
	  set_values++;
	}
      if (set_values == 2)
	break;
    }

  if (set_values != 2)
    {
      clib_warning ("BUG: only found %d values", set_values);
      return 0;
    }

  ep->name = (char *) hp->key;
  ep->pe_type = PERF_TYPE_RAW;
  ep->pe_config = pe_config;
  return 1;
}

static clib_error_t *
set_pmc_command_fn (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  perfmon_main_t *pm = &perfmon_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  perfmon_event_config_t ec;
  u32 timeout_seconds;
  u32 deadman;

  vec_reset_length (pm->events_to_collect);
  pm->ipc_event_index = ~0;
  pm->mispredict_event_index = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "counter names required...");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "timeout %u", &timeout_seconds))
	pm->timeout_interval = (f64) timeout_seconds;
      else if (unformat (line_input, "instructions-per-clock"))
	{
	  ec.name = "instructions";
	  ec.pe_type = PERF_TYPE_HARDWARE;
	  ec.pe_config = PERF_COUNT_HW_INSTRUCTIONS;
	  pm->ipc_event_index = vec_len (pm->events_to_collect);
	  vec_add1 (pm->events_to_collect, ec);
	  ec.name = "cpu-cycles";
	  ec.pe_type = PERF_TYPE_HARDWARE;
	  ec.pe_config = PERF_COUNT_HW_CPU_CYCLES;
	  vec_add1 (pm->events_to_collect, ec);
	}
      else if (unformat (line_input, "branch-mispredict-rate"))
	{
	  ec.name = "branch-misses";
	  ec.pe_type = PERF_TYPE_HARDWARE;
	  ec.pe_config = PERF_COUNT_HW_BRANCH_MISSES;
	  pm->mispredict_event_index = vec_len (pm->events_to_collect);
	  vec_add1 (pm->events_to_collect, ec);
	  ec.name = "branches";
	  ec.pe_type = PERF_TYPE_HARDWARE;
	  ec.pe_config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
	  vec_add1 (pm->events_to_collect, ec);
	}
      else if (unformat (line_input, "%U", unformat_processor_event, pm, &ec))
	{
	  vec_add1 (pm->events_to_collect, ec);
	}
      else if (unformat (line_input, "%U", unformat_generic_event, pm, &ec))
	{
	  vec_add1 (pm->events_to_collect, ec);
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, line_input);
    }

  if (vec_len (pm->events_to_collect) == 0)
    return clib_error_return (0, "no events specified...");

  vlib_cli_output (vm, "Start collection for %d events, wait %.2f seconds",
		   vec_len (pm->events_to_collect),
		   (f64) (vec_len (pm->events_to_collect))
		   * pm->timeout_interval);

  vlib_process_signal_event (pm->vlib_main, perfmon_periodic_node.index,
			     PERFMON_START, 0);

  /* Coarse-grained wait */
  vlib_process_suspend (vm,
			((f64) (vec_len (pm->events_to_collect)
				* pm->timeout_interval)));

  deadman = 0;
  /* Reasonable to guess that collection may not be quite done... */
  while (pm->state == PERFMON_STATE_RUNNING)
    {
      vlib_process_suspend (vm, 10e-3);
      if (deadman++ > 200)
	{
	  vlib_cli_output (vm, "DEADMAN: collection still running...");
	  break;
	}
    }

  vlib_cli_output (vm, "Data collection complete...");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_pmc_command, static) =
{
  .path = "set pmc",
  .short_help = "set pmc c1 [..., use \"show pmc events\"]",
  .function = set_pmc_command_fn,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static int
capture_name_sort (void *a1, void *a2)
{
  perfmon_capture_t *c1 = a1;
  perfmon_capture_t *c2 = a2;

  return strcmp ((char *) c1->thread_and_node_name,
		 (char *) c2->thread_and_node_name);
}

static u8 *
format_capture (u8 * s, va_list * args)
{
  perfmon_main_t *pm = va_arg (*args, perfmon_main_t *);
  perfmon_capture_t *c = va_arg (*args, perfmon_capture_t *);
  int verbose __attribute__ ((unused)) = va_arg (*args, int);
  f64 ticks_per_pkt;
  int i;

  if (c == 0)
    {
      s = format (s, "%=40s%=20s%=16s%=16s%=16s",
		  "Name", "Counter", "Count", "Pkts", "Counts/Pkt");
      return s;
    }

  for (i = 0; i < vec_len (c->counter_names); i++)
    {
      u8 *name;

      if (i == 0)
	name = c->thread_and_node_name;
      else
	{
	  vec_add1 (s, '\n');
	  name = (u8 *) "";
	}

      /* Deal with synthetic events right here */
      if (i == pm->ipc_event_index)
	{
	  f64 ipc_rate;
	  ASSERT (i + 1 < vec_len (c->counter_names));

	  if (c->counter_values[i + 1] > 0)
	    ipc_rate = (f64) c->counter_values[i]
	      / (f64) c->counter_values[i + 1];
	  else
	    ipc_rate = 0.0;

	  s = format (s, "%-40s%+20s%+16llu%+16llu%+16.2e\n",
		      name, "instructions-per-clock",
		      c->counter_values[i],
		      c->counter_values[i + 1], ipc_rate);
	  name = (u8 *) "";
	}

      if (i == pm->mispredict_event_index)
	{
	  f64 mispredict_rate;
	  ASSERT (i + 1 < vec_len (c->counter_names));

	  if (c->counter_values[i + 1] > 0)
	    mispredict_rate = (f64) c->counter_values[i]
	      / (f64) c->counter_values[i + 1];
	  else
	    mispredict_rate = 0.0;

	  s = format (s, "%-40s%+20s%+16llu%+16llu%+16.2e\n",
		      name, "branch-mispredict-rate",
		      c->counter_values[i],
		      c->counter_values[i + 1], mispredict_rate);
	  name = (u8 *) "";
	}

      if (c->vectors_this_counter[i])
	ticks_per_pkt =
	  ((f64) c->counter_values[i]) / ((f64) c->vectors_this_counter[i]);
      else
	ticks_per_pkt = 0.0;

      s = format (s, "%-40s%+20s%+16llu%+16llu%+16.2e",
		  name, c->counter_names[i],
		  c->counter_values[i],
		  c->vectors_this_counter[i], ticks_per_pkt);
    }
  return s;
}

static u8 *
format_generic_events (u8 * s, va_list * args)
{
  perfmon_main_t *pm = va_arg (*args, perfmon_main_t *);
  int verbose = va_arg (*args, int);

  perfmon_event_config_t *c;

  vec_foreach (c, pm->perfmon_generic_events) if (verbose == 0)
    s = format (s, "\n  %s", c->name);
  else
    s = format (s, "\n  %s (%d, %d)", c->name, c->pe_type, c->pe_config);
  return s;
}

typedef struct
{
  u8 *name;
  name_value_pair_t **nvps;
} sort_nvp_t;

static int
sort_nvps_by_name (void *a1, void *a2)
{
  sort_nvp_t *nvp1 = a1;
  sort_nvp_t *nvp2 = a2;

  return strcmp ((char *) nvp1->name, (char *) nvp2->name);
}

static u8 *
format_processor_events (u8 * s, va_list * args)
{
  perfmon_main_t *pm = va_arg (*args, perfmon_main_t *);
  int verbose = va_arg (*args, int);
  int i, j;
  sort_nvp_t *sort_nvps = 0;
  sort_nvp_t *sn;
  u8 *key;
  name_value_pair_t **value;

  /* *INDENT-OFF* */
  hash_foreach_mem (key, value, pm->perfmon_table,
  ({
    vec_add2 (sort_nvps, sn, 1);
    sn->name = key;
    sn->nvps = value;
  }));

  if (sort_nvps)
    vec_sort_with_function (sort_nvps, sort_nvps_by_name);

  if (verbose == 0)
    {
      for (i = 0; i < vec_len (sort_nvps); i++)
        s = format (s, "\n  %s ", sort_nvps[i].name);
    }
  else
    {
      for (i = 0; i < vec_len (sort_nvps); i++)
        {
          name_value_pair_t **nvps;
          s = format (s, "\n  %s:", sort_nvps[i].name);

          nvps = sort_nvps[i].nvps;

          for (j = 0; j < vec_len (nvps); j++)
            s = format (s, "\n    %s = %s", nvps[j]->name, nvps[j]->value);
        }
    }
  vec_free (sort_nvps);
  return s;
}


static clib_error_t *
show_pmc_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  perfmon_main_t *pm = &perfmon_main;
  int verbose = 0;
  int events = 0;
  int i;
  perfmon_capture_t *c;
  perfmon_capture_t *captures = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "events"))
        events = 1;
      else if (unformat (input, "verbose"))
        verbose = 1;
      else
	break;
    }

  if (events)
    {
      vlib_cli_output (vm, "Generic Events %U",
                       format_generic_events, pm, verbose);
      vlib_cli_output (vm, "Synthetic Events");
      vlib_cli_output (vm, "  instructions-per-clock");
      vlib_cli_output (vm, "  branch-mispredict-rate");
      if (pm->perfmon_table)
        vlib_cli_output (vm, "Processor Events %U",
                         format_processor_events, pm, verbose);
      return 0;
    }

  if (pm->state == PERFMON_STATE_RUNNING)
    {
      vlib_cli_output (vm, "Data collection in progress...");
      return 0;
    }

  if (pool_elts (pm->capture_pool) == 0)
    {
      vlib_cli_output (vm, "No data...");
      return 0;
    }

  /* *INDENT-OFF* */
  pool_foreach (c, pm->capture_pool,
  ({
    vec_add1 (captures, *c);
  }));
  /* *INDENT-ON* */

  vec_sort_with_function (captures, capture_name_sort);

  vlib_cli_output (vm, "%U", format_capture, pm, 0 /* header */ ,
		   0 /* verbose */ );

  for (i = 0; i < vec_len (captures); i++)
    {
      c = captures + i;

      vlib_cli_output (vm, "%U", format_capture, pm, c, verbose);
    }

  vec_free (captures);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_pmc_command, static) =
{
  .path = "show pmc",
  .short_help = "show pmc [verbose]",
  .function = show_pmc_command_fn,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
clear_pmc_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  perfmon_main_t *pm = &perfmon_main;
  u8 *key;
  u32 *value;

  if (pm->state == PERFMON_STATE_RUNNING)
    {
      vlib_cli_output (vm, "Performance monitor is still running...");
      return 0;
    }

  pool_free (pm->capture_pool);

  /* *INDENT-OFF* */
  hash_foreach_mem (key, value, pm->capture_by_thread_and_node_name,
  ({
    vec_free (key);
  }));
  /* *INDENT-ON* */
  hash_free (pm->capture_by_thread_and_node_name);
  pm->capture_by_thread_and_node_name =
    hash_create_string (0, sizeof (uword));
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_pmc_command, static) =
{
  .path = "clear pmc",
  .short_help = "clear the performance monitor counters",
  .function = clear_pmc_command_fn,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
