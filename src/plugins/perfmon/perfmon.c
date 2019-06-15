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
#include <perfmon/perfmon_intel.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <linux/limits.h>

perfmon_main_t perfmon_main;

void
perfmon_register_intel_pmc (perfmon_intel_pmc_cpu_model_t * m, int n_models,
			    perfmon_intel_pmc_event_t * e, int n_events)
{
  perfmon_main_t *pm = &perfmon_main;
  perfmon_intel_pmc_registration_t r;

  r.events = e;
  r.models = m;
  r.n_events = n_events;
  r.n_models = n_models;

  vec_add1 (pm->perfmon_tables, r);
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

static int
perfmon_cpu_model_matches (perfmon_intel_pmc_cpu_model_t * mt,
			   u32 n_models, u8 model, u8 stepping)
{
  u32 i;
  for (i = 0; i < n_models; i++)
    {
      if (mt[i].model != model)
	continue;

      if (mt[i].has_stepping)
	{
	  if (mt[i].stepping != stepping)
	    continue;
	}

      return 1;
    }
  return 0;
}

static perfmon_intel_pmc_event_t *
perfmon_find_table_by_model_stepping (perfmon_main_t * pm,
				      u8 model, u8 stepping)
{
  perfmon_intel_pmc_registration_t *rt;

  vec_foreach (rt, pm->perfmon_tables)
  {
    if (perfmon_cpu_model_matches (rt->models, rt->n_models, model, stepping))
      return rt->events;
  }
  return 0;
}

static clib_error_t *
perfmon_init (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;
  clib_error_t *error = 0;
  u32 cpuid;
  u8 model, stepping;
  perfmon_intel_pmc_event_t *ev;

  pm->vlib_main = vm;
  pm->vnet_main = vnet_get_main ();

  pm->capture_by_thread_and_node_name =
    hash_create_string (0, sizeof (uword));

  pm->log_class = vlib_log_register_class ("perfmon", 0);

  /* Default data collection interval */
  pm->timeout_interval = 2.0;	/* seconds */
  vec_validate (pm->pm_fds, 1);
  vec_validate (pm->pm_fds[0], vec_len (vlib_mains) - 1);
  vec_validate (pm->pm_fds[1], vec_len (vlib_mains) - 1);
  vec_validate (pm->perf_event_pages, 1);
  vec_validate (pm->perf_event_pages[0], vec_len (vlib_mains) - 1);
  vec_validate (pm->perf_event_pages[1], vec_len (vlib_mains) - 1);
  vec_validate (pm->rdpmc_indices, 1);
  vec_validate (pm->rdpmc_indices[0], vec_len (vlib_mains) - 1);
  vec_validate (pm->rdpmc_indices[1], vec_len (vlib_mains) - 1);
  pm->page_size = getpagesize ();

  pm->perfmon_table = 0;
  pm->pmc_event_by_name = 0;

  cpuid = get_cpuid ();
  model = ((cpuid >> 12) & 0xf0) | ((cpuid >> 4) & 0xf);
  stepping = cpuid & 0xf;

  pm->perfmon_table = perfmon_find_table_by_model_stepping (pm,
							    model, stepping);

  if (pm->perfmon_table == 0)
    {
      vlib_log_err (pm->log_class, "No table for cpuid %x", cpuid);
      vlib_log_err (pm->log_class, "  model %x, stepping %x",
		    model, stepping);
    }
  else
    {
      pm->pmc_event_by_name = hash_create_string (0, sizeof (u32));
      ev = pm->perfmon_table;

      for (; ev->event_name; ev++)
	{
	  hash_set_mem (pm->pmc_event_by_name, ev->event_name,
			ev - pm->perfmon_table);
	}
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
unformat_processor_event (unformat_input_t * input, va_list * args)
{
  perfmon_main_t *pm = va_arg (*args, perfmon_main_t *);
  perfmon_event_config_t *ep = va_arg (*args, perfmon_event_config_t *);
  u8 *s = 0;
  hash_pair_t *hp;
  u32 idx;
  u32 pe_config = 0;

  if (pm->perfmon_table == 0 || pm->pmc_event_by_name == 0)
    return 0;

  if (!unformat (input, "%s", &s))
    return 0;

  hp = hash_get_pair_mem (pm->pmc_event_by_name, s);

  vec_free (s);

  if (hp == 0)
    return 0;

  idx = (u32) (hp->value[0]);

  pe_config |= pm->perfmon_table[idx].event_code[0];
  pe_config |= pm->perfmon_table[idx].umask << 8;

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
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  int num_threads = 1 + vtm->n_threads;
  unformat_input_t _line_input, *line_input = &_line_input;
  perfmon_event_config_t ec;
  f64 delay;
  u32 timeout_seconds;
  u32 deadman;
  int last_set;
  clib_error_t *error;

  vec_reset_length (pm->single_events_to_collect);
  vec_reset_length (pm->paired_events_to_collect);
  pm->ipc_event_index = ~0;
  pm->mispredict_event_index = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "counter names required...");

  clib_bitmap_zero (pm->thread_bitmap);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "timeout %u", &timeout_seconds))
	pm->timeout_interval = (f64) timeout_seconds;
      else if (unformat (line_input, "instructions-per-clock"))
	{
	  ec.name = "instructions";
	  ec.pe_type = PERF_TYPE_HARDWARE;
	  ec.pe_config = PERF_COUNT_HW_INSTRUCTIONS;
	  pm->ipc_event_index = vec_len (pm->paired_events_to_collect);
	  vec_add1 (pm->paired_events_to_collect, ec);
	  ec.name = "cpu-cycles";
	  ec.pe_type = PERF_TYPE_HARDWARE;
	  ec.pe_config = PERF_COUNT_HW_CPU_CYCLES;
	  vec_add1 (pm->paired_events_to_collect, ec);
	}
      else if (unformat (line_input, "branch-mispredict-rate"))
	{
	  ec.name = "branch-misses";
	  ec.pe_type = PERF_TYPE_HARDWARE;
	  ec.pe_config = PERF_COUNT_HW_BRANCH_MISSES;
	  pm->mispredict_event_index = vec_len (pm->paired_events_to_collect);
	  vec_add1 (pm->paired_events_to_collect, ec);
	  ec.name = "branches";
	  ec.pe_type = PERF_TYPE_HARDWARE;
	  ec.pe_config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
	  vec_add1 (pm->paired_events_to_collect, ec);
	}
      else if (unformat (line_input, "threads %U",
			 unformat_bitmap_list, &pm->thread_bitmap))
	;
      else if (unformat (line_input, "thread %U",
			 unformat_bitmap_list, &pm->thread_bitmap))
	;
      else if (unformat (line_input, "%U", unformat_processor_event, pm, &ec))
	{
	  vec_add1 (pm->single_events_to_collect, ec);
	}
#define _(type,event,str)                       \
      else if (unformat (line_input, str))      \
        {                                       \
          ec.name = str;                        \
          ec.pe_type = type;                    \
          ec.pe_config = event;                 \
          vec_add1 (pm->single_events_to_collect, ec); \
        }
      foreach_perfmon_event
#undef _
	else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
	}
    }

  unformat_free (line_input);

  last_set = clib_bitmap_last_set (pm->thread_bitmap);
  if (last_set != ~0 && last_set >= num_threads)
    return clib_error_return (0, "thread %d does not exist", last_set);

  /* Stick paired events at the front of the (unified) list */
  if (vec_len (pm->paired_events_to_collect) > 0)
    {
      perfmon_event_config_t *tmp;
      /* first 2n events are pairs... */
      vec_append (pm->paired_events_to_collect, pm->single_events_to_collect);
      tmp = pm->single_events_to_collect;
      pm->single_events_to_collect = pm->paired_events_to_collect;
      pm->paired_events_to_collect = tmp;
    }

  if (vec_len (pm->single_events_to_collect) == 0)
    return clib_error_return (0, "no events specified...");

  /* Figure out how long data collection will take */
  delay =
    ((f64) vec_len (pm->single_events_to_collect)) * pm->timeout_interval;
  delay /= 2.0;			/* collect 2 stats at once */

  vlib_cli_output (vm, "Start collection for %d events, wait %.2f seconds",
		   vec_len (pm->single_events_to_collect), delay);

  vlib_process_signal_event (pm->vlib_main, perfmon_periodic_node.index,
			     PERFMON_START, 0);

  /* Coarse-grained wait */
  vlib_process_suspend (vm, delay);

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
  .short_help = "set pmc [threads n,n1-n2] c1... [see \"show pmc events\"]",
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
	  ASSERT ((i + 1) < vec_len (c->counter_names));

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
  int verbose = va_arg (*args, int);

#define _(type,config,name)                             \
  if (verbose == 0)                                     \
    s = format (s, "\n  %s", name);                     \
  else                                                  \
    s = format (s, "\n  %s (%d, %d)", name, type, config);
  foreach_perfmon_event;
#undef _
  return s;
}

typedef struct
{
  u8 *name;
  u32 index;
} sort_nvp_t;

static int
sort_nvps_by_name (void *a1, void *a2)
{
  sort_nvp_t *nvp1 = a1;
  sort_nvp_t *nvp2 = a2;

  return strcmp ((char *) nvp1->name, (char *) nvp2->name);
}

static u8 *
format_pmc_event (u8 * s, va_list * args)
{
  perfmon_intel_pmc_event_t *ev = va_arg (*args, perfmon_intel_pmc_event_t *);

  s = format (s, "%s\n", ev->event_name);
  s = format (s, "  umask: 0x%x\n", ev->umask);
  s = format (s, "  code:  0x%x", ev->event_code[0]);

  if (ev->event_code[1])
    s = format (s, " , 0x%x\n", ev->event_code[1]);
  else
    s = format (s, "\n");

  return s;
}

static u8 *
format_processor_events (u8 * s, va_list * args)
{
  perfmon_main_t *pm = va_arg (*args, perfmon_main_t *);
  int verbose = va_arg (*args, int);
  sort_nvp_t *sort_nvps = 0;
  sort_nvp_t *sn;
  u8 *key;
  u32 value;

  /* *INDENT-OFF* */
  hash_foreach_mem (key, value, pm->pmc_event_by_name,
  ({
    vec_add2 (sort_nvps, sn, 1);
    sn->name = key;
    sn->index = value;
  }));

  vec_sort_with_function (sort_nvps, sort_nvps_by_name);

  if (verbose == 0)
    {
      vec_foreach (sn, sort_nvps)
        s = format (s, "\n  %s ", sn->name);
    }
  else
    {
      vec_foreach (sn, sort_nvps)
        s = format(s, "%U", format_pmc_event, &pm->perfmon_table[sn->index]);
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
                       format_generic_events, verbose);
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
