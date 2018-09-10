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

/* define message IDs */
#include <perfmon/perfmon_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <perfmon/perfmon_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <perfmon/perfmon_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <perfmon/perfmon_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <perfmon/perfmon_all_api_h.h>
#undef vl_api_version

#define REPLY_MSG_ID_BASE pm->msg_id_base
#include <vlibapi/api_helper_macros.h>

perfmon_main_t perfmon_main;

/* List of message types that this plugin understands */

#define foreach_perfmon_plugin_api_msg                           \
_(PERFMON_ENABLE_DISABLE, perfmon_enable_disable)

static char *perfmon_json_path = "/usr/share/vpp/plugins/perfmon";

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
  s = format (0, "%s/usr/share/vpp/plugins/perfmon", path);
  vec_add1 (s, 0);
  perfmon_json_path = (char *) s;
}

int
perfmon_enable_disable (perfmon_main_t * pm, u32 sw_if_index,
			int enable_disable)
{
  vnet_sw_interface_t *sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (pm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (pm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("device-input", "perfmon",
			       sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
perfmon_enable_disable_command_fn (vlib_main_t * vm,
				   unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  perfmon_main_t *pm = &perfmon_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 pm->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = perfmon_enable_disable (pm, sw_if_index, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0,
				"Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "perfmon_enable_disable returned %d", rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (perfmon_enable_disable_command, static) =
{
  .path = "perfmon enable-disable",
  .short_help =
  "perfmon enable-disable <interface-name> [disable]",
  .function = perfmon_enable_disable_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_perfmon_enable_disable_t_handler
  (vl_api_perfmon_enable_disable_t * mp)
{
  vl_api_perfmon_enable_disable_reply_t *rmp;
  perfmon_main_t *pm = &perfmon_main;
  int rv;

  rv = perfmon_enable_disable (pm, ntohl (mp->sw_if_index),
			       (int) (mp->enable_disable));

  REPLY_MACRO (VL_API_PERFMON_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
perfmon_plugin_api_hookup (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + pm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_perfmon_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <perfmon/perfmon_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (perfmon_main_t * pm, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n  #crc, id + pm->msg_id_base);
  foreach_vl_msg_name_crc_perfmon;
#undef _
}

#define foreach_cpuid_table                     \
_(0x0306C3, haswell_core_v28.json)              \
_(0x0306F2, haswell_core_v28.json)              \
_(0x0406E3, skylake_core_v42.json)              \
_(0x0506E3, skylake_core_v42.json)

static inline u32
get_cpuid (void)
{
  u32 cpuid;
  asm volatile ("mov $1, %%eax; cpuid; mov %%eax, %0":"=r" (cpuid)::"%eax",
		"%edx", "%ecx", "%rbx");
  return cpuid;
}

static clib_error_t *
perfmon_init (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;
  clib_error_t *error = 0;
  u8 *name;
  u32 cpuid;
  uword *ht;
  int found_a_table = 0;

  pm->vlib_main = vm;
  pm->vnet_main = vnet_get_main ();

  name = format (0, "perfmon_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  pm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = perfmon_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (pm, &api_main);

  vec_free (name);

  pm->capture_by_thread_and_node_name =
    hash_create_string (0, sizeof (uword));


  pm->log_class = vlib_log_register_class ("perfmon", 0);

  /* Default data collection interval */
  pm->timeout_interval = 3.0;
  vec_validate (pm->pm_fds, vec_len (vlib_mains) - 1);
  vec_validate (pm->perf_event_pages, vec_len (vlib_mains) - 1);
  vec_validate (pm->rdpmc_indices, vec_len (vlib_mains) - 1);
  pm->page_size = getpagesize ();

  ht = pm->perfmon_table = 0;

  set_perfmon_json_path();

  cpuid = get_cpuid ();

  if (0)
    {
    }
#define _(id,table)                                             \
  else if (cpuid == id)                                         \
    {                                                           \
      vlib_log_debug (pm->log_class, "Found table %s", #table); \
      ht = perfmon_parse_table (pm, perfmon_json_path, #table); \
      found_a_table = 1;                                        \
    }
  foreach_cpuid_table;
#undef _

  pm->perfmon_table = ht;

  if (found_a_table == 0)
    vlib_log_err (pm->log_class, "No table for cpuid %x", cpuid);

  return error;
}

VLIB_INIT_FUNCTION (perfmon_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (perfmon, static) =
{
  .arc_name = "device-input",
  .node_name = "perfmon",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "x86_64 performance monitor plugin"
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
#define _(type,event,str)                       \
      else if (unformat (line_input, str))      \
        {                                       \
          ec.name = str;                        \
          ec.pe_type = type;                    \
          ec.pe_config = event;                 \
          vec_add1 (pm->events_to_collect, ec); \
        }
      foreach_perfmon_event
#undef _
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
