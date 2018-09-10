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

/* Action function shared between message handler and debug CLI */

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

static clib_error_t *
perfmon_init (vlib_main_t * vm)
{
  perfmon_main_t *pm = &perfmon_main;
  clib_error_t *error = 0;
  u8 *name;

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

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "counter names required...");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "timeout %u", &timeout_seconds))
	pm->timeout_interval = (f64) timeout_seconds;

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
  .short_help = "set pmc counter1 [counter2] [counter3] ... [counterN]",
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
  perfmon_capture_t *c = va_arg (*args, perfmon_capture_t *);
  int verbose __attribute__ ((unused)) = va_arg (*args, int);
  f64 ticks_per_pkt;
  int i;

  if (c == 0)
    {
      s = format (s, "%=30s%=20s%=16s%=16s%=16s",
		  "Name", "Counter", "Count", "Pkts", "Counts/Pkt");
      return s;
    }

  for (i = 0; i < vec_len (c->counter_names); i++)
    {
      u8 *name;

      if (i == 0)
	name = c->thread_and_node_name;
      else
	name = (u8 *) "";

      if (c->vectors_this_counter[i])
	ticks_per_pkt =
	  ((f64) c->counter_values[i]) / ((f64) c->vectors_this_counter[i]);
      else
	ticks_per_pkt = 0.0;

      s = format (s, "%=30s%=20s%=16llu%=16llu%=16.2f",
		  name, c->counter_names[i],
		  c->counter_values[i],
		  c->vectors_this_counter[i], ticks_per_pkt);
    }
  return s;
}

static clib_error_t *
show_pmc_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  perfmon_main_t *pm = &perfmon_main;
  int verbose = 0;
  int i;
  perfmon_capture_t *c;
  perfmon_capture_t *captures = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	break;
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

  vlib_cli_output (vm, "%U", format_capture, 0 /* header */ ,
		   0 /* verbose */ );

  for (i = 0; i < vec_len (captures); i++)
    {
      c = captures + i;

      vlib_cli_output (vm, "%U", format_capture, c, verbose);
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



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
