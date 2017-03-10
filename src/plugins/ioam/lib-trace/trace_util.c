/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <vppinfra/mem.h>
#include "trace_util.h"
#include "trace_config.h"

trace_main_t trace_main;

static int
trace_profile_cleanup (trace_profile * profile)
{

  memset (profile, 0, sizeof (trace_profile));
  profile->trace_tsp = TSP_MICROSECONDS;	/* Micro seconds */
  ip6_trace_profile_cleanup ();	/* lib-trace_TODO: Remove this once IOAM-IPv6 transport is a plugin */
  return 0;

}

static int
trace_main_profiles_reset (void)
{
  int rv;

  trace_main_t *sm = &trace_main;
  rv = trace_profile_cleanup (&(sm->profile));
  return (rv);
}

int
trace_util_init (void)
{
  int rv;

  rv = trace_main_profiles_reset ();
  return (rv);
}


int
trace_profile_create (trace_profile * profile, u8 trace_type, u8 num_elts,
		      u32 trace_tsp, u32 node_id, u32 app_data)
{

  if (!trace_type || !num_elts || !(node_id))
    {
      return (-1);
    }
  if (profile && !profile->valid)
    {
      //rv = trace_profile_cleanup (profile);
      profile->trace_type = trace_type;
      profile->num_elts = num_elts;
      profile->trace_tsp = trace_tsp;
      profile->node_id = node_id;
      profile->app_data = app_data;
      profile->valid = 1;

      /* lib-trace_TODO: Remove this once IOAM-IPv6 transport is a plugin */
      ip6_trace_profile_setup ();
      return (0);
    }

  return (-1);
}



clib_error_t *
clear_trace_profile_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{

  trace_main_profiles_reset ();
  return 0;
}

void
clear_trace_profiles (void)
{
  clear_trace_profile_command_fn (0, 0, 0);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(clear_trace_profile_command) =
{
.path = "clear ioam-trace profile",
.short_help = "clear ioam-trace profile [<index>|all]",
.function = clear_trace_profile_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
set_trace_profile_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  u8 trace_type = 0;
  u8 num_elts = 0;
  u32 node_id = 0;
  u32 app_data = 0;
  u32 trace_tsp = 0;
  trace_profile *profile = NULL;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "trace-type 0x%x", &trace_type));
      else if (unformat (input, "trace-elts %d", &num_elts));
      else if (unformat (input, "trace-tsp %d", &trace_tsp));
      else if (unformat (input, "node-id 0x%x", &node_id));
      else if (unformat (input, "app-data 0x%x", &app_data));
      else
	break;
    }
  profile = trace_profile_find ();
  if (profile)
    {
      trace_profile_create (profile, trace_type, num_elts, trace_tsp,
			    node_id, app_data);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_trace_profile_command, static) =
{
.path = "set ioam-trace profile",
.short_help = "set ioam-trace \
             trace-type <0x1f|0x3|0x9|0x11|0x19> trace-elts <nn> trace-tsp <0|1|2|3> \
             node-id <node id in hex> app-data <app_data in hex>",
.function = set_trace_profile_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_trace_profile_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  trace_profile *p = NULL;
  u8 *s = 0;
  p = trace_profile_find ();
  if (!(p && p->valid))
    {
      s = format (s, "\nTrace configuration not valid\n");
      vlib_cli_output (vm, "%v", s);
      vec_free (s);
      return 0;
    }
  s = format (s, " HOP BY HOP OPTIONS - TRACE CONFIG - \n");
  s = format (s, "                        Trace Type : 0x%x (%d)\n",
	      p->trace_type, p->trace_type);
  s =
    format (s, "         Trace timestamp precision : %d (%s)\n",
	    p->trace_tsp,
	    (p->trace_tsp ==
	     TSP_SECONDS) ? "Seconds" : ((p->trace_tsp ==
					  TSP_MILLISECONDS) ?
					 "Milliseconds"
					 : (((p->trace_tsp ==
					      TSP_MICROSECONDS) ?
					     "Microseconds" :
					     "Nanoseconds"))));
  s = format (s, "                Num of trace nodes : %d\n", p->num_elts);
  s =
    format (s, "                           Node-id : 0x%x (%d)\n",
	    p->node_id, p->node_id);
  s =
    format (s, "                          App Data : 0x%x (%d)\n",
	    p->app_data, p->app_data);
  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_trace_profile_command, static) =
{
.path = "show ioam-trace profile",
.short_help = "show ioam-trace profile",
.function = show_trace_profile_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
