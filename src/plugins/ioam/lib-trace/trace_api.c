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
/*
 *------------------------------------------------------------------
 * trace_api.c - iOAM Trace related APIs to create
 *               and maintain profiles
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <ioam/lib-trace/trace_util.h>
#include <ioam/lib-trace/trace_config.h>
#include <vlibapi/api_helper_macros.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <ioam/lib-trace/trace.api_enum.h>
#include <ioam/lib-trace/trace.api_types.h>

static void vl_api_trace_profile_add_t_handler
  (vl_api_trace_profile_add_t * mp)
{
  int rv = 0;
  vl_api_trace_profile_add_reply_t *rmp;
  trace_profile *profile = NULL;

  profile = trace_profile_find ();
  if (profile)
    {
      rv =
	trace_profile_create (profile, mp->trace_type, mp->num_elts,
			      mp->trace_tsp, ntohl (mp->node_id),
			      ntohl (mp->app_data));
      if (rv != 0)
	goto ERROROUT;
    }
  else
    {
      rv = -3;
    }
ERROROUT:
  REPLY_MACRO (VL_API_TRACE_PROFILE_ADD_REPLY);
}


static void vl_api_trace_profile_del_t_handler
  (vl_api_trace_profile_del_t * mp)
{
  int rv = 0;
  vl_api_trace_profile_del_reply_t *rmp;

  clear_trace_profiles ();

  REPLY_MACRO (VL_API_TRACE_PROFILE_DEL_REPLY);
}

static void vl_api_trace_profile_show_config_t_handler
  (vl_api_trace_profile_show_config_t * mp)
{
  vl_api_trace_profile_show_config_reply_t *rmp;
  int rv = 0;
  trace_profile *profile = trace_profile_find ();
  if (profile->valid)
    {
      REPLY_MACRO2 (VL_API_TRACE_PROFILE_SHOW_CONFIG_REPLY,
		    rmp->trace_type = profile->trace_type;
		    rmp->num_elts = profile->num_elts;
		    rmp->trace_tsp = profile->trace_tsp;
		    rmp->node_id = htonl (profile->node_id);
		    rmp->app_data = htonl (profile->app_data);
	);
    }
  else
    {
      REPLY_MACRO2 (VL_API_TRACE_PROFILE_SHOW_CONFIG_REPLY,
		    rmp->trace_type = 0;
		    rmp->num_elts = 0; rmp->trace_tsp = 0;
		    rmp->node_id = 0; rmp->app_data = 0;
	);
    }
}

#include <ioam/lib-trace/trace.api.c>
static clib_error_t *
trace_init (vlib_main_t * vm)
{
  trace_main_t *sm = &trace_main;

  bzero (sm, sizeof (trace_main));
  (void) trace_util_init ();

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (trace_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
