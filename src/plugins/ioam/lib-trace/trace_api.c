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

#include <vlibapi/api.h>
#include <vlibmemory/api.h>


/* define message IDs */
#include <ioam/lib-trace/trace_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ioam/lib-trace/trace_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ioam/lib-trace/trace_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ioam/lib-trace/trace_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ioam/lib-trace/trace_all_api_h.h>
#undef vl_api_version

/*
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */

#define TRACE_REPLY_MACRO(t)                                          \
do {                                                            \
    unix_shared_memory_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+sm->msg_id_base);               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

/* *INDENT-OFF* */
#define TRACE_REPLY_MACRO2(t, body)                                   \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+sm->msg_id_base);               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);
/* *INDENT-ON* */

/* List of message types that this plugin understands */

#define foreach_trace_plugin_api_msg                                      \
_(TRACE_PROFILE_ADD, trace_profile_add)                                     \
_(TRACE_PROFILE_DEL, trace_profile_del)                                     \
_(TRACE_PROFILE_SHOW_CONFIG, trace_profile_show_config)

static void vl_api_trace_profile_add_t_handler
  (vl_api_trace_profile_add_t * mp)
{
  trace_main_t *sm = &trace_main;
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
  TRACE_REPLY_MACRO (VL_API_TRACE_PROFILE_ADD_REPLY);
}


static void vl_api_trace_profile_del_t_handler
  (vl_api_trace_profile_del_t * mp)
{
  trace_main_t *sm = &trace_main;
  int rv = 0;
  vl_api_trace_profile_del_reply_t *rmp;

  clear_trace_profiles ();

  TRACE_REPLY_MACRO (VL_API_TRACE_PROFILE_DEL_REPLY);
}

static void vl_api_trace_profile_show_config_t_handler
  (vl_api_trace_profile_show_config_t * mp)
{
  trace_main_t *sm = &trace_main;
  vl_api_trace_profile_show_config_reply_t *rmp;
  int rv = 0;
  trace_profile *profile = trace_profile_find ();
  if (profile->valid)
    {
      TRACE_REPLY_MACRO2 (VL_API_TRACE_PROFILE_SHOW_CONFIG_REPLY,
			  rmp->trace_type = profile->trace_type;
			  rmp->num_elts = profile->num_elts;
			  rmp->trace_tsp = profile->trace_tsp;
			  rmp->node_id = htonl (profile->node_id);
			  rmp->app_data = htonl (profile->app_data);
	);
    }
  else
    {
      TRACE_REPLY_MACRO2 (VL_API_TRACE_PROFILE_SHOW_CONFIG_REPLY,
			  rmp->trace_type = 0;
			  rmp->num_elts = 0; rmp->trace_tsp = 0;
			  rmp->node_id = 0; rmp->app_data = 0;
	);
    }
}

/* Set up the API message handling tables */
static clib_error_t *
trace_plugin_api_hookup (vlib_main_t * vm)
{
  trace_main_t *sm = &trace_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_trace_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <ioam/lib-trace/trace_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (trace_main_t * sm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_trace;
#undef _
}

static clib_error_t *
trace_init (vlib_main_t * vm)
{
  trace_main_t *sm = &trace_main;
  clib_error_t *error = 0;
  u8 *name;

  bzero (sm, sizeof (trace_main));
  (void) trace_util_init ();

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  name = format (0, "ioam_trace_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  sm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = trace_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (sm, &api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (trace_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
