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
 * trace_test.c - test harness for trace plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip6_hop_by_hop.h>

/* Declare message IDs */
#include <ioam/lib-trace/trace_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ioam/lib-trace/trace_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <ioam/lib-trace/trace_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <ioam/lib-trace/trace_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ioam/lib-trace/trace_all_api_h.h>
#undef vl_api_version


typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} trace_test_main_t;

trace_test_main_t trace_test_main;

#define foreach_standard_reply_retval_handler     \
_(trace_profile_add_reply)                          \
_(trace_profile_del_reply)

#define foreach_custom_reply_handler     \
_(trace_profile_show_config_reply,										\
  if(mp->trace_type)												\
  {														\
     errmsg("                        Trace Type : 0x%x (%d)\n",mp->trace_type, mp->trace_type);			\
     errmsg("         Trace timestamp precision : %d (%s)\n",mp->trace_tsp,					\
       (mp->trace_tsp == TSP_SECONDS) ? "Seconds" : ((mp->trace_tsp ==TSP_MILLISECONDS) ?			\
         "Milliseconds": (((mp->trace_tsp == TSP_MICROSECONDS) ? "Microseconds" : "Nanoseconds"))));		\
     errmsg("                           Node Id : 0x%x (%d)\n",htonl(mp->node_id), htonl(mp->node_id));		\
     errmsg("                          App Data : 0x%x (%d)\n",htonl(mp->app_data), htonl(mp->app_data));	\
  }														\
    else errmsg("No valid trace profile configuration found\n");)
#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = trace_test_main.vat_main;   \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _

#define _(n,body)                                       \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = trace_test_main.vat_main;    \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
	if(retval>=0)do{body;} while(0);                 \
	else errmsg("Error, retval: %d",retval);        \
    }
foreach_custom_reply_handler;
#undef _
/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                                       \
_(TRACE_PROFILE_ADD_REPLY, trace_profile_add_reply)                         \
_(TRACE_PROFILE_DEL_REPLY, trace_profile_del_reply)                         \
_(TRACE_PROFILE_SHOW_CONFIG_REPLY, trace_profile_show_config_reply)


/* M: construct, but don't yet send a message */

#define M(T,t)                                                  \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc(sizeof(*mp));                         \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T + sm->msg_id_base);      \
    mp->client_index = vam->my_client_index;                    \
} while(0);

#define M2(T,t,n)                                               \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc(sizeof(*mp)+(n));                     \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T + sm->msg_id_base);      \
    mp->client_index = vam->my_client_index;                    \
} while(0);

/* S: send a message */
#define S (vl_msg_api_send_shmem (vam->vl_input_queue, (u8 *)&mp))

/* W: wait for results, with timeout */
#define W                                       \
do {                                            \
    timeout = vat_time_now (vam) + 1.0;         \
                                                \
    while (vat_time_now (vam) < timeout) {      \
        if (vam->result_ready == 1) {           \
            return (vam->retval);               \
        }                                       \
    }                                           \
    return -99;                                 \
} while(0);


static int
api_trace_profile_add (vat_main_t * vam)
{
  trace_test_main_t *sm = &trace_test_main;
  unformat_input_t *input = vam->input;
  vl_api_trace_profile_add_t *mp;
  u8 trace_type = 0;
  u8 num_elts = 0;
  int rv = 0;
  u32 node_id = 0;
  u32 app_data = 0;
  u8 trace_tsp = 0;
  f64 timeout;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "trace-type 0x%x", &trace_type))
	;
      else if (unformat (input, "trace-elts %d", &num_elts))
	;
      else if (unformat (input, "trace-tsp %d", &trace_tsp))
	;
      else if (unformat (input, "node-id 0x%x", &node_id))
	;
      else if (unformat (input, "app-data 0x%x", &app_data))
	;

      else
	break;
    }


  M (TRACE_PROFILE_ADD, trace_profile_add);

  mp->trace_type = trace_type;
  mp->trace_tsp = trace_tsp;
  mp->node_id = htonl (node_id);
  mp->app_data = htonl (app_data);
  mp->num_elts = num_elts;

  S;
  W;

  return (rv);
}



static int
api_trace_profile_del (vat_main_t * vam)
{
  trace_test_main_t *sm = &trace_test_main;
  vl_api_trace_profile_del_t *mp;
  f64 timeout;

  M (TRACE_PROFILE_DEL, trace_profile_del);
  S;
  W;
  return 0;
}

static int
api_trace_profile_show_config (vat_main_t * vam)
{
  trace_test_main_t *sm = &trace_test_main;
  vl_api_trace_profile_show_config_t *mp;
  f64 timeout;
  M (TRACE_PROFILE_SHOW_CONFIG, trace_profile_show_config);
  S;
  W;
  return 0;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg \
_(trace_profile_add, ""\
  "trace-type <0x1f|0x3|0x9|0x11|0x19> trace-elts <nn> trace-tsp <0|1|2|3> node-id <node id in hex> app-data <app_data in hex>")  \
_(trace_profile_del, "[id <nn>]")                    \
_(trace_profile_show_config, "[id <nn>]")


void
vat_api_hookup (vat_main_t * vam)
{
  trace_test_main_t *sm = &trace_test_main;
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#undef _

  /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_vpe_api_msg;
#undef _

  /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_vpe_api_msg;
#undef _
}

clib_error_t *
vat_plugin_register (vat_main_t * vam)
{
  trace_test_main_t *sm = &trace_test_main;
  u8 *name;

  sm->vat_main = vam;

  name = format (0, "ioam_trace_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~ 0)
    vat_api_hookup (vam);

  vec_free (name);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
