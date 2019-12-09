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

#include <vppinfra/error.h>

#define __plugin_msg_base trace_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <ioam/lib-trace/trace.api_enum.h>
#include <ioam/lib-trace/trace.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} trace_test_main_t;

trace_test_main_t trace_test_main;

static int
api_trace_profile_add (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_trace_profile_add_t *mp;
  u8 trace_type = 0;
  u8 num_elts = 0;
  u32 node_id = 0;
  u32 app_data = 0;
  u8 trace_tsp = 0;
  int ret;

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


  M (TRACE_PROFILE_ADD, mp);

  mp->trace_type = trace_type;
  mp->trace_tsp = trace_tsp;
  mp->node_id = htonl (node_id);
  mp->app_data = htonl (app_data);
  mp->num_elts = num_elts;

  S (mp);
  W (ret);
  return ret;
}



static int
api_trace_profile_del (vat_main_t * vam)
{
  vl_api_trace_profile_del_t *mp;
  int ret;

  M (TRACE_PROFILE_DEL, mp);
  S (mp);
  W (ret);
  return ret;
}

static int
api_trace_profile_show_config (vat_main_t * vam)
{
  vl_api_trace_profile_show_config_t *mp;
  int ret;

  M (TRACE_PROFILE_SHOW_CONFIG, mp);
  S (mp);
  W (ret);
  return ret;
}

static int
vl_api_trace_profile_show_config_reply_t_handler (vat_main_t * vam)
{
  return -1;
}

/* Override generated plugin register symbol */
#define vat_plugin_register trace_vat_plugin_register
#include <ioam/lib-trace/trace.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
