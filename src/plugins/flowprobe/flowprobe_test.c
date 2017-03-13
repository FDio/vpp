/*
 * flowprobe.c - skeleton vpp-api-test plug-in
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
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vppinfra/error.h>
#include <flowprobe/flowprobe.h>

#define __plugin_msg_base flowprobe_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/**
 * @file vpp_api_test plugin
 */

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <flowprobe/flowprobe_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <flowprobe/flowprobe_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <flowprobe/flowprobe_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <flowprobe/flowprobe_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <flowprobe/flowprobe_all_api_h.h>
#undef vl_api_version

typedef struct
{
    /** API message ID base */
  u16 msg_id_base;
    /** vat_main_t pointer */
  vat_main_t *vat_main;
} flowprobe_test_main_t;

flowprobe_test_main_t flowprobe_test_main;

#define foreach_standard_reply_retval_handler   \
_(flowprobe_tx_interface_add_del_reply)        \
_(flowprobe_params_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = flowprobe_test_main.vat_main;   \
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

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg               \
_(FLOWPROBE_TX_INTERFACE_ADD_DEL_REPLY,        \
  flowprobe_tx_interface_add_del_reply)        \
_(FLOWPROBE_PARAMS_REPLY, flowprobe_params_reply)

static int
api_flowprobe_tx_interface_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  int enable_disable = 1;
  u8 which = FLOW_VARIANT_IP4;
  u32 sw_if_index = ~0;
  vl_api_flowprobe_tx_interface_add_del_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "disable"))
	enable_disable = 0;
      else if (unformat (i, "ip4"))
	which = FLOW_VARIANT_IP4;
      else if (unformat (i, "ip6"))
	which = FLOW_VARIANT_IP6;
      else if (unformat (i, "l2"))
	which = FLOW_VARIANT_L2;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name / explicit sw_if_index number \n");
      return -99;
    }

  /* Construct the API message */
  M (FLOWPROBE_TX_INTERFACE_ADD_DEL, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = enable_disable;
  mp->which = which;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_flowprobe_params (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  u8 record_l2 = 0, record_l3 = 0, record_l4 = 0;
  u32 active_timer = ~0;
  u32 passive_timer = ~0;
  vl_api_flowprobe_params_t *mp;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "active %d", &active_timer))
	;
      else if (unformat (i, "passive %d", &passive_timer))
	;
      else if (unformat (i, "record"))
	while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	  {
	    if (unformat (i, "l2"))
	      record_l2 = 1;
	    else if (unformat (i, "l3"))
	      record_l3 = 1;
	    else if (unformat (i, "l4"))
	      record_l4 = 1;
	    else
	      break;
	  }
      else
	break;
    }

  if (passive_timer > 0 && active_timer > passive_timer)
    {
      errmsg ("Passive timer has to be greater than active one...\n");
      return -99;
    }

  /* Construct the API message */
  M (FLOWPROBE_PARAMS, mp);
  mp->record_l2 = record_l2;
  mp->record_l3 = record_l3;
  mp->record_l4 = record_l4;
  mp->active_timer = ntohl (active_timer);
  mp->passive_timer = ntohl (passive_timer);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  return ret;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg \
_(flowprobe_tx_interface_add_del, "<intfc> [disable]") \
_(flowprobe_params, "record <[l2] [l3] [l4]> [active <timer> passive <timer>]")

static void
flowprobe_vat_api_hookup (vat_main_t * vam)
{
  flowprobe_test_main_t *sm = &flowprobe_test_main;
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
  flowprobe_test_main_t *sm = &flowprobe_test_main;
  u8 *name;

  sm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "flowprobe_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  /* Don't attempt to hook up API messages if the data plane plugin is AWOL */
  if (sm->msg_id_base != (u16) ~ 0)
    flowprobe_vat_api_hookup (vam);

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
