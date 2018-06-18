/*
 * mactime.c - skeleton vpp-api-test plug-in
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
#include <vppinfra/error.h>
#include <vppinfra/time_range.h>

uword vat_unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <mactime/mactime_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <mactime/mactime_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <mactime/mactime_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <mactime/mactime_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <mactime/mactime_all_api_h.h>
#undef vl_api_version

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} mactime_test_main_t;

mactime_test_main_t mactime_test_main;

#define __plugin_msg_base mactime_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

#define foreach_standard_reply_retval_handler   \
_(mactime_enable_disable_reply)                 \
_(mactime_add_del_range_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = mactime_test_main.vat_main;   \
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

static u8 *
format_mac_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		 a[0], a[1], a[2], a[3], a[4], a[5]);
}

static uword
unformat_mac_address (unformat_input_t * input, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return unformat (input, "%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3],
		   &a[4], &a[5]);
}

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                               \
_(MACTIME_ENABLE_DISABLE_REPLY, mactime_enable_disable_reply)   \
_(MACTIME_ADD_DEL_RANGE_REPLY, mactime_add_del_range_reply)

static int
api_mactime_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  int enable_disable = 1;
  u32 sw_if_index = ~0;
  vl_api_mactime_enable_disable_t *mp;
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
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name / explicit sw_if_index number \n");
      return -99;
    }

  /* Construct the API message */
  M (MACTIME_ENABLE_DISABLE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable_disable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_mactime_add_del_range (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_mactime_add_del_range_t *mp;
  u8 mac_address[8];
  u8 *device_name = 0;
  clib_timebase_range_t *rp = 0;
  int name_set = 0;
  int mac_set = 0;
  u8 is_add = 1;
  u8 allow = 0;
  u8 drop = 0;
  int ret;
  int ii;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %s", &device_name))
	{
	  vec_add1 (device_name, 0);
	  name_set = 1;
	}
      else if (unformat (i, "allow-range %U",
			 unformat_clib_timebase_range_vector, &rp))
	allow = 1;
      else if (unformat (i, "drop-range %U",
			 unformat_clib_timebase_range_vector, &rp))
	drop = 1;
      else if (unformat (i, "allow-static"))
	allow = 1;
      else if (unformat (i, "drop-static"))
	drop = 1;
      else if (unformat (i, "mac %U", unformat_mac_address, mac_address))
	mac_set = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	break;
    }

  /* Sanity checks */
  if (mac_set == 0)
    {
      vec_free (rp);
      vec_free (device_name);
      errmsg ("mac address required, not set\n");
      return -99;
    }

  /* allow-range / drop-range parse errors cause this condition */
  if (is_add && allow == 0 && drop == 0)
    {
      vec_free (rp);
      vec_free (device_name);
      errmsg ("neither allow nor drop set, parse error...\n");
    }

  /* Unlikely, but check anyhow */
  if (vec_len (device_name) > ARRAY_LEN (mp->device_name))
    {
      vec_free (rp);
      vec_free (device_name);
      errmsg ("device name too long, max %d\n", ARRAY_LEN (mp->device_name));
      return -99;
    }

  /* Cough up a device name if none set */
  if (name_set == 0)
    {
      device_name = format (0, "mac %U%c", format_mac_address,
			    mac_address, 0);
    }

  /* Construct the API message */
  M2 (MACTIME_ADD_DEL_RANGE, mp, sizeof (rp[0]) * vec_len (rp));
  mp->is_add = is_add;
  mp->drop = drop;
  mp->allow = allow;
  memcpy (mp->mac_address, mac_address, sizeof (mp->mac_address));
  memcpy (mp->device_name, device_name, vec_len (device_name));
  mp->count = clib_host_to_net_u32 (vec_len (rp));

  for (ii = 0; ii < vec_len (rp); ii++)
    {
      mp->ranges[ii].start = rp[ii].start;
      mp->ranges[ii].end = rp[ii].end;
    }

  vec_free (rp);
  vec_free (device_name);

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
#define foreach_vpe_api_msg                     \
_(mactime_enable_disable, "<intfc> [disable]")  \
_(mactime_add_del_range,                        \
  "name <devname> mac <mac-addr> allow drop\n"  \
  "allow-range Mon - Fri 9:00 - 17:00")

static void
mactime_api_hookup (vat_main_t * vam)
{
  mactime_test_main_t *sm = &mactime_test_main;
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
  mactime_test_main_t *sm = &mactime_test_main;
  u8 *name;

  sm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "mactime_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~ 0)
    mactime_api_hookup (vam);

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
