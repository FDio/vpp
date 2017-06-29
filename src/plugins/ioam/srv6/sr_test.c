/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 * sr_test.c - test harness for SR IOAM plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vppinfra/error.h>

#define __plugin_msg_base sr_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <ioam/srv6/sr_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ioam/srv6/sr_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <ioam/srv6/sr_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <ioam/srv6/sr_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ioam/srv6/sr_all_api_h.h>
#undef vl_api_version
#include <ioam/srv6/sr_ioam.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} sr_test_main_t;

sr_test_main_t sr_test_main;

#define foreach_standard_reply_retval_handler     \
_(sr_ioam_enable_reply)                    \
_(sr_ioam_disable_reply)
#if 0
_(sr_ioam_disable_reply)
_(sr_ioam_vni_enable_reply)
_(sr_ioam_vni_disable_reply)
_(sr_ioam_transit_enable_reply) _(sr_ioam_transit_disable_reply)
#endif
#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = sr_test_main.vat_main;   \
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
#define foreach_vpe_api_reply_msg                                              \
_(SR_IOAM_ENABLE_REPLY, sr_ioam_enable_reply)                    \
_(SR_IOAM_DISABLE_REPLY, sr_ioam_disable_reply)                  \

     static int
     api_sr_ioam_enable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_sr_ioam_enable_t *mp;
  u32 id = 0;
  int has_trace_option = 0;
  int has_pow_option = 0;
  int has_ppc_option = 0;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "trace"))
	has_trace_option = 1;
      else if (unformat (input, "pow"))
	has_pow_option = 1;
#if 0
      else if (unformat (input, "ppc encap"))
	has_ppc_option = PPC_ENCAP;
      else if (unformat (input, "ppc decap"))
	has_ppc_option = PPC_DECAP;
      else if (unformat (input, "ppc none"))
	has_ppc_option = PPC_NONE;
#endif
      else
	break;
    }
  M (SR_IOAM_ENABLE, mp);
  mp->id = htons (id);
  mp->trace_ppc = has_ppc_option;
  mp->pow_enable = has_pow_option;
  mp->trace_enable = has_trace_option;


  S (mp);
  W (ret);
  return ret;
}


static int
api_sr_ioam_disable (vat_main_t * vam)
{
  vl_api_sr_ioam_disable_t *mp;
  int ret;

  M (SR_IOAM_DISABLE, mp);
  S (mp);
  W (ret);
  return ret;
}

#if 0
static int
api_sr_ioam_vni_enable (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_sr_ioam_vni_enable_t *mp;
  ip4_address_t local4, remote4;
  ip6_address_t local6, remote6;
  u8 ipv4_set = 0, ipv6_set = 0;
  u8 local_set = 0;
  u8 remote_set = 0;
  u32 vni;
  u8 vni_set = 0;
  int ret;


  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U", unformat_ip4_address, &local4))
	{
	  local_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "remote %U",
			 unformat_ip4_address, &remote4))
	{
	  remote_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "local %U",
			 unformat_ip6_address, &local6))
	{
	  local_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "remote %U",
			 unformat_ip6_address, &remote6))
	{
	  remote_set = 1;
	  ipv6_set = 1;
	}

      else if (unformat (line_input, "vni %d", &vni))
	vni_set = 1;
      else
	{
	  errmsg ("parse error '%U'\n", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (local_set == 0)
    {
      errmsg ("tunnel local address not specified\n");
      return -99;
    }
  if (remote_set == 0)
    {
      errmsg ("tunnel remote address not specified\n");
      return -99;
    }
  if (ipv4_set && ipv6_set)
    {
      errmsg ("both IPv4 and IPv6 addresses specified");
      return -99;
    }

  if (vni_set == 0)
    {
      errmsg ("vni not specified\n");
      return -99;
    }

  M (SR_IOAM_VNI_ENABLE, mp);


  if (ipv6_set)
    {
      clib_memcpy (&mp->local, &local6, sizeof (local6));
      clib_memcpy (&mp->remote, &remote6, sizeof (remote6));
    }
  else
    {
      clib_memcpy (&mp->local, &local4, sizeof (local4));
      clib_memcpy (&mp->remote, &remote4, sizeof (remote4));
    }

  mp->vni = ntohl (vni);
  mp->is_ipv6 = ipv6_set;

  S (mp);
  W (ret);
  return ret;
}

static int
api_sr_ioam_vni_disable (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_sr_ioam_vni_disable_t *mp;
  ip4_address_t local4, remote4;
  ip6_address_t local6, remote6;
  u8 ipv4_set = 0, ipv6_set = 0;
  u8 local_set = 0;
  u8 remote_set = 0;
  u32 vni;
  u8 vni_set = 0;
  int ret;


  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U", unformat_ip4_address, &local4))
	{
	  local_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "remote %U",
			 unformat_ip4_address, &remote4))
	{
	  remote_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "local %U",
			 unformat_ip6_address, &local6))
	{
	  local_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "remote %U",
			 unformat_ip6_address, &remote6))
	{
	  remote_set = 1;
	  ipv6_set = 1;
	}

      else if (unformat (line_input, "vni %d", &vni))
	vni_set = 1;
      else
	{
	  errmsg ("parse error '%U'\n", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (local_set == 0)
    {
      errmsg ("tunnel local address not specified\n");
      return -99;
    }
  if (remote_set == 0)
    {
      errmsg ("tunnel remote address not specified\n");
      return -99;
    }
  if (ipv4_set && ipv6_set)
    {
      errmsg ("both IPv4 and IPv6 addresses specified");
      return -99;
    }

  if (vni_set == 0)
    {
      errmsg ("vni not specified\n");
      return -99;
    }

  M (SR_IOAM_VNI_DISABLE, mp);


  if (ipv6_set)
    {
      clib_memcpy (&mp->local, &local6, sizeof (local6));
      clib_memcpy (&mp->remote, &remote6, sizeof (remote6));
    }
  else
    {
      clib_memcpy (&mp->local, &local4, sizeof (local4));
      clib_memcpy (&mp->remote, &remote4, sizeof (remote4));
    }

  mp->vni = ntohl (vni);
  mp->is_ipv6 = ipv6_set;

  S (mp);
  W (ret);
  return ret;
}

static int
api_sr_ioam_transit_enable (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_sr_ioam_transit_enable_t *mp;
  ip4_address_t local4;
  ip6_address_t local6;
  u8 ipv4_set = 0, ipv6_set = 0;
  u8 local_set = 0;
  u32 outer_fib_index = 0;
  int ret;


  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "dst-ip %U", unformat_ip4_address, &local4))
	{
	  local_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "dst-ip %U",
			 unformat_ip6_address, &local6))
	{
	  local_set = 1;
	  ipv6_set = 1;
	}

      else if (unformat (line_input, "outer-fib-index %d", &outer_fib_index))
	;
      else
	{
	  errmsg ("parse error '%U'\n", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (local_set == 0)
    {
      errmsg ("destination address not specified\n");
      return -99;
    }
  if (ipv4_set && ipv6_set)
    {
      errmsg ("both IPv4 and IPv6 addresses specified");
      return -99;
    }


  M (SR_IOAM_TRANSIT_ENABLE, mp);


  if (ipv6_set)
    {
      errmsg ("IPv6 currently unsupported");
      return -1;
    }
  else
    {
      clib_memcpy (&mp->dst_addr, &local4, sizeof (local4));
    }

  mp->outer_fib_index = htonl (outer_fib_index);
  mp->is_ipv6 = ipv6_set;

  S (mp);
  W (ret);
  return ret;
}

static int
api_sr_ioam_transit_disable (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_sr_ioam_transit_disable_t *mp;
  ip4_address_t local4;
  ip6_address_t local6;
  u8 ipv4_set = 0, ipv6_set = 0;
  u8 local_set = 0;
  u32 outer_fib_index = 0;
  int ret;


  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "dst-ip %U", unformat_ip4_address, &local4))
	{
	  local_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "dst-ip %U",
			 unformat_ip6_address, &local6))
	{
	  local_set = 1;
	  ipv6_set = 1;
	}

      else if (unformat (line_input, "outer-fib-index %d", &outer_fib_index))
	;
      else
	{
	  errmsg ("parse error '%U'\n", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (local_set == 0)
    {
      errmsg ("destination address not specified\n");
      return -99;
    }
  if (ipv4_set && ipv6_set)
    {
      errmsg ("both IPv4 and IPv6 addresses specified");
      return -99;
    }


  M (SR_IOAM_TRANSIT_DISABLE, mp);


  if (ipv6_set)
    {
      return -1;
    }
  else
    {
      clib_memcpy (&mp->dst_addr, &local4, sizeof (local4));
    }

  mp->outer_fib_index = htonl (outer_fib_index);
  mp->is_ipv6 = ipv6_set;

  S (mp);
  W (ret);
  return ret;
}
#endif

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg \
_(sr_ioam_enable, ""\
  "[trace] [pow] [ppc <encap|ppc decap>]") \
_(sr_ioam_disable, "")\



static void
sr_vat_api_hookup (vat_main_t * vam)
{
  sr_test_main_t *sm = &sr_test_main;
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
  sr_test_main_t *sm = &sr_test_main;
  u8 *name;

  sm->vat_main = vam;

  name = format (0, "ioam_sr_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~ 0)
    sr_vat_api_hookup (vam);

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
