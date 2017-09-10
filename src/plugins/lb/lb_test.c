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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <lb/lb.h>

#define __plugin_msg_base lb_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

//TODO: Move that to vat/plugin_api.c
//////////////////////////
uword unformat_ip46_address (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  if ((type != IP46_TYPE_IP6) &&
      unformat(input, "%U", unformat_ip4_address, &ip46->ip4)) {
    ip46_address_mask_ip4(ip46);
    return 1;
  } else if ((type != IP46_TYPE_IP4) &&
      unformat(input, "%U", unformat_ip6_address, &ip46->ip6)) {
    return 1;
  }
  return 0;
}
uword unformat_ip46_prefix (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  u8 *len = va_arg (*args, u8 *);
  ip46_type_t type = va_arg (*args, ip46_type_t);

  u32 l;
  if ((type != IP46_TYPE_IP6) && unformat(input, "%U/%u", unformat_ip4_address, &ip46->ip4, &l)) {
    if (l > 32)
      return 0;
    *len = l + 96;
    ip46->pad[0] = ip46->pad[1] = ip46->pad[2] = 0;
  } else if ((type != IP46_TYPE_IP4) && unformat(input, "%U/%u", unformat_ip6_address, &ip46->ip6, &l)) {
    if (l > 128)
      return 0;
    *len = l;
  } else {
    return 0;
  }
  return 1;
}
/////////////////////////

#define vl_msg_id(n,h) n,
typedef enum {
#include <lb/lb.api.h>
    /* We'll want to know how many messages IDs we need... */
    VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <lb/lb.api.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <lb/lb.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <lb/lb.api.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <lb/lb.api.h>
#undef vl_api_version

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} lb_test_main_t;

lb_test_main_t lb_test_main;

#define foreach_standard_reply_retval_handler   \
_(lb_conf_reply)                 \
_(lb_add_del_vip_reply)          \
_(lb_add_del_as_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = lb_test_main.vat_main;   \
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
#define foreach_vpe_api_reply_msg                               \
  _(LB_CONF_REPLY, lb_conf_reply)                                     \
  _(LB_ADD_DEL_VIP_REPLY, lb_add_del_vip_reply)                       \
  _(LB_ADD_DEL_AS_REPLY, lb_add_del_as_reply)

static int api_lb_conf (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_lb_conf_t mps, *mp;
  int ret;

  if (!unformat(i, "%U %U %u %u",
               unformat_ip4_address, &mps.ip4_src_address,
               unformat_ip6_address, mps.ip6_src_address,
               &mps.sticky_buckets_per_core,
               &mps.flow_timeout)) {
    errmsg ("invalid arguments\n");
    return -99;
  }

  M(LB_CONF, mp);
  S(mp);
  W (ret);
  return ret;
}

static int api_lb_add_del_vip (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_lb_add_del_vip_t mps, *mp;
  int ret;
  mps.is_del = 0;
  mps.is_gre4 = 0;

  if (!unformat(i, "%U",
                unformat_ip46_prefix, mps.ip_prefix, &mps.prefix_length, IP46_TYPE_ANY)) {
    errmsg ("invalid prefix\n");
    return -99;
  }

  if (unformat(i, "gre4")) {
    mps.is_gre4 = 1;
  } else if (unformat(i, "gre6")) {
    mps.is_gre4 = 0;
  } else {
    errmsg ("no encap\n");
    return -99;
  }

  if (!unformat(i, "%d", &mps.new_flows_table_length)) {
    errmsg ("no table lentgh\n");
    return -99;
  }

  if (unformat(i, "del")) {
    mps.is_del = 1;
  }

  M(LB_ADD_DEL_VIP, mp);
  S(mp);
  W (ret);
  return ret;
}

static int api_lb_add_del_as (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_lb_add_del_as_t mps, *mp;
  int ret;
  mps.is_del = 0;

  if (!unformat(i, "%U %U",
                unformat_ip46_prefix, mps.vip_ip_prefix, &mps.vip_prefix_length, IP46_TYPE_ANY,
                unformat_ip46_address, mps.as_address)) {
    errmsg ("invalid prefix or address\n");
    return -99;
  }

  if (unformat(i, "del")) {
    mps.is_del = 1;
  }

  M(LB_ADD_DEL_AS, mp);
  S(mp);
  W (ret);
  return ret;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                             \
_(lb_conf, "<ip4-src-addr> <ip6-src-address> <sticky_buckets_per_core> <flow_timeout>") \
_(lb_add_del_vip, "<ip-prefix> [gre4|gre6] <new_table_len> [del]") \
_(lb_add_del_as, "<vip-ip-prefix> <address> [del]")

static void 
lb_vat_api_hookup (vat_main_t *vam)
{
  lb_test_main_t * lbtm = &lb_test_main;
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + lbtm->msg_id_base),       \
                          #n,                                   \
                          vl_api_##n##_t_handler,               \
                          vl_noop_handler,                      \
                          vl_api_##n##_t_endian,                \
                          vl_api_##n##_t_print,                 \
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

clib_error_t * vat_plugin_register (vat_main_t *vam)
{
  lb_test_main_t * lbtm = &lb_test_main;

  u8 * name;

  lbtm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "lb_%08x%c", api_version, 0);
  lbtm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (lbtm->msg_id_base != (u16) ~0)
    lb_vat_api_hookup (vam);

  vec_free(name);

  return 0;
}
