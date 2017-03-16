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

#include <lb/lb.h>

#include <vppinfra/byte_order.h>
#include <vlibapi/api.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

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

/* define generated endian-swappers */
#define vl_endianfun
#include <lb/lb.api.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <lb/lb.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <lb/lb.api.h>
#undef vl_msg_name_crc_list


#define REPLY_MSG_ID_BASE lbm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
setup_message_id_table (lb_main_t * lbm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + lbm->msg_id_base);
  foreach_vl_msg_name_crc_lb;
#undef _
}

/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

static void
vl_api_lb_conf_t_handler
(vl_api_lb_conf_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_conf_reply_t * rmp;
  int rv = 0;

  rv = lb_conf((ip4_address_t *)&mp->ip4_src_address,
               (ip6_address_t *)mp->ip6_src_address,
               mp->sticky_buckets_per_core,
               mp->flow_timeout);

 REPLY_MACRO (VL_API_LB_CONF_REPLY);
}

static void *vl_api_lb_conf_t_print
(vl_api_lb_conf_t *mp, void * handle)
{
  u8 * s;
  s = format (0, "SCRIPT: lb_conf ");
  s = format (s, "%U ", format_ip4_address, (ip4_address_t *)&mp->ip4_src_address);
  s = format (s, "%U ", format_ip6_address, (ip6_address_t *)mp->ip6_src_address);
  s = format (s, "%u ", mp->sticky_buckets_per_core);
  s = format (s, "%u ", mp->flow_timeout);
  FINISH;
}


static void
vl_api_lb_add_del_vip_t_handler
(vl_api_lb_add_del_vip_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_conf_reply_t * rmp;
  int rv = 0;
  ip46_address_t prefix;
  memcpy(&prefix.ip6, mp->ip_prefix, sizeof(prefix.ip6));

  if (mp->is_del) {
    u32 vip_index;
    if (!(rv = lb_vip_find_index(&prefix, mp->prefix_length, &vip_index)))
      rv = lb_vip_del(vip_index);
  } else {
    u32 vip_index;
    lb_vip_type_t type;
    if (ip46_prefix_is_ip4(&prefix, mp->prefix_length)) {
      type = mp->is_gre4?LB_VIP_TYPE_IP4_GRE4:LB_VIP_TYPE_IP4_GRE6;
    } else {
      type = mp->is_gre4?LB_VIP_TYPE_IP6_GRE4:LB_VIP_TYPE_IP6_GRE6;
    }

    rv = lb_vip_add(&prefix, mp->prefix_length, type,
                    mp->new_flows_table_length, &vip_index);
  }
 REPLY_MACRO (VL_API_LB_CONF_REPLY);
}

static void *vl_api_lb_add_del_vip_t_print
(vl_api_lb_add_del_vip_t *mp, void * handle)
{
  u8 * s;
  s = format (0, "SCRIPT: lb_add_del_vip ");
  s = format (s, "%U ", format_ip46_prefix,
              (ip46_address_t *)mp->ip_prefix, mp->prefix_length, IP46_TYPE_ANY);
  s = format (s, "%s ", mp->is_gre4?"gre4":"gre6");
  s = format (s, "%u ", mp->new_flows_table_length);
  s = format (s, "%s ", mp->is_del?"del":"add");
  FINISH;
}

static void
vl_api_lb_add_del_as_t_handler
(vl_api_lb_add_del_as_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_conf_reply_t * rmp;
  int rv = 0;
  u32 vip_index;
  if ((rv = lb_vip_find_index((ip46_address_t *)mp->vip_ip_prefix,
                              mp->vip_prefix_length, &vip_index)))
    goto done;

  if (mp->is_del)
    rv = lb_vip_del_ass(vip_index, (ip46_address_t *)mp->as_address, 1);
  else
    rv = lb_vip_add_ass(vip_index, (ip46_address_t *)mp->as_address, 1);

done:
 REPLY_MACRO (VL_API_LB_CONF_REPLY);
}

static void *vl_api_lb_add_del_as_t_print
(vl_api_lb_add_del_as_t *mp, void * handle)
{
  u8 * s;
  s = format (0, "SCRIPT: lb_add_del_as ");
  s = format (s, "%U ", format_ip46_prefix,
              (ip46_address_t *)mp->vip_ip_prefix, mp->vip_prefix_length, IP46_TYPE_ANY);
  s = format (s, "%U ", format_ip46_address,
                (ip46_address_t *)mp->as_address, IP46_TYPE_ANY);
  s = format (s, "%s ", mp->is_del?"del":"add");
  FINISH;
}

/* List of message types that this plugin understands */
#define foreach_lb_plugin_api_msg            \
_(LB_CONF, lb_conf)                          \
_(LB_ADD_DEL_VIP, lb_add_del_vip)            \
_(LB_ADD_DEL_AS, lb_add_del_as)

static clib_error_t * lb_api_init (vlib_main_t * vm)
{
  lb_main_t *lbm = &lb_main;
  u8 *name = format (0, "lb_%08x%c", api_version, 0);
  lbm->msg_id_base = vl_msg_api_get_msg_ids
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + lbm->msg_id_base),     \
                           #n,                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_lb_plugin_api_msg;
#undef _

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (lbm, &api_main);

  return 0;
}

VLIB_INIT_FUNCTION (lb_api_init);
