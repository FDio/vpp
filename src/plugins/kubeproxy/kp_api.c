/*
 * Copyright (c) 2016 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "POD IS" BPODIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <kubeproxy/kp.h>

#include <vppinfra/byte_order.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#define vl_msg_id(n,h) n,
typedef enum {
#include <kubeproxy/kp.api.h>
    /* We'll want to know how many messages IDs we need... */
    VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id


/* define message structures */
#define vl_typedefs
#include <kubeproxy/kp.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <kubeproxy/kp.api.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <kubeproxy/kp.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <kubeproxy/kp.api.h>
#undef vl_msg_name_crc_list


#define REPLY_MSG_ID_BASE kpm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
setup_message_id_table (kp_main_t * kpm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + kpm->msg_id_base);
  foreach_vl_msg_name_crc_kp;
#undef _
}

/* Macro to finish up custom dump fns */
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

static void
vl_api_kp_conf_t_handler
(vl_api_kp_conf_t * mp)
{
  kp_main_t *kpm = &kp_main;
  vl_api_kp_conf_reply_t * rmp;
  int rv = 0;

  rv = kp_conf(mp->sticky_buckets_per_core,
               mp->flow_timeout);

 REPLY_MACRO (VL_API_KP_CONF_REPLY);
}

static void *vl_api_kp_conf_t_print
(vl_api_kp_conf_t *mp, void * handle)
{
  u8 * s;
  s = format (0, "SCRIPT: kp_conf ");
  s = format (s, "%u ", mp->sticky_buckets_per_core);
  s = format (s, "%u ", mp->flow_timeout);
  FINISH;
}


static void
vl_api_kp_add_del_vip_t_handler
(vl_api_kp_add_del_vip_t * mp)
{
  kp_main_t *kpm = &kp_main;
  vl_api_kp_conf_reply_t * rmp;
  int rv = 0;
  ip46_address_t prefix;
  u8 prefix_length = mp->prefix_length;

  if (mp->is_ipv6 == 0)
    {
      prefix_length += 96;
      memcpy(&prefix.ip4, mp->ip_prefix, sizeof(prefix.ip4));
      prefix.pad[0] = prefix.pad[1] = prefix.pad[2] = 0;
    }
  else
    {
      memcpy(&prefix.ip6, mp->ip_prefix, sizeof(prefix.ip6));
    }

  if (mp->is_del) {
    u32 vip_index;
    if (!(rv = kp_vip_find_index(&prefix, prefix_length, &vip_index)))
      rv = kp_vip_del(vip_index);
  } else {
    u32 vip_index;
    kp_vip_type_t type;
    if (mp->is_ipv6 == 0) {
      type = mp->is_nat4?KP_VIP_TYPE_IP4_NAT44:KP_VIP_TYPE_IP4_NAT46;
    } else {
      type = mp->is_nat4?KP_VIP_TYPE_IP6_NAT64:KP_VIP_TYPE_IP6_NAT66;
    }

    rv = kp_vip_add(&prefix, prefix_length, type,
		    ntohl(mp->new_flows_table_length), &vip_index,
		    ntohs(mp->port), ntohs(mp->target_port),
		    ntohs(mp->node_port));
  }
 REPLY_MACRO (VL_API_KP_CONF_REPLY);
}

static void *vl_api_kp_add_del_vip_t_print
(vl_api_kp_add_del_vip_t *mp, void * handle)
{
  u8 * s;
  s = format (0, "SCRIPT: kp_add_del_vip ");
  s = format (s, "%U ", format_ip46_prefix,
              (ip46_address_t *)mp->ip_prefix, mp->prefix_length, IP46_TYPE_ANY);
  s = format (s, "port %u ", mp->port);
  s = format (s, "target_port %u ", mp->target_port);
  s = format (s, "node_port %u ", mp->node_port);
  s = format (s, "%s ", mp->is_nat4?"nat4":"nat6");
  s = format (s, "%u ", mp->new_flows_table_length);
  s = format (s, "%s ", mp->is_del?"del":"add");
  FINISH;
}

static void
vl_api_kp_add_del_pod_t_handler
(vl_api_kp_add_del_pod_t * mp)
{
  kp_main_t *kpm = &kp_main;
  vl_api_kp_conf_reply_t * rmp;
  int rv = 0;
  u32 vip_index;

  ip46_address_t vip_ip_prefix;
  u8 vip_prefix_length = mp->vip_prefix_length;

  if (mp->vip_is_ipv6 == 0)
    {
      vip_prefix_length += 96;
      memcpy(&vip_ip_prefix.ip4, mp->vip_ip_prefix,
	     sizeof(vip_ip_prefix.ip4));
      vip_ip_prefix.pad[0] = vip_ip_prefix.pad[1] = vip_ip_prefix.pad[2] = 0;
    }
  else
    {
      memcpy(&vip_ip_prefix.ip6, mp->vip_ip_prefix,
	     sizeof(vip_ip_prefix.ip6));
    }

  ip46_address_t pod_address;

  if (mp->pod_is_ipv6 == 0)
    {
      memcpy(&pod_address.ip4, mp->pod_address,
	     sizeof(pod_address.ip4));
      pod_address.pad[0] = pod_address.pad[1] = pod_address.pad[2] = 0;
    }
  else
    {
      memcpy(&pod_address.ip6, mp->pod_address,
	     sizeof(pod_address.ip6));
    }

  if ((rv = kp_vip_find_index(&vip_ip_prefix, vip_prefix_length, &vip_index)))
    goto done;

  if (mp->is_del)
    rv = kp_vip_del_pods(vip_index, &pod_address, 1);
  else
    rv = kp_vip_add_pods(vip_index, &pod_address, 1);

done:
 REPLY_MACRO (VL_API_KP_CONF_REPLY);
}

static void *vl_api_kp_add_del_pod_t_print
(vl_api_kp_add_del_pod_t *mp, void * handle)
{
  u8 * s;
  s = format (0, "SCRIPT: kp_add_del_pod ");
  s = format (s, "%U ", format_ip46_prefix,
              (ip46_address_t *)mp->vip_ip_prefix, mp->vip_prefix_length, IP46_TYPE_ANY);
  s = format (s, "%U ", format_ip46_address,
                (ip46_address_t *)mp->pod_address, IP46_TYPE_ANY);
  s = format (s, "%s ", mp->is_del?"del":"add");
  FINISH;
}

/* List of message types that this plugin understands */
#define foreach_kp_plugin_api_msg            \
_(KP_CONF, kp_conf)                          \
_(KP_ADD_DEL_VIP, kp_add_del_vip)            \
_(KP_ADD_DEL_POD, kp_add_del_pod)

static clib_error_t * kp_api_init (vlib_main_t * vm)
{
  kp_main_t *kpm = &kp_main;
  u8 *name = format (0, "kp_%08x%c", api_version, 0);
  kpm->msg_id_base = vl_msg_api_get_msg_ids
      ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + kpm->msg_id_base),     \
                           #n,                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_kp_plugin_api_msg;
#undef _

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (kpm, &api_main);

  return 0;
}

VLIB_INIT_FUNCTION (kp_api_init);
