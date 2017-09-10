
/*
 * nat.c - skeleton vpp-api-test plug-in
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
#include <vnet/ip/ip.h>
#include <nat/nat.h>

#define __plugin_msg_base snat_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <nat/nat_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <nat/nat_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <nat/nat_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <nat/nat_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <nat/nat_all_api_h.h>
#undef vl_api_version

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} snat_test_main_t;

snat_test_main_t snat_test_main;

#define foreach_standard_reply_retval_handler   \
_(snat_add_address_range_reply)                 \
_(snat_interface_add_del_feature_reply)         \
_(snat_add_static_mapping_reply)                \
_(snat_set_workers_reply)                       \
_(snat_add_del_interface_addr_reply)            \
_(snat_ipfix_enable_disable_reply)              \
_(snat_add_det_map_reply)                       \
_(snat_det_set_timeouts_reply)                  \
_(snat_det_close_session_out_reply)             \
_(snat_det_close_session_in_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = snat_test_main.vat_main;   \
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
_(SNAT_ADD_ADDRESS_RANGE_REPLY, snat_add_address_range_reply)   \
_(SNAT_INTERFACE_ADD_DEL_FEATURE_REPLY,                         \
  snat_interface_add_del_feature_reply)                         \
_(SNAT_ADD_STATIC_MAPPING_REPLY, snat_add_static_mapping_reply) \
_(SNAT_CONTROL_PING_REPLY, snat_control_ping_reply)             \
_(SNAT_STATIC_MAPPING_DETAILS, snat_static_mapping_details)     \
_(SNAT_SHOW_CONFIG_REPLY, snat_show_config_reply)               \
_(SNAT_ADDRESS_DETAILS, snat_address_details)                   \
_(SNAT_INTERFACE_DETAILS, snat_interface_details)               \
_(SNAT_SET_WORKERS_REPLY, snat_set_workers_reply)               \
_(SNAT_WORKER_DETAILS, snat_worker_details)                     \
_(SNAT_ADD_DEL_INTERFACE_ADDR_REPLY,                            \
  snat_add_del_interface_addr_reply)                            \
_(SNAT_INTERFACE_ADDR_DETAILS, snat_interface_addr_details)     \
_(SNAT_IPFIX_ENABLE_DISABLE_REPLY,                              \
  snat_ipfix_enable_disable_reply)                              \
_(SNAT_USER_DETAILS, snat_user_details)                         \
_(SNAT_USER_SESSION_DETAILS, snat_user_session_details)         \
_(SNAT_ADD_DET_MAP_REPLY, snat_add_det_map_reply)               \
_(SNAT_DET_FORWARD_REPLY, snat_det_forward_reply)               \
_(SNAT_DET_REVERSE_REPLY, snat_det_reverse_reply)               \
_(SNAT_DET_MAP_DETAILS, snat_det_map_details)                   \
_(SNAT_DET_SET_TIMEOUTS_REPLY, snat_det_set_timeouts_reply)     \
_(SNAT_DET_GET_TIMEOUTS_REPLY, snat_det_get_timeouts_reply)     \
_(SNAT_DET_CLOSE_SESSION_OUT_REPLY,                             \
  snat_det_close_session_out_reply)                             \
_(SNAT_DET_CLOSE_SESSION_IN_REPLY,                              \
  snat_det_close_session_in_reply)                              \
_(SNAT_DET_SESSION_DETAILS, snat_det_session_details)

static int api_snat_add_address_range (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  ip4_address_t start_addr, end_addr;
  u32 start_host_order, end_host_order;
  vl_api_snat_add_address_range_t * mp;
  u8 is_add = 1;
  int count;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U - %U",
                    unformat_ip4_address, &start_addr,
                    unformat_ip4_address, &end_addr))
        ;
      else if (unformat (i, "%U", unformat_ip4_address, &start_addr))
        end_addr = start_addr;
      else if (unformat (i, "del"))
        is_add = 0;
      else
        {
          clib_warning("unknown input '%U'", format_unformat_error, i);
          return -99;
        }
    }

  start_host_order = clib_host_to_net_u32 (start_addr.as_u32);
  end_host_order = clib_host_to_net_u32 (end_addr.as_u32);
  
  if (end_host_order < start_host_order)
    {
      errmsg ("end address less than start address\n");
      return -99;
    }

  count = (end_host_order - start_host_order) + 1;

  if (count > 1024)
    {
    errmsg ("%U - %U, %d addresses...\n",
           format_ip4_address, &start_addr,
           format_ip4_address, &end_addr,
           count);
    }
  
  M(SNAT_ADD_ADDRESS_RANGE, mp);

  memcpy (mp->first_ip_address, &start_addr, 4);
  memcpy (mp->last_ip_address, &end_addr, 4);
  mp->is_ip4 = 1;
  mp->is_add = is_add;

  S(mp);
  W (ret);
  return ret;
}

static int api_snat_interface_add_del_feature (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_snat_interface_add_del_feature_t * mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 is_inside = 1; 
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
        sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
        sw_if_index_set = 1;
      else if (unformat (i, "out"))
        is_inside = 0;
      else if (unformat (i, "in"))
        is_inside = 1;
      else if (unformat (i, "del"))
        is_add = 0;
      else
        {
          clib_warning("unknown input '%U'", format_unformat_error, i);
          return -99;
        }
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("interface / sw_if_index required\n");
      return -99;
    }

  M(SNAT_INTERFACE_ADD_DEL_FEATURE, mp);
  mp->sw_if_index = ntohl(sw_if_index);
  mp->is_add = is_add;
  mp->is_inside = is_inside;
  
  S(mp);
  W (ret);
  return ret;
}

static int api_snat_add_static_mapping(vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_snat_add_static_mapping_t * mp;
  u8 external_addr_set = 0;
  u8 local_addr_set = 0;
  u8 is_add = 1;
  u8 addr_only = 1;
  ip4_address_t local_addr, external_addr;
  u32 local_port = 0, external_port = 0, vrf_id = ~0;
  u32 sw_if_index = ~0;
  u8 sw_if_index_set = 0;
  u32 proto = ~0;
  u8 proto_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "local_addr %U", unformat_ip4_address, &local_addr))
        local_addr_set = 1;
      else if (unformat (i, "external_addr %U", unformat_ip4_address,
                         &external_addr))
        external_addr_set = 1;
      else if (unformat (i, "local_port %u", &local_port))
        addr_only = 0;
      else if (unformat (i, "external_port %u", &external_port))
        addr_only = 0;
      else if (unformat (i, "external_if %U", unformat_sw_if_index, vam,
                         &sw_if_index))
        sw_if_index_set = 1;
      else if (unformat (i, "external_sw_if_index %d", &sw_if_index))
        sw_if_index_set = 1;
      else if (unformat (i, "vrf %u", &vrf_id))
        ;
      else if (unformat (i, "protocol %u", &proto))
        proto_set = 1;
      else if (unformat (i, "del"))
        is_add = 0;
      else
        {
          clib_warning("unknown input '%U'", format_unformat_error, i);
          return -99;
        }
    }

  if (!addr_only && !proto_set)
    {
      errmsg ("protocol required\n");
      return -99;
    }

  if (!local_addr_set)
    {
      errmsg ("local addr required\n");
      return -99;
    }
  if (!external_addr_set && !sw_if_index_set)
    {
      errmsg ("external addr or interface required\n");
      return -99;
    }

  M(SNAT_ADD_STATIC_MAPPING, mp);
  mp->is_add = is_add;
  mp->is_ip4 = 1;
  mp->addr_only = addr_only;
  mp->local_port = ntohs ((u16) local_port);
  mp->external_port = ntohs ((u16) external_port);
  mp->external_sw_if_index = ntohl (sw_if_index);
  mp->vrf_id = ntohl (vrf_id);
  mp->protocol = (u8) proto;
  memcpy (mp->local_ip_address, &local_addr, 4);
  memcpy (mp->external_ip_address, &external_addr, 4);

  S(mp);
  W (ret);
  return ret;
}

static void vl_api_snat_control_ping_reply_t_handler
  (vl_api_snat_control_ping_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }
}

static void vl_api_snat_static_mapping_details_t_handler
  (vl_api_snat_static_mapping_details_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;

  if (mp->addr_only && mp->external_sw_if_index != ~0)
      fformat (vam->ofp, "%15U%6s%15d%6s%11d%6d\n",
               format_ip4_address, &mp->local_ip_address, "",
               ntohl (mp->external_sw_if_index), "",
               ntohl (mp->vrf_id),
               mp->protocol);
  else if (mp->addr_only && mp->external_sw_if_index == ~0)
      fformat (vam->ofp, "%15U%6s%15U%6s%11d%6d\n",
               format_ip4_address, &mp->local_ip_address, "",
               format_ip4_address, &mp->external_ip_address, "",
               ntohl (mp->vrf_id),
               mp->protocol);
  else if (!mp->addr_only && mp->external_sw_if_index != ~0)
      fformat (vam->ofp, "%15U%6d%15d%6d%11d%6d\n",
               format_ip4_address, &mp->local_ip_address,
               ntohs (mp->local_port),
               ntohl (mp->external_sw_if_index),
               ntohs (mp->external_port),
               ntohl (mp->vrf_id),
               mp->protocol);
  else
      fformat (vam->ofp, "%15U%6d%15U%6d%11d%6d\n",
               format_ip4_address, &mp->local_ip_address,
               ntohs (mp->local_port),
               format_ip4_address, &mp->external_ip_address,
               ntohs (mp->external_port),
               ntohl (mp->vrf_id),
               mp->protocol);

}

static int api_snat_static_mapping_dump(vat_main_t * vam)
{
  vl_api_snat_static_mapping_dump_t * mp;
  vl_api_snat_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_static_mapping_dump");
      return -99;
    }

  fformat (vam->ofp, "%21s%21s\n", "local", "external");
  fformat (vam->ofp, "%15s%6s%15s%6s%11s%6s\n", "address", "port",
           "address/if_idx", "port", "vrf", "proto");

  M(SNAT_STATIC_MAPPING_DUMP, mp);
  S(mp);

  /* Use a control ping for synchronization */
  M(SNAT_CONTROL_PING, mp_ping);
  S(mp_ping);

  W (ret);
  return ret;
}

static void vl_api_snat_show_config_reply_t_handler
  (vl_api_snat_show_config_reply_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval >= 0)
    {
      fformat (vam->ofp, "translation hash buckets %d\n",
               ntohl (mp->translation_buckets));
      fformat (vam->ofp, "translation hash memory %d\n",
               ntohl (mp->translation_memory_size));
      fformat (vam->ofp, "user hash buckets %d\n", ntohl (mp->user_buckets));
      fformat (vam->ofp, "user hash memory %d\n", ntohl (mp->user_memory_size));
      fformat (vam->ofp, "max translations per user %d\n",
               ntohl (mp->max_translations_per_user));
      fformat (vam->ofp, "outside VRF id %d\n", ntohl (mp->outside_vrf_id));
      fformat (vam->ofp, "inside VRF id %d\n", ntohl (mp->inside_vrf_id));
      if (mp->static_mapping_only)
        {
          fformat (vam->ofp, "static mapping only");
          if (mp->static_mapping_connection_tracking)
            fformat (vam->ofp, " connection tracking");
          fformat (vam->ofp, "\n");
        }
    }
  vam->retval = retval;
  vam->result_ready = 1;
}

static int api_snat_show_config(vat_main_t * vam)
{
  vl_api_snat_show_config_t * mp;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_show_config");
      return -99;
    }

  M(SNAT_SHOW_CONFIG, mp);
  S(mp);
  W (ret);
  return ret;
}

static void vl_api_snat_address_details_t_handler
  (vl_api_snat_address_details_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;

  fformat (vam->ofp, "%U\n", format_ip4_address, &mp->ip_address);
}

static int api_snat_address_dump(vat_main_t * vam)
{
  vl_api_snat_address_dump_t * mp;
  vl_api_snat_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_address_dump");
      return -99;
    }

  M(SNAT_ADDRESS_DUMP, mp);
  S(mp);

  /* Use a control ping for synchronization */
  M(SNAT_CONTROL_PING, mp_ping);
  S(mp_ping);

  W (ret);
  return ret;
}

static void vl_api_snat_interface_details_t_handler
  (vl_api_snat_interface_details_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;

  fformat (vam->ofp, "sw_if_index %d %s\n", ntohl (mp->sw_if_index),
           mp->is_inside ? "in" : "out");
}

static int api_snat_interface_dump(vat_main_t * vam)
{
  vl_api_snat_interface_dump_t * mp;
  vl_api_snat_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_address_dump");
      return -99;
    }

  M(SNAT_INTERFACE_DUMP, mp);
  S(mp);

  /* Use a control ping for synchronization */
  M(SNAT_CONTROL_PING, mp_ping);
  S(mp_ping);

  W (ret);
  return ret;
}

static int api_snat_set_workers (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_snat_set_workers_t * mp;
  uword *bitmap;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_bitmap_list, &bitmap))
        ;
      else
        {
          clib_warning("unknown input '%U'", format_unformat_error, i);
          return -99;
        }
    }

  M(SNAT_SET_WORKERS, mp);
  mp->worker_mask = clib_host_to_net_u64 (bitmap[0]);

  S(mp);
  W (ret);
  return ret;
}

static void vl_api_snat_worker_details_t_handler
  (vl_api_snat_worker_details_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;

  fformat (vam->ofp, "worker_index %d (%s at lcore %u)\n",
           ntohl (mp->worker_index), mp->name, ntohl (mp->lcore_id));
}

static int api_snat_worker_dump(vat_main_t * vam)
{
  vl_api_snat_worker_dump_t * mp;
  vl_api_snat_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_address_dump");
      return -99;
    }

  M(SNAT_WORKER_DUMP, mp);
  S(mp);

  /* Use a control ping for synchronization */
  M(SNAT_CONTROL_PING, mp_ping);
  S(mp_ping);

  W (ret);
  return ret;
}

static int api_snat_add_del_interface_addr (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_snat_add_del_interface_addr_t * mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
        sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
        sw_if_index_set = 1;
      else if (unformat (i, "del"))
        is_add = 0;
      else
        {
          clib_warning("unknown input '%U'", format_unformat_error, i);
          return -99;
        }
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("interface / sw_if_index required\n");
      return -99;
    }

  M(SNAT_ADD_DEL_INTERFACE_ADDR, mp);
  mp->sw_if_index = ntohl(sw_if_index);
  mp->is_add = is_add;
  
  S(mp);
  W (ret);
  return ret;
}

static void vl_api_snat_interface_addr_details_t_handler
  (vl_api_snat_interface_addr_details_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;

  fformat (vam->ofp, "sw_if_index %d\n", ntohl (mp->sw_if_index));
}

static int api_snat_interface_addr_dump(vat_main_t * vam)
{
  vl_api_snat_interface_addr_dump_t * mp;
  vl_api_snat_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_address_dump");
      return -99;
    }

  M(SNAT_INTERFACE_ADDR_DUMP, mp);
  S(mp);

  /* Use a control ping for synchronization */
  M(SNAT_CONTROL_PING, mp_ping);
  S(mp_ping);

  W (ret);
  return ret;
}

static int api_snat_ipfix_enable_disable (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_snat_ipfix_enable_disable_t * mp;
  u32 domain_id = 0;
  u32 src_port = 0;
  u8 enable = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "domain %d", &domain_id))
        ;
      else if (unformat (i, "src_port %d", &src_port))
        ;
      else if (unformat (i, "disable"))
        enable = 0;
      else
        {
          clib_warning("unknown input '%U'", format_unformat_error, i);
          return -99;
        }
    }

  M(SNAT_IPFIX_ENABLE_DISABLE, mp);
  mp->domain_id = htonl(domain_id);
  mp->src_port = htons((u16) src_port);
  mp->enable = enable;

  S(mp);
  W (ret);
  return ret;
}

static void vl_api_snat_user_session_details_t_handler
  (vl_api_snat_user_session_details_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;

  fformat(vam->ofp, "%s session %U:%d to %U:%d protocol id %d "
                    "total packets %d total bytes %d\n",
          mp->is_static ? "static" : "dynamic",
          format_ip4_address, mp->inside_ip_address, ntohl(mp->inside_port),
          format_ip4_address, mp->outside_ip_address, ntohl(mp->outside_port),
          ntohl(mp->protocol), ntohl(mp->total_pkts), ntohl(mp->total_bytes));
}

static int api_snat_user_session_dump(vat_main_t * vam)
{
  unformat_input_t* i = vam->input;
  vl_api_snat_user_session_dump_t * mp;
  vl_api_snat_control_ping_t *mp_ping;
  ip4_address_t addr;
  u32 vrf_id = ~0;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_address_dump");
      return -99;
    }

  if (unformat (i, "ip_address %U vrf_id %d",
                unformat_ip4_address, &addr, &vrf_id))
    ;
  else
    {
      clib_warning("unknown input '%U'", format_unformat_error, i);
      return -99;
    }

  M(SNAT_USER_SESSION_DUMP, mp);
  S(mp);

  /* Use a control ping for synchronization */
  M(SNAT_CONTROL_PING, mp_ping);
  memset(mp->ip_address, 0, 16);
  clib_memcpy(mp->ip_address, &addr, 4);
  mp->vrf_id = htonl(vrf_id);
  mp->is_ip4 = 1;
  S(mp_ping);

  W (ret);
  return ret;
}

static void vl_api_snat_user_details_t_handler
  (vl_api_snat_user_details_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;

  fformat(vam->ofp, "user with ip %U with vrf_id %d "
                    "with %d sessions and %d static sessions\n",
          format_ip4_address, mp->ip_address, ntohl(mp->vrf_id),
          ntohl(mp->nsessions), ntohl(mp->nstaticsessions));
}

static int api_snat_user_dump(vat_main_t * vam)
{
  vl_api_snat_user_dump_t * mp;
  vl_api_snat_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_address_dump");
      return -99;
    }

  M(SNAT_USER_DUMP, mp);
  S(mp);

  /* Use a control ping for synchronization */
  M(SNAT_CONTROL_PING, mp_ping);
  S(mp_ping);

  W (ret);
  return ret;
}

static int api_snat_add_det_map (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_snat_add_det_map_t * mp;
  ip4_address_t in_addr, out_addr;
  u32 in_plen, out_plen;
  u8 is_add = 1;
  int ret;

  if (unformat (i, "in %U/%d out %U/%d",
                unformat_ip4_address, &in_addr, &in_plen,
                unformat_ip4_address, &out_addr, &out_plen))
    ;
  else if (unformat (i, "del"))
    is_add = 0;
  else
    {
      clib_warning("unknown input '%U'", format_unformat_error, i);
      return -99;
    }

  M(SNAT_ADD_DET_MAP, mp);
  clib_memcpy(mp->in_addr, &in_addr, 4);
  mp->in_plen = in_plen;
  clib_memcpy(mp->out_addr, &out_addr, 4);
  mp->out_plen = out_plen;
  mp->is_add = is_add;

  S(mp);
  W (ret);
  return ret;
}

static void vl_api_snat_det_forward_reply_t_handler
  (vl_api_snat_det_forward_reply_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;
  i32 retval = ntohl(mp->retval);

  if (retval >= 0)
  {
    fformat (vam->ofp, "outside address %U", format_ip4_address, &mp->out_addr);
    fformat (vam->ofp, " outside port range start %d", ntohs(mp->out_port_lo));
    fformat (vam->ofp, " outside port range end %d\n", ntohs(mp->out_port_hi));
  }

  vam->retval = retval;
  vam->result_ready = 1;
}

static int api_snat_det_forward (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_snat_det_forward_t * mp;
  ip4_address_t in_addr;
  int ret;

  if (unformat (i, "%U", unformat_ip4_address, &in_addr))
    ;
  else
    {
      clib_warning("unknown input '%U'", format_unformat_error, i);
      return -99;
    }

  M(SNAT_DET_FORWARD, mp);
  clib_memcpy(mp->in_addr, &in_addr, 4);

  S(mp);
  W(ret);
  return ret;
}

static void vl_api_snat_det_reverse_reply_t_handler
  (vl_api_snat_det_reverse_reply_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;
  i32 retval = ntohl(mp->retval);

  if (retval >= 0)
  {
    fformat (vam->ofp, "inside address %U\n", format_ip4_address, &mp->in_addr);
  }

  vam->retval = retval;
  vam->result_ready = 1;
}

static int api_snat_det_reverse (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_snat_det_reverse_t * mp;
  ip4_address_t out_addr;
  u32 out_port;
  int ret;

  if (unformat (i, "%U %d", unformat_ip4_address, &out_addr, &out_port))
    ;
  else
    {
      clib_warning("unknown input '%U'", format_unformat_error, i);
      return -99;
    }

  M(SNAT_DET_REVERSE, mp);
  clib_memcpy(mp->out_addr, &out_addr, 4);
  mp->out_port = htons((u16)out_port);

  S(mp);
  W(ret);
  return ret;
}

static void vl_api_snat_det_map_details_t_handler
  (vl_api_snat_det_map_details_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;

  fformat (vam->ofp, "Deterministic S-NAT mapping in %U/%d out %U/%d "
                     "ports per host %d sharing ratio %d "
                     "number of sessions %d",
           format_ip4_address, mp->in_addr, mp->in_plen,
           format_ip4_address, mp->out_addr, mp->out_plen,
           ntohs(mp->ports_per_host), ntohl(mp->sharing_ratio),
           ntohl(mp->ses_num));
}

static int api_snat_det_map_dump(vat_main_t * vam)
{
  vl_api_snat_det_map_dump_t * mp;
  vl_api_snat_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_det_map_dump");
      return -99;
    }

  M(SNAT_DET_MAP_DUMP, mp);
  S(mp);

  /* Use a control ping for synchronization */
  M(SNAT_CONTROL_PING, mp_ping);
  S(mp_ping);

  W (ret);
  return ret;
}

static int api_snat_det_set_timeouts (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_snat_det_set_timeouts_t * mp;
  u32 udp = SNAT_UDP_TIMEOUT;
  u32 tcp_established = SNAT_TCP_ESTABLISHED_TIMEOUT;
  u32 tcp_transitory = SNAT_TCP_TRANSITORY_TIMEOUT;
  u32 icmp = SNAT_ICMP_TIMEOUT;
  int ret;

  if (unformat (i, "udp %d", &udp))
    ;
  else if (unformat (i, "tcp_established %d", &tcp_established))
    ;
  else if (unformat (i, "tcp_transitory %d", &tcp_transitory))
    ;
  else if (unformat (i, "icmp %d", &icmp))
    ;
  else
    {
      clib_warning("unknown input '%U'", format_unformat_error, i);
      return -99;
    }

  M(SNAT_DET_SET_TIMEOUTS, mp);
  mp->udp = htonl(udp);
  mp->tcp_established = htonl(tcp_established);
  mp->tcp_transitory = htonl(tcp_transitory);
  mp->icmp = htonl(icmp);

  S(mp);
  W (ret);
  return ret;
}

static void vl_api_snat_det_get_timeouts_reply_t_handler
  (vl_api_snat_det_get_timeouts_reply_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval >= 0)
    {
      fformat (vam->ofp, "udp timeout: %dsec\n", ntohl (mp->udp));
      fformat (vam->ofp, "tcp-established timeout: %dsec",
               ntohl (mp->tcp_established));
      fformat (vam->ofp, "tcp-transitory timeout: %dsec",
               ntohl (mp->tcp_transitory));
      fformat (vam->ofp, "icmp timeout: %dsec", ntohl (mp->icmp));
    }
  vam->retval = retval;
  vam->result_ready = 1;
}

static int api_snat_det_get_timeouts(vat_main_t * vam)
{
  vl_api_snat_det_get_timeouts_t * mp;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_show_config");
      return -99;
    }

  M(SNAT_DET_GET_TIMEOUTS, mp);
  S(mp);
  W (ret);
  return ret;
}

static int api_snat_det_close_session_out (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_snat_det_close_session_out_t * mp;
  ip4_address_t out_addr, ext_addr;
  u32 out_port, ext_port;
  int ret;

  if (unformat (i, "%U:%d %U:%d",
                unformat_ip4_address, &out_addr, &out_port,
                unformat_ip4_address, &ext_addr, &ext_port))
    ;
  else
    {
      clib_warning("unknown input '%U'", format_unformat_error, i);
      return -99;
    }

  M(SNAT_DET_CLOSE_SESSION_OUT, mp);
  clib_memcpy(mp->out_addr, &out_addr, 4);
  mp->out_port = ntohs((u16)out_port);
  clib_memcpy(mp->ext_addr, &ext_addr, 4);
  mp->ext_port = ntohs((u16)ext_port);

  S(mp);
  W (ret);
  return ret;
}

static int api_snat_det_close_session_in (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  vl_api_snat_det_close_session_in_t * mp;
  ip4_address_t in_addr, ext_addr;
  u32 in_port, ext_port;
  int ret;

  if (unformat (i, "%U:%d %U:%d",
                unformat_ip4_address, &in_addr, &in_port,
                unformat_ip4_address, &ext_addr, &ext_port))
    ;
  else
    {
      clib_warning("unknown input '%U'", format_unformat_error, i);
      return -99;
    }

  M(SNAT_DET_CLOSE_SESSION_IN, mp);
  clib_memcpy(mp->in_addr, &in_addr, 4);
  mp->in_port = ntohs((u16)in_port);
  clib_memcpy(mp->ext_addr, &ext_addr, 4);
  mp->ext_port = ntohs((u16)ext_port);

  S(mp);
  W (ret);
  return ret;
}

static void vl_api_snat_det_session_details_t_handler
  (vl_api_snat_det_session_details_t *mp)
{
  snat_test_main_t * sm = &snat_test_main;
  vat_main_t *vam = sm->vat_main;

  fformat(vam->ofp, "deterministic session, external host address %U, "
                    "external host port %d, outer port %d, inside port %d",
          format_ip4_address, mp->ext_addr, mp->ext_port,
          mp->out_port, mp->in_port);
}

static int api_snat_det_session_dump(vat_main_t * vam)
{
  unformat_input_t* i = vam->input;
  vl_api_snat_det_session_dump_t * mp;
  vl_api_snat_control_ping_t *mp_ping;
  ip4_address_t user_addr;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_det_session_dump");
      return -99;
    }

  if (unformat (i, "user_addr %U", unformat_ip4_address, &user_addr))
    ;
  else
    {
      clib_warning ("unknown input '%U'", format_unformat_error, i);
      return -99;
    }

  M(SNAT_DET_SESSION_DUMP, mp);
  clib_memcpy (&mp->user_addr, &user_addr, 4);
  S(mp);

  /* Use a control ping for synchronization */
  M(SNAT_CONTROL_PING, mp_ping);
  S(mp_ping);

  W (ret);
  return ret;
}

/* 
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                                      \
_(snat_add_address_range, "<start-addr> [- <end-addr] [del]")    \
_(snat_interface_add_del_feature,                                \
  "<intfc> | sw_if_index <id> [in] [out] [del]")                 \
_(snat_add_static_mapping, "local_addr <ip> (external_addr <ip>" \
  " | external_if <intfc> | external_sw_if_ndex <id>) "          \
  "[local_port <n>] [external_port <n>] [vrf <table-id>] [del] " \
  "protocol <n>")                                                \
_(snat_set_workers, "<wokrers_bitmap>")                          \
_(snat_static_mapping_dump, "")                                  \
_(snat_show_config, "")                                          \
_(snat_address_dump, "")                                         \
_(snat_interface_dump, "")                                       \
_(snat_worker_dump, "")                                          \
_(snat_add_del_interface_addr,                                   \
  "<intfc> | sw_if_index <id> [del]")                            \
_(snat_interface_addr_dump, "")                                  \
_(snat_ipfix_enable_disable, "[domain <id>] [src_port <n>] "     \
  "[disable]")                                                   \
_(snat_user_dump, "")                                            \
_(snat_user_session_dump, "ip_address <ip> vrf_id <table-id>")   \
_(snat_add_det_map, "in <in_addr>/<in_plen> out "                \
  "<out_addr>/<out_plen> [del]")                                 \
_(snat_det_forward, "<in_addr>")                                 \
_(snat_det_reverse, "<out_addr> <out_port>")                     \
_(snat_det_map_dump, "")                                         \
_(snat_det_set_timeouts, "[udp <sec> | tcp_established <sec> | " \
  "tcp_transitory <sec> | icmp <sec>]")                          \
_(snat_det_get_timeouts, "")                                     \
_(snat_det_close_session_out, "<out_addr>:<out_port> "           \
  "<ext_addr>:<ext_port>")                                       \
_(snat_det_close_session_in, "<in_addr>:<in_port> "              \
  "<out_addr>:<out_port>")                                       \
_(snat_det_session_dump, "ip_address <user_addr>")

static void 
snat_vat_api_hookup (vat_main_t *vam)
{
  snat_test_main_t * sm __attribute__((unused)) = &snat_test_main;
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),       \
                          #n,                                   \
                          vl_api_##n##_t_handler,               \
                          vl_noop_handler,                      \
                          vl_api_##n##_t_endian,                \
                          vl_api_##n##_t_print,                 \
                          sizeof(vl_api_##n##_t), 1); 
  foreach_vpe_api_reply_msg;
#undef _

  /* API messages we can send */
#define _(n,h)                                          \
  hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_vpe_api_msg;
#undef _    
    
  /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_vpe_api_msg;
#undef _
}

clib_error_t * vat_plugin_register (vat_main_t *vam)
{
  snat_test_main_t * sm = &snat_test_main;
  u8 * name;

  sm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "snat_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~0)
    snat_vat_api_hookup (vam);
  
  vec_free(name);
  
  return 0;
}
