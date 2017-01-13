
/*
 * snat.c - skeleton vpp-api-test plug-in 
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
#include <vnet/ip/ip.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <snat/snat_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <snat/snat_all_api_h.h> 
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <snat/snat_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <snat/snat_all_api_h.h> 
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <snat/snat_all_api_h.h>
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
_(snat_ipfix_enable_disable_reply)

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
  snat_ipfix_enable_disable_reply)

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

static int api_snat_add_address_range (vat_main_t * vam)
{
  snat_test_main_t * sm = &snat_test_main;
  unformat_input_t * i = vam->input;
  f64 timeout;
  ip4_address_t start_addr, end_addr;
  u32 start_host_order, end_host_order;
  vl_api_snat_add_address_range_t * mp;
  u8 is_add = 1;
  int count;

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
  
  M(SNAT_ADD_ADDRESS_RANGE, snat_add_address_range);

  memcpy (mp->first_ip_address, &start_addr, 4);
  memcpy (mp->last_ip_address, &end_addr, 4);
  mp->is_ip4 = 1;
  mp->is_add = is_add;

  S; W;

  /* NOTREACHED */
  return 0;
}

static int api_snat_interface_add_del_feature (vat_main_t * vam)
{
  snat_test_main_t * sm = &snat_test_main;
  unformat_input_t * i = vam->input;
  f64 timeout;
  vl_api_snat_interface_add_del_feature_t * mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 is_inside = 1; 
  u8 is_add = 1;

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

  M(SNAT_INTERFACE_ADD_DEL_FEATURE, snat_interface_add_del_feature);
  mp->sw_if_index = ntohl(sw_if_index);
  mp->is_add = is_add;
  mp->is_inside = is_inside;
  
  S; W;
  /* NOTREACHED */
  return 0;
}

static int api_snat_add_static_mapping(vat_main_t * vam)
{
  snat_test_main_t * sm = &snat_test_main;
  unformat_input_t * i = vam->input;
  f64 timeout;
  vl_api_snat_add_static_mapping_t * mp;
  u8 addr_set_n = 0;
  u8 is_add = 1;
  u8 addr_only = 1;
  ip4_address_t local_addr, external_addr;
  u32 local_port = 0, external_port = 0, vrf_id = ~0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "local_addr %U", unformat_ip4_address, &local_addr))
        addr_set_n++;
      else if (unformat (i, "external_addr %U", unformat_ip4_address,
                         &external_addr))
        addr_set_n++;
      else if (unformat (i, "local_port %u", &local_port))
        addr_only = 0;
      else if (unformat (i, "external_port %u", &external_port))
        addr_only = 0;
      else if (unformat (i, "vrf %u", &vrf_id))
        ;
      else if (unformat (i, "del"))
        is_add = 0;
      else
        {
          clib_warning("unknown input '%U'", format_unformat_error, i);
          return -99;
        }
    }

  if (addr_set_n != 2)
    {
      errmsg ("local_addr and remote_addr required\n");
      return -99;
    }

  M(SNAT_ADD_STATIC_MAPPING, snat_add_static_mapping);
  mp->is_add = is_add;
  mp->is_ip4 = 1;
  mp->addr_only = addr_only;
  mp->local_port = ntohs ((u16) local_port);
  mp->external_port = ntohs ((u16) external_port);
  mp->vrf_id = ntohl (vrf_id);
  memcpy (mp->local_ip_address, &local_addr, 4);
  memcpy (mp->external_ip_address, &external_addr, 4);

  S; W;
  /* NOTREACHED */
  return 0;
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

  if (mp->addr_only)
      fformat (vam->ofp, "%15U%6s%15U%6s%11d\n",
               format_ip4_address, &mp->local_ip_address, "",
               format_ip4_address, &mp->external_ip_address, "",
               ntohl (mp->vrf_id));
  else
      fformat (vam->ofp, "%15U%6d%15U%6d%11d\n",
               format_ip4_address, &mp->local_ip_address,
               ntohs (mp->local_port),
               format_ip4_address, &mp->external_ip_address,
               ntohs (mp->external_port),
               ntohl (mp->vrf_id));

}

static int api_snat_static_mapping_dump(vat_main_t * vam)
{
  snat_test_main_t * sm = &snat_test_main;
  f64 timeout;
  vl_api_snat_static_mapping_dump_t * mp;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_static_mapping_dump");
      return -99;
    }

  fformat (vam->ofp, "%21s%21s\n", "local", "external");
  fformat (vam->ofp, "%15s%6s%15s%6s%11s\n", "address", "port", "address",
           "port", "vrf");

  M(SNAT_STATIC_MAPPING_DUMP, snat_static_mapping_dump);
  S;
  /* Use a control ping for synchronization */
  {
    vl_api_snat_control_ping_t *mp;
    M (SNAT_CONTROL_PING, snat_control_ping);
    S;
  }
  W;
  /* NOTREACHED */
  return 0;
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
  snat_test_main_t * sm = &snat_test_main;
  f64 timeout;
  vl_api_snat_show_config_t * mp;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_show_config");
      return -99;
    }

  M(SNAT_SHOW_CONFIG, snat_show_config);
  S; W;
  /* NOTREACHED */
  return 0;
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
  snat_test_main_t * sm = &snat_test_main;
  f64 timeout;
  vl_api_snat_address_dump_t * mp;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_address_dump");
      return -99;
    }

  M(SNAT_ADDRESS_DUMP, snat_address_dump);
  S;
  /* Use a control ping for synchronization */
  {
    vl_api_snat_control_ping_t *mp;
    M (SNAT_CONTROL_PING, snat_control_ping);
    S;
  }
  W;
  /* NOTREACHED */
  return 0;
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
  snat_test_main_t * sm = &snat_test_main;
  f64 timeout;
  vl_api_snat_interface_dump_t * mp;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_address_dump");
      return -99;
    }

  M(SNAT_INTERFACE_DUMP, snat_interface_dump);
  S;
  /* Use a control ping for synchronization */
  {
    vl_api_snat_control_ping_t *mp;
    M (SNAT_CONTROL_PING, snat_control_ping);
    S;
  }
  W;
  /* NOTREACHED */
  return 0;
}

static int api_snat_set_workers (vat_main_t * vam)
{
  snat_test_main_t * sm = &snat_test_main;
  unformat_input_t * i = vam->input;
  f64 timeout;
  vl_api_snat_set_workers_t * mp;
  uword *bitmap;

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

  M(SNAT_SET_WORKERS, snat_set_workers);
  mp->worker_mask = clib_host_to_net_u64 (bitmap[0]);

  S; W;

  /* NOTREACHED */
  return 0;
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
  snat_test_main_t * sm = &snat_test_main;
  f64 timeout;
  vl_api_snat_worker_dump_t * mp;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_address_dump");
      return -99;
    }

  M(SNAT_WORKER_DUMP, snat_worker_dump);
  S;
  /* Use a control ping for synchronization */
  {
    vl_api_snat_control_ping_t *mp;
    M (SNAT_CONTROL_PING, snat_control_ping);
    S;
  }
  W;
  /* NOTREACHED */
  return 0;
}

static int api_snat_ipfix_enable_disable (vat_main_t * vam)
{
  snat_test_main_t * sm = &snat_test_main;
  unformat_input_t * i = vam->input;
  f64 timeout;
  vl_api_snat_add_del_interface_addr_t * mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 is_add = 1;

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

  M(SNAT_ADD_DEL_INTERFACE_ADDR, snat_add_del_interface_addr);
  mp->sw_if_index = ntohl(sw_if_index);
  mp->is_add = is_add;
  
  S; W;
  /* NOTREACHED */
  return 0;
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
  snat_test_main_t * sm = &snat_test_main;
  f64 timeout;
  vl_api_snat_interface_addr_dump_t * mp;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for snat_address_dump");
      return -99;
    }

  M(SNAT_INTERFACE_ADDR_DUMP, snat_interface_addr_dump);
  S;
  /* Use a control ping for synchronization */
  {
    vl_api_snat_control_ping_t *mp;
    M (SNAT_CONTROL_PING, snat_control_ping);
    S;
  }
  W;
  /* NOTREACHED */
  return 0;
}

static int api_snat_add_del_interface_addr (vat_main_t * vam)
{
  snat_test_main_t * sm = &snat_test_main;
  unformat_input_t * i = vam->input;
  f64 timeout;
  vl_api_snat_ipfix_enable_disable_t * mp;
  u32 domain_id = 0;
  u32 src_port = 0;
  u8 enable = 1;

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

  M(SNAT_IPFIX_ENABLE_DISABLE, snat_ipfix_enable_disable);
  mp->domain_id = htonl(domain_id);
  mp->src_port = htons((u16) src_port);
  mp->enable = enable;

  S; W;
  /* NOTREACHED */
  return 0;
}

/* 
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                                      \
_(snat_add_address_range, "<start-addr> [- <end-addr] [del]")    \
_(snat_interface_add_del_feature,                                \
  "<intfc> | sw_if_index <id> [in] [out] [del]")                 \
_(snat_add_static_mapping, "local_addr <ip> external_addr <ip> " \
  "[local_port <n>] [external_port <n>] [vrf <table-id>] [del]") \
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
  "[disable]")

void vat_api_hookup (vat_main_t *vam)
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
  snat_test_main_t * sm = &snat_test_main;
  u8 * name;

  sm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "snat_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~0)
    vat_api_hookup (vam);
  
  vec_free(name);
  
  return 0;
}
