
/*
 * dpdk_test.c - skeleton vpp-api-test plug-in
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

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <dpdk/api/dpdk_msg_enum.h>

/* Declare message IDs */
#include <dpdk/device/dpdk.h>

/* Get CRC codes of the messages defined outside of this plugin */
#define vl_msg_name_crc_list
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

/* define message structures */
#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#include <dpdk/api/dpdk.api.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <dpdk/api/dpdk.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <dpdk/api/dpdk.api.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <dpdk/api/dpdk.api.h>
#undef vl_api_version

#define __plugin_msg_base dpdk_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    u32 ping_id;
    vat_main_t *vat_main;
} dpdk_test_main_t;

dpdk_test_main_t dpdk_test_main;

#define foreach_standard_reply_retval_handler         \
_(sw_interface_set_dpdk_hqos_pipe_reply)              \
_(sw_interface_set_dpdk_hqos_subport_reply)           \
_(sw_interface_set_dpdk_hqos_tctbl_reply)

#define _(n)                                          \
    static void vl_api_##n##_t_handler                \
    (vl_api_##n##_t * mp)                             \
    {                                                 \
        vat_main_t * vam = dpdk_test_main.vat_main;   \
        i32 retval = ntohl(mp->retval);               \
        if (vam->async_mode) {                        \
            vam->async_errors += (retval < 0);        \
        } else {                                      \
            vam->retval = retval;                     \
            vam->result_ready = 1;                    \
        }                                             \
    }
foreach_standard_reply_retval_handler;
#undef _

/* 
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                               \
_(SW_INTERFACE_SET_DPDK_HQOS_PIPE_REPLY,                        \
  sw_interface_set_dpdk_hqos_pipe_reply)                        \
_(SW_INTERFACE_SET_DPDK_HQOS_SUBPORT_REPLY,                     \
  sw_interface_set_dpdk_hqos_subport_reply)                     \
_(SW_INTERFACE_SET_DPDK_HQOS_TCTBL_REPLY,                       \
  sw_interface_set_dpdk_hqos_tctbl_reply)                       \
_(DPDK_DEVICE_DETAILS,                                          \
  dpdk_device_details)


static int
api_sw_interface_set_dpdk_hqos_pipe (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_dpdk_hqos_pipe_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u32 subport;
  u8 subport_set = 0;
  u32 pipe;
  u8 pipe_set = 0;
  u32 profile;
  u8 profile_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (i, "rx sw_if_index %u", &sw_if_index))
  sw_if_index_set = 1;
      else if (unformat (i, "subport %u", &subport))
  subport_set = 1;
      else if (unformat (i, "pipe %u", &pipe))
  pipe_set = 1;
      else if (unformat (i, "profile %u", &profile))
  profile_set = 1;
      else
  break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (subport_set == 0)
    {
      errmsg ("missing subport ");
      return -99;
    }

  if (pipe_set == 0)
    {
      errmsg ("missing pipe");
      return -99;
    }

  if (profile_set == 0)
    {
      errmsg ("missing profile");
      return -99;
    }

  M (SW_INTERFACE_SET_DPDK_HQOS_PIPE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->subport = ntohl (subport);
  mp->pipe = ntohl (pipe);
  mp->profile = ntohl (profile);


  S (mp);
  W (ret);
  /* NOTREACHED */
  return ret;
}

static int
api_sw_interface_set_dpdk_hqos_subport (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_dpdk_hqos_subport_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u32 subport;
  u8 subport_set = 0;
  u32 tb_rate = 1250000000; /* 10GbE */
  u32 tb_size = 1000000;
  u32 tc_rate[] = { 1250000000, 1250000000, 1250000000, 1250000000 };
  u32 tc_period = 10;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "rx sw_if_index %u", &sw_if_index))
  sw_if_index_set = 1;
      else if (unformat (i, "subport %u", &subport))
  subport_set = 1;
      else if (unformat (i, "rate %u", &tb_rate))
  {
    u32 tc_id;

    for (tc_id = 0; tc_id < (sizeof (tc_rate) / sizeof (tc_rate[0]));
         tc_id++)
      tc_rate[tc_id] = tb_rate;
  }
      else if (unformat (i, "bktsize %u", &tb_size))
  ;
      else if (unformat (i, "tc0 %u", &tc_rate[0]))
  ;
      else if (unformat (i, "tc1 %u", &tc_rate[1]))
  ;
      else if (unformat (i, "tc2 %u", &tc_rate[2]))
  ;
      else if (unformat (i, "tc3 %u", &tc_rate[3]))
  ;
      else if (unformat (i, "period %u", &tc_period))
  ;
      else
  break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (subport_set == 0)
    {
      errmsg ("missing subport ");
      return -99;
    }

  M (SW_INTERFACE_SET_DPDK_HQOS_SUBPORT, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->subport = ntohl (subport);
  mp->tb_rate = ntohl (tb_rate);
  mp->tb_size = ntohl (tb_size);
  mp->tc_rate[0] = ntohl (tc_rate[0]);
  mp->tc_rate[1] = ntohl (tc_rate[1]);
  mp->tc_rate[2] = ntohl (tc_rate[2]);
  mp->tc_rate[3] = ntohl (tc_rate[3]);
  mp->tc_period = ntohl (tc_period);

  S (mp);
  W (ret);
  /* NOTREACHED */
  return ret;
}

static int
api_sw_interface_set_dpdk_hqos_tctbl (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_dpdk_hqos_tctbl_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 entry_set = 0;
  u8 tc_set = 0;
  u8 queue_set = 0;
  u32 entry, tc, queue;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "rx sw_if_index %u", &sw_if_index))
  sw_if_index_set = 1;
      else if (unformat (i, "entry %d", &entry))
  entry_set = 1;
      else if (unformat (i, "tc %d", &tc))
  tc_set = 1;
      else if (unformat (i, "queue %d", &queue))
  queue_set = 1;
      else
  break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (entry_set == 0)
    {
      errmsg ("missing entry ");
      return -99;
    }

  if (tc_set == 0)
    {
      errmsg ("missing traffic class ");
      return -99;
    }

  if (queue_set == 0)
    {
      errmsg ("missing queue ");
      return -99;
    }

  M (SW_INTERFACE_SET_DPDK_HQOS_TCTBL, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->entry = ntohl (entry);
  mp->tc = ntohl (tc);
  mp->queue = ntohl (queue);

  S (mp);
  W (ret);
  /* NOTREACHED */
  return ret;
}

u8 * format_pmd (u8 * s, va_list * args)
{
  u32 pmd = va_arg (*args, uword);
  u8 *t = 0;
  switch(pmd){
#define _(c,f) \
  case VNET_DPDK_PMD_##f:\
    t = format (t, "%s%s", t ? " ":"", c);\
    break;
  foreach_dpdk_pmd
#undef _
  }
  if (t) {
    s = format (s, "%v", t);
    vec_free (t);
  }
  return s;
}

u8 * format_port_type (u8 * s, va_list * args)
{
  u32 ptype = va_arg (*args, uword);
  u8 *t = 0;
  switch(ptype){
#define _(c,f) \
  case VNET_DPDK_PORT_TYPE_##f:\
    t = format (t, "%s%s", t ? " ":"", c);\
    break;
  foreach_dpdk_port_type
#undef _
  }
  if (t) {
    s = format (s, "%v", t);
    vec_free (t);
  }
  return s;
}

static void vl_api_dpdk_device_details_t_handler
  (vl_api_dpdk_device_details_t * mp)
{
  vat_main_t * vam = dpdk_test_main.vat_main;
  u16 flags = ntohs(mp->flags);
  u32 pmd = ntohl(mp->pmd);
  u32 ptype = ntohl(mp->port_type);
  print (vam->ofp,
         "%-12d %-16U %-16U %-12d 0x%-16X      %-6d: %d/%d/%d",
         ntohl(mp->sw_if_index), format_pmd, pmd, format_port_type, ptype, mp->cpu_socket, flags,
         ntohs(mp->pci_domain), mp->pci_bus, mp->pci_slot, mp->pci_function);
#define _(a, b, c) {\
  if (flags & (1 << a)) \
    print (vam->ofp,\
           "%-12s %-16s %-16s %-12s %-16s",\
           "", "", "", "", c);\
}
  foreach_dpdk_device_flags
#undef _
  print (vam->ofp,"");
}

static int
api_dpdk_device_dump (vat_main_t * vam)
{
  dpdk_test_main_t *dm = &dpdk_test_main;
  unformat_input_t *i = vam->input;
  vl_api_dpdk_device_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%u", &sw_if_index))
        sw_if_index_set = 1;
      else
  break;
    }

  if (sw_if_index_set == 0)
    {
      sw_if_index = ~0;
    }

  print (vam->ofp,
         "\n%-12s %-16s %-16s %-12s %-16s PCI: %-6s: %s/%s/%s",
         "sw_if_index", "pmd", "port_type", "cpu_socket", "flags",
	 "domain", "bus", "slot", "function");

  M (DPDK_DEVICE_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  /* Use a control ping for synchronization */
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (dm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  /* NOTREACHED */
  return ret;
}

/* 
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                                               \
_(sw_interface_set_dpdk_hqos_pipe,                                        \
  "rx sw_if_index <id> subport <subport-id> pipe <pipe-id>\n"             \
  "profile <profile-id>\n")                                               \
_(sw_interface_set_dpdk_hqos_subport,                                     \
  "rx sw_if_index <id> subport <subport-id> [rate <n>]\n"                 \
  "[bktsize <n>] [tc0 <n>] [tc1 <n>] [tc2 <n>] [tc3 <n>] [period <n>]\n") \
_(sw_interface_set_dpdk_hqos_tctbl,                                       \
  "rx sw_if_index <id> entry <n> tc <n> queue <n>\n")                     \
_(dpdk_device_dump,                                       \
  "[<id>]\n")

static void dpdk_api_hookup (vat_main_t *vam)
{
  dpdk_test_main_t * dm __attribute__((unused)) = &dpdk_test_main;
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + dm->msg_id_base),       \
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
  dpdk_test_main_t * dm = &dpdk_test_main;
  u8 * name;

  dm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "dpdk_%08x%c", api_version, 0);
  dm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  /* Get the control ping ID */
#define _(id,n,crc) \
  const char *id ## _CRC __attribute__ ((unused)) = #n "_" #crc;
  foreach_vl_msg_name_crc_vpe;
#undef _
  dm->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));

  if (dm->msg_id_base != (u16) ~0)
    dpdk_api_hookup (vam);
  
  vec_free(name);
  
  return 0;
}
