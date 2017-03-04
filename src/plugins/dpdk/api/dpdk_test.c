
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
#include <vlibsocket/api.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <dpdk/api/dpdk_msg_enum.h>

/* define message structures */
#define vl_typedefs
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

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
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
        vat_main_t * vam = dpdk_test_main.vat_main;  \
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
  sw_interface_set_dpdk_hqos_tctbl_reply)

/* M: construct, but don't yet send a message */
#define M(T,t)                                                  \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc(sizeof(*mp));                         \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T + dm->msg_id_base);      \
    mp->client_index = vam->my_client_index;                    \
} while(0);

#define M2(T,t,n)                                               \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc(sizeof(*mp)+(n));                     \
    memset (mp, 0, sizeof (*mp));                               \
    mp->_vl_msg_id = ntohs (VL_API_##T + dm->msg_id_base);      \
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

static int
api_sw_interface_set_dpdk_hqos_pipe (vat_main_t * vam)
{
  dpdk_test_main_t * dm = &dpdk_test_main;
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_dpdk_hqos_pipe_t *mp;
  f64 timeout;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u32 subport;
  u8 subport_set = 0;
  u32 pipe;
  u8 pipe_set = 0;
  u32 profile;
  u8 profile_set = 0;

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

  M (SW_INTERFACE_SET_DPDK_HQOS_PIPE, sw_interface_set_dpdk_hqos_pipe);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->subport = ntohl (subport);
  mp->pipe = ntohl (pipe);
  mp->profile = ntohl (profile);


  S;
  W;
  /* NOTREACHED */
  return 0;
}

static int
api_sw_interface_set_dpdk_hqos_subport (vat_main_t * vam)
{
  dpdk_test_main_t * dm = &dpdk_test_main;
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_dpdk_hqos_subport_t *mp;
  f64 timeout;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u32 subport;
  u8 subport_set = 0;
  u32 tb_rate = 1250000000; /* 10GbE */
  u32 tb_size = 1000000;
  u32 tc_rate[] = { 1250000000, 1250000000, 1250000000, 1250000000 };
  u32 tc_period = 10;

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

  M (SW_INTERFACE_SET_DPDK_HQOS_SUBPORT, sw_interface_set_dpdk_hqos_subport);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->subport = ntohl (subport);
  mp->tb_rate = ntohl (tb_rate);
  mp->tb_size = ntohl (tb_size);
  mp->tc_rate[0] = ntohl (tc_rate[0]);
  mp->tc_rate[1] = ntohl (tc_rate[1]);
  mp->tc_rate[2] = ntohl (tc_rate[2]);
  mp->tc_rate[3] = ntohl (tc_rate[3]);
  mp->tc_period = ntohl (tc_period);

  S;
  W;
  /* NOTREACHED */
  return 0;
}

static int
api_sw_interface_set_dpdk_hqos_tctbl (vat_main_t * vam)
{
  dpdk_test_main_t * dm = &dpdk_test_main;
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_dpdk_hqos_tctbl_t *mp;
  f64 timeout;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 entry_set = 0;
  u8 tc_set = 0;
  u8 queue_set = 0;
  u32 entry, tc, queue;

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

  M (SW_INTERFACE_SET_DPDK_HQOS_TCTBL, sw_interface_set_dpdk_hqos_tctbl);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->entry = ntohl (entry);
  mp->tc = ntohl (tc);
  mp->queue = ntohl (queue);

  S;
  W;
  /* NOTREACHED */
  return 0;
}

/* 
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                                               \
_(sw_interface_set_dpdk_hqos_pipe,                                        \
  "rx sw_if_index <id> subport <subport-id> pipe <pipe-id>\n"   \
  "profile <profile-id>\n")                                               \
_(sw_interface_set_dpdk_hqos_subport,                                     \
  "rx sw_if_index <id> subport <subport-id> [rate <n>]\n"       \
  "[bktsize <n>] [tc0 <n>] [tc1 <n>] [tc2 <n>] [tc3 <n>] [period <n>]\n") \
_(sw_interface_set_dpdk_hqos_tctbl,                                       \
  "rx sw_if_index <id> entry <n> tc <n> queue <n>\n")

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

  if (dm->msg_id_base != (u16) ~0)
    dpdk_api_hookup (vam);
  
  vec_free(name);
  
  return 0;
}
