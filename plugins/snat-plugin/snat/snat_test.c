
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
_(snat_interface_add_del_feature_reply)

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
 _(SNAT_INTERFACE_ADD_DEL_FEATURE_REPLY,                        \
   snat_interface_add_del_feature_reply)

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
  int count;

  if (unformat (i, "%U - %U", 
                unformat_ip4_address, &start_addr,
                unformat_ip4_address, &end_addr))
    ;
  else if (unformat (i, "%U", unformat_ip4_address, &start_addr))
    end_addr = start_addr;

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

/* 
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                             \
_(snat_add_address_range, "<start-addr> [- <end-addr]") \
_(snat_interface_add_del_feature,                       \
  "<intfc> | sw_if_index <id> [in] [out] [del]")

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
