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
/*
 *------------------------------------------------------------------
 * udp_ping_test.c - test harness for udp ping plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip.h>

/* Declare message IDs */
#include <ioam/udp-ping/udp_ping_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <ioam/udp-ping/udp_ping_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <ioam/udp-ping/udp_ping_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <ioam/udp-ping/udp_ping_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ioam/udp-ping/udp_ping_all_api_h.h>
#undef vl_api_version


typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} udp_ping_test_main_t;

udp_ping_test_main_t udp_ping_test_main;

#define foreach_standard_reply_retval_handler     \
_(udp_ping_add_reply)                          \
_(udp_ping_del_reply)                     \
_(udp_ping_export_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = udp_ping_test_main.vat_main;   \
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
#define foreach_vpe_api_reply_msg                                       \
_(UDP_PING_ADD_REPLY, udp_ping_add_reply)                         \
_(UDP_PING_DELE_REPLY, udp_ping_del_reply)               \
_(UDP_PING_EXPORT_REPLY, udp_ping_export_reply)                         \


/* M: construct, but don't yet send a message */

#define M(T,t)                                                  \
do {                                                            \
    vam->result_ready = 0;                                      \
    mp = vl_msg_api_alloc(sizeof(*mp));                         \
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


static int api_udp_ping_add (vat_main_t *vam)
{
    udp_ping_test_main_t * sm = &udp_ping_test_main;
    unformat_input_t *input = vam->input;
    vl_api_udp_ping_add_mod_del_req_t *mp;
    u8 *name = NULL;
    int rv = 0;
    ip46_address_t dst, src;
    u16 start_src_port, end_src_port;
    u16 start_dst_port, end_dst_port;
    u32 interval;
    u8 is_disable = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (input, "src %U", unformat_ip46_address, &src, IP46_TYPE_ANY))
            ;
          else if (unformat(input, "src-port-range %U",
                            unformat_port_range, &start_src_port, &end_src_port))
            ;
          else if (unformat(input, "dst %U", unformat_ip46_address, &dst, IP46_TYPE_ANY))
            ;
          else if (unformat(input, "dst-port-range %U",
                            unformat_port_range, &start_dst_port, &end_dst_port))
            ;
          else if (unformat(input, "interval %d", &interval))
            ;
          else if (unformat(input, "disable"))
            is_disable = 1;
          else
            break;
        }

    M(UDP_PING_ADD, udp_ping_add);

    clib_memcpy(mp->src_ip_address, src.ip6, 16);
    clib_memcpy(mp->dst_ip_address, dst.ip6, 16);
    mp->start_src_port = start_src_port;
    mp->end_src_port = end_src_port;
    mp->start_dst_port = start_dst_port;
    mp->end_dst_port = end_dst_port;
    mp->interval = (u16)interval;
    mp->is_ipv4 = 0;

    S; W;

OUT:
    return(rv);
}

static int api_udp_ping_del (vat_main_t *vam)
{
    udp_ping_test_main_t * sm = &udp_ping_test_main;
    unformat_input_t *input = vam->input;
    vl_api_udp_ping_add_mod_del_req_t *mp;
    u8 *name = NULL;
    int rv = 0;
    ip46_address_t dst, src;
    u16 start_src_port, end_src_port;
    u16 start_dst_port, end_dst_port;
    u32 interval;
    u8 is_disable = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat (input, "src %U", unformat_ip46_address, &src, IP46_TYPE_ANY))
            ;
          else if (unformat(input, "src-port-range %U",
                            unformat_port_range, &start_src_port, &end_src_port))
            ;
          else if (unformat(input, "dst %U", unformat_ip46_address, &dst, IP46_TYPE_ANY))
            ;
          else if (unformat(input, "dst-port-range %U",
                            unformat_port_range, &start_dst_port, &end_dst_port))
            ;
          else if (unformat(input, "interval %d", &interval))
            ;
          else if (unformat(input, "disable"))
            is_disable = 1;
          else
            break;
        }

    M(UDP_PING_DEL, udp_ping_del);

    clib_memcpy(mp->src_ip_address, src.ip6, 16);
    clib_memcpy(mp->dst_ip_address, dst.ip6, 16);
    mp->start_src_port = start_src_port;
    mp->end_src_port = end_src_port;
    mp->start_dst_port = start_dst_port;
    mp->end_dst_port = end_dst_port;
    mp->interval = (u16)interval;
    mp->is_ipv4 = 0;

    S; W;

OUT:
    return(rv);
}

static int api_udp_ping_export (vat_main_t *vam)
{
    udp_ping_test_main_t * sm = &udp_ping_test_main;
    unformat_input_t *input = vam->input;
    vl_api_udp_ping_export_req_t *mp;
    u8 *name = NULL;
    int rv = 0;
    int is_add = 1;

      while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
        {
          if (unformat(input, "export"))
            is_add = 1;
          else if (unformat(input, "disable"))
            is_add = 0;
          else
            break;
        }

    M(UDP_PING_EXPORT, udp_ping_export);

    mp->enable = is_add;

    S; W;

OUT:
    return(rv);
}

/* 
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg \
_(udp_ping_add, "src <local IPv6 address>  src-port-range <local port range> "\
  "dst <remote IPv6 address> dst-port-range <destination port range> "\
  "interval <time interval in sec for which ping packet will be sent> ")    \
_(udp_ping_del, "src <local IPv6 address>  src-port-range <local port range> "\
  "dst <remote IPv6 address> dst-port-range <destination port range> "\
  "interval <time interval in sec for which ping packet will be sent> "\
  "disable")                         \
_(pudp_ping_export, "set udp-ping export [disable]")                                         \


void vat_api_hookup (vat_main_t *vam)
{
    udp_ping_test_main_t * sm = &udp_ping_test_main;
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

clib_error_t * vat_plugin_register (vat_main_t *vam)
{
  udp_ping_test_main_t *sm = &udp_ping_test_main;
  u8 * name;

  sm->vat_main = vam;

  name = format (0, "udp_ping_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~0)
    vat_api_hookup (vam);
  
  vec_free(name);
  
  return 0;
}
