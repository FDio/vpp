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
  _(LB_CONF_REPLY, lb_conf_reply)                               \
  _(LB_ADD_DEL_VIP_REPLY, lb_add_del_vip_reply)                 \
  _(LB_ADD_DEL_AS_REPLY, lb_add_del_as_reply)

static int api_lb_conf (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_lb_conf_t *mp;
  u32 ip4_src_address = 0xffffffff;
  ip46_address_t ip6_src_address;
  u32 sticky_buckets_per_core = LB_DEFAULT_PER_CPU_STICKY_BUCKETS;
  u32 flow_timeout = LB_DEFAULT_FLOW_TIMEOUT;
  int ret;

  ip6_src_address.as_u64[0] = 0xffffffffffffffffL;
  ip6_src_address.as_u64[1] = 0xffffffffffffffffL;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "ip4-src-address %U", unformat_ip4_address, &ip4_src_address))
      ;
    else if (unformat(line_input, "ip6-src-address %U", unformat_ip6_address, &ip6_src_address))
      ;
    else if (unformat(line_input, "buckets %d", &sticky_buckets_per_core))
      ;
    else if (unformat(line_input, "timeout %d", &flow_timeout))
      ;
    else {
        errmsg ("invalid arguments\n");
        return -99;
    }
  }

  M(LB_CONF, mp);
  clib_memcpy (&(mp->ip4_src_address), &ip4_src_address, sizeof (ip4_src_address));
  clib_memcpy (&(mp->ip6_src_address), &ip6_src_address, sizeof (ip6_src_address));
  mp->sticky_buckets_per_core = htonl (sticky_buckets_per_core);
  mp->flow_timeout = htonl (flow_timeout);

  S(mp);
  W (ret);
  return ret;
}

static int api_lb_add_del_vip (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_lb_add_del_vip_t *mp;
  int ret;
  ip46_address_t ip_prefix;
  u8 prefix_length = 0;
  u8 protocol;
  u32 port = 0;
  u32 encap = 0;
  u32 dscp = ~0;
  u32 srv_type = LB_SRV_TYPE_CLUSTERIP;
  u32 target_port = 0;
  u32 new_length = 1024;

  if (!unformat(line_input, "%U", unformat_ip46_prefix, &ip_prefix,
                &prefix_length, IP46_TYPE_ANY, &prefix_length)) {
    errmsg ("lb_add_del_vip: invalid vip prefix\n");
    return -99;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "new_len %d", &new_length))
      ;
    else if (unformat(line_input, "del"))
      mp->is_del = 1;
    else if (unformat(line_input, "protocol tcp"))
      {
        protocol = IP_PROTOCOL_TCP;
      }
    else if (unformat(line_input, "protocol udp"))
      {
        protocol = IP_PROTOCOL_UDP;
      }
    else if (unformat(line_input, "port %d", &port))
      ;
    else if (unformat(line_input, "encap gre4"))
      encap = LB_ENCAP_TYPE_GRE4;
    else if (unformat(line_input, "encap gre6"))
      encap = LB_ENCAP_TYPE_GRE6;
    else if (unformat(line_input, "encap l3dsr"))
      encap = LB_ENCAP_TYPE_L3DSR;
    else if (unformat(line_input, "encap nat4"))
      encap = LB_ENCAP_TYPE_NAT4;
    else if (unformat(line_input, "encap nat6"))
      encap = LB_ENCAP_TYPE_NAT6;
    else if (unformat(line_input, "dscp %d", &dscp))
      ;
    else if (unformat(line_input, "type clusterip"))
      srv_type = LB_SRV_TYPE_CLUSTERIP;
    else if (unformat(line_input, "type nodeport"))
      srv_type = LB_SRV_TYPE_NODEPORT;
    else if (unformat(line_input, "target_port %d", &target_port))
      ;
    else {
        errmsg ("invalid arguments\n");
        return -99;
    }
  }

  if ((encap != LB_ENCAP_TYPE_L3DSR) && (dscp != ~0))
    {
      errmsg("lb_vip_add error: should not configure dscp for none L3DSR.");
      return -99;
    }

  if ((encap == LB_ENCAP_TYPE_L3DSR) && (dscp >= 64))
    {
      errmsg("lb_vip_add error: dscp for L3DSR should be less than 64.");
      return -99;
    }

  M(LB_ADD_DEL_VIP, mp);
  clib_memcpy (mp->ip_prefix, &ip_prefix, sizeof (ip_prefix));
  mp->prefix_length = prefix_length;
  mp->protocol = (u8)protocol;
  mp->port = htons((u16)port);
  mp->encap = (u8)encap;
  mp->dscp = (u8)dscp;
  mp->type = (u8)srv_type;
  mp->target_port = htons((u16)target_port);
  mp->node_port = htons((u16)target_port);
  mp->new_flows_table_length = htonl(new_length);

  S(mp);
  W (ret);
  return ret;
}

static int api_lb_add_del_as (vat_main_t * vam)
{

  unformat_input_t *line_input = vam->input;
  vl_api_lb_add_del_as_t *mp;
  int ret;
  ip46_address_t vip_prefix, as_addr;
  u8 vip_plen;
  ip46_address_t *as_array = 0;
  u32 vip_index;
  u32 port = 0;
  u8 protocol = 0;
  u8 is_del = 0;
  u8 is_flush = 0;

  if (!unformat(line_input, "%U", unformat_ip46_prefix,
                &vip_prefix, &vip_plen, IP46_TYPE_ANY))
  {
      errmsg ("lb_add_del_as: invalid vip prefix\n");
      return -99;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "%U", unformat_ip46_address,
                 &as_addr, IP46_TYPE_ANY))
      {
        vec_add1(as_array, as_addr);
      }
    else if (unformat(line_input, "del"))
      {
        is_del = 1;
      }
    else if (unformat(line_input, "flush"))
      {
        is_flush = 1;
      }
    else if (unformat(line_input, "protocol tcp"))
      {
          protocol = IP_PROTOCOL_TCP;
      }
    else if (unformat(line_input, "protocol udp"))
      {
          protocol = IP_PROTOCOL_UDP;
      }
    else if (unformat(line_input, "port %d", &port))
      ;
    else {
        errmsg ("invalid arguments\n");
        return -99;
    }
  }

  if (!vec_len(as_array)) {
    errmsg ("No AS address provided \n");
    return -99;
  }

  M(LB_ADD_DEL_AS, mp);
  clib_memcpy (mp->vip_ip_prefix, &vip_prefix, sizeof (vip_prefix));
  mp->vip_prefix_length = vip_plen;
  mp->protocol = (u8)protocol;
  mp->port = htons((u16)port);
  clib_memcpy (mp->as_address, &as_addr, sizeof (as_addr));
  mp->is_del = is_del;
  mp->is_flush = is_flush;

  S(mp);
  W (ret);
  return ret;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                             \
_(lb_conf, "[ip4-src-address <addr>] [ip6-src-address <addr>] " \
           "[buckets <n>] [timeout <s>]")  \
_(lb_add_del_vip, "<prefix> "  \
                  "[protocol (tcp|udp) port <n>] "  \
                  "[encap (gre6|gre4|l3dsr|nat4|nat6)] " \
                  "[dscp <n>] "  \
                  "[type (nodeport|clusterip) target_port <n>] " \
                  "[new_len <n>] [del]")  \
_(lb_add_del_as, "<vip-prefix> [protocol (tcp|udp) port <n>] "  \
                 "[<address>] [del] [flush]")

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
