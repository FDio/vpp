/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 * acl_test.c - test harness plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip.h>
#include <arpa/inet.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <acl/acl_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <acl/acl_all_api_h.h>
#undef vl_typedefs

/* define message structures */
#define vl_endianfun
#include <acl/acl_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <acl/acl_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <acl/acl_all_api_h.h>
#undef vl_api_version

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} acl_test_main_t;

acl_test_main_t acl_test_main;

#define foreach_standard_reply_retval_handler   \
_(acl_del_reply) \
_(acl_interface_add_del_reply) \
_(macip_acl_interface_add_del_reply) \
_(acl_interface_set_acl_list_reply) \
_(macip_acl_del_reply)

#define foreach_reply_retval_aclindex_handler  \
_(acl_add_replace_reply) \
_(macip_acl_add_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = acl_test_main.vat_main;   \
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

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = acl_test_main.vat_main;   \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            clib_warning("ACL index: %d", ntohl(mp->acl_index)); \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_reply_retval_aclindex_handler;
#undef _

/* These two ought to be in a library somewhere but they aren't */
static uword
my_unformat_mac_address (unformat_input_t * input, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return unformat (input, "%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3],
                   &a[4], &a[5]);
}

static u8 *
my_format_mac_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
                 a[0], a[1], a[2], a[3], a[4], a[5]);
}



static void vl_api_acl_plugin_get_version_reply_t_handler
    (vl_api_acl_plugin_get_version_reply_t * mp)
    {
        vat_main_t * vam = acl_test_main.vat_main;
        clib_warning("ACL plugin version: %d.%d", ntohl(mp->major), ntohl(mp->minor));
        vam->result_ready = 1;
    }

static void vl_api_acl_interface_list_details_t_handler
    (vl_api_acl_interface_list_details_t * mp)
    {
        int i;
        vat_main_t * vam = acl_test_main.vat_main;
        u8 *out = 0;
        vl_api_acl_interface_list_details_t_endian(mp);
	out = format(out, "sw_if_index: %d, count: %d, n_input: %d\n", mp->sw_if_index, mp->count, mp->n_input);
        out = format(out, "   input ");
	for(i=0; i<mp->count; i++) {
          out = format(out, "%d ", mp->acls[i]);
          if (i == mp->n_input-1)
            out = format(out, "\n  output ");
	}
        out = format(out, "\n");
        clib_warning("%s", out);
        vec_free(out);
        vam->result_ready = 1;
    }


static inline u8 *
vl_api_acl_rule_t_pretty_format (u8 *out, vl_api_acl_rule_t * a)
{
  int af = a->is_ipv6 ? AF_INET6 : AF_INET;
  u8 src[INET6_ADDRSTRLEN];
  u8 dst[INET6_ADDRSTRLEN];
  inet_ntop(af, a->src_ip_addr, (void *)src, sizeof(src));
  inet_ntop(af, a->dst_ip_addr, (void *)dst, sizeof(dst));

  out = format(out, "%s action %d src %s/%d dst %s/%d proto %d sport %d-%d dport %d-%d tcpflags %d %d",
                     a->is_ipv6 ? "ipv6" : "ipv4", a->is_permit,
                     src, a->src_ip_prefix_len,
                     dst, a->dst_ip_prefix_len,
                     a->proto,
                     a->srcport_or_icmptype_first, a->srcport_or_icmptype_last,
	             a->dstport_or_icmpcode_first, a->dstport_or_icmpcode_last,
                     a->tcp_flags_mask, a->tcp_flags_value);
  return(out);
}



static void vl_api_acl_details_t_handler
    (vl_api_acl_details_t * mp)
    {
        int i;
        vat_main_t * vam = acl_test_main.vat_main;
        vl_api_acl_details_t_endian(mp);
        u8 *out = 0;
        out = format(0, "acl_index: %d, count: %d\n   tag {%s}\n", mp->acl_index, mp->count, mp->tag);
	for(i=0; i<mp->count; i++) {
          out = format(out, "   ");
          out = vl_api_acl_rule_t_pretty_format(out, &mp->r[i]);
          out = format(out, "%s\n", i<mp->count-1 ? "," : "");
	}
        clib_warning("%s", out);
        vec_free(out);
        vam->result_ready = 1;
    }

static inline u8 *
vl_api_macip_acl_rule_t_pretty_format (u8 *out, vl_api_macip_acl_rule_t * a)
{
  int af = a->is_ipv6 ? AF_INET6 : AF_INET;
  u8 src[INET6_ADDRSTRLEN];
  inet_ntop(af, a->src_ip_addr, (void *)src, sizeof(src));

  out = format(out, "%s action %d ip %s/%d mac %U mask %U",
                     a->is_ipv6 ? "ipv6" : "ipv4", a->is_permit,
                     src, a->src_ip_prefix_len,
                     my_format_mac_address, a->src_mac,
                     my_format_mac_address, a->src_mac_mask);
  return(out);
}


static void vl_api_macip_acl_details_t_handler
    (vl_api_macip_acl_details_t * mp)
    {
        int i;
        vat_main_t * vam = acl_test_main.vat_main;
        vl_api_macip_acl_details_t_endian(mp);
        u8 *out = format(0,"MACIP acl_index: %d, count: %d\n   tag {%s}\n", mp->acl_index, mp->count, mp->tag);
	for(i=0; i<mp->count; i++) {
          out = format(out, "   ");
          out = vl_api_macip_acl_rule_t_pretty_format(out, &mp->r[i]);
          out = format(out, "%s\n", i<mp->count-1 ? "," : "");
	}
        clib_warning("%s", out);
        vec_free(out);
        vam->result_ready = 1;
    }

static void vl_api_macip_acl_interface_get_reply_t_handler
    (vl_api_macip_acl_interface_get_reply_t * mp)
    {
        int i;
        vat_main_t * vam = acl_test_main.vat_main;
        u8 *out = format(0, "sw_if_index with MACIP ACL count: %d\n", ntohl(mp->count));
	for(i=0; i<ntohl(mp->count); i++) {
          out = format(out, "  macip_acl_interface_add_del sw_if_index %d add acl %d\n", i, ntohl(mp->acls[i]));
	}
        out = format(out, "\n");
        clib_warning("%s", out);
        vec_free(out);
        vam->result_ready = 1;
    }


/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                                       \
_(ACL_ADD_REPLACE_REPLY, acl_add_replace_reply) \
_(ACL_DEL_REPLY, acl_del_reply) \
_(ACL_INTERFACE_ADD_DEL_REPLY, acl_interface_add_del_reply)  \
_(ACL_INTERFACE_SET_ACL_LIST_REPLY, acl_interface_set_acl_list_reply) \
_(ACL_INTERFACE_LIST_DETAILS, acl_interface_list_details)  \
_(ACL_DETAILS, acl_details)  \
_(MACIP_ACL_ADD_REPLY, macip_acl_add_reply) \
_(MACIP_ACL_DEL_REPLY, macip_acl_del_reply) \
_(MACIP_ACL_DETAILS, macip_acl_details)  \
_(MACIP_ACL_INTERFACE_ADD_DEL_REPLY, macip_acl_interface_add_del_reply)  \
_(MACIP_ACL_INTERFACE_GET_REPLY, macip_acl_interface_get_reply)  \
_(ACL_PLUGIN_GET_VERSION_REPLY, acl_plugin_get_version_reply)

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

static int api_acl_plugin_get_version (vat_main_t * vam)
{
    acl_test_main_t * sm = &acl_test_main;
    vl_api_acl_plugin_get_version_t * mp;
    u32 msg_size = sizeof(*mp);
    f64 timeout;

    vam->result_ready = 0;
    mp = vl_msg_api_alloc_as_if_client(msg_size);
    memset (mp, 0, msg_size);
    mp->_vl_msg_id = ntohs (VL_API_ACL_PLUGIN_GET_VERSION + sm->msg_id_base);
    mp->client_index = vam->my_client_index;

    /* send it... */
    S;

    /* Wait for a reply... */
    W;

    return 0;
}

static int api_macip_acl_interface_get (vat_main_t * vam)
{
    acl_test_main_t * sm = &acl_test_main;
    vl_api_acl_plugin_get_version_t * mp;
    u32 msg_size = sizeof(*mp);
    f64 timeout;

    vam->result_ready = 0;
    mp = vl_msg_api_alloc_as_if_client(msg_size);
    memset (mp, 0, msg_size);
    mp->_vl_msg_id = ntohs (VL_API_MACIP_ACL_INTERFACE_GET + sm->msg_id_base);
    mp->client_index = vam->my_client_index;

    /* send it... */
    S;

    /* Wait for a reply... */
    W;

    return 0;
}

#define vec_validate_acl_rules(v, idx) \
  do {                                 \
    if (vec_len(v) < idx+1) {  \
      vec_validate(v, idx); \
      v[idx].is_permit = 0x1; \
      v[idx].srcport_or_icmptype_last = 0xffff; \
      v[idx].dstport_or_icmpcode_last = 0xffff; \
    } \
  } while (0)


static int api_acl_add_replace (vat_main_t * vam)
{
    acl_test_main_t * sm = &acl_test_main;
    unformat_input_t * i = vam->input;
    f64 timeout;
    vl_api_acl_add_replace_t * mp;
    u32 acl_index = ~0;
    u32 msg_size = sizeof (*mp); /* without the rules */

    vl_api_acl_rule_t *rules = 0;
    int rule_idx = 0;
    int n_rules = 0;
    u32 proto = 0;
    u32 port1 = 0;
    u32 port2 = 0;
    u32 action = 0;
    u32 tcpflags, tcpmask;
    u32 src_prefix_length = 0, dst_prefix_length = 0;
    ip4_address_t src_v4address, dst_v4address;
    ip6_address_t src_v6address, dst_v6address;
    u8 *tag = 0;

    if (!unformat (i, "%d", &acl_index)) {
	/* Just assume -1 */
    }

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (i, "ipv6"))
          {
            vec_validate_acl_rules(rules, rule_idx);
            rules[rule_idx].is_ipv6 = 1;
          }
        else if (unformat (i, "ipv4"))
          {
            vec_validate_acl_rules(rules, rule_idx);
            rules[rule_idx].is_ipv6 = 0;
          }
        else if (unformat (i, "permit+reflect"))
          {
            vec_validate_acl_rules(rules, rule_idx);
            rules[rule_idx].is_permit = 2;
          }
        else if (unformat (i, "permit"))
          {
            vec_validate_acl_rules(rules, rule_idx);
            rules[rule_idx].is_permit = 1;
          }
        else if (unformat (i, "action %d", &action))
          {
            vec_validate_acl_rules(rules, rule_idx);
            rules[rule_idx].is_permit = action;
          }
        else if (unformat (i, "src %U/%d",
         unformat_ip4_address, &src_v4address, &src_prefix_length))
          {
            vec_validate_acl_rules(rules, rule_idx);
            memcpy (rules[rule_idx].src_ip_addr, &src_v4address, 4);
            rules[rule_idx].src_ip_prefix_len = src_prefix_length;
            rules[rule_idx].is_ipv6 = 0;
          }
        else if (unformat (i, "src %U/%d",
         unformat_ip6_address, &src_v6address, &src_prefix_length))
          {
            vec_validate_acl_rules(rules, rule_idx);
            memcpy (rules[rule_idx].src_ip_addr, &src_v6address, 16);
            rules[rule_idx].src_ip_prefix_len = src_prefix_length;
            rules[rule_idx].is_ipv6 = 1;
          }
        else if (unformat (i, "dst %U/%d",
         unformat_ip4_address, &dst_v4address, &dst_prefix_length))
          {
            vec_validate_acl_rules(rules, rule_idx);
            memcpy (rules[rule_idx].dst_ip_addr, &dst_v4address, 4);
            rules[rule_idx].dst_ip_prefix_len = dst_prefix_length;
            rules[rule_idx].is_ipv6 = 0;
          }
        else if (unformat (i, "dst %U/%d",
         unformat_ip6_address, &dst_v6address, &dst_prefix_length))
          {
            vec_validate_acl_rules(rules, rule_idx);
            memcpy (rules[rule_idx].dst_ip_addr, &dst_v6address, 16);
            rules[rule_idx].dst_ip_prefix_len = dst_prefix_length;
            rules[rule_idx].is_ipv6 = 1;
          }
        else if (unformat (i, "sport %d-%d", &port1, &port2))
          {
            vec_validate_acl_rules(rules, rule_idx);
            rules[rule_idx].srcport_or_icmptype_first = htons(port1);
            rules[rule_idx].srcport_or_icmptype_last = htons(port2);
          }
        else if (unformat (i, "sport %d", &port1))
          {
            vec_validate_acl_rules(rules, rule_idx);
            rules[rule_idx].srcport_or_icmptype_first = htons(port1);
            rules[rule_idx].srcport_or_icmptype_last = htons(port1);
          }
        else if (unformat (i, "dport %d-%d", &port1, &port2))
          {
            vec_validate_acl_rules(rules, rule_idx);
            rules[rule_idx].dstport_or_icmpcode_first = htons(port1);
            rules[rule_idx].dstport_or_icmpcode_last = htons(port2);
          }
        else if (unformat (i, "dport %d", &port1))
          {
            vec_validate_acl_rules(rules, rule_idx);
            rules[rule_idx].dstport_or_icmpcode_first = htons(port1);
            rules[rule_idx].dstport_or_icmpcode_last = htons(port1);
          }
        else if (unformat (i, "tcpflags %d %d", &tcpflags, &tcpmask))
          {
            vec_validate_acl_rules(rules, rule_idx);
            rules[rule_idx].tcp_flags_value = tcpflags;
            rules[rule_idx].tcp_flags_mask = tcpmask;
          }
        else if (unformat (i, "proto %d", &proto))
          {
            vec_validate_acl_rules(rules, rule_idx);
            rules[rule_idx].proto = proto;
          }
        else if (unformat (i, "tag %s", &tag))
          {
          }
        else if (unformat (i, ","))
          {
            rule_idx++;
            vec_validate_acl_rules(rules, rule_idx);
          }
        else
    break;
    }

    /* Construct the API message */
    vam->result_ready = 0;

    if(rules)
      n_rules = vec_len(rules);
    else
      n_rules = 0;

    msg_size += n_rules*sizeof(rules[0]);

    mp = vl_msg_api_alloc_as_if_client(msg_size);
    memset (mp, 0, msg_size);
    mp->_vl_msg_id = ntohs (VL_API_ACL_ADD_REPLACE + sm->msg_id_base);
    mp->client_index = vam->my_client_index;
    if (n_rules > 0)
      clib_memcpy(mp->r, rules, n_rules*sizeof (vl_api_acl_rule_t));
    if (tag)
      {
        if (vec_len(tag) >= sizeof(mp->tag))
          {
            tag[sizeof(mp->tag)-1] = 0;
            _vec_len(tag) = sizeof(mp->tag);
          }
        clib_memcpy(mp->tag, tag, vec_len(tag));
        vec_free(tag);
      }
    mp->acl_index = ntohl(acl_index);
    mp->count = htonl(n_rules);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_acl_del (vat_main_t * vam)
{
    acl_test_main_t * sm = &acl_test_main;
    unformat_input_t * i = vam->input;
    f64 timeout;
    vl_api_acl_del_t * mp;
    u32 acl_index = ~0;

    if (!unformat (i, "%d", &acl_index)) {
      errmsg ("missing acl index\n");
      return -99;
    }

    /* Construct the API message */
    M(ACL_DEL, acl_del);
    mp->acl_index = ntohl(acl_index);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_macip_acl_del (vat_main_t * vam)
{
    acl_test_main_t * sm = &acl_test_main;
    unformat_input_t * i = vam->input;
    f64 timeout;
    vl_api_acl_del_t * mp;
    u32 acl_index = ~0;

    if (!unformat (i, "%d", &acl_index)) {
      errmsg ("missing acl index\n");
      return -99;
    }

    /* Construct the API message */
    M(MACIP_ACL_DEL, acl_del);
    mp->acl_index = ntohl(acl_index);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_acl_interface_add_del (vat_main_t * vam)
{
    acl_test_main_t * sm = &acl_test_main;
    unformat_input_t * i = vam->input;
    f64 timeout;
    vl_api_acl_interface_add_del_t * mp;
    u32 sw_if_index = ~0;
    u32 acl_index = ~0;
    u8 is_input = 0;
    u8 is_add = 0;

//    acl_interface_add_del <intfc> | sw_if_index <if-idx> acl_index <acl-idx> [out] [del]

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (i, "%d", &acl_index))
    ;
        else
    break;
    }


    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            ;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            ;
        else if (unformat (i, "add"))
            is_add = 1;
        else if (unformat (i, "del"))
            is_add = 0;
        else if (unformat (i, "acl %d", &acl_index))
            ;
        else if (unformat (i, "input"))
            is_input = 1;
        else if (unformat (i, "output"))
            is_input = 0;
        else
            break;
    }

    if (sw_if_index == ~0) {
        errmsg ("missing interface name / explicit sw_if_index number \n");
        return -99;
    }

    if (acl_index == ~0) {
        errmsg ("missing ACL index\n");
        return -99;
    }



    /* Construct the API message */
    M(ACL_INTERFACE_ADD_DEL, acl_interface_add_del);
    mp->acl_index = ntohl(acl_index);
    mp->sw_if_index = ntohl(sw_if_index);
    mp->is_add = is_add;
    mp->is_input = is_input;

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_macip_acl_interface_add_del (vat_main_t * vam)
{
    acl_test_main_t * sm = &acl_test_main;
    unformat_input_t * i = vam->input;
    f64 timeout;
    vl_api_macip_acl_interface_add_del_t * mp;
    u32 sw_if_index = ~0;
    u32 acl_index = ~0;
    u8 is_add = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            ;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            ;
        else if (unformat (i, "add"))
            is_add = 1;
        else if (unformat (i, "del"))
            is_add = 0;
        else if (unformat (i, "acl %d", &acl_index))
            ;
        else
            break;
    }

    if (sw_if_index == ~0) {
        errmsg ("missing interface name / explicit sw_if_index number \n");
        return -99;
    }

    if (acl_index == ~0) {
        errmsg ("missing ACL index\n");
        return -99;
    }



    /* Construct the API message */
    M(MACIP_ACL_INTERFACE_ADD_DEL, macip_acl_interface_add_del);
    mp->acl_index = ntohl(acl_index);
    mp->sw_if_index = ntohl(sw_if_index);
    mp->is_add = is_add;

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_acl_interface_set_acl_list (vat_main_t * vam)
{
    acl_test_main_t * sm = &acl_test_main;
    unformat_input_t * i = vam->input;
    f64 timeout;
    vl_api_acl_interface_set_acl_list_t * mp;
    u32 sw_if_index = ~0;
    u32 acl_index = ~0;
    u32 *inacls = 0;
    u32 *outacls = 0;
    u8 is_input = 0;

//  acl_interface_set_acl_list <intfc> | sw_if_index <if-idx> input [acl-idx list] output [acl-idx list]

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            ;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            ;
        else if (unformat (i, "%d", &acl_index))
          {
            if(is_input)
              vec_add1(inacls, htonl(acl_index));
            else
              vec_add1(outacls, htonl(acl_index));
          }
        else if (unformat (i, "acl %d", &acl_index))
            ;
        else if (unformat (i, "input"))
            is_input = 1;
        else if (unformat (i, "output"))
            is_input = 0;
        else
            break;
    }

    if (sw_if_index == ~0) {
        errmsg ("missing interface name / explicit sw_if_index number \n");
        return -99;
    }

    /* Construct the API message */
    M2(ACL_INTERFACE_SET_ACL_LIST, acl_interface_set_acl_list, sizeof(u32) * (vec_len(inacls) + vec_len(outacls)));
    mp->sw_if_index = ntohl(sw_if_index);
    mp->n_input = vec_len(inacls);
    mp->count = vec_len(inacls) + vec_len(outacls);
    vec_append(inacls, outacls);
    if (vec_len(inacls) > 0)
      clib_memcpy(mp->acls, inacls, vec_len(inacls)*sizeof(u32));

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}


static int api_acl_interface_list_dump (vat_main_t * vam)
{
    acl_test_main_t * sm = &acl_test_main;
    unformat_input_t * i = vam->input;
    f64 timeout;
    u32 sw_if_index = ~0;
    vl_api_acl_interface_list_dump_t * mp;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
            ;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
            ;
        else
            break;
    }

    /* Construct the API message */
    M(ACL_INTERFACE_LIST_DUMP, acl_interface_list_dump);
    mp->sw_if_index = ntohl (sw_if_index);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_acl_dump (vat_main_t * vam)
{
    acl_test_main_t * sm = &acl_test_main;
    unformat_input_t * i = vam->input;
    f64 timeout;
    u32 acl_index = ~0;
    vl_api_acl_dump_t * mp;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%d", &acl_index))
            ;
        else
            break;
    }

    /* Construct the API message */
    M(ACL_DUMP, acl_dump);
    mp->acl_index = ntohl (acl_index);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

static int api_macip_acl_dump (vat_main_t * vam)
{
    acl_test_main_t * sm = &acl_test_main;
    unformat_input_t * i = vam->input;
    f64 timeout;
    u32 acl_index = ~0;
    vl_api_acl_dump_t * mp;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "%d", &acl_index))
            ;
        else
            break;
    }

    /* Construct the API message */
    M(MACIP_ACL_DUMP, macip_acl_dump);
    mp->acl_index = ntohl (acl_index);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

#define vec_validate_macip_acl_rules(v, idx) \
  do {                                 \
    if (vec_len(v) < idx+1) {  \
      vec_validate(v, idx); \
      v[idx].is_permit = 0x1; \
    } \
  } while (0)


static int api_macip_acl_add (vat_main_t * vam)
{
    acl_test_main_t * sm = &acl_test_main;
    unformat_input_t * i = vam->input;
    f64 timeout;
    vl_api_macip_acl_add_t * mp;
    u32 msg_size = sizeof (*mp); /* without the rules */

    vl_api_macip_acl_rule_t *rules = 0;
    int rule_idx = 0;
    int n_rules = 0;
    u32 src_prefix_length = 0;
    u32 action = 0;
    ip4_address_t src_v4address;
    ip6_address_t src_v6address;
    u8 src_mac[6];
    u8 *tag = 0;
    u8 mac_mask_all_1[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (i, "ipv6"))
          {
            vec_validate_macip_acl_rules(rules, rule_idx);
            rules[rule_idx].is_ipv6 = 1;
          }
        else if (unformat (i, "ipv4"))
          {
            vec_validate_macip_acl_rules(rules, rule_idx);
            rules[rule_idx].is_ipv6 = 1;
          }
        else if (unformat (i, "permit"))
          {
            vec_validate_macip_acl_rules(rules, rule_idx);
            rules[rule_idx].is_permit = 1;
          }
        else if (unformat (i, "deny"))
          {
            vec_validate_macip_acl_rules(rules, rule_idx);
            rules[rule_idx].is_permit = 0;
          }
        else if (unformat (i, "action %d", &action))
          {
            vec_validate_macip_acl_rules(rules, rule_idx);
            rules[rule_idx].is_permit = action;
          }
        else if (unformat (i, "ip %U/%d",
         unformat_ip4_address, &src_v4address, &src_prefix_length))
          {
            vec_validate_macip_acl_rules(rules, rule_idx);
            memcpy (rules[rule_idx].src_ip_addr, &src_v4address, 4);
            rules[rule_idx].src_ip_prefix_len = src_prefix_length;
            rules[rule_idx].is_ipv6 = 0;
          }
        else if (unformat (i, "ip %U/%d",
         unformat_ip6_address, &src_v6address, &src_prefix_length))
          {
            vec_validate_macip_acl_rules(rules, rule_idx);
            memcpy (rules[rule_idx].src_ip_addr, &src_v6address, 16);
            rules[rule_idx].src_ip_prefix_len = src_prefix_length;
            rules[rule_idx].is_ipv6 = 1;
          }
        else if (unformat (i, "mac %U",
         my_unformat_mac_address, &src_mac))
          {
            vec_validate_macip_acl_rules(rules, rule_idx);
            memcpy (rules[rule_idx].src_mac, &src_mac, 6);
            memcpy (rules[rule_idx].src_mac_mask, &mac_mask_all_1, 6);
          }
        else if (unformat (i, "mask %U",
         my_unformat_mac_address, &src_mac))
          {
            vec_validate_macip_acl_rules(rules, rule_idx);
            memcpy (rules[rule_idx].src_mac_mask, &src_mac, 6);
          }
        else if (unformat (i, "tag %s", &tag))
          {
          }
        else if (unformat (i, ","))
          {
            rule_idx++;
            vec_validate_macip_acl_rules(rules, rule_idx);
          }
        else
    break;
    }

    /* Construct the API message */
    vam->result_ready = 0;

    if(rules)
      n_rules = vec_len(rules);
    else
      n_rules = 0;

    msg_size += n_rules*sizeof(rules[0]);

    mp = vl_msg_api_alloc_as_if_client(msg_size);
    memset (mp, 0, msg_size);
    mp->_vl_msg_id = ntohs (VL_API_MACIP_ACL_ADD + sm->msg_id_base);
    mp->client_index = vam->my_client_index;
    if (n_rules > 0)
      clib_memcpy(mp->r, rules, n_rules*sizeof (mp->r[0]));
    if (tag)
      {
        if (vec_len(tag) >= sizeof(mp->tag))
          {
            tag[sizeof(mp->tag)-1] = 0;
            _vec_len(tag) = sizeof(mp->tag);
          }
        clib_memcpy(mp->tag, tag, vec_len(tag));
        vec_free(tag);
      }

    mp->count = htonl(n_rules);

    /* send it... */
    S;

    /* Wait for a reply... */
    W;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg \
_(acl_plugin_get_version, "") \
_(acl_add_replace, "<acl-idx> [<ipv4|ipv6> <permit|permit+reflect|deny|action N> [src IP/plen] [dst IP/plen] [sport X-Y] [dport X-Y] [proto P] [tcpflags FL MASK], ... , ...") \
_(acl_del, "<acl-idx>") \
_(acl_dump, "[<acl-idx>]") \
_(acl_interface_add_del, "<intfc> | sw_if_index <if-idx> [add|del] [input|output] acl <acl-idx>") \
_(acl_interface_set_acl_list, "<intfc> | sw_if_index <if-idx> input [acl-idx list] output [acl-idx list]") \
_(acl_interface_list_dump, "[<intfc> | sw_if_index <if-idx>]") \
_(macip_acl_add, "...") \
_(macip_acl_del, "<acl-idx>")\
_(macip_acl_dump, "[<acl-idx>]") \
_(macip_acl_interface_add_del, "<intfc> | sw_if_index <if-idx> [add|del] acl <acl-idx>") \
_(macip_acl_interface_get, "")



void vat_api_hookup (vat_main_t *vam)
{
    acl_test_main_t * sm = &acl_test_main;
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
  acl_test_main_t * sm = &acl_test_main;
  u8 * name;

  sm->vat_main = vam;

  name = format (0, "acl_%08x%c", api_version, 0);
  sm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (sm->msg_id_base != (u16) ~0)
    vat_api_hookup (vam);

  vec_free(name);

  return 0;
}
