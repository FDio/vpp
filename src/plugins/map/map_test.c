/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 * map_test.c - test harness plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip.h>

#define __plugin_msg_base map_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <map/map_msg_enum.h>

/* Get CRC codes of the messages defined outside of this plugin */
#define vl_msg_name_crc_list
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

/* define message structures */
#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#include <map/map_all_api_h.h> 
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <map/map_all_api_h.h> 
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <map/map_all_api_h.h> 
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <map/map_all_api_h.h>
#undef vl_api_version

typedef struct {
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} map_test_main_t;

map_test_main_t map_test_main;

#define foreach_standard_reply_retval_handler   \
_(map_del_domain_reply)				\
_(map_add_del_rule_reply)

#define _(n)								\
    static void vl_api_##n##_t_handler					\
    (vl_api_##n##_t * mp)						\
    {									\
        vat_main_t * vam = map_test_main.vat_main;			\
        i32 retval = ntohl(mp->retval);					\
	if (vam->json_output) {						\
	  vat_json_node_t node;						\
	  vat_json_init_object (&node);					\
	  vat_json_object_add_int (&node, "retval", ntohl (mp->retval)); \
	  vat_json_print (vam->ofp, &node);				\
	  vat_json_free (&node);					\
	  return;							\
	}								\
        if (vam->async_mode) {						\
            vam->async_errors += (retval < 0);				\
        } else {							\
            vam->retval = retval;					\
            vam->result_ready = 1;					\
        }								\
    }
foreach_standard_reply_retval_handler;
#undef _

/* 
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg			\
_(MAP_ADD_DOMAIN_REPLY, map_add_domain_reply)		\
_(MAP_DEL_DOMAIN_REPLY, map_del_domain_reply)		\
_(MAP_ADD_DEL_RULE_REPLY, map_add_del_rule_reply)	\
_(MAP_DOMAIN_DETAILS, map_domain_details)

static int
api_map_add_domain (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_map_add_domain_t *mp;

  ip4_address_t ip4_prefix;
  ip6_address_t ip6_prefix;
  ip6_address_t ip6_src;
  u32 num_m_args = 0;
  u32 ip6_prefix_len = 0, ip4_prefix_len = 0, ea_bits_len = 0, psid_offset =
    0, psid_length = 0;
  u8 is_translation = 0;
  u32 mtu = 0;
  u32 ip6_src_len = 128;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "ip4-pfx %U/%d", unformat_ip4_address,
                   &ip4_prefix, &ip4_prefix_len))
       num_m_args++;
      else if (unformat (i, "ip6-pfx %U/%d", unformat_ip6_address,
                        &ip6_prefix, &ip6_prefix_len))
       num_m_args++;
      else
       if (unformat
           (i, "ip6-src %U/%d", unformat_ip6_address, &ip6_src,
            &ip6_src_len))
       num_m_args++;
      else if (unformat (i, "ip6-src %U", unformat_ip6_address, &ip6_src))
       num_m_args++;
      else if (unformat (i, "ea-bits-len %d", &ea_bits_len))
       num_m_args++;
      else if (unformat (i, "psid-offset %d", &psid_offset))
       num_m_args++;
      else if (unformat (i, "psid-len %d", &psid_length))
       num_m_args++;
      else if (unformat (i, "mtu %d", &mtu))
       num_m_args++;
      else if (unformat (i, "map-t"))
       is_translation = 1;
      else
       {
         clib_warning ("parse error '%U'", format_unformat_error, i);
         return -99;
       }
    }

  if (num_m_args < 3)
    {
      errmsg ("mandatory argument(s) missing");
      return -99;
    }

  /* Construct the API message */
  M (MAP_ADD_DOMAIN, mp);

  clib_memcpy (mp->ip4_prefix, &ip4_prefix, sizeof (ip4_prefix));
  mp->ip4_prefix_len = ip4_prefix_len;

  clib_memcpy (mp->ip6_prefix, &ip6_prefix, sizeof (ip6_prefix));
  mp->ip6_prefix_len = ip6_prefix_len;

  clib_memcpy (mp->ip6_src, &ip6_src, sizeof (ip6_src));
  mp->ip6_src_prefix_len = ip6_src_len;

  mp->ea_bits_len = ea_bits_len;
  mp->psid_offset = psid_offset;
  mp->psid_length = psid_length;
  mp->is_translation = is_translation;
  mp->mtu = htons (mtu);

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}
static int
api_map_del_domain (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_map_del_domain_t *mp;

  u32 num_m_args = 0;
  u32 index;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "index %d", &index))
       num_m_args++;
      else
       {
         clib_warning ("parse error '%U'", format_unformat_error, i);
         return -99;
       }
    }

  if (num_m_args != 1)
    {
      errmsg ("mandatory argument(s) missing");
      return -99;
    }

  /* Construct the API message */
  M (MAP_DEL_DOMAIN, mp);

  mp->index = ntohl (index);

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}

static int
api_map_add_del_rule (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_map_add_del_rule_t *mp;
  u8 is_add = 1;
  ip6_address_t ip6_dst;
  u32 num_m_args = 0, index, psid = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "index %d", &index))
       num_m_args++;
      else if (unformat (i, "psid %d", &psid))
       num_m_args++;
      else if (unformat (i, "dst %U", unformat_ip6_address, &ip6_dst))
       num_m_args++;
      else if (unformat (i, "del"))
       {
         is_add = 0;
       }
      else
       {
         clib_warning ("parse error '%U'", format_unformat_error, i);
         return -99;
       }
    }

  /* Construct the API message */
  M (MAP_ADD_DEL_RULE, mp);

  mp->index = ntohl (index);
  mp->is_add = is_add;
  clib_memcpy (mp->ip6_dst, &ip6_dst, sizeof (ip6_dst));
  mp->psid = ntohs (psid);

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}
static int
api_map_domain_dump (vat_main_t * vam)
{
  map_test_main_t *mm = &map_test_main;
  vl_api_map_domain_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  /* Construct the API message */
  M (MAP_DOMAIN_DUMP, mp);

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (mm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", mm->ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);

  return ret;
}

static int
api_map_rule_dump (vat_main_t * vam)
{
  map_test_main_t *mm = &map_test_main;
  unformat_input_t *i = vam->input;
  vl_api_map_rule_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 domain_index = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "index %u", &domain_index))
       ;
      else
       break;
    }

  if (domain_index == ~0)
    {
      clib_warning ("parse error: domain index expected");
      return -99;
    }

  /* Construct the API message */
  M (MAP_RULE_DUMP, mp);

  mp->domain_index = htonl (domain_index);

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  /* Use a control ping for synchronization */
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (mm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  return ret;
}

static void vl_api_map_add_domain_reply_t_handler
  (vl_api_map_add_domain_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (vam->json_output) {
    vat_json_node_t node;
    vat_json_init_object (&node);
    vat_json_object_add_int (&node, "retval", ntohl (mp->retval));
    vat_json_object_add_uint (&node, "index", ntohl (mp->index));
    vat_json_print (vam->ofp, &node);
    vat_json_free (&node);
  }

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

static void vl_api_map_domain_details_t_handler_json
  (vl_api_map_domain_details_t * mp)
{
  vat_json_node_t *node = NULL;
  vat_main_t *vam = &vat_main;
  struct in6_addr ip6;
  struct in_addr ip4;

  if (VAT_JSON_ARRAY != vam->json_tree.type)
    {
      ASSERT (VAT_JSON_NONE == vam->json_tree.type);
      vat_json_init_array (&vam->json_tree);
    }

  node = vat_json_array_add (&vam->json_tree);
  vat_json_init_object (node);

  vat_json_object_add_uint (node, "domain_index",
                           clib_net_to_host_u32 (mp->domain_index));
  clib_memcpy (&ip6, mp->ip6_prefix, sizeof (ip6));
  vat_json_object_add_ip6 (node, "ip6_prefix", ip6);
  clib_memcpy (&ip4, mp->ip4_prefix, sizeof (ip4));
  vat_json_object_add_ip4 (node, "ip4_prefix", ip4);
  clib_memcpy (&ip6, mp->ip6_src, sizeof (ip6));
  vat_json_object_add_ip6 (node, "ip6_src", ip6);
  vat_json_object_add_int (node, "ip6_prefix_len", mp->ip6_prefix_len);
  vat_json_object_add_int (node, "ip4_prefix_len", mp->ip4_prefix_len);
  vat_json_object_add_int (node, "ip6_src_len", mp->ip6_src_len);
  vat_json_object_add_int (node, "ea_bits_len", mp->ea_bits_len);
  vat_json_object_add_int (node, "psid_offset", mp->psid_offset);
  vat_json_object_add_int (node, "psid_length", mp->psid_length);
  vat_json_object_add_uint (node, "flags", mp->flags);
  vat_json_object_add_uint (node, "mtu", clib_net_to_host_u16 (mp->mtu));
  vat_json_object_add_int (node, "is_translation", mp->is_translation);
}

static void vl_api_map_domain_details_t_handler
  (vl_api_map_domain_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  if (vam->json_output)
    return vl_api_map_domain_details_t_handler_json (mp);

  if (mp->is_translation)
    {
      print (vam->ofp,
            "* %U/%d (ipv4-prefix) %U/%d (ipv6-prefix) %U/%d (ip6-src) index: %u",
            format_ip4_address, mp->ip4_prefix, mp->ip4_prefix_len,
            format_ip6_address, mp->ip6_prefix, mp->ip6_prefix_len,
            format_ip6_address, mp->ip6_src, mp->ip6_src_len,
            clib_net_to_host_u32 (mp->domain_index));
    }
  else
    {
      print (vam->ofp,
            "* %U/%d (ipv4-prefix) %U/%d (ipv6-prefix) %U (ip6-src) index: %u",
            format_ip4_address, mp->ip4_prefix, mp->ip4_prefix_len,
            format_ip6_address, mp->ip6_prefix, mp->ip6_prefix_len,
            format_ip6_address, mp->ip6_src,
            clib_net_to_host_u32 (mp->domain_index));
    }
  print (vam->ofp, "  ea-len %d psid-offset %d psid-len %d mtu %d %s",
        mp->ea_bits_len, mp->psid_offset, mp->psid_length, mp->mtu,
        mp->is_translation ? "map-t" : "");
}

/* 
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg				\
_(map_add_domain,					\
  "ip4-pfx <ip4pfx> ip6-pfx <ip6pfx> "			\
  "ip6-src <ip6addr> "					\
  "ea-bits-len <n> psid-offset <n> psid-len <n>")	\
_(map_del_domain, "index <n>")				\
_(map_add_del_rule,					\
  "index <n> psid <n> dst <ip6addr> [del]")		\
_(map_domain_dump, "")					\
_(map_rule_dump, "index <map-domain>")

static void map_api_hookup (vat_main_t *vam)
{
    map_test_main_t * mm = &map_test_main;
    /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + mm->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1); 
    foreach_vpe_api_reply_msg;
#undef _

    /* API messages we can send */
#define _(n,h) \
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
  map_test_main_t * mm = &map_test_main;
  u8 * name;

  mm->vat_main = vam;

  name = format (0, "map_%08x%c", api_version, 0);
  mm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  /* Get the control ping ID */
#define _(id,n,crc) \
  const char *id ## _CRC __attribute__ ((unused)) = #n "_" #crc;
  foreach_vl_msg_name_crc_vpe;
#undef _
  mm->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));

  if (mm->msg_id_base != (u16) ~0)
    map_api_hookup (vam);

  vec_free(name);

  return 0;
}
