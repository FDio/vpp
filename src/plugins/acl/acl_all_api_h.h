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
/* Include the generated file, see BUILT_SOURCES in Makefile.am */
#include <acl/acl.api.h>

#ifdef vl_printfun

#ifdef LP64
#define _uword_fmt "%lld"
#define _uword_cast (long long)
#else
#define _uword_fmt "%ld"
#define _uword_cast long
#endif

static inline void *
vl_api_acl_rule_t_print (vl_api_acl_rule_t * a, void *handle)
{
  vl_print (handle, "vl_api_acl_rule_t:\n");
  vl_print (handle, "is_permit: %u\n", (unsigned) a->is_permit);
  vl_print (handle, "is_ipv6: %u\n", (unsigned) a->is_ipv6);
  {
    int _i;
    for (_i = 0; _i < 16; _i++)
      {
        vl_print (handle, "src_ip_addr[%d]: %u\n", _i, a->src_ip_addr[_i]);
      }
  }
  vl_print (handle, "src_ip_prefix_len: %u\n",
            (unsigned) a->src_ip_prefix_len);
  {
    int _i;
    for (_i = 0; _i < 16; _i++)
      {
        vl_print (handle, "dst_ip_addr[%d]: %u\n", _i, a->dst_ip_addr[_i]);
      }
  }
  vl_print (handle, "dst_ip_prefix_len: %u\n",
            (unsigned) a->dst_ip_prefix_len);
  vl_print (handle, "proto: %u\n", (unsigned) a->proto);
  vl_print (handle, "srcport_or_icmptype_first: %u\n",
            (unsigned) a->srcport_or_icmptype_first);
  vl_print (handle, "srcport_or_icmptype_last: %u\n",
            (unsigned) a->srcport_or_icmptype_last);
  vl_print (handle, "dstport_or_icmpcode_first: %u\n",
            (unsigned) a->dstport_or_icmpcode_first);
  vl_print (handle, "dstport_or_icmpcode_last: %u\n",
            (unsigned) a->dstport_or_icmpcode_last);
  vl_print (handle, "tcp_flags_mask: %u\n", (unsigned) a->tcp_flags_mask);
  vl_print (handle, "tcp_flags_value: %u\n", (unsigned) a->tcp_flags_value);
  return handle;
}

static inline void *
vl_api_acl_add_replace_t_print (vl_api_acl_add_replace_t * a, void *handle)
{
  int i;
  vl_print (handle, "vl_api_acl_add_replace_t:\n");
  vl_print (handle, "_vl_msg_id: %u\n", (unsigned) a->_vl_msg_id);
  vl_print (handle, "client_index: %u\n", (unsigned) a->client_index);
  vl_print (handle, "context: %u\n", (unsigned) a->context);
  vl_print (handle, "acl_index: %u\n", (unsigned) a->acl_index);
  vl_print (handle, "count: %u\n", (unsigned) a->count);
  vl_print (handle, "r ----- \n");
  for (i = 0; i < a->count; i++)
    {
      vl_print (handle, "  r[%d]:\n", i);
      vl_api_acl_rule_t_print (&a->r[i], handle);
    }
  vl_print (handle, "r ----- END \n");
  return handle;
}


static inline void *vl_api_acl_details_t_print (vl_api_acl_details_t *a,void *handle)
{
    vl_print(handle, "vl_api_acl_details_t:\n");
    vl_print(handle, "_vl_msg_id: %u\n", (unsigned) a->_vl_msg_id);
    vl_print(handle, "context: %u\n", (unsigned) a->context);
    vl_print(handle, "acl_index: %u\n", (unsigned) a->acl_index);
    {
        int _i;
        for (_i = 0; _i < 64; _i++) {
            vl_print(handle, "tag[%d]: %u\n", _i, a->tag[_i]);
        }
    }
    vl_print(handle, "count: %u\n", (unsigned) a->count);
    vl_print(handle, "r ----- \n");
    // FIXME vl_api_acl_rule_t_print(&a->r, handle);
    vl_print(handle, "r ----- END \n");
    return handle;
}

static inline void *
vl_api_macip_acl_rule_t_print (vl_api_macip_acl_rule_t * a, void *handle)
{
  vl_print (handle, "vl_api_macip_acl_rule_t:\n");
  vl_print (handle, "is_permit: %u\n", (unsigned) a->is_permit);
  vl_print (handle, "is_ipv6: %u\n", (unsigned) a->is_ipv6);
  {
    int _i;
    for (_i = 0; _i < 6; _i++)
      {
        vl_print (handle, "src_mac[%d]: %u\n", _i, a->src_mac[_i]);
      }
  }
  {
    int _i;
    for (_i = 0; _i < 6; _i++)
      {
        vl_print (handle, "src_mac_mask[%d]: %u\n", _i, a->src_mac_mask[_i]);
      }
  }
  {
    int _i;
    for (_i = 0; _i < 16; _i++)
      {
        vl_print (handle, "src_ip_addr[%d]: %u\n", _i, a->src_ip_addr[_i]);
      }
  }
  vl_print (handle, "src_ip_prefix_len: %u\n",
            (unsigned) a->src_ip_prefix_len);
  return handle;
}

static inline void *
vl_api_macip_acl_add_t_print (vl_api_macip_acl_add_t * a, void *handle)
{
  int i;
  vl_print (handle, "vl_api_macip_acl_add_t:\n");
  vl_print (handle, "_vl_msg_id: %u\n", (unsigned) a->_vl_msg_id);
  vl_print (handle, "client_index: %u\n", (unsigned) a->client_index);
  vl_print (handle, "context: %u\n", (unsigned) a->context);
  vl_print (handle, "count: %u\n", (unsigned) a->count);
  vl_print (handle, "r ----- \n");
  for (i = 0; i < a->count; i++)
    {
      vl_print (handle, "  r[%d]:\n", i);
      vl_api_macip_acl_rule_t_print (&a->r[i], handle);
    }
  vl_print (handle, "r ----- END \n");
  return handle;
}

static inline void *vl_api_macip_acl_details_t_print (vl_api_macip_acl_details_t *a,void *handle)
{
    int i;
    vl_print(handle, "vl_api_macip_acl_details_t:\n");
    vl_print(handle, "_vl_msg_id: %u\n", (unsigned) a->_vl_msg_id);
    vl_print(handle, "context: %u\n", (unsigned) a->context);
    vl_print(handle, "acl_index: %u\n", (unsigned) a->acl_index);
    {
        int _i;
        for (_i = 0; _i < 64; _i++) {
            vl_print(handle, "tag[%d]: %u\n", _i, a->tag[_i]);
        }
    }
    vl_print(handle, "count: %u\n", (unsigned) a->count);
    vl_print(handle, "r ----- \n");
    for (i = 0; i < a->count; i++)
      {
        vl_print (handle, "  r[%d]:\n", i);
        vl_api_macip_acl_rule_t_print (&a->r[i], handle);
      }
    vl_print(handle, "r ----- END \n");
    return handle;
}

#endif /* vl_printfun */


#ifdef vl_endianfun

#undef clib_net_to_host_uword
#ifdef LP64
#define clib_net_to_host_uword clib_net_to_host_u64
#else
#define clib_net_to_host_uword clib_net_to_host_u32
#endif

/*
 * Manual endian/print functions created by copypasting the automatically
 * generated ones with small required adjustments. Appears the codegen
 * can't make code to print the contents of custom-type array.
 */

static inline void
vl_api_acl_rule_t_endian (vl_api_acl_rule_t * a)
{
  /* a->is_permit = a->is_permit (no-op) */
  /* a->is_ipv6 = a->is_ipv6 (no-op) */
  /* a->src_ip_addr[0..15] = a->src_ip_addr[0..15] (no-op) */
  /* a->src_ip_prefix_len = a->src_ip_prefix_len (no-op) */
  /* a->dst_ip_addr[0..15] = a->dst_ip_addr[0..15] (no-op) */
  /* a->dst_ip_prefix_len = a->dst_ip_prefix_len (no-op) */
  /* a->proto = a->proto (no-op) */
  a->srcport_or_icmptype_first =
    clib_net_to_host_u16 (a->srcport_or_icmptype_first);
  a->srcport_or_icmptype_last =
    clib_net_to_host_u16 (a->srcport_or_icmptype_last);
  a->dstport_or_icmpcode_first =
    clib_net_to_host_u16 (a->dstport_or_icmpcode_first);
  a->dstport_or_icmpcode_last =
    clib_net_to_host_u16 (a->dstport_or_icmpcode_last);
  /* a->tcp_flags_mask = a->tcp_flags_mask (no-op) */
  /* a->tcp_flags_value = a->tcp_flags_value (no-op) */
}

static inline void
vl_api_acl_add_replace_t_endian (vl_api_acl_add_replace_t * a)
{
  int i;
  a->_vl_msg_id = clib_net_to_host_u16 (a->_vl_msg_id);
  a->client_index = clib_net_to_host_u32 (a->client_index);
  a->context = clib_net_to_host_u32 (a->context);
  a->acl_index = clib_net_to_host_u32 (a->acl_index);
  a->count = clib_net_to_host_u32 (a->count);
  for (i = 0; i < a->count; i++)
    {
      vl_api_acl_rule_t_endian (&a->r[i]);
    }
}

static inline void vl_api_acl_details_t_endian (vl_api_acl_details_t *a)
{
    int i;
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
    /* a->tag[0..63] = a->tag[0..63] (no-op) */
    a->count = clib_net_to_host_u32(a->count);
    for (i = 0; i < a->count; i++)
    {
      vl_api_acl_rule_t_endian (&a->r[i]);
    }
}

static inline void vl_api_acl_interface_list_details_t_endian (vl_api_acl_interface_list_details_t *a)
{
    int i;
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
    /* a->count = a->count (no-op) */
    /* a->n_input = a->n_input (no-op) */
    for(i=0; i<a->count; i++) {
      a->acls[i] = clib_net_to_host_u32(a->acls[i]);
    }
}

static inline void vl_api_acl_interface_set_acl_list_t_endian (vl_api_acl_interface_set_acl_list_t *a)
{
    int i;
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->client_index = clib_net_to_host_u32(a->client_index);
    a->context = clib_net_to_host_u32(a->context);
    a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
    /* a->count = a->count (no-op) */
    /* a->n_input = a->n_input (no-op) */
    for(i=0; i<a->count; i++) {
      a->acls[i] = clib_net_to_host_u32(a->acls[i]);
    }
}

static inline void
vl_api_macip_acl_rule_t_endian (vl_api_macip_acl_rule_t * a)
{
  /* a->is_permit = a->is_permit (no-op) */
  /* a->is_ipv6 = a->is_ipv6 (no-op) */
  /* a->src_mac[0..5] = a->src_mac[0..5] (no-op) */
  /* a->src_mac_mask[0..5] = a->src_mac_mask[0..5] (no-op) */
  /* a->src_ip_addr[0..15] = a->src_ip_addr[0..15] (no-op) */
  /* a->src_ip_prefix_len = a->src_ip_prefix_len (no-op) */
}

static inline void
vl_api_macip_acl_add_t_endian (vl_api_macip_acl_add_t * a)
{
  int i;
  a->_vl_msg_id = clib_net_to_host_u16 (a->_vl_msg_id);
  a->client_index = clib_net_to_host_u32 (a->client_index);
  a->context = clib_net_to_host_u32 (a->context);
  a->count = clib_net_to_host_u32 (a->count);
  for (i = 0; i < a->count; i++)
    {
      vl_api_macip_acl_rule_t_endian (&a->r[i]);
    }
}

static inline void vl_api_macip_acl_details_t_endian (vl_api_macip_acl_details_t *a)
{
    int i;
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    a->acl_index = clib_net_to_host_u32(a->acl_index);
    /* a->tag[0..63] = a->tag[0..63] (no-op) */
    a->count = clib_net_to_host_u32(a->count);
    for (i = 0; i < a->count; i++)
      {
        vl_api_macip_acl_rule_t_endian (&a->r[i]);
      }
}




#endif /* vl_printfun */


