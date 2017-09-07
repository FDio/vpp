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

#ifndef included_manual_fns_h
#define included_manual_fns_h

#include <vnet/ip/format.h>
#include <vnet/ethernet/ethernet.h>

/* Macro to finish up custom dump fns */
#define PRINT_S \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);

static inline void
vl_api_acl_rule_t_array_endian(vl_api_acl_rule_t *rules, u32 count)
{
  u32 i;
  for(i=0; i<count; i++) {
    vl_api_acl_rule_t_endian (&rules[i]);
  }
}

static inline void
vl_api_macip_acl_rule_t_array_endian(vl_api_macip_acl_rule_t *rules, u32 count)
{
  u32 i;
  for(i=0; i<count; i++) {
    vl_api_macip_acl_rule_t_endian (&rules[i]);
  }
}

static inline void
vl_api_acl_details_t_endian (vl_api_acl_details_t * a)
{
  a->_vl_msg_id = clib_net_to_host_u16 (a->_vl_msg_id);
  a->context = clib_net_to_host_u32 (a->context);
  a->acl_index = clib_net_to_host_u32 (a->acl_index);
  /* a->tag[0..63] = a->tag[0..63] (no-op) */
  a->count = clib_net_to_host_u32 (a->count);
  vl_api_acl_rule_t_array_endian (a->r, a->count);
}

static inline void
vl_api_macip_acl_details_t_endian (vl_api_macip_acl_details_t * a)
{
  a->_vl_msg_id = clib_net_to_host_u16 (a->_vl_msg_id);
  a->context = clib_net_to_host_u32 (a->context);
  a->acl_index = clib_net_to_host_u32 (a->acl_index);
  /* a->tag[0..63] = a->tag[0..63] (no-op) */
  a->count = clib_net_to_host_u32 (a->count);
  vl_api_macip_acl_rule_t_array_endian (a->r, a->count);
}


static inline void
vl_api_acl_add_replace_t_endian (vl_api_acl_add_replace_t * a)
{
  a->_vl_msg_id = clib_net_to_host_u16 (a->_vl_msg_id);
  a->client_index = clib_net_to_host_u32 (a->client_index);
  a->context = clib_net_to_host_u32 (a->context);
  a->acl_index = clib_net_to_host_u32 (a->acl_index);
  /* a->tag[0..63] = a->tag[0..63] (no-op) */
  a->count = clib_net_to_host_u32 (a->count);
  vl_api_acl_rule_t_array_endian (a->r, a->count);
}

static inline void
vl_api_macip_acl_add_t_endian (vl_api_macip_acl_add_t * a)
{
  a->_vl_msg_id = clib_net_to_host_u16 (a->_vl_msg_id);
  a->client_index = clib_net_to_host_u32 (a->client_index);
  a->context = clib_net_to_host_u32 (a->context);
  /* a->tag[0..63] = a->tag[0..63] (no-op) */
  a->count = clib_net_to_host_u32 (a->count);
  vl_api_macip_acl_rule_t_array_endian (a->r, a->count);
}

static inline void
vl_api_macip_acl_add_replace_t_endian (vl_api_macip_acl_add_replace_t * a)
{
  a->_vl_msg_id = clib_net_to_host_u16 (a->_vl_msg_id);
  a->client_index = clib_net_to_host_u32 (a->client_index);
  a->context = clib_net_to_host_u32 (a->context);
  a->acl_index = clib_net_to_host_u32 (a->acl_index);
  /* a->tag[0..63] = a->tag[0..63] (no-op) */
  a->count = clib_net_to_host_u32 (a->count);
  vl_api_macip_acl_rule_t_array_endian (a->r, a->count);
}

static inline u8 *
format_acl_action(u8 *s, u8 action)
{
  switch(action) {
    case 0:
      s = format (s, "deny");
      break;
    case 1:
      s = format (s, "permit");
      break;
    case 2:
      s = format (s, "permit+reflect");
      break;
    default:
      s = format (s, "action %d", action);
  }
  return(s);
}

static inline void *
vl_api_acl_rule_t_print (vl_api_acl_rule_t * a, void *handle)
{
  u8 *s;

  s = format (0, "  %s ", a->is_ipv6 ? "ipv6" : "ipv4");
  s = format_acl_action (s, a->is_permit);
  s = format (s, " \\\n");

  if (a->is_ipv6)
    s = format (s, "    src %U/%d dst %U/%d \\\n",
		format_ip6_address, a->src_ip_addr, a->src_ip_prefix_len,
		format_ip6_address, a->dst_ip_addr, a->dst_ip_prefix_len);
  else
    s = format (s, "    src %U/%d dst %U/%d \\\n",
		format_ip4_address, a->src_ip_addr, a->src_ip_prefix_len,
		format_ip4_address, a->dst_ip_addr, a->dst_ip_prefix_len);
  s = format (s, "    proto %d \\\n", a->proto);
  s = format (s, "    sport %d-%d dport %d-%d \\\n",
	      clib_net_to_host_u16 (a->srcport_or_icmptype_first),
	      clib_net_to_host_u16 (a->srcport_or_icmptype_last),
	      clib_net_to_host_u16 (a->dstport_or_icmpcode_first),
	      clib_net_to_host_u16 (a->dstport_or_icmpcode_last));

  s = format (s, "    tcpflags %u mask %u, \\",
	      a->tcp_flags_value, a->tcp_flags_mask);
  PRINT_S;
  return handle;
}



static inline void *
vl_api_macip_acl_rule_t_print (vl_api_macip_acl_rule_t * a, void *handle)
{
  u8 *s;

  s = format (0, "  %s %s \\\n", a->is_ipv6 ? "ipv6" : "ipv4",
              a->is_permit ? "permit" : "deny");

  s = format (s, "    src mac %U mask %U \\\n",
	      format_ethernet_address, a->src_mac,
	      format_ethernet_address, a->src_mac_mask);

  if (a->is_ipv6)
    s = format (s, "    src ip %U/%d, \\",
		format_ip6_address, a->src_ip_addr, a->src_ip_prefix_len);
  else
    s = format (s, "    src ip %U/%d, \\",
		format_ip4_address, a->src_ip_addr, a->src_ip_prefix_len);

  PRINT_S;
  return handle;
}

static inline void *
vl_api_acl_add_replace_t_print (vl_api_acl_add_replace_t * a, void *handle)
{
  u8 *s = 0;
  int i;
  u32 acl_index = clib_net_to_host_u32 (a->acl_index);
  u32 count = clib_net_to_host_u32 (a->count);
  if (count > 0x100000)
    {
      s = format (s, "WARN: acl_add_replace count endianness wrong? Fixup to avoid long loop.\n");
      count = a->count;
    }

  s = format (s, "SCRIPT: acl_add_replace %d count %d ",
	      acl_index, count);

  if (a->tag[0])
    s = format (s, "tag %s ", a->tag);

  s = format(s, "\\\n");
  PRINT_S;

  for (i = 0; i < count; i++)
    vl_api_acl_rule_t_print (&a->r[i], handle);

  s = format(s, "\n");
  PRINT_S;
  return handle;
}

static inline void *
vl_api_acl_del_t_print (vl_api_macip_acl_del_t * a, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: acl_del %d ",
              clib_host_to_net_u32 (a->acl_index));

  PRINT_S;
  return handle;
}


static inline void *
vl_api_acl_details_t_print (vl_api_acl_details_t * a, void *handle)
{
  u8 *s = 0;
  int i;
  u32 acl_index = clib_net_to_host_u32 (a->acl_index);
  u32 count = clib_net_to_host_u32 (a->count);
  if (count > 0x100000)
    {
      s = format (s, "WARN: acl_defails count endianness wrong? Fixup to avoid long loop.\n");
      count = a->count;
    }

  s = format (s, "acl_details index %d count %d ",
	      acl_index, count);

  if (a->tag[0])
    s = format (s, "tag %s ", a->tag);

  s = format(s, "\n");
  PRINT_S;

  for (i = 0; i < count; i++)
    vl_api_acl_rule_t_print (&a->r[i], handle);

  return handle;
}

static inline void *
vl_api_macip_acl_details_t_print (vl_api_macip_acl_details_t * a,
				  void *handle)
{
  u8 *s = 0;
  int i;
  u32 acl_index = clib_net_to_host_u32 (a->acl_index);
  u32 count = clib_net_to_host_u32 (a->count);
  if (count > 0x100000)
    {
      s = format (s, "WARN: macip_acl_defails count endianness wrong? Fixup to avoid long loop.\n");
      count = a->count;
    }

  s = format (s, "macip_acl_details index %d count %d ",
	      acl_index, count);

  if (a->tag[0])
    s = format (s, "tag %s ", a->tag);

  s = format(s, "\n");
  PRINT_S;

  for (i = 0; i < count; i++)
    vl_api_macip_acl_rule_t_print (&a->r[i], handle);

  return handle;
}

static inline void *
vl_api_macip_acl_add_t_print (vl_api_macip_acl_add_t * a, void *handle)
{
  u8 *s = 0;
  int i;
  u32 count = clib_net_to_host_u32 (a->count);
  if (count > 0x100000)
    {
      s = format (s, "WARN: macip_acl_add count endianness wrong? Fixup to avoid long loop.\n");
      count = a->count;
    }

  s = format (s, "SCRIPT: macip_acl_add ");
  if (a->tag[0])
    s = format (s, "tag %s ", a->tag);

  s = format (s, "count %d \\\n", count);

  PRINT_S;

  for (i = 0; i < count; i++)
    vl_api_macip_acl_rule_t_print (&a->r[i], handle);

  s = format (0, "\n");
  PRINT_S;

  return handle;
}

static inline void *
vl_api_macip_acl_add_replace_t_print (vl_api_macip_acl_add_replace_t * a, void *handle)
{
  u8 *s = 0;
  int i;
  u32 acl_index = clib_net_to_host_u32 (a->acl_index);
  u32 count = clib_net_to_host_u32 (a->count);
  if (count > 0x100000)
    {
      s = format (s, "WARN: macip_acl_add_replace count endianness wrong? Fixup to avoid long loop.\n");
      count = a->count;
    }

  s = format (s, "SCRIPT: macip_acl_add_replace %d count %d ",
        acl_index, count);
  if (a->tag[0])
    s = format (s, "tag %s ", a->tag);

  s = format (s, "count %d \\\n", count);

  PRINT_S;

  for (i = 0; i < count; i++)
    vl_api_macip_acl_rule_t_print (&a->r[i], handle);

  s = format (0, "\n");
  PRINT_S;

  return handle;
}

static inline void *
vl_api_acl_interface_set_acl_list_t_print (vl_api_acl_interface_set_acl_list_t
					   * a, void *handle)
{
  u8 *s;
  int i;

  s = format
    (0, "SCRIPT: acl_interface_set_acl_list sw_if_index %d count %d\n",
     clib_net_to_host_u32 (a->sw_if_index), (u32) a->count);

  s = format (s, "    input ");

  for (i = 0; i < a->count; i++)
    {
      if (i == a->n_input)
        s = format (s, "output ");
      s = format (s, "%d ", clib_net_to_host_u32 (a->acls[i]));
    }

  PRINT_S;
  return handle;
}

static inline void *
vl_api_acl_interface_add_del_t_print (vl_api_acl_interface_add_del_t * a,
				      void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: acl_interface_add_del sw_if_index %d acl %d ",
	      clib_net_to_host_u32 (a->sw_if_index),
	      clib_net_to_host_u32 (a->acl_index));
  s = format (s, "%s %s",
	      a->is_input ? "input" : "output", a->is_add ? "add" : "del");

  PRINT_S;
  return handle;
}

static inline void *vl_api_macip_acl_interface_add_del_t_print
  (vl_api_macip_acl_interface_add_del_t * a, void *handle)
{
  u8 *s;

  s = format
    (0,
     "SCRIPT: macip_acl_interface_add_del sw_if_index %d acl_index %d ",
     clib_net_to_host_u32 (a->sw_if_index),
     clib_net_to_host_u32 (a->acl_index));
  s = format (s, "%s", a->is_add ? "add" : "del");

  PRINT_S;
  return handle;
}


static inline void *
vl_api_macip_acl_del_t_print (vl_api_macip_acl_del_t * a, void *handle)
{
  u8 *s;

  s = format (0, "SCRIPT: macip_acl_del %d ",
	      clib_host_to_net_u32 (a->acl_index));

  PRINT_S;
  return handle;
}


#endif /* included_manual_fns_h */
