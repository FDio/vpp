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

#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <acl/acl.h>
#include <acl/l2sess.h>

#include <vnet/l2/l2_classify.h>
#include <vnet/classify/input_acl.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

/* define message IDs */
#include <acl/acl_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <acl/acl_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <acl/acl_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <acl/acl_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <acl/acl_all_api_h.h>
#undef vl_api_version

#include "node_in.h"
#include "node_out.h"

acl_main_t acl_main;

/*
 * A handy macro to set up a message reply.
 * Assumes that the following variables are available:
 * mp - pointer to request message
 * rmp - pointer to reply message type
 * rv - return value
 */

#define REPLY_MACRO(t)                                          \
do {                                                            \
    unix_shared_memory_queue_t * q =                            \
    vl_api_client_index_to_input_queue (mp->client_index);      \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+sm->msg_id_base);               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
                                                                \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define REPLY_MACRO2(t, body)                                   \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp));                     \
    rmp->_vl_msg_id = ntohs((t)+am->msg_id_base);                               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);

#define REPLY_MACRO3(t, n, body)                                \
do {                                                            \
    unix_shared_memory_queue_t * q;                             \
    rv = vl_msg_api_pd_handler (mp, rv);                        \
    q = vl_api_client_index_to_input_queue (mp->client_index);  \
    if (!q)                                                     \
        return;                                                 \
                                                                \
    rmp = vl_msg_api_alloc (sizeof (*rmp) + n);                 \
    rmp->_vl_msg_id = ntohs((t)+am->msg_id_base);                               \
    rmp->context = mp->context;                                 \
    rmp->retval = ntohl(rv);                                    \
    do {body;} while (0);                                       \
    vl_msg_api_send_shmem (q, (u8 *)&rmp);                      \
} while(0);


/* List of message types that this plugin understands */

#define foreach_acl_plugin_api_msg		\
_(ACL_PLUGIN_GET_VERSION, acl_plugin_get_version) \
_(ACL_ADD_REPLACE, acl_add_replace)				\
_(ACL_DEL, acl_del)				\
_(ACL_INTERFACE_ADD_DEL, acl_interface_add_del)	\
_(ACL_INTERFACE_SET_ACL_LIST, acl_interface_set_acl_list)	\
_(ACL_DUMP, acl_dump)  \
_(ACL_INTERFACE_LIST_DUMP, acl_interface_list_dump) \
_(MACIP_ACL_ADD, macip_acl_add) \
_(MACIP_ACL_DEL, macip_acl_del) \
_(MACIP_ACL_INTERFACE_ADD_DEL, macip_acl_interface_add_del) \
_(MACIP_ACL_DUMP, macip_acl_dump) \
_(MACIP_ACL_INTERFACE_GET, macip_acl_interface_get)

/*
 * This routine exists to convince the vlib plugin framework that
 * we haven't accidentally copied a random .dll into the plugin directory.
 *
 * Also collects global variable pointers passed from the vpp engine
 */

clib_error_t *
vlib_plugin_register (vlib_main_t * vm, vnet_plugin_handoff_t * h,
		      int from_early_init)
{
  acl_main_t *am = &acl_main;
  clib_error_t *error = 0;

  am->vlib_main = vm;
  am->vnet_main = h->vnet_main;
  am->ethernet_main = h->ethernet_main;

  l2sess_vlib_plugin_register(vm, h, from_early_init);

  return error;
}


static void
vl_api_acl_plugin_get_version_t_handler (vl_api_acl_plugin_get_version_t * mp)
{
  acl_main_t *am = &acl_main;
  vl_api_acl_plugin_get_version_reply_t *rmp;
  int msg_size = sizeof (*rmp);
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  rmp = vl_msg_api_alloc (msg_size);
  memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_ACL_PLUGIN_GET_VERSION_REPLY + am->msg_id_base);
  rmp->context = mp->context;
  rmp->major = htonl (ACL_PLUGIN_VERSION_MAJOR);
  rmp->minor = htonl (ACL_PLUGIN_VERSION_MINOR);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}


static int
acl_add_list (u32 count, vl_api_acl_rule_t rules[],
	      u32 * acl_list_index, u8 * tag)
{
  acl_main_t *am = &acl_main;
  acl_list_t *a;
  acl_rule_t *r;
  acl_rule_t *acl_new_rules;
  int i;

  if (*acl_list_index != ~0)
    {
      /* They supplied some number, let's see if this ACL exists */
      if (pool_is_free_index (am->acls, *acl_list_index))
	{
	  /* tried to replace a non-existent ACL, no point doing anything */
	  return -1;
	}
    }

  /* Create and populate the rules */
  acl_new_rules = clib_mem_alloc_aligned (sizeof (acl_rule_t) * count,
					  CLIB_CACHE_LINE_BYTES);
  if (!acl_new_rules)
    {
      /* Could not allocate rules. New or existing ACL - bail out regardless */
      return -1;
    }

  for (i = 0; i < count; i++)
    {
      r = &acl_new_rules[i];
      r->is_permit = rules[i].is_permit;
      r->is_ipv6 = rules[i].is_ipv6;
      if (r->is_ipv6)
        {
          memcpy (&r->src, rules[i].src_ip_addr, sizeof (r->src));
          memcpy (&r->dst, rules[i].dst_ip_addr, sizeof (r->dst));
        }
      else
        {
          memcpy (&r->src.ip4, rules[i].src_ip_addr, sizeof (r->src.ip4));
          memcpy (&r->dst.ip4, rules[i].dst_ip_addr, sizeof (r->dst.ip4));
        }
      r->src_prefixlen = rules[i].src_ip_prefix_len;
      r->dst_prefixlen = rules[i].dst_ip_prefix_len;
      r->proto = rules[i].proto;
      r->src_port_or_type_first = rules[i].srcport_or_icmptype_first;
      r->src_port_or_type_last = rules[i].srcport_or_icmptype_last;
      r->dst_port_or_code_first = rules[i].dstport_or_icmpcode_first;
      r->dst_port_or_code_last = rules[i].dstport_or_icmpcode_last;
      r->tcp_flags_value = rules[i].tcp_flags_value;
      r->tcp_flags_mask = rules[i].tcp_flags_mask;
    }

  if (~0 == *acl_list_index)
    {
      /* Get ACL index */
      pool_get_aligned (am->acls, a, CLIB_CACHE_LINE_BYTES);
      memset (a, 0, sizeof (*a));
      /* Will return the newly allocated ACL index */
      *acl_list_index = a - am->acls;
    }
  else
    {
      a = am->acls + *acl_list_index;
      /* Get rid of the old rules */
      clib_mem_free (a->rules);
    }
  a->rules = acl_new_rules;
  a->count = count;
  memcpy (a->tag, tag, sizeof (a->tag));

  return 0;
}

static int
acl_del_list (u32 acl_list_index)
{
  acl_main_t *am = &acl_main;
  acl_list_t *a;
  int i, ii;
  if (pool_is_free_index (am->acls, acl_list_index))
    {
      return -1;
    }

  /* delete any references to the ACL */
  for (i = 0; i < vec_len (am->output_acl_vec_by_sw_if_index); i++)
    {
      for (ii = 0; ii < vec_len (am->output_acl_vec_by_sw_if_index[i]);
	   /* see body */ )
	{
	  if (acl_list_index == am->output_acl_vec_by_sw_if_index[i][ii])
	    {
	      vec_del1 (am->output_acl_vec_by_sw_if_index[i], ii);
	    }
	  else
	    {
	      ii++;
	    }
	}
    }
  for (i = 0; i < vec_len (am->input_acl_vec_by_sw_if_index); i++)
    {
      for (ii = 0; ii < vec_len (am->input_acl_vec_by_sw_if_index[i]);
	   /* see body */ )
	{
	  if (acl_list_index == am->input_acl_vec_by_sw_if_index[i][ii])
	    {
	      vec_del1 (am->input_acl_vec_by_sw_if_index[i], ii);
	    }
	  else
	    {
	      ii++;
	    }
	}
    }

  /* now we can delete the ACL itself */
  a = &am->acls[acl_list_index];
  if (a->rules)
    {
      clib_mem_free (a->rules);
    }
  pool_put (am->acls, a);
  return 0;
}

/* Some aids in ASCII graphing the content */
#define XX "\377"
#define __ "\000"
#define _(x)
#define v

u8 ip4_5tuple_mask[] =
_("             dmac               smac            etype ")
_(ether) __ __ __ __ __ __ v __ __ __ __ __ __ v __ __ v
  _("        v ihl totlen   ")
  _(0x0000)
  __ __ __ __
  _("        ident fl+fo    ")
  _(0x0004)
  __ __ __ __
  _("       ttl pr checksum ")
  _(0x0008)
  __ XX __ __
  _("        src address    ")
  _(0x000C)
  XX XX XX XX
  _("        dst address    ")
  _(0x0010)
  XX XX XX XX
  _("L4 T/U  sport dport    ")
  _(tcpudp)
  XX XX XX XX
  _(padpad)
  __ __ __ __
  _(padpad)
  __ __ __ __
  _(padeth)
  __ __;

     u8 ip6_5tuple_mask[] =
       _("             dmac               smac            etype ")
  _(ether) __ __ __ __ __ __ v __ __ __ __ __ __ v __ __ v
  _("        v  tc + flow ")
  _(0x0000) __ __ __ __
  _("        plen  nh hl  ")
  _(0x0004) __ __ XX __
  _("        src address  ")
  _(0x0008) XX XX XX XX
  _(0x000C) XX XX XX XX
  _(0x0010) XX XX XX XX
  _(0x0014) XX XX XX XX
  _("        dst address  ")
  _(0x0018) XX XX XX XX
  _(0x001C) XX XX XX XX
  _(0x0020) XX XX XX XX
  _(0x0024) XX XX XX XX
  _("L4T/U  sport dport   ")
  _(tcpudp) XX XX XX XX _(padpad) __ __ __ __ _(padeth) __ __;

#undef XX
#undef __
#undef _
#undef v

     static int count_skip (u8 * p, u32 size)
{
  u64 *p64 = (u64 *) p;
  /* Be tolerant to null pointer */
  if (0 == p)
    return 0;

  while ((0ULL == *p64) && ((u8 *) p64 - p) < size)
    {
      p64++;
    }
  return (p64 - (u64 *) p) / 2;
}

static int
acl_classify_add_del_table_big (vnet_classify_main_t * cm, u8 * mask,
			    u32 mask_len, u32 next_table_index,
			    u32 miss_next_index, u32 * table_index,
			    int is_add)
{
  u32 nbuckets = 65536;
  u32 memory_size = 2 << 30;
  u32 skip = count_skip (mask, mask_len);
  u32 match = (mask_len / 16) - skip;
  u8 *skip_mask_ptr = mask + 16 * skip;
  u32 current_data_flag = 0;
  int current_data_offset = 0;

  if (0 == match)
    match = 1;

  return vnet_classify_add_del_table (cm, skip_mask_ptr, nbuckets,
				      memory_size, skip, match,
				      next_table_index, miss_next_index,
				      table_index, current_data_flag,
				      current_data_offset, is_add,
				      1 /* delete_chain */);
}

static int
acl_classify_add_del_table_small (vnet_classify_main_t * cm, u8 * mask,
			    u32 mask_len, u32 next_table_index,
			    u32 miss_next_index, u32 * table_index,
			    int is_add)
{
  u32 nbuckets = 32;
  u32 memory_size = 2 << 20;
  u32 skip = count_skip (mask, mask_len);
  u32 match = (mask_len / 16) - skip;
  u8 *skip_mask_ptr = mask + 16 * skip;
  u32 current_data_flag = 0;
  int current_data_offset = 0;

  if (0 == match)
    match = 1;

  return vnet_classify_add_del_table (cm, skip_mask_ptr, nbuckets,
				      memory_size, skip, match,
				      next_table_index, miss_next_index,
				      table_index, current_data_flag,
				      current_data_offset, is_add,
				      1 /* delete_chain */);
}


static int
acl_unhook_l2_input_classify (acl_main_t * am, u32 sw_if_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;

  vec_validate_init_empty (am->acl_ip4_input_classify_table_by_sw_if_index,
			   sw_if_index, ~0);
  vec_validate_init_empty (am->acl_ip6_input_classify_table_by_sw_if_index,
			   sw_if_index, ~0);

  vnet_l2_input_classify_enable_disable (sw_if_index, 0);

  if (am->acl_ip4_input_classify_table_by_sw_if_index[sw_if_index] != ~0)
    {
      ip4_table_index =
	am->acl_ip4_input_classify_table_by_sw_if_index[sw_if_index];
      am->acl_ip4_input_classify_table_by_sw_if_index[sw_if_index] = ~0;
      acl_classify_add_del_table_big (cm, ip4_5tuple_mask,
				  sizeof (ip4_5tuple_mask) - 1, ~0,
				  am->l2_input_classify_next_acl,
				  &ip4_table_index, 0);
    }
  if (am->acl_ip6_input_classify_table_by_sw_if_index[sw_if_index] != ~0)
    {
      ip6_table_index =
	am->acl_ip6_input_classify_table_by_sw_if_index[sw_if_index];
      am->acl_ip6_input_classify_table_by_sw_if_index[sw_if_index] = ~0;
      acl_classify_add_del_table_big (cm, ip6_5tuple_mask,
				  sizeof (ip6_5tuple_mask) - 1, ~0,
				  am->l2_input_classify_next_acl,
				  &ip6_table_index, 0);
    }

  return 0;
}

static int
acl_unhook_l2_output_classify (acl_main_t * am, u32 sw_if_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;

  vec_validate_init_empty (am->acl_ip4_output_classify_table_by_sw_if_index,
			   sw_if_index, ~0);
  vec_validate_init_empty (am->acl_ip6_output_classify_table_by_sw_if_index,
			   sw_if_index, ~0);

  vnet_l2_output_classify_enable_disable (sw_if_index, 0);

  if (am->acl_ip4_output_classify_table_by_sw_if_index[sw_if_index] != ~0)
    {
      ip4_table_index =
	am->acl_ip4_output_classify_table_by_sw_if_index[sw_if_index];
      am->acl_ip4_output_classify_table_by_sw_if_index[sw_if_index] = ~0;
      acl_classify_add_del_table_big (cm, ip4_5tuple_mask,
				  sizeof (ip4_5tuple_mask) - 1, ~0,
				  am->l2_output_classify_next_acl,
				  &ip4_table_index, 0);
    }
  if (am->acl_ip6_output_classify_table_by_sw_if_index[sw_if_index] != ~0)
    {
      ip6_table_index =
	am->acl_ip6_output_classify_table_by_sw_if_index[sw_if_index];
      am->acl_ip6_output_classify_table_by_sw_if_index[sw_if_index] = ~0;
      acl_classify_add_del_table_big (cm, ip6_5tuple_mask,
				  sizeof (ip6_5tuple_mask) - 1, ~0,
				  am->l2_output_classify_next_acl,
				  &ip6_table_index, 0);
    }

  return 0;
}

static int
acl_hook_l2_input_classify (acl_main_t * am, u32 sw_if_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  int rv;

  /* in case there were previous tables attached */
  acl_unhook_l2_input_classify (am, sw_if_index);
  rv =
    acl_classify_add_del_table_big (cm, ip4_5tuple_mask,
				sizeof (ip4_5tuple_mask) - 1, ~0,
				am->l2_input_classify_next_acl,
				&ip4_table_index, 1);
  if (rv)
    return rv;
  rv =
    acl_classify_add_del_table_big (cm, ip6_5tuple_mask,
				sizeof (ip6_5tuple_mask) - 1, ~0,
				am->l2_input_classify_next_acl,
				&ip6_table_index, 1);
  if (rv)
    {
      acl_classify_add_del_table_big (cm, ip4_5tuple_mask,
				  sizeof (ip4_5tuple_mask) - 1, ~0,
				  am->l2_input_classify_next_acl,
				  &ip4_table_index, 0);
      return rv;
    }
  rv =
    vnet_l2_input_classify_set_tables (sw_if_index, ip4_table_index,
				       ip6_table_index, ~0);
  clib_warning
    ("ACL enabling on interface sw_if_index %d, setting tables to the following: ip4: %d ip6: %d\n",
     sw_if_index, ip4_table_index, ip6_table_index);
  if (rv)
    {
      acl_classify_add_del_table_big (cm, ip6_5tuple_mask,
				  sizeof (ip6_5tuple_mask) - 1, ~0,
				  am->l2_input_classify_next_acl,
				  &ip6_table_index, 0);
      acl_classify_add_del_table_big (cm, ip4_5tuple_mask,
				  sizeof (ip4_5tuple_mask) - 1, ~0,
				  am->l2_input_classify_next_acl,
				  &ip4_table_index, 0);
      return rv;
    }

  am->acl_ip4_input_classify_table_by_sw_if_index[sw_if_index] =
    ip4_table_index;
  am->acl_ip6_input_classify_table_by_sw_if_index[sw_if_index] =
    ip6_table_index;

  vnet_l2_input_classify_enable_disable (sw_if_index, 1);
  return rv;
}

static int
acl_hook_l2_output_classify (acl_main_t * am, u32 sw_if_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  int rv;

  /* in case there were previous tables attached */
  acl_unhook_l2_output_classify (am, sw_if_index);
  rv =
    acl_classify_add_del_table_big (cm, ip4_5tuple_mask,
				sizeof (ip4_5tuple_mask) - 1, ~0,
				am->l2_output_classify_next_acl,
				&ip4_table_index, 1);
  if (rv)
    return rv;
  rv =
    acl_classify_add_del_table_big (cm, ip6_5tuple_mask,
				sizeof (ip6_5tuple_mask) - 1, ~0,
				am->l2_output_classify_next_acl,
				&ip6_table_index, 1);
  if (rv)
    {
      acl_classify_add_del_table_big (cm, ip4_5tuple_mask,
				  sizeof (ip4_5tuple_mask) - 1, ~0,
				  am->l2_output_classify_next_acl,
				  &ip4_table_index, 0);
      return rv;
    }
  rv =
    vnet_l2_output_classify_set_tables (sw_if_index, ip4_table_index,
					ip6_table_index, ~0);
  clib_warning
    ("ACL enabling on interface sw_if_index %d, setting tables to the following: ip4: %d ip6: %d\n",
     sw_if_index, ip4_table_index, ip6_table_index);
  if (rv)
    {
      acl_classify_add_del_table_big (cm, ip6_5tuple_mask,
				  sizeof (ip6_5tuple_mask) - 1, ~0,
				  am->l2_output_classify_next_acl,
				  &ip6_table_index, 0);
      acl_classify_add_del_table_big (cm, ip4_5tuple_mask,
				  sizeof (ip4_5tuple_mask) - 1, ~0,
				  am->l2_output_classify_next_acl,
				  &ip4_table_index, 0);
      return rv;
    }

  am->acl_ip4_output_classify_table_by_sw_if_index[sw_if_index] =
    ip4_table_index;
  am->acl_ip6_output_classify_table_by_sw_if_index[sw_if_index] =
    ip6_table_index;

  vnet_l2_output_classify_enable_disable (sw_if_index, 1);
  return rv;
}


int
acl_interface_in_enable_disable (acl_main_t * am, u32 sw_if_index,
				 int enable_disable)
{
  int rv;

  /* Utterly wrong? */
  if (pool_is_free_index (am->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (enable_disable)
    {
      rv = acl_hook_l2_input_classify (am, sw_if_index);
    }
  else
    {
      rv = acl_unhook_l2_input_classify (am, sw_if_index);
    }

  return rv;
}

int
acl_interface_out_enable_disable (acl_main_t * am, u32 sw_if_index,
				  int enable_disable)
{
  int rv;

  /* Utterly wrong? */
  if (pool_is_free_index (am->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (enable_disable)
    {
      rv = acl_hook_l2_output_classify (am, sw_if_index);
    }
  else
    {
      rv = acl_unhook_l2_output_classify (am, sw_if_index);
    }

  return rv;
}


static int
acl_interface_add_inout_acl (u32 sw_if_index, u8 is_input, u32 acl_list_index)
{
  acl_main_t *am = &acl_main;
  if (is_input)
    {
      vec_validate (am->input_acl_vec_by_sw_if_index, sw_if_index);
      vec_add (am->input_acl_vec_by_sw_if_index[sw_if_index], &acl_list_index,
	       1);
      acl_interface_in_enable_disable (am, sw_if_index, 1);
    }
  else
    {
      vec_validate (am->output_acl_vec_by_sw_if_index, sw_if_index);
      vec_add (am->output_acl_vec_by_sw_if_index[sw_if_index],
	       &acl_list_index, 1);
      acl_interface_out_enable_disable (am, sw_if_index, 1);
    }
  return 0;
}

static int
acl_interface_del_inout_acl (u32 sw_if_index, u8 is_input, u32 acl_list_index)
{
  acl_main_t *am = &acl_main;
  int i;
  int rv = -1;
  if (is_input)
    {
      vec_validate (am->input_acl_vec_by_sw_if_index, sw_if_index);
      for (i = 0; i < vec_len (am->input_acl_vec_by_sw_if_index[sw_if_index]);
	   i++)
	{
	  if (acl_list_index ==
	      am->input_acl_vec_by_sw_if_index[sw_if_index][i])
	    {
	      vec_del1 (am->input_acl_vec_by_sw_if_index[sw_if_index], i);
	      rv = 0;
	      break;
	    }
	}
      if (0 == vec_len (am->input_acl_vec_by_sw_if_index[sw_if_index]))
	{
	  acl_interface_in_enable_disable (am, sw_if_index, 0);
	}
    }
  else
    {
      vec_validate (am->output_acl_vec_by_sw_if_index, sw_if_index);
      for (i = 0;
	   i < vec_len (am->output_acl_vec_by_sw_if_index[sw_if_index]); i++)
	{
	  if (acl_list_index ==
	      am->output_acl_vec_by_sw_if_index[sw_if_index][i])
	    {
	      vec_del1 (am->output_acl_vec_by_sw_if_index[sw_if_index], i);
	      rv = 0;
	      break;
	    }
	}
      if (0 == vec_len (am->output_acl_vec_by_sw_if_index[sw_if_index]))
	{
	  acl_interface_out_enable_disable (am, sw_if_index, 0);
	}
    }
  return rv;
}

static void
acl_interface_reset_inout_acls (u32 sw_if_index, u8 is_input)
{
  acl_main_t *am = &acl_main;
  if (is_input)
    {
      acl_interface_in_enable_disable (am, sw_if_index, 0);
      vec_validate (am->input_acl_vec_by_sw_if_index, sw_if_index);
      vec_reset_length (am->input_acl_vec_by_sw_if_index[sw_if_index]);
    }
  else
    {
      acl_interface_out_enable_disable (am, sw_if_index, 0);
      vec_validate (am->output_acl_vec_by_sw_if_index, sw_if_index);
      vec_reset_length (am->output_acl_vec_by_sw_if_index[sw_if_index]);
    }
}

static int
acl_interface_add_del_inout_acl (u32 sw_if_index, u8 is_add, u8 is_input,
				 u32 acl_list_index)
{
  int rv = -1;
  if (is_add)
    {
      rv =
	acl_interface_add_inout_acl (sw_if_index, is_input, acl_list_index);
    }
  else
    {
      rv =
	acl_interface_del_inout_acl (sw_if_index, is_input, acl_list_index);
    }
  return rv;
}


static void *
get_ptr_to_offset (vlib_buffer_t * b0, int offset)
{
  u8 *p = vlib_buffer_get_current (b0) + offset;
  return p;
}

static u8
acl_get_l4_proto (vlib_buffer_t * b0, int node_is_ip6)
{
  u8 proto;
  int proto_offset;
  if (node_is_ip6)
    {
      proto_offset = 20;
    }
  else
    {
      proto_offset = 23;
    }
  proto = *((u8 *) vlib_buffer_get_current (b0) + proto_offset);
  return proto;
}

static int
acl_match_addr (ip46_address_t * addr1, ip46_address_t * addr2, int prefixlen,
		int is_ip6)
{
  if (prefixlen == 0)
    {
      /* match any always succeeds */
      return 1;
    }
  if (is_ip6)
    {
      if (memcmp (addr1, addr2, prefixlen / 8))
	{
	  /* If the starting full bytes do not match, no point in bittwidling the thumbs further */
	  return 0;
	}
      if (prefixlen % 8)
	{
	  u8 b1 = *((u8 *) addr1 + 1 + prefixlen / 8);
	  u8 b2 = *((u8 *) addr2 + 1 + prefixlen / 8);
	  u8 mask0 = (0xff - ((1 << (8 - (prefixlen % 8))) - 1));
	  return (b1 & mask0) == b2;
	}
      else
	{
	  /* The prefix fits into integer number of bytes, so nothing left to do */
	  return 1;
	}
    }
  else
    {
      uint32_t a1 = ntohl (addr1->ip4.as_u32);
      uint32_t a2 = ntohl (addr2->ip4.as_u32);
      uint32_t mask0 = 0xffffffff - ((1 << (32 - prefixlen)) - 1);
      return (a1 & mask0) == a2;
    }
}

static int
acl_match_port (u16 port, u16 port_first, u16 port_last, int is_ip6)
{
  return ((port >= port_first) && (port <= port_last));
}

static int
acl_packet_match (acl_main_t * am, u32 acl_index, vlib_buffer_t * b0,
		  u8 * r_action, int *r_is_ip6, u32 * r_acl_match_p,
		  u32 * r_rule_match_p, u32 * trace_bitmap)
{
  ethernet_header_t *h0;
  u16 type0;

  ip46_address_t src, dst;
  int is_ip6;
  int is_ip4;
  u8 proto;
  u16 src_port;
  u16 dst_port;
  u8 tcp_flags = 0;
  int i;
  acl_list_t *a;
  acl_rule_t *r;

  h0 = vlib_buffer_get_current (b0);
  type0 = clib_net_to_host_u16 (h0->type);
  is_ip4 = (type0 == ETHERNET_TYPE_IP4);
  is_ip6 = (type0 == ETHERNET_TYPE_IP6);

  if (!(is_ip4 || is_ip6))
    {
      return 0;
    }
  /* The bunch of hardcoded offsets here is intentional to get rid of them
     ASAP, when getting to a faster matching code */
  if (is_ip4)
    {
      clib_memcpy (&src.ip4, get_ptr_to_offset (b0, 26), 4);
      clib_memcpy (&dst.ip4, get_ptr_to_offset (b0, 30), 4);
      proto = acl_get_l4_proto (b0, 0);
      if (1 == proto)
	{
	  *trace_bitmap |= 0x00000001;
	  /* type */
	  src_port = *(u8 *) get_ptr_to_offset (b0, 34);
	  /* code */
	  dst_port = *(u8 *) get_ptr_to_offset (b0, 35);
	}
      else
	{
	  /* assume TCP/UDP */
	  src_port = (*(u16 *) get_ptr_to_offset (b0, 34));
	  dst_port = (*(u16 *) get_ptr_to_offset (b0, 36));
	  /* UDP gets ability to check on an oddball data byte as a bonus */
	  tcp_flags = *(u8 *) get_ptr_to_offset (b0, 14 + 20 + 13);
	}
    }
  else /* is_ipv6 implicitly */
    {
      clib_memcpy (&src, get_ptr_to_offset (b0, 22), 16);
      clib_memcpy (&dst, get_ptr_to_offset (b0, 38), 16);
      proto = acl_get_l4_proto (b0, 1);
      if (58 == proto)
	{
	  *trace_bitmap |= 0x00000002;
	  /* type */
	  src_port = *(u8 *) get_ptr_to_offset (b0, 54);
	  /* code */
	  dst_port = *(u8 *) get_ptr_to_offset (b0, 55);
	}
      else
	{
	  /* assume TCP/UDP */
	  src_port = (*(u16 *) get_ptr_to_offset (b0, 54));
	  dst_port = (*(u16 *) get_ptr_to_offset (b0, 56));
	  tcp_flags = *(u8 *) get_ptr_to_offset (b0, 14 + 40 + 13);
	}
    }
  if (pool_is_free_index (am->acls, acl_index))
    {
      if (r_acl_match_p)
	*r_acl_match_p = acl_index;
      if (r_rule_match_p)
	*r_rule_match_p = -1;
      /* the ACL does not exist but is used for policy. Block traffic. */
      return 0;
    }
  a = am->acls + acl_index;
  for (i = 0; i < a->count; i++)
    {
      r = a->rules + i;
      if (is_ip6 != r->is_ipv6)
	{
	  continue;
	}
      if (!acl_match_addr (&dst, &r->dst, r->dst_prefixlen, is_ip6))
	continue;
      if (!acl_match_addr (&src, &r->src, r->src_prefixlen, is_ip6))
	continue;
      if (r->proto)
	{
	  if (proto != r->proto)
	    continue;
	  if (!acl_match_port
	      (src_port, r->src_port_or_type_first, r->src_port_or_type_last,
	       is_ip6))
	    continue;
	  if (!acl_match_port
	      (dst_port, r->dst_port_or_code_first, r->dst_port_or_code_last,
	       is_ip6))
	    continue;
	  /* No need for check of proto == TCP, since in other rules both fields should be zero, so this match will succeed */
	  if ((tcp_flags & r->tcp_flags_mask) != r->tcp_flags_value)
	    continue;
	}
      /* everything matches! */
      *r_action = r->is_permit;
      *r_is_ip6 = is_ip6;
      if (r_acl_match_p)
	*r_acl_match_p = acl_index;
      if (r_rule_match_p)
	*r_rule_match_p = i;
      return 1;
    }
  return 0;
}

void
input_acl_packet_match (u32 sw_if_index, vlib_buffer_t * b0, u32 * nextp,
			u32 * acl_match_p, u32 * rule_match_p,
			u32 * trace_bitmap)
{
  acl_main_t *am = &acl_main;
  uint8_t action = 0;
  int is_ip6 = 0;
  int i;
  vec_validate (am->input_acl_vec_by_sw_if_index, sw_if_index);
  for (i = 0; i < vec_len (am->input_acl_vec_by_sw_if_index[sw_if_index]);
       i++)
    {
      if (acl_packet_match
	  (am, am->input_acl_vec_by_sw_if_index[sw_if_index][i], b0, &action,
	   &is_ip6, acl_match_p, rule_match_p, trace_bitmap))
	{
	  if (is_ip6)
	    {
	      *nextp = am->acl_in_ip6_match_next[action];
	    }
	  else
	    {
	      *nextp = am->acl_in_ip4_match_next[action];
	    }
	  return;
	}
    }
  if (vec_len (am->input_acl_vec_by_sw_if_index[sw_if_index]) > 0)
    {
      /* If there are ACLs and none matched, deny by default */
      *nextp = 0;
    }

}

void
output_acl_packet_match (u32 sw_if_index, vlib_buffer_t * b0, u32 * nextp,
			 u32 * acl_match_p, u32 * rule_match_p,
			 u32 * trace_bitmap)
{
  acl_main_t *am = &acl_main;
  uint8_t action = 0;
  int is_ip6 = 0;
  int i;
  vec_validate (am->output_acl_vec_by_sw_if_index, sw_if_index);
  for (i = 0; i < vec_len (am->output_acl_vec_by_sw_if_index[sw_if_index]);
       i++)
    {
      if (acl_packet_match
	  (am, am->output_acl_vec_by_sw_if_index[sw_if_index][i], b0, &action,
	   &is_ip6, acl_match_p, rule_match_p, trace_bitmap))
	{
	  if (is_ip6)
	    {
	      *nextp = am->acl_out_ip6_match_next[action];
	    }
	  else
	    {
	      *nextp = am->acl_out_ip4_match_next[action];
	    }
	  return;
	}
    }
  if (vec_len (am->output_acl_vec_by_sw_if_index[sw_if_index]) > 0)
    {
      /* If there are ACLs and none matched, deny by default */
      *nextp = 0;
    }
}

typedef struct
{
  u8 is_ipv6;
  u8 mac_mask[6];
  u8 prefix_len;
  u32 count;
  u32 table_index;
} macip_match_type_t;

static u32
macip_find_match_type (macip_match_type_t * mv, u8 * mac_mask, u8 prefix_len,
		       u8 is_ipv6)
{
  u32 i;
  if (mv)
    {
      for (i = 0; i < vec_len (mv); i++)
	{
	  if ((mv[i].prefix_len == prefix_len) && (mv[i].is_ipv6 == is_ipv6)
	      && (0 == memcmp (mv[i].mac_mask, mac_mask, 6)))
	    {
	      return i;
	    }
	}
    }
  return ~0;
}


/* Get metric used to sort match types.
   The more specific and the more often seen - the bigger the metric */
static int
match_type_metric (macip_match_type_t * m)
{
  /* FIXME: count the ones in the MAC mask as well, check how well this heuristic works in real life */
  return m->prefix_len + m->is_ipv6 + 10 * m->count;
}

static int
match_type_compare (macip_match_type_t * m1, macip_match_type_t * m2)
{
  /* Ascending sort based on the metric values */
  return match_type_metric (m1) - match_type_metric (m2);
}

/* Get the offset of L3 source within ethernet packet */
static int
get_l3_src_offset(int is6)
{
  if(is6)
    return (sizeof(ethernet_header_t) + offsetof(ip6_header_t, src_address));
  else
    return (sizeof(ethernet_header_t) + offsetof(ip4_header_t, src_address));
}

static int
macip_create_classify_tables (acl_main_t * am, u32 macip_acl_index)
{
  macip_match_type_t *mvec = NULL;
  macip_match_type_t *mt;
  macip_acl_list_t *a = &am->macip_acls[macip_acl_index];
  int i;
  u32 match_type_index;
  u32 last_table;
  u8 mask[5 * 16];
  vnet_classify_main_t *cm = &vnet_classify_main;

  /* Count the number of different types of rules */
  for (i = 0; i < a->count; i++)
    {
      if (~0 ==
	  (match_type_index =
	   macip_find_match_type (mvec, a->rules[i].src_mac_mask,
				  a->rules[i].src_prefixlen,
				  a->rules[i].is_ipv6)))
	{
	  match_type_index = vec_len (mvec);
	  vec_validate (mvec, match_type_index);
	  memcpy (mvec[match_type_index].mac_mask,
		  a->rules[match_type_index].src_mac_mask, 6);
	  mvec[match_type_index].prefix_len = a->rules[i].src_prefixlen;
	  mvec[match_type_index].is_ipv6 = a->rules[i].is_ipv6;
	  mvec[match_type_index].table_index = ~0;
	}
      mvec[match_type_index].count++;
    }
  /* Put the most frequently used tables last in the list so we can create classifier tables in reverse order */
  vec_sort_with_function (mvec, match_type_compare);
  /* Create the classifier tables */
  last_table = ~0;
  vec_foreach (mt, mvec)
  {
    int mask_len;
    int is6 = mt->is_ipv6;
    int l3_src_offs = get_l3_src_offset(is6);
    memset (mask, 0, sizeof (mask));
    memcpy (&mask[6], mt->mac_mask, 6);
    for (i = 0; i < (mt->prefix_len / 8); i++)
      {
	mask[l3_src_offs + i] = 0xff;
      }
    if (mt->prefix_len % 8)
      {
	mask[l3_src_offs + (mt->prefix_len / 8)] =
	  0xff - ((1 << (8 - mt->prefix_len % 8)) - 1);
      }
    /*
     * Round-up the number of bytes needed to store the prefix,
     * and round up the number of vectors too
     */
    mask_len = ((l3_src_offs + ((mt->prefix_len+7) / 8) +
                (sizeof (u32x4)-1))/sizeof(u32x4)) * sizeof (u32x4);
    acl_classify_add_del_table_small (cm, mask, mask_len, last_table,
				(~0 == last_table) ? 0 : ~0, &mt->table_index,
				1);
    last_table = mt->table_index;
  }
  a->ip4_table_index = ~0;
  a->ip6_table_index = ~0;
  a->l2_table_index = last_table;

  /* Populate the classifier tables with rules from the MACIP ACL */
  for (i = 0; i < a->count; i++)
    {
      u32 action = 0;
      u32 metadata = 0;
      int is6 = a->rules[i].is_ipv6;
      int l3_src_offs = get_l3_src_offset(is6);
      memset (mask, 0, sizeof (mask));
      memcpy (&mask[6], a->rules[i].src_mac, 6);
      if (is6)
	{
	  memcpy (&mask[l3_src_offs], &a->rules[i].src_ip_addr.ip6, 16);
	}
      else
	{
	  memcpy (&mask[l3_src_offs], &a->rules[i].src_ip_addr.ip4, 4);
	}
      match_type_index =
	macip_find_match_type (mvec, a->rules[i].src_mac_mask,
			       a->rules[i].src_prefixlen,
			       a->rules[i].is_ipv6);
      /* add session to table mvec[match_type_index].table_index; */
      vnet_classify_add_del_session (cm, mvec[match_type_index].table_index,
				     mask, a->rules[i].is_permit ? ~0 : 0, i,
				     0, action, metadata, 1);
    }
  return 0;
}

static void
macip_destroy_classify_tables (acl_main_t * am, u32 macip_acl_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  macip_acl_list_t *a = &am->macip_acls[macip_acl_index];

  if (a->ip4_table_index != ~0)
    {
      acl_classify_add_del_table_small (cm, 0, ~0, ~0, ~0, &a->ip4_table_index, 0);
      a->ip4_table_index = ~0;
    }
  if (a->ip6_table_index != ~0)
    {
      acl_classify_add_del_table_small (cm, 0, ~0, ~0, ~0, &a->ip6_table_index, 0);
      a->ip6_table_index = ~0;
    }
  if (a->l2_table_index != ~0)
    {
      acl_classify_add_del_table_small (cm, 0, ~0, ~0, ~0, &a->l2_table_index, 0);
      a->l2_table_index = ~0;
    }
}

static int
macip_acl_add_list (u32 count, vl_api_macip_acl_rule_t rules[],
		    u32 * acl_list_index, u8 * tag)
{
  acl_main_t *am = &acl_main;
  macip_acl_list_t *a;
  macip_acl_rule_t *r;
  macip_acl_rule_t *acl_new_rules;
  int i;

  /* Create and populate the rules */
  acl_new_rules = clib_mem_alloc_aligned (sizeof (macip_acl_rule_t) * count,
					  CLIB_CACHE_LINE_BYTES);
  if (!acl_new_rules)
    {
      /* Could not allocate rules. New or existing ACL - bail out regardless */
      return -1;
    }

  for (i = 0; i < count; i++)
    {
      r = &acl_new_rules[i];
      r->is_permit = rules[i].is_permit;
      r->is_ipv6 = rules[i].is_ipv6;
      memcpy (&r->src_mac, rules[i].src_mac, 6);
      memcpy (&r->src_mac_mask, rules[i].src_mac_mask, 6);
      if(rules[i].is_ipv6)
        memcpy (&r->src_ip_addr.ip6, rules[i].src_ip_addr, 16);
      else
        memcpy (&r->src_ip_addr.ip4, rules[i].src_ip_addr, 4);
      r->src_prefixlen = rules[i].src_ip_prefix_len;
    }

  /* Get ACL index */
  pool_get_aligned (am->macip_acls, a, CLIB_CACHE_LINE_BYTES);
  memset (a, 0, sizeof (*a));
  /* Will return the newly allocated ACL index */
  *acl_list_index = a - am->macip_acls;

  a->rules = acl_new_rules;
  a->count = count;
  memcpy (a->tag, tag, sizeof (a->tag));

  /* Create and populate the classifer tables */
  macip_create_classify_tables (am, *acl_list_index);

  return 0;
}


/* No check for validity of sw_if_index - the callers were supposed to validate */

static int
macip_acl_interface_del_acl (acl_main_t * am, u32 sw_if_index)
{
  int rv;
  u32 macip_acl_index;
  macip_acl_list_t *a;
  vec_validate_init_empty (am->macip_acl_by_sw_if_index, sw_if_index, ~0);
  macip_acl_index = am->macip_acl_by_sw_if_index[sw_if_index];
  /* No point in deleting MACIP ACL which is not applied */
  if (~0 == macip_acl_index)
    return -1;
  a = &am->macip_acls[macip_acl_index];
  /* remove the classifier tables off the interface L2 ACL */
  rv =
    vnet_set_input_acl_intfc (am->vlib_main, sw_if_index, a->ip4_table_index,
			      a->ip6_table_index, a->l2_table_index, 0);
  /* Unset the MACIP ACL index */
  am->macip_acl_by_sw_if_index[sw_if_index] = ~0;
  return rv;
}

/* No check for validity of sw_if_index - the callers were supposed to validate */

static int
macip_acl_interface_add_acl (acl_main_t * am, u32 sw_if_index,
			     u32 macip_acl_index)
{
  macip_acl_list_t *a;
  int rv;
  if (pool_is_free_index (am->macip_acls, macip_acl_index))
    {
      return -1;
    }
  a = &am->macip_acls[macip_acl_index];
  vec_validate_init_empty (am->macip_acl_by_sw_if_index, sw_if_index, ~0);
  /* If there already a MACIP ACL applied, unapply it */
  if (~0 != am->macip_acl_by_sw_if_index[sw_if_index])
    macip_acl_interface_del_acl(am, sw_if_index);
  am->macip_acl_by_sw_if_index[sw_if_index] = macip_acl_index;
  /* Apply the classifier tables for L2 ACLs */
  rv =
    vnet_set_input_acl_intfc (am->vlib_main, sw_if_index, a->ip4_table_index,
			      a->ip6_table_index, a->l2_table_index, 1);
  return rv;
}

static int
macip_acl_del_list (u32 acl_list_index)
{
  acl_main_t *am = &acl_main;
  macip_acl_list_t *a;
  int i;
  if (pool_is_free_index (am->macip_acls, acl_list_index))
    {
      return -1;
    }

  /* delete any references to the ACL */
  for (i = 0; i < vec_len (am->macip_acl_by_sw_if_index); i++)
    {
      if (am->macip_acl_by_sw_if_index[i] == acl_list_index)
	{
	  macip_acl_interface_del_acl (am, i);
	}
    }

  /* Now that classifier tables are detached, clean them up */
  macip_destroy_classify_tables (am, acl_list_index);

  /* now we can delete the ACL itself */
  a = &am->macip_acls[acl_list_index];
  if (a->rules)
    {
      clib_mem_free (a->rules);
    }
  pool_put (am->macip_acls, a);
  return 0;
}


static int
macip_acl_interface_add_del_acl (u32 sw_if_index, u8 is_add,
				 u32 acl_list_index)
{
  acl_main_t *am = &acl_main;
  int rv = -1;
  if (is_add)
    {
      rv = macip_acl_interface_add_acl (am, sw_if_index, acl_list_index);
    }
  else
    {
      rv = macip_acl_interface_del_acl (am, sw_if_index);
    }
  return rv;
}

/* API message handler */
static void
vl_api_acl_add_replace_t_handler (vl_api_acl_add_replace_t * mp)
{
  vl_api_acl_add_replace_reply_t *rmp;
  acl_main_t *am = &acl_main;
  int rv;
  u32 acl_list_index = ntohl (mp->acl_index);

  rv = acl_add_list (ntohl (mp->count), mp->r, &acl_list_index, mp->tag);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_ACL_ADD_REPLACE_REPLY,
  ({
    rmp->acl_index = htonl(acl_list_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_acl_del_t_handler (vl_api_acl_del_t * mp)
{
  acl_main_t *sm = &acl_main;
  vl_api_acl_del_reply_t *rmp;
  int rv;

  rv = acl_del_list (ntohl (mp->acl_index));

  REPLY_MACRO (VL_API_ACL_DEL_REPLY);
}

static void
vl_api_acl_interface_add_del_t_handler (vl_api_acl_interface_add_del_t * mp)
{
  acl_main_t *sm = &acl_main;
  vnet_interface_main_t *im = &sm->vnet_main->interface_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vl_api_acl_interface_add_del_reply_t *rmp;
  int rv = -1;

  if (pool_is_free_index(im->sw_interfaces, sw_if_index))
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  else
    rv =
      acl_interface_add_del_inout_acl (sw_if_index, mp->is_add,
				     mp->is_input, ntohl (mp->acl_index));

  REPLY_MACRO (VL_API_ACL_INTERFACE_ADD_DEL_REPLY);
}

static void
vl_api_acl_interface_set_acl_list_t_handler
  (vl_api_acl_interface_set_acl_list_t * mp)
{
  acl_main_t *sm = &acl_main;
  vl_api_acl_interface_set_acl_list_reply_t *rmp;
  int rv = 0;
  int i;
  vnet_interface_main_t *im = &sm->vnet_main->interface_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (pool_is_free_index(im->sw_interfaces, sw_if_index))
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  else
    {
      acl_interface_reset_inout_acls (sw_if_index, 0);
      acl_interface_reset_inout_acls (sw_if_index, 1);

      for (i = 0; i < mp->count; i++)
        {
          acl_interface_add_del_inout_acl (sw_if_index, 1, (i < mp->n_input),
				       ntohl (mp->acls[i]));
        }
    }

  REPLY_MACRO (VL_API_ACL_INTERFACE_SET_ACL_LIST_REPLY);
}

static void
copy_acl_rule_to_api_rule (vl_api_acl_rule_t * api_rule, acl_rule_t * r)
{
  api_rule->is_permit = r->is_permit;
  api_rule->is_ipv6 = r->is_ipv6;
  if(r->is_ipv6)
    {
      memcpy (api_rule->src_ip_addr, &r->src, sizeof (r->src));
      memcpy (api_rule->dst_ip_addr, &r->dst, sizeof (r->dst));
    }
  else
    {
      memcpy (api_rule->src_ip_addr, &r->src.ip4, sizeof (r->src.ip4));
      memcpy (api_rule->dst_ip_addr, &r->dst.ip4, sizeof (r->dst.ip4));
    }
  api_rule->src_ip_prefix_len = r->src_prefixlen;
  api_rule->dst_ip_prefix_len = r->dst_prefixlen;
  api_rule->proto = r->proto;
  api_rule->srcport_or_icmptype_first = r->src_port_or_type_first;
  api_rule->srcport_or_icmptype_last = r->src_port_or_type_last;
  api_rule->dstport_or_icmpcode_first = r->dst_port_or_code_first;
  api_rule->dstport_or_icmpcode_last = r->dst_port_or_code_last;
  api_rule->tcp_flags_mask = r->tcp_flags_mask;
  api_rule->tcp_flags_value = r->tcp_flags_value;
}

static void
send_acl_details (acl_main_t * am, unix_shared_memory_queue_t * q,
		  acl_list_t * acl, u32 context)
{
  vl_api_acl_details_t *mp;
  vl_api_acl_rule_t *rules;
  int i;
  int msg_size = sizeof (*mp) + sizeof (mp->r[0]) * acl->count;

  mp = vl_msg_api_alloc (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_ACL_DETAILS + am->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->count = htonl (acl->count);
  mp->acl_index = htonl (acl - am->acls);
  memcpy (mp->tag, acl->tag, sizeof (mp->tag));
  // clib_memcpy (mp->r, acl->rules, acl->count * sizeof(acl->rules[0]));
  rules = mp->r;
  for (i = 0; i < acl->count; i++)
    {
      copy_acl_rule_to_api_rule (&rules[i], &acl->rules[i]);
    }

  clib_warning("Sending acl details for ACL index %d", ntohl(mp->acl_index));
  vl_msg_api_send_shmem (q, (u8 *) & mp);
}


static void
vl_api_acl_dump_t_handler (vl_api_acl_dump_t * mp)
{
  acl_main_t *am = &acl_main;
  u32 acl_index;
  acl_list_t *acl;

  int rv = -1;
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  if (mp->acl_index == ~0)
    {
    /* *INDENT-OFF* */
    /* Just dump all ACLs */
    pool_foreach (acl, am->acls,
    ({
      send_acl_details(am, q, acl, mp->context);
    }));
    /* *INDENT-ON* */
    }
  else
    {
      acl_index = ntohl (mp->acl_index);
      if (!pool_is_free_index (am->acls, acl_index))
	{
	  acl = &am->acls[acl_index];
	  send_acl_details (am, q, acl, mp->context);
	}
    }

  if (rv == -1)
    {
      /* FIXME API: should we signal an error here at all ? */
      return;
    }
}

static void
send_acl_interface_list_details (acl_main_t * am,
				 unix_shared_memory_queue_t * q,
				 u32 sw_if_index, u32 context)
{
  vl_api_acl_interface_list_details_t *mp;
  int msg_size;
  int n_input;
  int n_output;
  int count;
  int i = 0;

  vec_validate (am->input_acl_vec_by_sw_if_index, sw_if_index);
  vec_validate (am->output_acl_vec_by_sw_if_index, sw_if_index);

  n_input = vec_len (am->input_acl_vec_by_sw_if_index[sw_if_index]);
  n_output = vec_len (am->output_acl_vec_by_sw_if_index[sw_if_index]);
  count = n_input + n_output;

  msg_size = sizeof (*mp);
  msg_size += sizeof (mp->acls[0]) * count;

  mp = vl_msg_api_alloc (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id =
    ntohs (VL_API_ACL_INTERFACE_LIST_DETAILS + am->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);
  mp->count = count;
  mp->n_input = n_input;
  for (i = 0; i < n_input; i++)
    {
      mp->acls[i] = htonl (am->input_acl_vec_by_sw_if_index[sw_if_index][i]);
    }
  for (i = 0; i < n_output; i++)
    {
      mp->acls[n_input + i] =
	htonl (am->output_acl_vec_by_sw_if_index[sw_if_index][i]);
    }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_acl_interface_list_dump_t_handler (vl_api_acl_interface_list_dump_t *
					  mp)
{
  acl_main_t *am = &acl_main;
  vnet_sw_interface_t *swif;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;

  u32 sw_if_index;
  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  if (mp->sw_if_index == ~0)
    {
    /* *INDENT-OFF* */
    pool_foreach (swif, im->sw_interfaces,
    ({
      send_acl_interface_list_details(am, q, swif->sw_if_index, mp->context);
    }));
    /* *INDENT-ON* */
    }
  else
    {
      sw_if_index = ntohl (mp->sw_if_index);
      if (!pool_is_free_index(im->sw_interfaces, sw_if_index))
        send_acl_interface_list_details (am, q, sw_if_index, mp->context);
    }
}

/* MACIP ACL API handlers */

static void
vl_api_macip_acl_add_t_handler (vl_api_macip_acl_add_t * mp)
{
  vl_api_macip_acl_add_reply_t *rmp;
  acl_main_t *am = &acl_main;
  int rv;
  u32 acl_list_index = ~0;

  rv =
    macip_acl_add_list (ntohl (mp->count), mp->r, &acl_list_index, mp->tag);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MACIP_ACL_ADD_REPLY,
  ({
    rmp->acl_index = htonl(acl_list_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_macip_acl_del_t_handler (vl_api_macip_acl_del_t * mp)
{
  acl_main_t *sm = &acl_main;
  vl_api_macip_acl_del_reply_t *rmp;
  int rv;

  rv = macip_acl_del_list (ntohl (mp->acl_index));

  REPLY_MACRO (VL_API_MACIP_ACL_DEL_REPLY);
}

static void
vl_api_macip_acl_interface_add_del_t_handler
  (vl_api_macip_acl_interface_add_del_t * mp)
{
  acl_main_t *sm = &acl_main;
  vl_api_macip_acl_interface_add_del_reply_t *rmp;
  int rv = -1;
  vnet_interface_main_t *im = &sm->vnet_main->interface_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (pool_is_free_index(im->sw_interfaces, sw_if_index))
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  else
    rv =
      macip_acl_interface_add_del_acl (ntohl (mp->sw_if_index), mp->is_add,
				     ntohl (mp->acl_index));

  REPLY_MACRO (VL_API_MACIP_ACL_INTERFACE_ADD_DEL_REPLY);
}

static void
send_macip_acl_details (acl_main_t * am, unix_shared_memory_queue_t * q,
			macip_acl_list_t * acl, u32 context)
{
  vl_api_macip_acl_details_t *mp;
  vl_api_macip_acl_rule_t *rules;
  macip_acl_rule_t *r;
  int i;
  int msg_size = sizeof (*mp) + (acl ? sizeof (mp->r[0]) * acl->count : 0);

  mp = vl_msg_api_alloc (msg_size);
  memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_MACIP_ACL_DETAILS + am->msg_id_base);

  /* fill in the message */
  mp->context = context;
  if (acl)
    {
      memcpy (mp->tag, acl->tag, sizeof (mp->tag));
      mp->count = htonl (acl->count);
      mp->acl_index = htonl (acl - am->macip_acls);
      rules = mp->r;
      for (i = 0; i < acl->count; i++)
	{
	  r = &acl->rules[i];
	  rules[i].is_permit = r->is_permit;
	  rules[i].is_ipv6 = r->is_ipv6;
	  memcpy (rules[i].src_mac, &r->src_mac, sizeof (r->src_mac));
	  memcpy (rules[i].src_mac_mask, &r->src_mac_mask,
		  sizeof (r->src_mac_mask));
          if (r->is_ipv6)
            memcpy (rules[i].src_ip_addr, &r->src_ip_addr.ip6,
		  sizeof (r->src_ip_addr.ip6));
          else
            memcpy (rules[i].src_ip_addr, &r->src_ip_addr.ip4,
		  sizeof (r->src_ip_addr.ip4));
	  rules[i].src_ip_prefix_len = r->src_prefixlen;
	}
    }
  else
    {
      /* No martini, no party - no ACL applied to this interface. */
      mp->acl_index = ~0;
      mp->count = 0;
    }

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}


static void
vl_api_macip_acl_dump_t_handler (vl_api_macip_acl_dump_t * mp)
{
  acl_main_t *am = &acl_main;
  macip_acl_list_t *acl;

  unix_shared_memory_queue_t *q;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  if (mp->acl_index == ~0)
    {
      /* Just dump all ACLs for now, with sw_if_index = ~0 */
      pool_foreach (acl, am->macip_acls, (
					   {
					   send_macip_acl_details (am, q, acl,
								   mp->
								   context);}
		    ));
      /* *INDENT-ON* */
    }
  else
    {
      u32 acl_index = ntohl (mp->acl_index);
      if (!pool_is_free_index (am->macip_acls, acl_index))
	{
	  acl = &am->macip_acls[acl_index];
	  send_macip_acl_details (am, q, acl, mp->context);
	}
    }
}

static void
vl_api_macip_acl_interface_get_t_handler (vl_api_macip_acl_interface_get_t *
					  mp)
{
  acl_main_t *am = &acl_main;
  vl_api_macip_acl_interface_get_reply_t *rmp;
  u32 count = vec_len (am->macip_acl_by_sw_if_index);
  int msg_size = sizeof (*rmp) + sizeof (rmp->acls[0]) * count;
  unix_shared_memory_queue_t *q;
  int i;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  rmp = vl_msg_api_alloc (msg_size);
  memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_MACIP_ACL_INTERFACE_GET_REPLY + am->msg_id_base);
  rmp->context = mp->context;
  rmp->count = htonl (count);
  for (i = 0; i < count; i++)
    {
      rmp->acls[i] = htonl (am->macip_acl_by_sw_if_index[i]);
    }

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}



/* Set up the API message handling tables */
static clib_error_t *
acl_plugin_api_hookup (vlib_main_t * vm)
{
  acl_main_t *sm = &acl_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_acl_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <acl/acl_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (acl_main_t * sm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_acl;
#undef _
}

u32
register_match_action_nexts (u32 next_in_ip4, u32 next_in_ip6,
			     u32 next_out_ip4, u32 next_out_ip6)
{
  acl_main_t *am = &acl_main;
  u32 act = am->n_match_actions;
  if (am->n_match_actions == 255)
    {
      return ~0;
    }
  am->n_match_actions++;
  am->acl_in_ip4_match_next[act] = next_in_ip4;
  am->acl_in_ip6_match_next[act] = next_in_ip6;
  am->acl_out_ip4_match_next[act] = next_out_ip4;
  am->acl_out_ip6_match_next[act] = next_out_ip6;
  return act;
}

void
acl_setup_nodes (void)
{
  vlib_main_t *vm = vlib_get_main ();
  acl_main_t *am = &acl_main;
  vlib_node_t *n;

  n = vlib_get_node_by_name (vm, (u8 *) "l2-input-classify");
  am->l2_input_classify_next_acl =
    vlib_node_add_next_with_slot (vm, n->index, acl_in_node.index, ~0);
  n = vlib_get_node_by_name (vm, (u8 *) "l2-output-classify");
  am->l2_output_classify_next_acl =
    vlib_node_add_next_with_slot (vm, n->index, acl_out_node.index, ~0);

  feat_bitmap_init_next_nodes (vm, acl_in_node.index, L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       am->acl_in_node_input_next_node_index);

  memset (&am->acl_in_ip4_match_next[0], 0,
	  sizeof (am->acl_in_ip4_match_next));
  memset (&am->acl_in_ip6_match_next[0], 0,
	  sizeof (am->acl_in_ip6_match_next));
  memset (&am->acl_out_ip4_match_next[0], 0,
	  sizeof (am->acl_out_ip4_match_next));
  memset (&am->acl_out_ip6_match_next[0], 0,
	  sizeof (am->acl_out_ip6_match_next));
  am->n_match_actions = 0;

  register_match_action_nexts (0, 0, 0, 0);	/* drop */
  register_match_action_nexts (~0, ~0, ~0, ~0);	/* permit */
  register_match_action_nexts (ACL_IN_L2S_INPUT_IP4_ADD, ACL_IN_L2S_INPUT_IP6_ADD, ACL_OUT_L2S_OUTPUT_IP4_ADD, ACL_OUT_L2S_OUTPUT_IP6_ADD);	/* permit + create session */
}



static clib_error_t *
acl_init (vlib_main_t * vm)
{
  acl_main_t *am = &acl_main;
  clib_error_t *error = 0;
  memset (am, 0, sizeof (*am));
  am->vlib_main = vm;
  am->vnet_main = vnet_get_main ();

  u8 *name = format (0, "acl_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  am->msg_id_base = vl_msg_api_get_msg_ids ((char *) name,
					    VL_MSG_FIRST_AVAILABLE);

  error = acl_plugin_api_hookup (vm);
  acl_setup_nodes ();

 /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (am, &api_main);

  vec_free (name);

  return error;
}

VLIB_INIT_FUNCTION (acl_init);
