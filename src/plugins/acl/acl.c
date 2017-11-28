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

#include <vnet/l2/l2_classify.h>
#include <vnet/classify/input_acl.h>
#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

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

#include "fa_node.h"
#include "hash_lookup.h"

acl_main_t acl_main;

#define REPLY_MSG_ID_BASE am->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

#define foreach_acl_plugin_api_msg		\
_(ACL_PLUGIN_GET_VERSION, acl_plugin_get_version) \
_(ACL_PLUGIN_CONTROL_PING, acl_plugin_control_ping) \
_(ACL_ADD_REPLACE, acl_add_replace)				\
_(ACL_DEL, acl_del)				\
_(ACL_INTERFACE_ADD_DEL, acl_interface_add_del)	\
_(ACL_INTERFACE_SET_ACL_LIST, acl_interface_set_acl_list)	\
_(ACL_DUMP, acl_dump)  \
_(ACL_INTERFACE_LIST_DUMP, acl_interface_list_dump) \
_(MACIP_ACL_ADD, macip_acl_add) \
_(MACIP_ACL_ADD_REPLACE, macip_acl_add_replace) \
_(MACIP_ACL_DEL, macip_acl_del) \
_(MACIP_ACL_INTERFACE_ADD_DEL, macip_acl_interface_add_del) \
_(MACIP_ACL_DUMP, macip_acl_dump) \
_(MACIP_ACL_INTERFACE_GET, macip_acl_interface_get) \
_(MACIP_ACL_INTERFACE_LIST_DUMP, macip_acl_interface_list_dump)


/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Access Control Lists",
};
/* *INDENT-ON* */


static void *
acl_set_heap (acl_main_t * am)
{
  if (0 == am->acl_mheap)
    {
      am->acl_mheap = mheap_alloc (0 /* use VM */ , am->acl_mheap_size);
      mheap_t *h = mheap_header (am->acl_mheap);
      h->flags |= MHEAP_FLAG_THREAD_SAFE;
    }
  void *oldheap = clib_mem_set_heap (am->acl_mheap);
  return oldheap;
}

void
acl_plugin_acl_set_validate_heap (acl_main_t * am, int on)
{
  clib_mem_set_heap (acl_set_heap (am));
  mheap_t *h = mheap_header (am->acl_mheap);
  if (on)
    {
      h->flags |= MHEAP_FLAG_VALIDATE;
      h->flags &= ~MHEAP_FLAG_SMALL_OBJECT_CACHE;
      mheap_validate (h);
    }
  else
    {
      h->flags &= ~MHEAP_FLAG_VALIDATE;
      h->flags |= MHEAP_FLAG_SMALL_OBJECT_CACHE;
    }
}

void
acl_plugin_acl_set_trace_heap (acl_main_t * am, int on)
{
  clib_mem_set_heap (acl_set_heap (am));
  mheap_t *h = mheap_header (am->acl_mheap);
  if (on)
    {
      h->flags |= MHEAP_FLAG_TRACE;
    }
  else
    {
      h->flags &= ~MHEAP_FLAG_TRACE;
    }
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

static void
vl_api_acl_plugin_control_ping_t_handler (vl_api_acl_plugin_control_ping_t *
					  mp)
{
  vl_api_acl_plugin_control_ping_reply_t *rmp;
  acl_main_t *am = &acl_main;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_ACL_PLUGIN_CONTROL_PING_REPLY,
  ({
    rmp->vpe_pid = ntohl (getpid ());
  }));
  /* *INDENT-ON* */
}

static int
acl_add_list (u32 count, vl_api_acl_rule_t rules[],
	      u32 * acl_list_index, u8 * tag)
{
  acl_main_t *am = &acl_main;
  acl_list_t *a;
  acl_rule_t *r;
  acl_rule_t *acl_new_rules = 0;
  int i;

  if (*acl_list_index != ~0)
    {
      /* They supplied some number, let's see if this ACL exists */
      if (pool_is_free_index (am->acls, *acl_list_index))
	{
	  /* tried to replace a non-existent ACL, no point doing anything */
	  clib_warning
	    ("acl-plugin-error: Trying to replace nonexistent ACL %d (tag %s)",
	     *acl_list_index, tag);
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
	}
    }
  if (0 == count)
    {
      clib_warning
	("acl-plugin-warning: supplied no rules for ACL %d (tag %s)",
	 *acl_list_index, tag);
    }

  void *oldheap = acl_set_heap (am);

  /* Create and populate the rules */
  if (count > 0)
    vec_validate (acl_new_rules, count - 1);

  for (i = 0; i < count; i++)
    {
      r = vec_elt_at_index (acl_new_rules, i);
      memset (r, 0, sizeof (*r));
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
      r->src_port_or_type_first = ntohs (rules[i].srcport_or_icmptype_first);
      r->src_port_or_type_last = ntohs (rules[i].srcport_or_icmptype_last);
      r->dst_port_or_code_first = ntohs (rules[i].dstport_or_icmpcode_first);
      r->dst_port_or_code_last = ntohs (rules[i].dstport_or_icmpcode_last);
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
      hash_acl_delete (am, *acl_list_index);
      /* Get rid of the old rules */
      if (a->rules)
	vec_free (a->rules);
    }
  a->rules = acl_new_rules;
  a->count = count;
  memcpy (a->tag, tag, sizeof (a->tag));
  hash_acl_add (am, *acl_list_index);
  clib_mem_set_heap (oldheap);
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
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (acl_list_index < vec_len (am->input_sw_if_index_vec_by_acl))
    {
      if (vec_len (vec_elt (am->input_sw_if_index_vec_by_acl, acl_list_index))
	  > 0)
	{
	  /* ACL is applied somewhere inbound. Refuse to delete */
	  return VNET_API_ERROR_ACL_IN_USE_INBOUND;
	}
    }
  if (acl_list_index < vec_len (am->output_sw_if_index_vec_by_acl))
    {
      if (vec_len
	  (vec_elt (am->output_sw_if_index_vec_by_acl, acl_list_index)) > 0)
	{
	  /* ACL is applied somewhere outbound. Refuse to delete */
	  return VNET_API_ERROR_ACL_IN_USE_OUTBOUND;
	}
    }

  void *oldheap = acl_set_heap (am);
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
  /* delete the hash table data */

  hash_acl_delete (am, acl_list_index);
  /* now we can delete the ACL itself */
  a = pool_elt_at_index (am->acls, acl_list_index);
  if (a->rules)
    vec_free (a->rules);

  pool_put (am->acls, a);
  clib_mem_set_heap (oldheap);
  return 0;
}

/* Some aids in ASCII graphing the content */
#define XX "\377"
#define __ "\000"
#define _(x)
#define v
/* *INDENT-OFF* */

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

 u8 dot1q_5tuple_mask[] =
   _("             dmac               smac          dot1q         etype ")
   _(ether) __ __ __ __ __ __ v __ __ __ __ __ __ v XX XX __ __ v XX XX v
   _(padpad) __ __ __ __
   _(padpad) __ __ __ __
   _(padpad) __ __ __ __
   _(padeth) __ __;

 u8 dot1ad_5tuple_mask[] =
   _("             dmac               smac          dot1ad      dot1q         etype ")
   _(ether) __ __ __ __ __ __ v __ __ __ __ __ __ v XX XX __ __ XX XX __ __ v XX XX v
   _(padpad) __ __ __ __
   _(padpad) __ __ __ __
   _(padeth) __ __;

/* *INDENT-ON* */
#undef XX
#undef __
#undef _
#undef v

static int
count_skip (u8 * p, u32 size)
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
acl_classify_add_del_table_tiny (vnet_classify_main_t * cm, u8 * mask,
				 u32 mask_len, u32 next_table_index,
				 u32 miss_next_index, u32 * table_index,
				 int is_add)
{
  u32 nbuckets = 1;
  u32 memory_size = 2 << 13;
  u32 skip = count_skip (mask, mask_len);
  u32 match = (mask_len / 16) - skip;
  u8 *skip_mask_ptr = mask + 16 * skip;
  u32 current_data_flag = 0;
  int current_data_offset = 0;

  if (0 == match)
    match = 1;
  void *oldheap = clib_mem_set_heap (cm->vlib_main->heap_base);
  int ret = vnet_classify_add_del_table (cm, skip_mask_ptr, nbuckets,
					 memory_size, skip, match,
					 next_table_index, miss_next_index,
					 table_index, current_data_flag,
					 current_data_offset, is_add,
					 1 /* delete_chain */ );
  clib_mem_set_heap (oldheap);
  return ret;
}

static int
acl_classify_add_del_table_small (vnet_classify_main_t * cm, u8 * mask,
				  u32 mask_len, u32 next_table_index,
				  u32 miss_next_index, u32 * table_index,
				  int is_add)
{
  u32 nbuckets = 32;
  u32 memory_size = 2 << 22;
  u32 skip = count_skip (mask, mask_len);
  u32 match = (mask_len / 16) - skip;
  u8 *skip_mask_ptr = mask + 16 * skip;
  u32 current_data_flag = 0;
  int current_data_offset = 0;

  if (0 == match)
    match = 1;

  void *oldheap = clib_mem_set_heap (cm->vlib_main->heap_base);
  int ret = vnet_classify_add_del_table (cm, skip_mask_ptr, nbuckets,
					 memory_size, skip, match,
					 next_table_index, miss_next_index,
					 table_index, current_data_flag,
					 current_data_offset, is_add,
					 1 /* delete_chain */ );
  clib_mem_set_heap (oldheap);
  return ret;
}

static int
acl_unhook_l2_input_classify (acl_main_t * am, u32 sw_if_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u32 dot1q_table_index = ~0;
  u32 dot1ad_table_index = ~0;
  void *oldheap = acl_set_heap (am);

  vec_validate_init_empty (am->acl_ip4_input_classify_table_by_sw_if_index,
			   sw_if_index, ~0);
  vec_validate_init_empty (am->acl_ip6_input_classify_table_by_sw_if_index,
			   sw_if_index, ~0);
  vec_validate_init_empty (am->acl_dot1q_input_classify_table_by_sw_if_index,
			   sw_if_index, ~0);
  vec_validate_init_empty (am->acl_dot1ad_input_classify_table_by_sw_if_index,
			   sw_if_index, ~0);

  /* switch to global heap while calling vnet_* functions */
  clib_mem_set_heap (cm->vlib_main->heap_base);
  vnet_l2_input_classify_enable_disable (sw_if_index, 0);

  if (am->acl_ip4_input_classify_table_by_sw_if_index[sw_if_index] != ~0)
    {
      ip4_table_index =
	am->acl_ip4_input_classify_table_by_sw_if_index[sw_if_index];
      am->acl_ip4_input_classify_table_by_sw_if_index[sw_if_index] = ~0;
      acl_classify_add_del_table_tiny (cm, ip4_5tuple_mask,
				       sizeof (ip4_5tuple_mask) - 1, ~0,
				       am->l2_input_classify_next_acl_ip4,
				       &ip4_table_index, 0);
    }
  if (am->acl_ip6_input_classify_table_by_sw_if_index[sw_if_index] != ~0)
    {
      ip6_table_index =
	am->acl_ip6_input_classify_table_by_sw_if_index[sw_if_index];
      am->acl_ip6_input_classify_table_by_sw_if_index[sw_if_index] = ~0;
      acl_classify_add_del_table_tiny (cm, ip6_5tuple_mask,
				       sizeof (ip6_5tuple_mask) - 1, ~0,
				       am->l2_input_classify_next_acl_ip6,
				       &ip6_table_index, 0);
    }
  if (am->acl_dot1q_input_classify_table_by_sw_if_index[sw_if_index] != ~0)
    {
      dot1q_table_index =
	am->acl_dot1q_input_classify_table_by_sw_if_index[sw_if_index];
      am->acl_dot1q_input_classify_table_by_sw_if_index[sw_if_index] = ~0;
      acl_classify_add_del_table_tiny (cm, ip6_5tuple_mask,
				       sizeof (ip6_5tuple_mask) - 1, ~0,
				       ~0, &dot1q_table_index, 0);
    }
  if (am->acl_dot1ad_input_classify_table_by_sw_if_index[sw_if_index] != ~0)
    {
      dot1ad_table_index =
	am->acl_dot1ad_input_classify_table_by_sw_if_index[sw_if_index];
      am->acl_dot1ad_input_classify_table_by_sw_if_index[sw_if_index] = ~0;
      acl_classify_add_del_table_tiny (cm, dot1ad_5tuple_mask,
				       sizeof (dot1ad_5tuple_mask) - 1, ~0,
				       ~0, &dot1ad_table_index, 0);
    }
  clib_mem_set_heap (oldheap);
  return 0;
}

static int
acl_unhook_l2_output_classify (acl_main_t * am, u32 sw_if_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u32 dot1q_table_index = ~0;
  u32 dot1ad_table_index = ~0;
  void *oldheap = acl_set_heap (am);

  vec_validate_init_empty (am->acl_ip4_output_classify_table_by_sw_if_index,
			   sw_if_index, ~0);
  vec_validate_init_empty (am->acl_ip6_output_classify_table_by_sw_if_index,
			   sw_if_index, ~0);
  vec_validate_init_empty (am->acl_dot1q_output_classify_table_by_sw_if_index,
			   sw_if_index, ~0);
  vec_validate_init_empty
    (am->acl_dot1ad_output_classify_table_by_sw_if_index, sw_if_index, ~0);

  /* switch to global heap while calling vnet_* functions */
  clib_mem_set_heap (cm->vlib_main->heap_base);

  vnet_l2_output_classify_enable_disable (sw_if_index, 0);

  if (am->acl_ip4_output_classify_table_by_sw_if_index[sw_if_index] != ~0)
    {
      ip4_table_index =
	am->acl_ip4_output_classify_table_by_sw_if_index[sw_if_index];
      am->acl_ip4_output_classify_table_by_sw_if_index[sw_if_index] = ~0;
      acl_classify_add_del_table_tiny (cm, ip4_5tuple_mask,
				       sizeof (ip4_5tuple_mask) - 1, ~0,
				       am->l2_output_classify_next_acl_ip4,
				       &ip4_table_index, 0);
    }
  if (am->acl_ip6_output_classify_table_by_sw_if_index[sw_if_index] != ~0)
    {
      ip6_table_index =
	am->acl_ip6_output_classify_table_by_sw_if_index[sw_if_index];
      am->acl_ip6_output_classify_table_by_sw_if_index[sw_if_index] = ~0;
      acl_classify_add_del_table_tiny (cm, ip6_5tuple_mask,
				       sizeof (ip6_5tuple_mask) - 1, ~0,
				       am->l2_output_classify_next_acl_ip6,
				       &ip6_table_index, 0);
    }
  if (am->acl_dot1q_output_classify_table_by_sw_if_index[sw_if_index] != ~0)
    {
      dot1q_table_index =
	am->acl_dot1q_output_classify_table_by_sw_if_index[sw_if_index];
      am->acl_dot1q_output_classify_table_by_sw_if_index[sw_if_index] = ~0;
      acl_classify_add_del_table_tiny (cm, ip6_5tuple_mask,
				       sizeof (ip6_5tuple_mask) - 1, ~0,
				       ~0, &dot1q_table_index, 0);
    }
  if (am->acl_dot1ad_output_classify_table_by_sw_if_index[sw_if_index] != ~0)
    {
      dot1ad_table_index =
	am->acl_dot1ad_output_classify_table_by_sw_if_index[sw_if_index];
      am->acl_dot1ad_output_classify_table_by_sw_if_index[sw_if_index] = ~0;
      acl_classify_add_del_table_tiny (cm, dot1ad_5tuple_mask,
				       sizeof (dot1ad_5tuple_mask) - 1, ~0,
				       ~0, &dot1ad_table_index, 0);
    }
  clib_mem_set_heap (oldheap);
  return 0;
}

static void
acl_add_vlan_session (acl_main_t * am, u32 table_index, u8 is_output,
		      u8 is_dot1ad, u8 is_ip6)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u8 *match;
  u32 next_acl;
  u8 idx;
  u8 session_idx;

  if (is_ip6)
    {
      next_acl =
	(is_output) ? am->
	l2_output_classify_next_acl_ip6 : am->l2_input_classify_next_acl_ip6;
    }
  else
    {
      next_acl =
	(is_output) ? am->
	l2_output_classify_next_acl_ip4 : am->l2_input_classify_next_acl_ip4;
    }
  match = (is_dot1ad) ? dot1ad_5tuple_mask : dot1q_5tuple_mask;
  idx = (is_dot1ad) ? 20 : 16;
  if (is_dot1ad)
    {
      /* 802.1ad ethertype */
      match[12] = 0x88;
      match[13] = 0xa8;
      /* 802.1q ethertype */
      match[16] = 0x81;
      match[17] = 0x00;
    }
  else
    {
      /* 802.1q ethertype */
      match[12] = 0x81;
      match[13] = 0x00;
    }

  /* add sessions to vlan tables per ethernet_type */
  if (is_ip6)
    {
      match[idx] = 0x86;
      match[idx + 1] = 0xdd;
      session_idx = 1;
    }
  else
    {
      match[idx] = 0x08;
      match[idx + 1] = 0x00;
      session_idx = 0;
    }
  vnet_classify_add_del_session (cm, table_index, match, next_acl,
				 session_idx, 0, 0, 0, 1);
  /* reset the mask back to being a mask */
  match[idx] = 0xff;
  match[idx + 1] = 0xff;
  match[12] = 0xff;
  match[13] = 0xff;
  if (is_dot1ad)
    {
      match[16] = 0xff;
      match[17] = 0xff;
    }
}

static int
acl_hook_l2_input_classify (acl_main_t * am, u32 sw_if_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u32 dot1q_table_index = ~0;
  u32 dot1ad_table_index = ~0;
  int rv;

  void *prevheap = clib_mem_set_heap (cm->vlib_main->heap_base);

  /* in case there were previous tables attached */
  acl_unhook_l2_input_classify (am, sw_if_index);
  rv =
    acl_classify_add_del_table_tiny (cm, ip4_5tuple_mask,
				     sizeof (ip4_5tuple_mask) - 1, ~0,
				     am->l2_input_classify_next_acl_ip4,
				     &ip4_table_index, 1);
  if (rv)
    goto done;

  rv =
    acl_classify_add_del_table_tiny (cm, ip6_5tuple_mask,
				     sizeof (ip6_5tuple_mask) - 1, ~0,
				     am->l2_input_classify_next_acl_ip6,
				     &ip6_table_index, 1);
  if (rv)
    {
      acl_classify_add_del_table_tiny (cm, ip4_5tuple_mask,
				       sizeof (ip4_5tuple_mask) - 1, ~0,
				       am->l2_input_classify_next_acl_ip4,
				       &ip4_table_index, 0);
      goto done;
    }

  rv =
    acl_classify_add_del_table_tiny (cm, dot1ad_5tuple_mask,
				     sizeof (dot1ad_5tuple_mask) - 1, ~0,
				     ~0, &dot1ad_table_index, 1);
  rv =
    acl_classify_add_del_table_tiny (cm, dot1q_5tuple_mask,
				     sizeof (dot1q_5tuple_mask) - 1,
				     dot1ad_table_index, ~0,
				     &dot1q_table_index, 1);
  if (rv)
    {
      acl_classify_add_del_table_tiny (cm, dot1ad_5tuple_mask,
				       sizeof (dot1ad_5tuple_mask) - 1, ~0,
				       ~0, &dot1ad_table_index, 0);
      acl_classify_add_del_table_tiny (cm, ip6_5tuple_mask,
				       sizeof (ip6_5tuple_mask) - 1, ~0,
				       am->l2_input_classify_next_acl_ip6,
				       &ip6_table_index, 0);
      acl_classify_add_del_table_tiny (cm, ip4_5tuple_mask,
				       sizeof (ip4_5tuple_mask) - 1, ~0,
				       am->l2_input_classify_next_acl_ip4,
				       &ip4_table_index, 0);
      goto done;
    }

  rv =
    vnet_l2_input_classify_set_tables (sw_if_index, ip4_table_index,
				       ip6_table_index, dot1q_table_index);

  if (rv)
    {
      acl_classify_add_del_table_tiny (cm, ip4_5tuple_mask,
				       sizeof (ip4_5tuple_mask) - 1, ~0,
				       am->l2_input_classify_next_acl_ip4,
				       &ip4_table_index, 0);
      acl_classify_add_del_table_tiny (cm, ip6_5tuple_mask,
				       sizeof (ip6_5tuple_mask) - 1, ~0,
				       am->l2_input_classify_next_acl_ip6,
				       &ip6_table_index, 0);
      acl_classify_add_del_table_tiny (cm, dot1q_5tuple_mask,
				       sizeof (dot1q_5tuple_mask) - 1, ~0,
				       ~0, &dot1q_table_index, 0);
      acl_classify_add_del_table_tiny (cm, dot1ad_5tuple_mask,
				       sizeof (dot1ad_5tuple_mask) - 1, ~0,
				       ~0, &dot1ad_table_index, 0);
      goto done;
    }

  /* add sessions to vlan tables per ethernet_type */
  acl_add_vlan_session (am, dot1q_table_index, 0, 0, 0);
  acl_add_vlan_session (am, dot1q_table_index, 0, 0, 1);
  acl_add_vlan_session (am, dot1ad_table_index, 0, 1, 0);
  acl_add_vlan_session (am, dot1ad_table_index, 0, 1, 1);

  am->acl_ip4_input_classify_table_by_sw_if_index[sw_if_index] =
    ip4_table_index;
  am->acl_ip6_input_classify_table_by_sw_if_index[sw_if_index] =
    ip6_table_index;
  am->acl_dot1q_input_classify_table_by_sw_if_index[sw_if_index] =
    dot1q_table_index;
  am->acl_dot1ad_input_classify_table_by_sw_if_index[sw_if_index] =
    dot1ad_table_index;

  vnet_l2_input_classify_enable_disable (sw_if_index, 1);
done:
  clib_mem_set_heap (prevheap);
  return rv;
}

static int
acl_hook_l2_output_classify (acl_main_t * am, u32 sw_if_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u32 dot1q_table_index = ~0;
  u32 dot1ad_table_index = ~0;
  int rv;

  void *prevheap = clib_mem_set_heap (cm->vlib_main->heap_base);

  /* in case there were previous tables attached */
  acl_unhook_l2_output_classify (am, sw_if_index);
  rv =
    acl_classify_add_del_table_tiny (cm, ip4_5tuple_mask,
				     sizeof (ip4_5tuple_mask) - 1, ~0,
				     am->l2_output_classify_next_acl_ip4,
				     &ip4_table_index, 1);
  if (rv)
    goto done;
  rv =
    acl_classify_add_del_table_tiny (cm, ip6_5tuple_mask,
				     sizeof (ip6_5tuple_mask) - 1, ~0,
				     am->l2_output_classify_next_acl_ip6,
				     &ip6_table_index, 1);
  if (rv)
    {
      acl_classify_add_del_table_tiny (cm, ip4_5tuple_mask,
				       sizeof (ip4_5tuple_mask) - 1, ~0,
				       am->l2_output_classify_next_acl_ip4,
				       &ip4_table_index, 0);
      goto done;
    }

  rv =
    acl_classify_add_del_table_tiny (cm, dot1ad_5tuple_mask,
				     sizeof (dot1ad_5tuple_mask) - 1, ~0,
				     ~0, &dot1ad_table_index, 1);
  rv =
    acl_classify_add_del_table_tiny (cm, dot1q_5tuple_mask,
				     sizeof (dot1q_5tuple_mask) - 1,
				     dot1ad_table_index, ~0,
				     &dot1q_table_index, 1);
  if (rv)
    {
      acl_classify_add_del_table_tiny (cm, dot1ad_5tuple_mask,
				       sizeof (dot1ad_5tuple_mask) - 1, ~0,
				       ~0, &dot1ad_table_index, 0);
      acl_classify_add_del_table_tiny (cm, ip6_5tuple_mask,
				       sizeof (ip6_5tuple_mask) - 1, ~0,
				       am->l2_output_classify_next_acl_ip6,
				       &ip6_table_index, 0);
      acl_classify_add_del_table_tiny (cm, ip4_5tuple_mask,
				       sizeof (ip4_5tuple_mask) - 1, ~0,
				       am->l2_output_classify_next_acl_ip4,
				       &ip4_table_index, 0);
      goto done;
    }

  rv =
    vnet_l2_output_classify_set_tables (sw_if_index, ip4_table_index,
					ip6_table_index, dot1q_table_index);

  clib_warning
    ("ACL enabling on interface sw_if_index %d, setting tables to the following: ip4: %d ip6: %d\n",
     sw_if_index, ip4_table_index, ip6_table_index);
  if (rv)
    {
      acl_classify_add_del_table_tiny (cm, ip6_5tuple_mask,
				       sizeof (ip6_5tuple_mask) - 1, ~0,
				       am->l2_output_classify_next_acl_ip6,
				       &ip6_table_index, 0);
      acl_classify_add_del_table_tiny (cm, ip4_5tuple_mask,
				       sizeof (ip4_5tuple_mask) - 1, ~0,
				       am->l2_output_classify_next_acl_ip4,
				       &ip4_table_index, 0);
      acl_classify_add_del_table_tiny (cm, dot1q_5tuple_mask,
				       sizeof (dot1q_5tuple_mask) - 1, ~0,
				       ~0, &dot1q_table_index, 0);
      acl_classify_add_del_table_tiny (cm, dot1ad_5tuple_mask,
				       sizeof (dot1ad_5tuple_mask) - 1, ~0,
				       ~0, &dot1ad_table_index, 0);
      goto done;
    }

  /* add sessions to vlan tables per ethernet_type */
  acl_add_vlan_session (am, dot1q_table_index, 1, 0, 0);
  acl_add_vlan_session (am, dot1q_table_index, 1, 0, 1);
  acl_add_vlan_session (am, dot1ad_table_index, 1, 1, 0);
  acl_add_vlan_session (am, dot1ad_table_index, 1, 1, 1);

  am->acl_ip4_output_classify_table_by_sw_if_index[sw_if_index] =
    ip4_table_index;
  am->acl_ip6_output_classify_table_by_sw_if_index[sw_if_index] =
    ip6_table_index;
  am->acl_dot1q_output_classify_table_by_sw_if_index[sw_if_index] =
    dot1q_table_index;
  am->acl_dot1ad_output_classify_table_by_sw_if_index[sw_if_index] =
    dot1ad_table_index;

  vnet_l2_output_classify_enable_disable (sw_if_index, 1);
done:
  clib_mem_set_heap (prevheap);
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

  acl_fa_enable_disable (sw_if_index, 1, enable_disable);

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

  acl_fa_enable_disable (sw_if_index, 0, enable_disable);

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
acl_is_not_defined (acl_main_t * am, u32 acl_list_index)
{
  return (pool_is_free_index (am->acls, acl_list_index));
}


static int
acl_interface_add_inout_acl (u32 sw_if_index, u8 is_input, u32 acl_list_index)
{
  acl_main_t *am = &acl_main;
  if (acl_is_not_defined (am, acl_list_index))
    {
      /* ACL is not defined. Can not apply */
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
  void *oldheap = acl_set_heap (am);

  if (is_input)
    {
      vec_validate (am->input_acl_vec_by_sw_if_index, sw_if_index);

      u32 index = vec_search (am->input_acl_vec_by_sw_if_index[sw_if_index],
			      acl_list_index);
      if (index < vec_len (am->input_acl_vec_by_sw_if_index[sw_if_index]))
	{
	  clib_warning
	    ("ACL %d is already applied inbound on sw_if_index %d (index %d)",
	     acl_list_index, sw_if_index, index);
	  /* the entry is already there */
	  clib_mem_set_heap (oldheap);
	  return VNET_API_ERROR_ACL_IN_USE_INBOUND;
	}
      /* if there was no ACL applied before, enable the ACL processing */
      if (vec_len (am->input_acl_vec_by_sw_if_index[sw_if_index]) == 0)
	{
	  acl_interface_in_enable_disable (am, sw_if_index, 1);
	}
      vec_add (am->input_acl_vec_by_sw_if_index[sw_if_index], &acl_list_index,
	       1);
      vec_validate (am->input_sw_if_index_vec_by_acl, acl_list_index);
      vec_add (am->input_sw_if_index_vec_by_acl[acl_list_index], &sw_if_index,
	       1);
    }
  else
    {
      vec_validate (am->output_acl_vec_by_sw_if_index, sw_if_index);

      u32 index = vec_search (am->output_acl_vec_by_sw_if_index[sw_if_index],
			      acl_list_index);
      if (index < vec_len (am->output_acl_vec_by_sw_if_index[sw_if_index]))
	{
	  clib_warning
	    ("ACL %d is already applied outbound on sw_if_index %d (index %d)",
	     acl_list_index, sw_if_index, index);
	  /* the entry is already there */
	  clib_mem_set_heap (oldheap);
	  return VNET_API_ERROR_ACL_IN_USE_OUTBOUND;
	}
      /* if there was no ACL applied before, enable the ACL processing */
      if (vec_len (am->output_acl_vec_by_sw_if_index[sw_if_index]) == 0)
	{
	  acl_interface_out_enable_disable (am, sw_if_index, 1);
	}
      vec_add (am->output_acl_vec_by_sw_if_index[sw_if_index],
	       &acl_list_index, 1);
      vec_validate (am->output_sw_if_index_vec_by_acl, acl_list_index);
      vec_add (am->output_sw_if_index_vec_by_acl[acl_list_index],
	       &sw_if_index, 1);
    }
  clib_mem_set_heap (oldheap);
  return 0;
}


static int
acl_interface_del_inout_acl (u32 sw_if_index, u8 is_input, u32 acl_list_index)
{
  acl_main_t *am = &acl_main;
  int i;
  int rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  void *oldheap = acl_set_heap (am);
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

      if (acl_list_index < vec_len (am->input_sw_if_index_vec_by_acl))
	{
	  u32 index =
	    vec_search (am->input_sw_if_index_vec_by_acl[acl_list_index],
			sw_if_index);
	  if (index <
	      vec_len (am->input_sw_if_index_vec_by_acl[acl_list_index]))
	    {
	      hash_acl_unapply (am, sw_if_index, is_input, acl_list_index);
	      vec_del1 (am->input_sw_if_index_vec_by_acl[acl_list_index],
			index);
	    }
	}

      /* If there is no more ACLs applied on an interface, disable ACL processing */
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

      if (acl_list_index < vec_len (am->output_sw_if_index_vec_by_acl))
	{
	  u32 index =
	    vec_search (am->output_sw_if_index_vec_by_acl[acl_list_index],
			sw_if_index);
	  if (index <
	      vec_len (am->output_sw_if_index_vec_by_acl[acl_list_index]))
	    {
	      hash_acl_unapply (am, sw_if_index, is_input, acl_list_index);
	      vec_del1 (am->output_sw_if_index_vec_by_acl[acl_list_index],
			index);
	    }
	}

      /* If there is no more ACLs applied on an interface, disable ACL processing */
      if (0 == vec_len (am->output_acl_vec_by_sw_if_index[sw_if_index]))
	{
	  acl_interface_out_enable_disable (am, sw_if_index, 0);
	}
    }
  clib_mem_set_heap (oldheap);
  return rv;
}

static void
acl_interface_reset_inout_acls (u32 sw_if_index, u8 is_input)
{
  acl_main_t *am = &acl_main;
  int i;
  void *oldheap = acl_set_heap (am);
  if (is_input)
    {
      vec_validate (am->input_acl_vec_by_sw_if_index, sw_if_index);
      if (vec_len (am->input_acl_vec_by_sw_if_index[sw_if_index]) > 0)
	{
	  acl_interface_in_enable_disable (am, sw_if_index, 0);
	}

      for (i = vec_len (am->input_acl_vec_by_sw_if_index[sw_if_index]) - 1;
	   i >= 0; i--)
	{
	  u32 acl_list_index =
	    am->input_acl_vec_by_sw_if_index[sw_if_index][i];
	  hash_acl_unapply (am, sw_if_index, is_input, acl_list_index);
	  if (acl_list_index < vec_len (am->input_sw_if_index_vec_by_acl))
	    {
	      u32 index =
		vec_search (am->input_sw_if_index_vec_by_acl[acl_list_index],
			    sw_if_index);
	      if (index <
		  vec_len (am->input_sw_if_index_vec_by_acl[acl_list_index]))
		{
		  vec_del1 (am->input_sw_if_index_vec_by_acl[acl_list_index],
			    index);
		}
	    }
	}

      vec_reset_length (am->input_acl_vec_by_sw_if_index[sw_if_index]);
    }
  else
    {
      vec_validate (am->output_acl_vec_by_sw_if_index, sw_if_index);
      if (vec_len (am->output_acl_vec_by_sw_if_index[sw_if_index]) > 0)
	{
	  acl_interface_out_enable_disable (am, sw_if_index, 0);
	}

      for (i = vec_len (am->output_acl_vec_by_sw_if_index[sw_if_index]) - 1;
	   i >= 0; i--)
	{
	  u32 acl_list_index =
	    am->output_acl_vec_by_sw_if_index[sw_if_index][i];
	  hash_acl_unapply (am, sw_if_index, is_input, acl_list_index);
	  if (acl_list_index < vec_len (am->output_sw_if_index_vec_by_acl))
	    {
	      u32 index =
		vec_search (am->output_sw_if_index_vec_by_acl[acl_list_index],
			    sw_if_index);
	      if (index <
		  vec_len (am->output_sw_if_index_vec_by_acl[acl_list_index]))
		{
		  vec_del1 (am->output_sw_if_index_vec_by_acl[acl_list_index],
			    index);
		}
	    }
	}

      vec_reset_length (am->output_acl_vec_by_sw_if_index[sw_if_index]);
    }
  clib_mem_set_heap (oldheap);
}

static int
acl_interface_add_del_inout_acl (u32 sw_if_index, u8 is_add, u8 is_input,
				 u32 acl_list_index)
{
  int rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  acl_main_t *am = &acl_main;
  if (is_add)
    {
      rv =
	acl_interface_add_inout_acl (sw_if_index, is_input, acl_list_index);
      if (rv == 0)
	{
	  hash_acl_apply (am, sw_if_index, is_input, acl_list_index);
	}
    }
  else
    {
      hash_acl_unapply (am, sw_if_index, is_input, acl_list_index);
      rv =
	acl_interface_del_inout_acl (sw_if_index, is_input, acl_list_index);
    }
  return rv;
}


typedef struct
{
  u8 is_ipv6;
  u8 mac_mask[6];
  u8 prefix_len;
  u32 count;
  u32 table_index;
  u32 arp_table_index;
  u32 dot1q_table_index;
  u32 dot1ad_table_index;
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
  unsigned int mac_bits_set = 0;
  unsigned int mac_byte;
  int i;
  for (i = 0; i < 6; i++)
    {
      mac_byte = m->mac_mask[i];
      for (; mac_byte; mac_byte >>= 1)
	mac_bits_set += mac_byte & 1;
    }
  /*
   * Attempt to place the more specific and the more used rules on top.
   * There are obvious caveat corner cases to this, but they do not
   * seem to be sensible in real world (e.g. specific IPv4 with wildcard MAC
   * going with a wildcard IPv4 with a specific MAC).
   */
  return m->prefix_len + mac_bits_set + m->is_ipv6 + 10 * m->count;
}

static int
match_type_compare (macip_match_type_t * m1, macip_match_type_t * m2)
{
  /* Ascending sort based on the metric values */
  return match_type_metric (m1) - match_type_metric (m2);
}

/* Get the offset of L3 source within ethernet packet */
static int
get_l3_src_offset (int is6)
{
  if (is6)
    return (sizeof (ethernet_header_t) +
	    offsetof (ip6_header_t, src_address));
  else
    return (sizeof (ethernet_header_t) +
	    offsetof (ip4_header_t, src_address));
}

static int
macip_create_classify_tables (acl_main_t * am, u32 macip_acl_index)
{
  macip_match_type_t *mvec = NULL;
  macip_match_type_t *mt;
  macip_acl_list_t *a = pool_elt_at_index (am->macip_acls, macip_acl_index);
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
		  a->rules[i].src_mac_mask, 6);
	  mvec[match_type_index].prefix_len = a->rules[i].src_prefixlen;
	  mvec[match_type_index].is_ipv6 = a->rules[i].is_ipv6;
	  mvec[match_type_index].table_index = ~0;
	  mvec[match_type_index].dot1q_table_index = ~0;
	  mvec[match_type_index].dot1ad_table_index = ~0;
	}
      mvec[match_type_index].count++;
    }
  /* Put the most frequently used tables last in the list so we can create classifier tables in reverse order */
  vec_sort_with_function (mvec, match_type_compare);
  /* Create the classifier tables */
  last_table = ~0;
  /* First add ARP tables */
  vec_foreach (mt, mvec)
  {
    int mask_len;
    int is6 = mt->is_ipv6;

    mt->arp_table_index = ~0;
    if (!is6)
      {
	memset (mask, 0, sizeof (mask));
	memcpy (&mask[6], mt->mac_mask, 6);
	memset (&mask[12], 0xff, 2);	/* ethernet protocol */
	memcpy (&mask[14 + 8], mt->mac_mask, 6);

	for (i = 0; i < (mt->prefix_len / 8); i++)
	  mask[14 + 14 + i] = 0xff;
	if (mt->prefix_len % 8)
	  mask[14 + 14 + (mt->prefix_len / 8)] =
	    0xff - ((1 << (8 - mt->prefix_len % 8)) - 1);

	mask_len = ((14 + 14 + ((mt->prefix_len + 7) / 8) +
		     (sizeof (u32x4) - 1)) / sizeof (u32x4)) * sizeof (u32x4);
	acl_classify_add_del_table_small (cm, mask, mask_len, last_table,
					  (~0 == last_table) ? 0 : ~0,
					  &mt->arp_table_index, 1);
	last_table = mt->arp_table_index;
      }
  }
  /* Now add IP[46] tables */
  vec_foreach (mt, mvec)
  {
    int mask_len;
    int is6 = mt->is_ipv6;
    int l3_src_offs = get_l3_src_offset (is6);
    int tags;
    u32 *last_tag_table;

    /*
     * create chained tables for VLAN (no-tags, dot1q and dot1ad) packets
     */
    l3_src_offs += 8;
    for (tags = 2; tags >= 0; tags--)
      {
	memset (mask, 0, sizeof (mask));
	memcpy (&mask[6], mt->mac_mask, 6);
	switch (tags)
	  {
	  case 0:
	  default:
	    memset (&mask[12], 0xff, 2);	/* ethernet protocol */
	    last_tag_table = &mt->table_index;
	    break;
	  case 1:
	    memset (&mask[12], 0xff, 2);	/* VLAN tag1 */
	    memset (&mask[16], 0xff, 2);	/* ethernet protocol */
	    last_tag_table = &mt->dot1q_table_index;
	    break;
	  case 2:
	    memset (&mask[12], 0xff, 2);	/* VLAN tag1 */
	    memset (&mask[16], 0xff, 2);	/* VLAN tag2 */
	    memset (&mask[20], 0xff, 2);	/* ethernet protocol */
	    last_tag_table = &mt->dot1ad_table_index;
	    break;
	  }
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
	mask_len = ((l3_src_offs + ((mt->prefix_len + 7) / 8) +
		     (sizeof (u32x4) - 1)) / sizeof (u32x4)) * sizeof (u32x4);
	acl_classify_add_del_table_small (cm, mask, mask_len, last_table,
					  (~0 == last_table) ? 0 : ~0,
					  last_tag_table, 1);
	last_table = *last_tag_table;

	memset (&mask[12], 0, sizeof (mask) - 12);
	l3_src_offs -= 4;
      }
  }
  a->ip4_table_index = last_table;
  a->ip6_table_index = last_table;
  a->l2_table_index = last_table;

  /* Populate the classifier tables with rules from the MACIP ACL */
  for (i = 0; i < a->count; i++)
    {
      u32 action = 0;
      u32 metadata = 0;
      int is6 = a->rules[i].is_ipv6;
      int l3_src_offs = get_l3_src_offset (is6);
      u32 tag_table;
      int tags, eth;

      match_type_index =
	macip_find_match_type (mvec, a->rules[i].src_mac_mask,
			       a->rules[i].src_prefixlen,
			       a->rules[i].is_ipv6);
      ASSERT (match_type_index != ~0);

      l3_src_offs += 8;
      for (tags = 2; tags >= 0; tags--)
	{
	  memset (mask, 0, sizeof (mask));
	  memcpy (&mask[6], a->rules[i].src_mac, 6);
	  switch (tags)
	    {
	    case 0:
	    default:
	      tag_table = mvec[match_type_index].table_index;
	      eth = 12;
	      break;
	    case 1:
	      tag_table = mvec[match_type_index].dot1q_table_index;
	      mask[12] = 0x81;
	      mask[13] = 0x00;
	      eth = 16;
	      break;
	    case 2:
	      tag_table = mvec[match_type_index].dot1ad_table_index;
	      mask[12] = 0x88;
	      mask[13] = 0xa8;
	      mask[16] = 0x81;
	      mask[17] = 0x00;
	      eth = 20;
	      break;
	    }
	  if (is6)
	    {
	      memcpy (&mask[l3_src_offs], &a->rules[i].src_ip_addr.ip6, 16);
	      mask[eth] = 0x86;
	      mask[eth + 1] = 0xdd;
	    }
	  else
	    {
	      memcpy (&mask[l3_src_offs], &a->rules[i].src_ip_addr.ip4, 4);
	      mask[eth] = 0x08;
	      mask[eth + 1] = 0x00;
	    }

	  /* add session to table mvec[match_type_index].table_index; */
	  vnet_classify_add_del_session (cm, tag_table,
					 mask, a->rules[i].is_permit ? ~0 : 0,
					 i, 0, action, metadata, 1);
	  memset (&mask[12], 0, sizeof (mask) - 12);
	  l3_src_offs -= 4;
	}

      /* add ARP table entry too */
      if (!is6 && (mvec[match_type_index].arp_table_index != ~0))
	{
	  memset (mask, 0, sizeof (mask));
	  memcpy (&mask[6], a->rules[i].src_mac, 6);
	  mask[12] = 0x08;
	  mask[13] = 0x06;
	  memcpy (&mask[14 + 8], a->rules[i].src_mac, 6);
	  memcpy (&mask[14 + 14], &a->rules[i].src_ip_addr.ip4, 4);
	  vnet_classify_add_del_session (cm,
					 mvec
					 [match_type_index].arp_table_index,
					 mask, a->rules[i].is_permit ? ~0 : 0,
					 i, 0, action, metadata, 1);
	}
    }
  return 0;
}

static void
macip_destroy_classify_tables (acl_main_t * am, u32 macip_acl_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  macip_acl_list_t *a = pool_elt_at_index (am->macip_acls, macip_acl_index);

  if (a->ip4_table_index != ~0)
    {
      acl_classify_add_del_table_small (cm, 0, ~0, ~0, ~0,
					&a->ip4_table_index, 0);
      a->ip4_table_index = ~0;
    }
  if (a->ip6_table_index != ~0)
    {
      acl_classify_add_del_table_small (cm, 0, ~0, ~0, ~0,
					&a->ip6_table_index, 0);
      a->ip6_table_index = ~0;
    }
  if (a->l2_table_index != ~0)
    {
      acl_classify_add_del_table_small (cm, 0, ~0, ~0, ~0, &a->l2_table_index,
					0);
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
  macip_acl_rule_t *acl_new_rules = 0;
  int i;

  if (*acl_list_index != ~0)
    {
      /* They supplied some number, let's see if this MACIP ACL exists */
      if (pool_is_free_index (am->macip_acls, *acl_list_index))
	{
	  /* tried to replace a non-existent ACL, no point doing anything */
	  clib_warning
	    ("acl-plugin-error: Trying to replace nonexistent MACIP ACL %d (tag %s)",
	     *acl_list_index, tag);
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
	}
    }

  if (0 == count)
    {
      clib_warning
	("acl-plugin-warning: Trying to create empty MACIP ACL (tag %s)",
	 tag);
    }
  void *oldheap = acl_set_heap (am);
  /* Create and populate the rules */
  if (count > 0)
    vec_validate (acl_new_rules, count - 1);

  for (i = 0; i < count; i++)
    {
      r = &acl_new_rules[i];
      r->is_permit = rules[i].is_permit;
      r->is_ipv6 = rules[i].is_ipv6;
      memcpy (&r->src_mac, rules[i].src_mac, 6);
      memcpy (&r->src_mac_mask, rules[i].src_mac_mask, 6);
      if (rules[i].is_ipv6)
	memcpy (&r->src_ip_addr.ip6, rules[i].src_ip_addr, 16);
      else
	memcpy (&r->src_ip_addr.ip4, rules[i].src_ip_addr, 4);
      r->src_prefixlen = rules[i].src_ip_prefix_len;
    }

  if (~0 == *acl_list_index)
    {
      /* Get ACL index */
      pool_get_aligned (am->macip_acls, a, CLIB_CACHE_LINE_BYTES);
      memset (a, 0, sizeof (*a));
      /* Will return the newly allocated ACL index */
      *acl_list_index = a - am->macip_acls;
    }
  else
    {
      a = pool_elt_at_index (am->macip_acls, *acl_list_index);
      if (a->rules)
	{
	  vec_free (a->rules);
	}
      macip_destroy_classify_tables (am, *acl_list_index);
    }

  a->rules = acl_new_rules;
  a->count = count;
  memcpy (a->tag, tag, sizeof (a->tag));

  /* Create and populate the classifer tables */
  macip_create_classify_tables (am, *acl_list_index);
  clib_mem_set_heap (oldheap);
  return 0;
}


/* No check for validity of sw_if_index - the callers were supposed to validate */

static int
macip_acl_interface_del_acl (acl_main_t * am, u32 sw_if_index)
{
  int rv;
  u32 macip_acl_index;
  macip_acl_list_t *a;
  void *oldheap = acl_set_heap (am);
  vec_validate_init_empty (am->macip_acl_by_sw_if_index, sw_if_index, ~0);
  clib_mem_set_heap (oldheap);
  macip_acl_index = am->macip_acl_by_sw_if_index[sw_if_index];
  /* No point in deleting MACIP ACL which is not applied */
  if (~0 == macip_acl_index)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  a = pool_elt_at_index (am->macip_acls, macip_acl_index);
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
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
  void *oldheap = acl_set_heap (am);
  a = pool_elt_at_index (am->macip_acls, macip_acl_index);
  vec_validate_init_empty (am->macip_acl_by_sw_if_index, sw_if_index, ~0);
  clib_mem_set_heap (oldheap);
  /* If there already a MACIP ACL applied, unapply it */
  if (~0 != am->macip_acl_by_sw_if_index[sw_if_index])
    macip_acl_interface_del_acl (am, sw_if_index);
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
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  /* delete any references to the ACL */
  for (i = 0; i < vec_len (am->macip_acl_by_sw_if_index); i++)
    {
      if (am->macip_acl_by_sw_if_index[i] == acl_list_index)
	{
	  macip_acl_interface_del_acl (am, i);
	}
    }

  void *oldheap = acl_set_heap (am);
  /* Now that classifier tables are detached, clean them up */
  macip_destroy_classify_tables (am, acl_list_index);

  /* now we can delete the ACL itself */
  a = pool_elt_at_index (am->macip_acls, acl_list_index);
  if (a->rules)
    {
      vec_free (a->rules);
    }
  pool_put (am->macip_acls, a);
  clib_mem_set_heap (oldheap);
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

/*
 * If the client does not allocate enough memory for a variable-length
 * message, and then proceed to use it as if the full memory allocated,
 * absent the check we happily consume that on the VPP side, and go
 * along as if nothing happened. However, the resulting
 * effects range from just garbage in the API decode
 * (because the decoder snoops too far), to potential memory
 * corruptions.
 *
 * This verifies that the actual length of the message is
 * at least expected_len, and complains loudly if it is not.
 *
 * A failing check here is 100% a software bug on the API user side,
 * so we might as well yell.
 *
 */
static int
verify_message_len (void *mp, u32 expected_len, char *where)
{
  u32 supplied_len = vl_msg_api_get_msg_length (mp);
  if (supplied_len < expected_len)
    {
      clib_warning ("%s: Supplied message length %d is less than expected %d",
		    where, supplied_len, expected_len);
      return 0;
    }
  else
    {
      return 1;
    }
}

/* API message handler */
static void
vl_api_acl_add_replace_t_handler (vl_api_acl_add_replace_t * mp)
{
  vl_api_acl_add_replace_reply_t *rmp;
  acl_main_t *am = &acl_main;
  int rv;
  u32 acl_list_index = ntohl (mp->acl_index);
  u32 acl_count = ntohl (mp->count);
  u32 expected_len = sizeof (*mp) + acl_count * sizeof (mp->r[0]);

  if (verify_message_len (mp, expected_len, "acl_add_replace"))
    {
      rv = acl_add_list (acl_count, mp->r, &acl_list_index, mp->tag);
    }
  else
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
    }

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
  acl_main_t *am = &acl_main;
  vl_api_acl_del_reply_t *rmp;
  int rv;

  rv = acl_del_list (ntohl (mp->acl_index));

  REPLY_MACRO (VL_API_ACL_DEL_REPLY);
}

static void
vl_api_acl_interface_add_del_t_handler (vl_api_acl_interface_add_del_t * mp)
{
  acl_main_t *am = &acl_main;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  vl_api_acl_interface_add_del_reply_t *rmp;
  int rv = -1;

  if (pool_is_free_index (im->sw_interfaces, sw_if_index))
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
  acl_main_t *am = &acl_main;
  vl_api_acl_interface_set_acl_list_reply_t *rmp;
  int rv = 0;
  int i;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (pool_is_free_index (im->sw_interfaces, sw_if_index))
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  else
    {
      acl_interface_reset_inout_acls (sw_if_index, 0);
      acl_interface_reset_inout_acls (sw_if_index, 1);

      for (i = 0; i < mp->count; i++)
	{
	  if (acl_is_not_defined (am, ntohl (mp->acls[i])))
	    {
	      /* ACL does not exist, so we can not apply it */
	      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	    }
	}
      if (0 == rv)
	{
	  for (i = 0; i < mp->count; i++)
	    {
	      acl_interface_add_del_inout_acl (sw_if_index, 1,
					       (i < mp->n_input),
					       ntohl (mp->acls[i]));
	    }
	}
    }

  REPLY_MACRO (VL_API_ACL_INTERFACE_SET_ACL_LIST_REPLY);
}

static void
copy_acl_rule_to_api_rule (vl_api_acl_rule_t * api_rule, acl_rule_t * r)
{
  api_rule->is_permit = r->is_permit;
  api_rule->is_ipv6 = r->is_ipv6;
  if (r->is_ipv6)
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
  api_rule->srcport_or_icmptype_first = htons (r->src_port_or_type_first);
  api_rule->srcport_or_icmptype_last = htons (r->src_port_or_type_last);
  api_rule->dstport_or_icmpcode_first = htons (r->dst_port_or_code_first);
  api_rule->dstport_or_icmpcode_last = htons (r->dst_port_or_code_last);
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
  void *oldheap = acl_set_heap (am);

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

  clib_mem_set_heap (oldheap);
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
	  acl = pool_elt_at_index (am->acls, acl_index);
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
  void *oldheap = acl_set_heap (am);

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
  clib_mem_set_heap (oldheap);
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
      if (!pool_is_free_index (im->sw_interfaces, sw_if_index))
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
  u32 acl_count = ntohl (mp->count);
  u32 expected_len = sizeof (*mp) + acl_count * sizeof (mp->r[0]);

  if (verify_message_len (mp, expected_len, "macip_acl_add"))
    {
      rv = macip_acl_add_list (acl_count, mp->r, &acl_list_index, mp->tag);
    }
  else
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MACIP_ACL_ADD_REPLY,
  ({
    rmp->acl_index = htonl(acl_list_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_macip_acl_add_replace_t_handler (vl_api_macip_acl_add_replace_t * mp)
{
  vl_api_macip_acl_add_replace_reply_t *rmp;
  acl_main_t *am = &acl_main;
  int rv;
  u32 acl_list_index = ntohl (mp->acl_index);
  u32 acl_count = ntohl (mp->count);
  u32 expected_len = sizeof (*mp) + acl_count * sizeof (mp->r[0]);

  if (verify_message_len (mp, expected_len, "macip_acl_add_replace"))
    {
      rv = macip_acl_add_list (acl_count, mp->r, &acl_list_index, mp->tag);
    }
  else
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MACIP_ACL_ADD_REPLACE_REPLY,
  ({
    rmp->acl_index = htonl(acl_list_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_macip_acl_del_t_handler (vl_api_macip_acl_del_t * mp)
{
  acl_main_t *am = &acl_main;
  vl_api_macip_acl_del_reply_t *rmp;
  int rv;

  rv = macip_acl_del_list (ntohl (mp->acl_index));

  REPLY_MACRO (VL_API_MACIP_ACL_DEL_REPLY);
}

static void
  vl_api_macip_acl_interface_add_del_t_handler
  (vl_api_macip_acl_interface_add_del_t * mp)
{
  acl_main_t *am = &acl_main;
  vl_api_macip_acl_interface_add_del_reply_t *rmp;
  int rv = -1;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (pool_is_free_index (im->sw_interfaces, sw_if_index))
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
	  acl = pool_elt_at_index (am->macip_acls, acl_index);
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

static void
send_macip_acl_interface_list_details (acl_main_t * am,
				       unix_shared_memory_queue_t * q,
				       u32 sw_if_index,
				       u32 acl_index, u32 context)
{
  vl_api_macip_acl_interface_list_details_t *rmp;
  /* at this time there is only ever 1 mac ip acl per interface */
  int msg_size = sizeof (*rmp) + sizeof (rmp->acls[0]);

  rmp = vl_msg_api_alloc (msg_size);
  memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_MACIP_ACL_INTERFACE_LIST_DETAILS + am->msg_id_base);

  /* fill in the message */
  rmp->context = context;
  rmp->count = 1;
  rmp->sw_if_index = htonl (sw_if_index);
  rmp->acls[0] = htonl (acl_index);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
  vl_api_macip_acl_interface_list_dump_t_handler
  (vl_api_macip_acl_interface_list_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  acl_main_t *am = &acl_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  if (sw_if_index == ~0)
    {
      vec_foreach_index (sw_if_index, am->macip_acl_by_sw_if_index)
      {
	if (~0 != am->macip_acl_by_sw_if_index[sw_if_index])
	  {
	    send_macip_acl_interface_list_details (am, q, sw_if_index,
						   am->macip_acl_by_sw_if_index
						   [sw_if_index],
						   mp->context);
	  }
      }
    }
  else
    {
      if (vec_len (am->macip_acl_by_sw_if_index) > sw_if_index)
	{
	  send_macip_acl_interface_list_details (am, q, sw_if_index,
						 am->macip_acl_by_sw_if_index
						 [sw_if_index], mp->context);
	}
    }
}

/* Set up the API message handling tables */
static clib_error_t *
acl_plugin_api_hookup (vlib_main_t * vm)
{
  acl_main_t *am = &acl_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + am->msg_id_base),     \
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
setup_message_id_table (acl_main_t * am, api_main_t * apim)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (apim, #n "_" #crc, id + am->msg_id_base);
  foreach_vl_msg_name_crc_acl;
#undef _
}

static void
acl_setup_fa_nodes (void)
{
  vlib_main_t *vm = vlib_get_main ();
  acl_main_t *am = &acl_main;
  vlib_node_t *n, *n4, *n6;

  n = vlib_get_node_by_name (vm, (u8 *) "l2-input-classify");
  n4 = vlib_get_node_by_name (vm, (u8 *) "acl-plugin-in-ip4-l2");
  n6 = vlib_get_node_by_name (vm, (u8 *) "acl-plugin-in-ip6-l2");


  am->l2_input_classify_next_acl_ip4 =
    vlib_node_add_next_with_slot (vm, n->index, n4->index, ~0);
  am->l2_input_classify_next_acl_ip6 =
    vlib_node_add_next_with_slot (vm, n->index, n6->index, ~0);

  feat_bitmap_init_next_nodes (vm, n4->index, L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       am->fa_acl_in_ip4_l2_node_feat_next_node_index);

  feat_bitmap_init_next_nodes (vm, n6->index, L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       am->fa_acl_in_ip6_l2_node_feat_next_node_index);


  n = vlib_get_node_by_name (vm, (u8 *) "l2-output-classify");
  n4 = vlib_get_node_by_name (vm, (u8 *) "acl-plugin-out-ip4-l2");
  n6 = vlib_get_node_by_name (vm, (u8 *) "acl-plugin-out-ip6-l2");

  am->l2_output_classify_next_acl_ip4 =
    vlib_node_add_next_with_slot (vm, n->index, n4->index, ~0);
  am->l2_output_classify_next_acl_ip6 =
    vlib_node_add_next_with_slot (vm, n->index, n6->index, ~0);

  feat_bitmap_init_next_nodes (vm, n4->index, L2OUTPUT_N_FEAT,
			       l2output_get_feat_names (),
			       am->fa_acl_out_ip4_l2_node_feat_next_node_index);

  feat_bitmap_init_next_nodes (vm, n6->index, L2OUTPUT_N_FEAT,
			       l2output_get_feat_names (),
			       am->fa_acl_out_ip6_l2_node_feat_next_node_index);
}

static void
acl_set_timeout_sec (int timeout_type, u32 value)
{
  acl_main_t *am = &acl_main;
  clib_time_t *ct = &am->vlib_main->clib_time;

  if (timeout_type < ACL_N_TIMEOUTS)
    {
      am->session_timeout_sec[timeout_type] = value;
    }
  else
    {
      clib_warning ("Unknown timeout type %d", timeout_type);
      return;
    }
  am->session_timeout[timeout_type] =
    (u64) (((f64) value) / ct->seconds_per_clock);
}

static void
acl_set_session_max_entries (u32 value)
{
  acl_main_t *am = &acl_main;
  am->fa_conn_table_max_entries = value;
}

static int
acl_set_skip_ipv6_eh (u32 eh, u32 value)
{
  acl_main_t *am = &acl_main;

  if ((eh < 256) && (value < 2))
    {
      am->fa_ipv6_known_eh_bitmap =
	clib_bitmap_set (am->fa_ipv6_known_eh_bitmap, eh, value);
      return 1;
    }
  else
    return 0;
}


static clib_error_t *
acl_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  acl_main_t *am = &acl_main;
  if (0 == am->acl_mheap)
    {
      /* ACL heap is not initialized, so definitely nothing to do. */
      return 0;
    }
  if (0 == is_add)
    {
      vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
				 ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX,
				 sw_if_index);
      /* also unapply any ACLs in case the users did not do so. */
      macip_acl_interface_del_acl (am, sw_if_index);
      acl_interface_reset_inout_acls (sw_if_index, 0);
      acl_interface_reset_inout_acls (sw_if_index, 1);
    }
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (acl_sw_interface_add_del);



static clib_error_t *
acl_set_aclplugin_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  u32 timeout = 0;
  u32 val = 0;
  u32 eh_val = 0;
  uword memory_size = 0;
  acl_main_t *am = &acl_main;

  if (unformat (input, "skip-ipv6-extension-header %u %u", &eh_val, &val))
    {
      if (!acl_set_skip_ipv6_eh (eh_val, val))
	{
	  error = clib_error_return (0, "expecting eh=0..255, value=0..1");
	}
      goto done;
    }
  if (unformat (input, "use-hash-acl-matching %u", &val))
    {
      am->use_hash_acl_matching = (val != 0);
      goto done;
    }
  if (unformat (input, "l4-match-nonfirst-fragment %u", &val))
    {
      am->l4_match_nonfirst_fragment = (val != 0);
      goto done;
    }
  if (unformat (input, "heap"))
    {
      if (unformat (input, "main"))
	{
	  if (unformat (input, "validate %u", &val))
	    acl_plugin_acl_set_validate_heap (am, val);
	  else if (unformat (input, "trace %u", &val))
	    acl_plugin_acl_set_trace_heap (am, val);
	  goto done;
	}
      else if (unformat (input, "hash"))
	{
	  if (unformat (input, "validate %u", &val))
	    acl_plugin_hash_acl_set_validate_heap (am, val);
	  else if (unformat (input, "trace %u", &val))
	    acl_plugin_hash_acl_set_trace_heap (am, val);
	  goto done;
	}
      goto done;
    }
  if (unformat (input, "session"))
    {
      if (unformat (input, "table"))
	{
	  /* The commands here are for tuning/testing. No user-serviceable parts inside */
	  if (unformat (input, "max-entries"))
	    {
	      if (!unformat (input, "%u", &val))
		{
		  error = clib_error_return (0,
					     "expecting maximum number of entries, got `%U`",
					     format_unformat_error, input);
		  goto done;
		}
	      else
		{
		  acl_set_session_max_entries (val);
		  goto done;
		}
	    }
	  if (unformat (input, "hash-table-buckets"))
	    {
	      if (!unformat (input, "%u", &val))
		{
		  error = clib_error_return (0,
					     "expecting maximum number of hash table buckets, got `%U`",
					     format_unformat_error, input);
		  goto done;
		}
	      else
		{
		  am->fa_conn_table_hash_num_buckets = val;
		  goto done;
		}
	    }
	  if (unformat (input, "hash-table-memory"))
	    {
	      if (!unformat (input, "%U", unformat_memory_size, &memory_size))
		{
		  error = clib_error_return (0,
					     "expecting maximum amount of hash table memory, got `%U`",
					     format_unformat_error, input);
		  goto done;
		}
	      else
		{
		  am->fa_conn_table_hash_memory_size = memory_size;
		  goto done;
		}
	    }
	  goto done;
	}
      if (unformat (input, "timeout"))
	{
	  if (unformat (input, "udp"))
	    {
	      if (unformat (input, "idle"))
		{
		  if (!unformat (input, "%u", &timeout))
		    {
		      error = clib_error_return (0,
						 "expecting timeout value in seconds, got `%U`",
						 format_unformat_error,
						 input);
		      goto done;
		    }
		  else
		    {
		      acl_set_timeout_sec (ACL_TIMEOUT_UDP_IDLE, timeout);
		      goto done;
		    }
		}
	    }
	  if (unformat (input, "tcp"))
	    {
	      if (unformat (input, "idle"))
		{
		  if (!unformat (input, "%u", &timeout))
		    {
		      error = clib_error_return (0,
						 "expecting timeout value in seconds, got `%U`",
						 format_unformat_error,
						 input);
		      goto done;
		    }
		  else
		    {
		      acl_set_timeout_sec (ACL_TIMEOUT_TCP_IDLE, timeout);
		      goto done;
		    }
		}
	      if (unformat (input, "transient"))
		{
		  if (!unformat (input, "%u", &timeout))
		    {
		      error = clib_error_return (0,
						 "expecting timeout value in seconds, got `%U`",
						 format_unformat_error,
						 input);
		      goto done;
		    }
		  else
		    {
		      acl_set_timeout_sec (ACL_TIMEOUT_TCP_TRANSIENT,
					   timeout);
		      goto done;
		    }
		}
	    }
	  goto done;
	}
    }
done:
  return error;
}

static u8 *
my_format_mac_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		 a[0], a[1], a[2], a[3], a[4], a[5]);
}

static inline u8 *
my_macip_acl_rule_t_pretty_format (u8 * out, va_list * args)
{
  macip_acl_rule_t *a = va_arg (*args, macip_acl_rule_t *);

  out = format (out, "%s action %d ip %U/%d mac %U mask %U",
		a->is_ipv6 ? "ipv6" : "ipv4", a->is_permit,
		format_ip46_address, &a->src_ip_addr,
		a->is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		a->src_prefixlen,
		my_format_mac_address, a->src_mac,
		my_format_mac_address, a->src_mac_mask);
  return (out);
}

static void
macip_acl_print (acl_main_t * am, u32 macip_acl_index)
{
  vlib_main_t *vm = am->vlib_main;
  int i;

  /* Don't try to print someone else's memory */
  if (macip_acl_index > vec_len (am->macip_acls))
    return;

  macip_acl_list_t *a = vec_elt_at_index (am->macip_acls, macip_acl_index);
  int free_pool_slot = pool_is_free_index (am->macip_acls, macip_acl_index);

  vlib_cli_output (vm,
		   "MACIP acl_index: %d, count: %d (true len %d) tag {%s} is free pool slot: %d\n",
		   macip_acl_index, a->count, vec_len (a->rules), a->tag,
		   free_pool_slot);
  vlib_cli_output (vm,
		   "  ip4_table_index %d, ip6_table_index %d, l2_table_index %d\n",
		   a->ip4_table_index, a->ip6_table_index, a->l2_table_index);
  for (i = 0; i < vec_len (a->rules); i++)
    vlib_cli_output (vm, "    rule %d: %U\n", i,
		     my_macip_acl_rule_t_pretty_format,
		     vec_elt_at_index (a->rules, i));

}

static clib_error_t *
acl_show_aclplugin_macip_acl_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;
  int i;
  for (i = 0; i < vec_len (am->macip_acls); i++)
    macip_acl_print (am, i);
  return error;
}

static clib_error_t *
acl_show_aclplugin_macip_interface_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;
  int i;
  for (i = 0; i < vec_len (am->macip_acl_by_sw_if_index); i++)
    {
      vlib_cli_output (vm, "  sw_if_index %d: %d\n", i,
		       vec_elt (am->macip_acl_by_sw_if_index, i));
    }
  return error;
}

#define PRINT_AND_RESET(vm, out0) do { vlib_cli_output(vm, "%v", out0); vec_reset_length(out0); } while(0)
static void
acl_print_acl (vlib_main_t * vm, acl_main_t * am, int acl_index)
{
  acl_rule_t *r;
  u8 *out0 = format (0, "acl-index %u count %u tag {%s}\n", acl_index,
		     am->acls[acl_index].count, am->acls[acl_index].tag);
  int j;
  PRINT_AND_RESET (vm, out0);
  for (j = 0; j < am->acls[acl_index].count; j++)
    {
      r = &am->acls[acl_index].rules[j];
      out0 = format (out0, "  %4d: %s ", j, r->is_ipv6 ? "ipv6" : "ipv4");
      out0 = format_acl_action (out0, r->is_permit);
      out0 = format (out0, " src %U/%d", format_ip46_address, &r->src,
		     r->is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     r->src_prefixlen);
      out0 =
	format (out0, " dst %U/%d", format_ip46_address, &r->dst,
		r->is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4, r->dst_prefixlen);
      out0 = format (out0, " proto %d", r->proto);
      out0 = format (out0, " sport %d", r->src_port_or_type_first);
      if (r->src_port_or_type_first != r->src_port_or_type_last)
	{
	  out0 = format (out0, "-%d", r->src_port_or_type_last);
	}
      out0 = format (out0, " dport %d", r->dst_port_or_code_first);
      if (r->dst_port_or_code_first != r->dst_port_or_code_last)
	{
	  out0 = format (out0, "-%d", r->dst_port_or_code_last);
	}
      if (r->tcp_flags_mask || r->tcp_flags_value)
	{
	  out0 =
	    format (out0, " tcpflags %d mask %d", r->tcp_flags_value,
		    r->tcp_flags_mask);
	}
      out0 = format (out0, "\n");
      PRINT_AND_RESET (vm, out0);
    }
}

#undef PRINT_AND_RESET

static void
acl_plugin_show_acl (acl_main_t * am, u32 acl_index)
{
  u32 i;
  vlib_main_t *vm = am->vlib_main;

  for (i = 0; i < vec_len (am->acls); i++)
    {
      if (acl_is_not_defined (am, i))
	{
	  /* don't attempt to show the ACLs that do not exist */
	  continue;
	}
      if ((acl_index != ~0) && (acl_index != i))
	{
	  continue;
	}
      acl_print_acl (vm, am, i);

      if (i < vec_len (am->input_sw_if_index_vec_by_acl))
	{
	  vlib_cli_output (vm, "  applied inbound on sw_if_index: %U\n",
			   format_vec32, am->input_sw_if_index_vec_by_acl[i],
			   "%d");
	}
      if (i < vec_len (am->output_sw_if_index_vec_by_acl))
	{
	  vlib_cli_output (vm, "  applied outbound on sw_if_index: %U\n",
			   format_vec32, am->output_sw_if_index_vec_by_acl[i],
			   "%d");
	}
    }
}

static clib_error_t *
acl_show_aclplugin_acl_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;

  u32 acl_index = ~0;
  (void) unformat (input, "index %u", &acl_index);

  acl_plugin_show_acl (am, acl_index);
  return error;
}

static void
acl_plugin_show_interface (acl_main_t * am, u32 sw_if_index, int show_acl)
{
  vlib_main_t *vm = am->vlib_main;
  u32 swi;
  u32 *pj;
  for (swi = 0; (swi < vec_len (am->input_acl_vec_by_sw_if_index)) ||
       (swi < vec_len (am->output_acl_vec_by_sw_if_index)); swi++)
    {
      /* if we need a particular interface, skip all the others */
      if ((sw_if_index != ~0) && (sw_if_index != swi))
	continue;

      vlib_cli_output (vm, "sw_if_index %d:\n", swi);

      if ((swi < vec_len (am->input_acl_vec_by_sw_if_index)) &&
	  (vec_len (am->input_acl_vec_by_sw_if_index[swi]) > 0))
	{
	  vlib_cli_output (vm, "  input acl(s): %U", format_vec32,
			   am->input_acl_vec_by_sw_if_index[swi], "%d");
	  if (show_acl)
	    {
	      vlib_cli_output (vm, "\n");
	      vec_foreach (pj, am->input_acl_vec_by_sw_if_index[swi])
	      {
		acl_print_acl (vm, am, *pj);
	      }
	      vlib_cli_output (vm, "\n");
	    }
	}

      if ((swi < vec_len (am->output_acl_vec_by_sw_if_index)) &&
	  (vec_len (am->output_acl_vec_by_sw_if_index[swi]) > 0))
	{
	  vlib_cli_output (vm, "  output acl(s): %U", format_vec32,
			   am->output_acl_vec_by_sw_if_index[swi], "%d");
	  if (show_acl)
	    {
	      vlib_cli_output (vm, "\n");
	      vec_foreach (pj, am->output_acl_vec_by_sw_if_index[swi])
	      {
		acl_print_acl (vm, am, *pj);
	      }
	      vlib_cli_output (vm, "\n");
	    }
	}
    }

}

static clib_error_t *
acl_show_aclplugin_interface_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;

  u32 sw_if_index = ~0;
  (void) unformat (input, "sw_if_index %u", &sw_if_index);
  int show_acl = unformat (input, "acl");

  acl_plugin_show_interface (am, sw_if_index, show_acl);
  return error;
}

static clib_error_t *
acl_show_aclplugin_memory_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;

  vlib_cli_output (vm, "ACL plugin main heap statistics:\n");
  if (am->acl_mheap)
    {
      vlib_cli_output (vm, " %U\n", format_mheap, am->acl_mheap, 1);
    }
  else
    {
      vlib_cli_output (vm, " Not initialized\n");
    }
  vlib_cli_output (vm, "ACL hash lookup support heap statistics:\n");
  if (am->hash_lookup_mheap)
    {
      vlib_cli_output (vm, " %U\n", format_mheap, am->hash_lookup_mheap, 1);
    }
  else
    {
      vlib_cli_output (vm, " Not initialized\n");
    }
  return error;
}

static void
acl_plugin_show_sessions (acl_main_t * am,
			  u32 show_session_thread_id,
			  u32 show_session_session_index)
{
  vlib_main_t *vm = am->vlib_main;
  u16 wk;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;
  vnet_sw_interface_t *swif;

  {
    u64 n_adds = am->fa_session_total_adds;
    u64 n_dels = am->fa_session_total_dels;
    vlib_cli_output (vm, "Sessions total: add %lu - del %lu = %lu", n_adds,
		     n_dels, n_adds - n_dels);
  }
  vlib_cli_output (vm, "\n\nPer-thread data:");
  for (wk = 0; wk < vec_len (am->per_worker_data); wk++)
    {
      acl_fa_per_worker_data_t *pw = &am->per_worker_data[wk];
      vlib_cli_output (vm, "Thread #%d:", wk);
      if (show_session_thread_id == wk
	  && show_session_session_index < pool_len (pw->fa_sessions_pool))
	{
	  vlib_cli_output (vm, "  session index %u:",
			   show_session_session_index);
	  fa_session_t *sess =
	    pw->fa_sessions_pool + show_session_session_index;
	  u64 *m = (u64 *) & sess->info;
	  vlib_cli_output (vm,
			   "    info: %016llx %016llx %016llx %016llx %016llx %016llx",
			   m[0], m[1], m[2], m[3], m[4], m[5]);
	  vlib_cli_output (vm, "    sw_if_index: %u", sess->sw_if_index);
	  vlib_cli_output (vm, "    tcp_flags_seen: %x",
			   sess->tcp_flags_seen.as_u16);
	  vlib_cli_output (vm, "    last active time: %lu",
			   sess->last_active_time);
	  vlib_cli_output (vm, "    thread index: %u", sess->thread_index);
	  vlib_cli_output (vm, "    link enqueue time: %lu",
			   sess->link_enqueue_time);
	  vlib_cli_output (vm, "    link next index: %u",
			   sess->link_next_idx);
	  vlib_cli_output (vm, "    link prev index: %u",
			   sess->link_prev_idx);
	  vlib_cli_output (vm, "    link list id: %u", sess->link_list_id);
	}
      vlib_cli_output (vm, "  connection add/del stats:", wk);
      pool_foreach (swif, im->sw_interfaces, (
					       {
					       u32 sw_if_index =
					       swif->sw_if_index;
					       u64 n_adds =
					       sw_if_index <
					       vec_len
					       (pw->fa_session_adds_by_sw_if_index)
					       ?
					       pw->fa_session_adds_by_sw_if_index
					       [sw_if_index] : 0;
					       u64 n_dels =
					       sw_if_index <
					       vec_len
					       (pw->fa_session_dels_by_sw_if_index)
					       ?
					       pw->fa_session_dels_by_sw_if_index
					       [sw_if_index] : 0;
					       vlib_cli_output (vm,
								"    sw_if_index %d: add %lu - del %lu = %lu",
								sw_if_index,
								n_adds,
								n_dels,
								n_adds -
								n_dels);
					       }
		    ));

      vlib_cli_output (vm, "  connection timeout type lists:", wk);
      u8 tt = 0;
      for (tt = 0; tt < ACL_N_TIMEOUTS; tt++)
	{
	  u32 head_session_index = pw->fa_conn_list_head[tt];
	  vlib_cli_output (vm, "  fa_conn_list_head[%d]: %d", tt,
			   head_session_index);
	  if (~0 != head_session_index)
	    {
	      fa_session_t *sess = pw->fa_sessions_pool + head_session_index;
	      vlib_cli_output (vm, "    last active time: %lu",
			       sess->last_active_time);
	      vlib_cli_output (vm, "    link enqueue time: %lu",
			       sess->link_enqueue_time);
	    }
	}

      vlib_cli_output (vm, "  Next expiry time: %lu", pw->next_expiry_time);
      vlib_cli_output (vm, "  Requeue until time: %lu",
		       pw->requeue_until_time);
      vlib_cli_output (vm, "  Current time wait interval: %lu",
		       pw->current_time_wait_interval);
      vlib_cli_output (vm, "  Count of deleted sessions: %lu",
		       pw->cnt_deleted_sessions);
      vlib_cli_output (vm, "  Delete already deleted: %lu",
		       pw->cnt_already_deleted_sessions);
      vlib_cli_output (vm, "  Session timers restarted: %lu",
		       pw->cnt_session_timer_restarted);
      vlib_cli_output (vm, "  Swipe until this time: %lu",
		       pw->swipe_end_time);
      vlib_cli_output (vm, "  sw_if_index serviced bitmap: %U",
		       format_bitmap_hex, pw->serviced_sw_if_index_bitmap);
      vlib_cli_output (vm, "  pending clear intfc bitmap : %U",
		       format_bitmap_hex,
		       pw->pending_clear_sw_if_index_bitmap);
      vlib_cli_output (vm, "  clear in progress: %u", pw->clear_in_process);
      vlib_cli_output (vm, "  interrupt is pending: %d",
		       pw->interrupt_is_pending);
      vlib_cli_output (vm, "  interrupt is needed: %d",
		       pw->interrupt_is_needed);
      vlib_cli_output (vm, "  interrupt is unwanted: %d",
		       pw->interrupt_is_unwanted);
      vlib_cli_output (vm, "  interrupt generation: %d",
		       pw->interrupt_generation);
    }
  vlib_cli_output (vm, "\n\nConn cleaner thread counters:");
#define _(cnt, desc) vlib_cli_output(vm, "             %20lu: %s", am->cnt, desc);
  foreach_fa_cleaner_counter;
#undef _
  vlib_cli_output (vm, "Interrupt generation: %d",
		   am->fa_interrupt_generation);
  vlib_cli_output (vm,
		   "Sessions per interval: min %lu max %lu increment: %f ms current: %f ms",
		   am->fa_min_deleted_sessions_per_interval,
		   am->fa_max_deleted_sessions_per_interval,
		   am->fa_cleaner_wait_time_increment * 1000.0,
		   ((f64) am->fa_current_cleaner_timer_wait_interval) *
		   1000.0 / (f64) vm->clib_time.clocks_per_second);
}

static clib_error_t *
acl_show_aclplugin_sessions_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;

  u32 show_bihash_verbose = 0;
  u32 show_session_thread_id = ~0;
  u32 show_session_session_index = ~0;
  (void) unformat (input, "thread %u index %u", &show_session_thread_id,
		   &show_session_session_index);
  (void) unformat (input, "verbose %u", &show_bihash_verbose);

  acl_plugin_show_sessions (am, show_session_thread_id,
			    show_session_session_index);
  show_fa_sessions_hash (vm, show_bihash_verbose);
  return error;
}

static void
acl_plugin_show_tables_mask_type (acl_main_t * am)
{
  vlib_main_t *vm = am->vlib_main;
  ace_mask_type_entry_t *mte;

  vlib_cli_output (vm, "Mask-type entries:");
    /* *INDENT-OFF* */
    pool_foreach(mte, am->ace_mask_type_pool,
    ({
      vlib_cli_output(vm, "     %3d: %016llx %016llx %016llx %016llx %016llx %016llx  refcount %d",
		    mte - am->ace_mask_type_pool,
		    mte->mask.kv.key[0], mte->mask.kv.key[1], mte->mask.kv.key[2],
		    mte->mask.kv.key[3], mte->mask.kv.key[4], mte->mask.kv.value, mte->refcount);
    }));
    /* *INDENT-ON* */
}

static void
acl_plugin_show_tables_acl_hash_info (acl_main_t * am, u32 acl_index)
{
  vlib_main_t *vm = am->vlib_main;
  u32 i, j;
  u64 *m;
  vlib_cli_output (vm, "Mask-ready ACL representations\n");
  for (i = 0; i < vec_len (am->hash_acl_infos); i++)
    {
      if ((acl_index != ~0) && (acl_index != i))
	{
	  continue;
	}
      hash_acl_info_t *ha = &am->hash_acl_infos[i];
      vlib_cli_output (vm, "acl-index %u bitmask-ready layout\n", i);
      vlib_cli_output (vm, "  applied  inbound on sw_if_index list: %U\n",
		       format_vec32, ha->inbound_sw_if_index_list, "%d");
      vlib_cli_output (vm, "  applied outbound on sw_if_index list: %U\n",
		       format_vec32, ha->outbound_sw_if_index_list, "%d");
      vlib_cli_output (vm, "  mask type index bitmap: %U\n",
		       format_bitmap_hex, ha->mask_type_index_bitmap);
      for (j = 0; j < vec_len (ha->rules); j++)
	{
	  hash_ace_info_t *pa = &ha->rules[j];
	  m = (u64 *) & pa->match;
	  vlib_cli_output (vm,
			   "    %4d: %016llx %016llx %016llx %016llx %016llx %016llx mask index %d acl %d rule %d action %d src/dst portrange not ^2: %d,%d\n",
			   j, m[0], m[1], m[2], m[3], m[4], m[5],
			   pa->mask_type_index, pa->acl_index, pa->ace_index,
			   pa->action, pa->src_portrange_not_powerof2,
			   pa->dst_portrange_not_powerof2);
	}
    }
}

static void
acl_plugin_print_pae (vlib_main_t * vm, int j, applied_hash_ace_entry_t * pae)
{
  vlib_cli_output (vm,
		   "    %4d: acl %d rule %d action %d bitmask-ready rule %d next %d prev %d tail %d hitcount %lld",
		   j, pae->acl_index, pae->ace_index, pae->action,
		   pae->hash_ace_info_index, pae->next_applied_entry_index,
		   pae->prev_applied_entry_index,
		   pae->tail_applied_entry_index, pae->hitcount);
}

static void
acl_plugin_show_tables_applied_info (acl_main_t * am, u32 sw_if_index)
{
  vlib_main_t *vm = am->vlib_main;
  u32 swi, j;
  vlib_cli_output (vm, "Applied lookup entries for interfaces");

  for (swi = 0;
       (swi < vec_len (am->input_applied_hash_acl_info_by_sw_if_index))
       || (swi < vec_len (am->output_applied_hash_acl_info_by_sw_if_index))
       || (swi < vec_len (am->input_hash_entry_vec_by_sw_if_index))
       || (swi < vec_len (am->output_hash_entry_vec_by_sw_if_index)); swi++)
    {
      if ((sw_if_index != ~0) && (sw_if_index != swi))
	{
	  continue;
	}
      vlib_cli_output (vm, "sw_if_index %d:", swi);
      if (swi < vec_len (am->input_applied_hash_acl_info_by_sw_if_index))
	{
	  applied_hash_acl_info_t *pal =
	    &am->input_applied_hash_acl_info_by_sw_if_index[swi];
	  vlib_cli_output (vm, "  input lookup mask_type_index_bitmap: %U",
			   format_bitmap_hex, pal->mask_type_index_bitmap);
	  vlib_cli_output (vm, "  input applied acls: %U", format_vec32,
			   pal->applied_acls, "%d");
	}
      if (swi < vec_len (am->input_hash_entry_vec_by_sw_if_index))
	{
	  vlib_cli_output (vm, "  input lookup applied entries:");
	  for (j = 0;
	       j < vec_len (am->input_hash_entry_vec_by_sw_if_index[swi]);
	       j++)
	    {
	      acl_plugin_print_pae (vm, j,
				    &am->input_hash_entry_vec_by_sw_if_index
				    [swi][j]);
	    }
	}

      if (swi < vec_len (am->output_applied_hash_acl_info_by_sw_if_index))
	{
	  applied_hash_acl_info_t *pal =
	    &am->output_applied_hash_acl_info_by_sw_if_index[swi];
	  vlib_cli_output (vm, "  output lookup mask_type_index_bitmap: %U",
			   format_bitmap_hex, pal->mask_type_index_bitmap);
	  vlib_cli_output (vm, "  output applied acls: %U", format_vec32,
			   pal->applied_acls, "%d");
	}
      if (swi < vec_len (am->output_hash_entry_vec_by_sw_if_index))
	{
	  vlib_cli_output (vm, "  output lookup applied entries:");
	  for (j = 0;
	       j < vec_len (am->output_hash_entry_vec_by_sw_if_index[swi]);
	       j++)
	    {
	      acl_plugin_print_pae (vm, j,
				    &am->output_hash_entry_vec_by_sw_if_index
				    [swi][j]);
	    }
	}
    }
}

static void
acl_plugin_show_tables_bihash (acl_main_t * am, u32 show_bihash_verbose)
{
  vlib_main_t *vm = am->vlib_main;
  show_hash_acl_hash (vm, am, show_bihash_verbose);
}

static clib_error_t *
acl_show_aclplugin_tables_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;

  u32 acl_index = ~0;
  u32 sw_if_index = ~0;
  int show_acl_hash_info = 0;
  int show_applied_info = 0;
  int show_mask_type = 0;
  int show_bihash = 0;
  u32 show_bihash_verbose = 0;

  if (unformat (input, "acl"))
    {
      show_acl_hash_info = 1;
      /* mask-type is handy to see as well right there */
      show_mask_type = 1;
      unformat (input, "index %u", &acl_index);
    }
  else if (unformat (input, "applied"))
    {
      show_applied_info = 1;
      unformat (input, "sw_if_index %u", &sw_if_index);
    }
  else if (unformat (input, "mask"))
    {
      show_mask_type = 1;
    }
  else if (unformat (input, "hash"))
    {
      show_bihash = 1;
      unformat (input, "verbose %u", &show_bihash_verbose);
    }

  if (!
      (show_mask_type || show_acl_hash_info || show_applied_info
       || show_bihash))
    {
      /* if no qualifiers specified, show all */
      show_mask_type = 1;
      show_acl_hash_info = 1;
      show_applied_info = 1;
      show_bihash = 1;
    }
  if (show_mask_type)
    acl_plugin_show_tables_mask_type (am);
  if (show_acl_hash_info)
    acl_plugin_show_tables_acl_hash_info (am, acl_index);
  if (show_applied_info)
    acl_plugin_show_tables_applied_info (am, sw_if_index);
  if (show_bihash)
    acl_plugin_show_tables_bihash (am, show_bihash_verbose);

  return error;
}

static clib_error_t *
acl_clear_aclplugin_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;
  vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
			     ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX, ~0);
  return error;
}

 /* *INDENT-OFF* */
VLIB_CLI_COMMAND (aclplugin_set_command, static) = {
    .path = "set acl-plugin",
    .short_help = "set acl-plugin session timeout {{udp idle}|tcp {idle|transient}} <seconds>",
    .function = acl_set_aclplugin_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_acl_command, static) = {
    .path = "show acl-plugin acl",
    .short_help = "show acl-plugin acl [index N]",
    .function = acl_show_aclplugin_acl_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_interface_command, static) = {
    .path = "show acl-plugin interface",
    .short_help = "show acl-plugin interface [sw_if_index N] [acl]",
    .function = acl_show_aclplugin_interface_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_memory_command, static) = {
    .path = "show acl-plugin memory",
    .short_help = "show acl-plugin memory",
    .function = acl_show_aclplugin_memory_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_sessions_command, static) = {
    .path = "show acl-plugin sessions",
    .short_help = "show acl-plugin sessions",
    .function = acl_show_aclplugin_sessions_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_tables_command, static) = {
    .path = "show acl-plugin tables",
    .short_help = "show acl-plugin tables [ acl [index N] | applied [ sw_if_index N ] | mask | hash [verbose N] ]",
    .function = acl_show_aclplugin_tables_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_macip_acl_command, static) = {
    .path = "show acl-plugin macip acl",
    .short_help = "show acl-plugin macip acl",
    .function = acl_show_aclplugin_macip_acl_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_macip_interface_command, static) = {
    .path = "show acl-plugin macip interface",
    .short_help = "show acl-plugin macip interface",
    .function = acl_show_aclplugin_macip_interface_fn,
};

VLIB_CLI_COMMAND (aclplugin_clear_command, static) = {
    .path = "clear acl-plugin sessions",
    .short_help = "clear acl-plugin sessions",
    .function = acl_clear_aclplugin_fn,
};
/* *INDENT-ON* */

static clib_error_t *
acl_plugin_config (vlib_main_t * vm, unformat_input_t * input)
{
  acl_main_t *am = &acl_main;
  u32 conn_table_hash_buckets;
  u32 conn_table_hash_memory_size;
  u32 conn_table_max_entries;
  u32 main_heap_size;
  u32 hash_heap_size;
  u32 hash_lookup_hash_buckets;
  u32 hash_lookup_hash_memory;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "connection hash buckets %d", &conn_table_hash_buckets))
	am->fa_conn_table_hash_num_buckets = conn_table_hash_buckets;
      else if (unformat (input, "connection hash memory %d",
			 &conn_table_hash_memory_size))
	am->fa_conn_table_hash_memory_size = conn_table_hash_memory_size;
      else if (unformat (input, "connection count max %d",
			 &conn_table_max_entries))
	am->fa_conn_table_max_entries = conn_table_max_entries;
      else if (unformat (input, "main heap size %d", &main_heap_size))
	am->acl_mheap_size = main_heap_size;
      else if (unformat (input, "hash lookup heap size %d", &hash_heap_size))
	am->hash_lookup_mheap_size = hash_heap_size;
      else if (unformat (input, "hash lookup hash buckets %d",
			 &hash_lookup_hash_buckets))
	am->hash_lookup_hash_buckets = hash_lookup_hash_buckets;
      else if (unformat (input, "hash lookup hash memory %d",
			 &hash_lookup_hash_memory))
	am->hash_lookup_hash_memory = hash_lookup_hash_memory;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (acl_plugin_config, "acl-plugin");

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

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (am, &api_main);

  vec_free (name);

  acl_setup_fa_nodes ();

  am->acl_mheap_size = ACL_FA_DEFAULT_HEAP_SIZE;
  am->hash_lookup_mheap_size = ACL_PLUGIN_HASH_LOOKUP_HEAP_SIZE;

  am->hash_lookup_hash_buckets = ACL_PLUGIN_HASH_LOOKUP_HASH_BUCKETS;
  am->hash_lookup_hash_memory = ACL_PLUGIN_HASH_LOOKUP_HASH_MEMORY;

  am->session_timeout_sec[ACL_TIMEOUT_TCP_TRANSIENT] =
    TCP_SESSION_TRANSIENT_TIMEOUT_SEC;
  am->session_timeout_sec[ACL_TIMEOUT_TCP_IDLE] =
    TCP_SESSION_IDLE_TIMEOUT_SEC;
  am->session_timeout_sec[ACL_TIMEOUT_UDP_IDLE] =
    UDP_SESSION_IDLE_TIMEOUT_SEC;

  am->fa_conn_table_hash_num_buckets =
    ACL_FA_CONN_TABLE_DEFAULT_HASH_NUM_BUCKETS;
  am->fa_conn_table_hash_memory_size =
    ACL_FA_CONN_TABLE_DEFAULT_HASH_MEMORY_SIZE;
  am->fa_conn_table_max_entries = ACL_FA_CONN_TABLE_DEFAULT_MAX_ENTRIES;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vec_validate (am->per_worker_data, tm->n_vlib_mains - 1);
  {
    u16 wk;
    u8 tt;
    for (wk = 0; wk < vec_len (am->per_worker_data); wk++)
      {
	acl_fa_per_worker_data_t *pw = &am->per_worker_data[wk];
	vec_validate (pw->fa_conn_list_head, ACL_N_TIMEOUTS - 1);
	vec_validate (pw->fa_conn_list_tail, ACL_N_TIMEOUTS - 1);
	for (tt = 0; tt < ACL_N_TIMEOUTS; tt++)
	  {
	    pw->fa_conn_list_head[tt] = ~0;
	    pw->fa_conn_list_tail[tt] = ~0;
	  }
      }
  }

  am->fa_min_deleted_sessions_per_interval =
    ACL_FA_DEFAULT_MIN_DELETED_SESSIONS_PER_INTERVAL;
  am->fa_max_deleted_sessions_per_interval =
    ACL_FA_DEFAULT_MAX_DELETED_SESSIONS_PER_INTERVAL;
  am->fa_cleaner_wait_time_increment =
    ACL_FA_DEFAULT_CLEANER_WAIT_TIME_INCREMENT;

  am->fa_cleaner_cnt_delete_by_sw_index = 0;
  am->fa_cleaner_cnt_delete_by_sw_index_ok = 0;
  am->fa_cleaner_cnt_unknown_event = 0;
  am->fa_cleaner_cnt_timer_restarted = 0;
  am->fa_cleaner_cnt_wait_with_timeout = 0;


#define _(N, v, s) am->fa_ipv6_known_eh_bitmap = clib_bitmap_set(am->fa_ipv6_known_eh_bitmap, v, 1);
  foreach_acl_eh
#undef _
    am->l4_match_nonfirst_fragment = 1;

  /* use the new fancy hash-based matching */
  am->use_hash_acl_matching = 1;

  return error;
}

VLIB_INIT_FUNCTION (acl_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
