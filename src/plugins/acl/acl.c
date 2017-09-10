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
acl_set_heap(acl_main_t *am)
{
  if (0 == am->acl_mheap) {
    am->acl_mheap = mheap_alloc (0 /* use VM */ , 2 << 29);
    mheap_t *h = mheap_header (am->acl_mheap);
    h->flags |= MHEAP_FLAG_THREAD_SAFE;
  }
  void *oldheap = clib_mem_set_heap(am->acl_mheap);
  return oldheap;
}

void
acl_plugin_acl_set_validate_heap(acl_main_t *am, int on)
{
  clib_mem_set_heap(acl_set_heap(am));
  mheap_t *h = mheap_header (am->acl_mheap);
  if (on) {
    h->flags |= MHEAP_FLAG_VALIDATE;
    h->flags &= ~MHEAP_FLAG_SMALL_OBJECT_CACHE;
    mheap_validate(h);
  } else {
    h->flags &= ~MHEAP_FLAG_VALIDATE;
    h->flags |= MHEAP_FLAG_SMALL_OBJECT_CACHE;
  }
}

void
acl_plugin_acl_set_trace_heap(acl_main_t *am, int on)
{
  clib_mem_set_heap(acl_set_heap(am));
  mheap_t *h = mheap_header (am->acl_mheap);
  if (on) {
    h->flags |= MHEAP_FLAG_TRACE;
  } else {
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
vl_api_acl_plugin_control_ping_t_handler (vl_api_acl_plugin_control_ping_t * mp)
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
          clib_warning("acl-plugin-error: Trying to replace nonexistent ACL %d (tag %s)", *acl_list_index, tag);
	  return -1;
	}
    }
  if (0 == count) {
    clib_warning("acl-plugin-warning: supplied no rules for ACL %d (tag %s)", *acl_list_index, tag);
  }

  void *oldheap = acl_set_heap(am);

  /* Create and populate the rules */
  if (count > 0)
    vec_validate(acl_new_rules, count-1);

  for (i = 0; i < count; i++)
    {
      r = vec_elt_at_index(acl_new_rules, i);
      memset(r, 0, sizeof(*r));
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
      r->src_port_or_type_first = ntohs ( rules[i].srcport_or_icmptype_first );
      r->src_port_or_type_last = ntohs ( rules[i].srcport_or_icmptype_last );
      r->dst_port_or_code_first = ntohs ( rules[i].dstport_or_icmpcode_first );
      r->dst_port_or_code_last = ntohs ( rules[i].dstport_or_icmpcode_last );
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
      hash_acl_delete(am, *acl_list_index);
      /* Get rid of the old rules */
      if (a->rules)
        vec_free (a->rules);
    }
  a->rules = acl_new_rules;
  a->count = count;
  memcpy (a->tag, tag, sizeof (a->tag));
  hash_acl_add(am, *acl_list_index);
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
      return -1;
    }

  if (acl_list_index < vec_len(am->input_sw_if_index_vec_by_acl)) {
    if (vec_len(am->input_sw_if_index_vec_by_acl[acl_list_index]) > 0) {
      /* ACL is applied somewhere inbound. Refuse to delete */
      return -1;
    }
  }
  if (acl_list_index < vec_len(am->output_sw_if_index_vec_by_acl)) {
    if (vec_len(am->output_sw_if_index_vec_by_acl[acl_list_index]) > 0) {
      /* ACL is applied somewhere outbound. Refuse to delete */
      return -1;
    }
  }

  void *oldheap = acl_set_heap(am);
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

  hash_acl_delete(am, acl_list_index);
  /* now we can delete the ACL itself */
  a = &am->acls[acl_list_index];
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
				      1 /* delete_chain */);
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
  u32 memory_size = 2 << 20;
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
				      1 /* delete_chain */);
  clib_mem_set_heap (oldheap);
  return ret;
}


static int
acl_unhook_l2_input_classify (acl_main_t * am, u32 sw_if_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  void *oldheap = acl_set_heap(am);

  vec_validate_init_empty (am->acl_ip4_input_classify_table_by_sw_if_index,
			   sw_if_index, ~0);
  vec_validate_init_empty (am->acl_ip6_input_classify_table_by_sw_if_index,
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
  clib_mem_set_heap (oldheap);
  return 0;
}

static int
acl_unhook_l2_output_classify (acl_main_t * am, u32 sw_if_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  void *oldheap = acl_set_heap(am);

  vec_validate_init_empty (am->acl_ip4_output_classify_table_by_sw_if_index,
			   sw_if_index, ~0);
  vec_validate_init_empty (am->acl_ip6_output_classify_table_by_sw_if_index,
			   sw_if_index, ~0);

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
  clib_mem_set_heap (oldheap);
  return 0;
}

static int
acl_hook_l2_input_classify (acl_main_t * am, u32 sw_if_index)
{
  vnet_classify_main_t *cm = &vnet_classify_main;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
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
    vnet_l2_input_classify_set_tables (sw_if_index, ip4_table_index,
				       ip6_table_index, ~0);
  clib_warning
    ("ACL enabling on interface sw_if_index %d, setting tables to the following: ip4: %d ip6: %d\n",
     sw_if_index, ip4_table_index, ip6_table_index);
  if (rv)
    {
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

  am->acl_ip4_input_classify_table_by_sw_if_index[sw_if_index] =
    ip4_table_index;
  am->acl_ip6_input_classify_table_by_sw_if_index[sw_if_index] =
    ip6_table_index;

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
    vnet_l2_output_classify_set_tables (sw_if_index, ip4_table_index,
					ip6_table_index, ~0);
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
      goto done;
    }

  am->acl_ip4_output_classify_table_by_sw_if_index[sw_if_index] =
    ip4_table_index;
  am->acl_ip6_output_classify_table_by_sw_if_index[sw_if_index] =
    ip6_table_index;

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

  acl_fa_enable_disable(sw_if_index, 1, enable_disable);

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

  acl_fa_enable_disable(sw_if_index, 0, enable_disable);

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
acl_is_not_defined(acl_main_t *am, u32 acl_list_index)
{
  return (pool_is_free_index (am->acls, acl_list_index));
}


static int
acl_interface_add_inout_acl (u32 sw_if_index, u8 is_input, u32 acl_list_index)
{
  acl_main_t *am = &acl_main;
  if (acl_is_not_defined(am, acl_list_index)) {
    /* ACL is not defined. Can not apply */
    return -1;
  }
  void *oldheap = acl_set_heap(am);

  if (is_input)
    {
      vec_validate (am->input_acl_vec_by_sw_if_index, sw_if_index);

      u32 index = vec_search(am->input_acl_vec_by_sw_if_index[sw_if_index], acl_list_index);
      if (index < vec_len(am->input_acl_vec_by_sw_if_index[sw_if_index])) {
        clib_warning("ACL %d is already applied inbound on sw_if_index %d (index %d)",
                     acl_list_index, sw_if_index, index);
        /* the entry is already there */
        clib_mem_set_heap (oldheap);
        return -1;
      }
      /* if there was no ACL applied before, enable the ACL processing */
      if (vec_len(am->input_acl_vec_by_sw_if_index[sw_if_index]) == 0) {
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

      u32 index = vec_search(am->output_acl_vec_by_sw_if_index[sw_if_index], acl_list_index);
      if (index < vec_len(am->output_acl_vec_by_sw_if_index[sw_if_index])) {
        clib_warning("ACL %d is already applied outbound on sw_if_index %d (index %d)",
                     acl_list_index, sw_if_index, index);
        /* the entry is already there */
        clib_mem_set_heap (oldheap);
        return -1;
      }
      /* if there was no ACL applied before, enable the ACL processing */
      if (vec_len(am->output_acl_vec_by_sw_if_index[sw_if_index]) == 0) {
        acl_interface_out_enable_disable (am, sw_if_index, 1);
      }
      vec_add (am->output_acl_vec_by_sw_if_index[sw_if_index],
	       &acl_list_index, 1);
      vec_validate (am->output_sw_if_index_vec_by_acl, acl_list_index);
      vec_add (am->output_sw_if_index_vec_by_acl[acl_list_index], &sw_if_index,
	       1);
    }
  clib_mem_set_heap (oldheap);
  return 0;
}


static int
acl_interface_del_inout_acl (u32 sw_if_index, u8 is_input, u32 acl_list_index)
{
  acl_main_t *am = &acl_main;
  int i;
  int rv = -1;
  void *oldheap = acl_set_heap(am);
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

      if (acl_list_index < vec_len(am->input_sw_if_index_vec_by_acl)) {
        u32 index = vec_search(am->input_sw_if_index_vec_by_acl[acl_list_index], sw_if_index);
        if (index < vec_len(am->input_sw_if_index_vec_by_acl[acl_list_index])) {
          hash_acl_unapply(am, sw_if_index, is_input, acl_list_index);
          vec_del1 (am->input_sw_if_index_vec_by_acl[acl_list_index], index);
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

      if (acl_list_index < vec_len(am->output_sw_if_index_vec_by_acl)) {
        u32 index = vec_search(am->output_sw_if_index_vec_by_acl[acl_list_index], sw_if_index);
        if (index < vec_len(am->output_sw_if_index_vec_by_acl[acl_list_index])) {
          hash_acl_unapply(am, sw_if_index, is_input, acl_list_index);
          vec_del1 (am->output_sw_if_index_vec_by_acl[acl_list_index], index);
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
  void *oldheap = acl_set_heap(am);
  if (is_input)
    {
      vec_validate (am->input_acl_vec_by_sw_if_index, sw_if_index);
      if (vec_len(am->input_acl_vec_by_sw_if_index[sw_if_index]) > 0) {
        acl_interface_in_enable_disable (am, sw_if_index, 0);
      }

      for(i = vec_len(am->input_acl_vec_by_sw_if_index[sw_if_index])-1; i>=0; i--) {
        u32 acl_list_index = am->input_acl_vec_by_sw_if_index[sw_if_index][i];
        hash_acl_unapply(am, sw_if_index, is_input, acl_list_index);
        if (acl_list_index < vec_len(am->input_sw_if_index_vec_by_acl)) {
          u32 index = vec_search(am->input_sw_if_index_vec_by_acl[acl_list_index], sw_if_index);
          if (index < vec_len(am->input_sw_if_index_vec_by_acl[acl_list_index])) {
            vec_del1 (am->input_sw_if_index_vec_by_acl[acl_list_index], index);
          }
        }
      }

      vec_reset_length (am->input_acl_vec_by_sw_if_index[sw_if_index]);
    }
  else
    {
      vec_validate (am->output_acl_vec_by_sw_if_index, sw_if_index);
      if (vec_len(am->output_acl_vec_by_sw_if_index[sw_if_index]) > 0) {
        acl_interface_out_enable_disable (am, sw_if_index, 0);
      }

      for(i = vec_len(am->output_acl_vec_by_sw_if_index[sw_if_index])-1; i>=0; i--) {
        u32 acl_list_index = am->output_acl_vec_by_sw_if_index[sw_if_index][i];
        hash_acl_unapply(am, sw_if_index, is_input, acl_list_index);
        if (acl_list_index < vec_len(am->output_sw_if_index_vec_by_acl)) {
          u32 index = vec_search(am->output_sw_if_index_vec_by_acl[acl_list_index], sw_if_index);
          if (index < vec_len(am->output_sw_if_index_vec_by_acl[acl_list_index])) {
            vec_del1 (am->output_sw_if_index_vec_by_acl[acl_list_index], index);
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
  int rv = -1;
  acl_main_t *am = &acl_main;
  void *oldheap = acl_set_heap(am);
  if (is_add)
    {
      rv =
	acl_interface_add_inout_acl (sw_if_index, is_input, acl_list_index);
      if (rv == 0)
        {
          hash_acl_apply(am, sw_if_index, is_input, acl_list_index);
        }
    }
  else
    {
      hash_acl_unapply(am, sw_if_index, is_input, acl_list_index);
      rv =
	acl_interface_del_inout_acl (sw_if_index, is_input, acl_list_index);
    }
  clib_mem_set_heap (oldheap);
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
   for (i=0; i<6; i++)
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
		  a->rules[i].src_mac_mask, 6);
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
        memset (&mask[12], 0xff, 2); /* ethernet protocol */
        memcpy (&mask[14 + 8], mt->mac_mask, 6);

        for (i = 0; i < (mt->prefix_len / 8); i++)
          mask[14 + 14 + i] = 0xff;
        if (mt->prefix_len % 8)
          mask[14 + 14 + (mt->prefix_len / 8)] = 0xff - ((1 << (8 - mt->prefix_len % 8)) - 1);

        mask_len = ((14 + 14 + ((mt->prefix_len+7) / 8) +
                (sizeof (u32x4)-1))/sizeof(u32x4)) * sizeof (u32x4);
        acl_classify_add_del_table_small (cm, mask, mask_len, last_table,
                               (~0 == last_table) ? 0 : ~0, &mt->arp_table_index,
                               1);
        last_table = mt->arp_table_index;
      }
  }
  /* Now add IP[46] tables */
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
      memset (&mask[12], 0xff, 2); /* ethernet protocol */
      if (is6)
	{
	  memcpy (&mask[l3_src_offs], &a->rules[i].src_ip_addr.ip6, 16);
	  mask[12] = 0x86;
	  mask[13] = 0xdd;
	}
      else
	{
	  memcpy (&mask[l3_src_offs], &a->rules[i].src_ip_addr.ip4, 4);
	  mask[12] = 0x08;
	  mask[13] = 0x00;
	}
      match_type_index =
	macip_find_match_type (mvec, a->rules[i].src_mac_mask,
			       a->rules[i].src_prefixlen,
			       a->rules[i].is_ipv6);
      ASSERT(match_type_index != ~0);
      /* add session to table mvec[match_type_index].table_index; */
      vnet_classify_add_del_session (cm, mvec[match_type_index].table_index,
				     mask, a->rules[i].is_permit ? ~0 : 0, i,
				     0, action, metadata, 1);
      /* add ARP table entry too */
      if (!is6 && (mvec[match_type_index].arp_table_index != ~0))
        {
          memset (mask, 0, sizeof (mask));
          memcpy (&mask[6], a->rules[i].src_mac, 6);
          mask[12] = 0x08;
          mask[13] = 0x06;
          memcpy (&mask[14 + 8], a->rules[i].src_mac, 6);
          memcpy (&mask[14 + 14], &a->rules[i].src_ip_addr.ip4, 4);
          vnet_classify_add_del_session (cm, mvec[match_type_index].arp_table_index,
                                    mask, a->rules[i].is_permit ? ~0 : 0, i,
                                    0, action, metadata, 1);
        }
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
  macip_acl_rule_t *acl_new_rules = 0;
  int i;
  if (0 == count) {
    clib_warning("acl-plugin-warning: Trying to create empty MACIP ACL (tag %s)", tag);
  }
  void *oldheap = acl_set_heap(am);
  /* Create and populate the rules */
  if (count > 0)
    vec_validate(acl_new_rules, count-1);

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
  void *oldheap = acl_set_heap(am);
  vec_validate_init_empty (am->macip_acl_by_sw_if_index, sw_if_index, ~0);
  clib_mem_set_heap (oldheap);
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
  void *oldheap = acl_set_heap(am);
  a = &am->macip_acls[macip_acl_index];
  vec_validate_init_empty (am->macip_acl_by_sw_if_index, sw_if_index, ~0);
  /* If there already a MACIP ACL applied, unapply it */
  if (~0 != am->macip_acl_by_sw_if_index[sw_if_index])
    macip_acl_interface_del_acl(am, sw_if_index);
  am->macip_acl_by_sw_if_index[sw_if_index] = macip_acl_index;
  clib_mem_set_heap (oldheap);

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
  void *oldheap = acl_set_heap(am);
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
  void *oldheap = acl_set_heap(am);
  int rv = -1;
  if (is_add)
    {
      rv = macip_acl_interface_add_acl (am, sw_if_index, acl_list_index);
    }
  else
    {
      rv = macip_acl_interface_del_acl (am, sw_if_index);
    }
  clib_mem_set_heap (oldheap);
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
static int verify_message_len(void *mp, u32 expected_len, char *where)
{
  u32 supplied_len = vl_msg_api_get_msg_length (mp);
  if (supplied_len < expected_len) {
      clib_warning("%s: Supplied message length %d is less than expected %d",
                   where, supplied_len, expected_len);
      return 0;
  } else {
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
  u32 expected_len = sizeof(*mp) + acl_count*sizeof(mp->r[0]);

  if (verify_message_len(mp, expected_len, "acl_add_replace")) {
      rv = acl_add_list (acl_count, mp->r, &acl_list_index, mp->tag);
  } else {
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
  acl_main_t *am = &acl_main;
  vl_api_acl_interface_set_acl_list_reply_t *rmp;
  int rv = 0;
  int i;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  if (pool_is_free_index(im->sw_interfaces, sw_if_index))
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  else
    {
      acl_interface_reset_inout_acls (sw_if_index, 0);
      acl_interface_reset_inout_acls (sw_if_index, 1);

      for (i = 0; i < mp->count; i++)
        {
          if(acl_is_not_defined(am, ntohl (mp->acls[i]))) {
            /* ACL does not exist, so we can not apply it */
            rv = -1;
          }
        }
      if (0 == rv) {
        for (i = 0; i < mp->count; i++)
          {
            acl_interface_add_del_inout_acl (sw_if_index, 1, (i < mp->n_input),
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
  void *oldheap = acl_set_heap(am);

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
  void *oldheap = acl_set_heap(am);

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
  u32 acl_count = ntohl (mp->count);
  u32 expected_len = sizeof(*mp) + acl_count*sizeof(mp->r[0]);

  if (verify_message_len(mp, expected_len, "macip_acl_add")) {
      rv = macip_acl_add_list (acl_count, mp->r, &acl_list_index, mp->tag);
  } else {
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

static void
send_macip_acl_interface_list_details (acl_main_t * am,
                                       unix_shared_memory_queue_t * q,
                                       u32 sw_if_index,
                                       u32 acl_index,
                                       u32 context)
{
  vl_api_macip_acl_interface_list_details_t *rmp;
  /* at this time there is only ever 1 mac ip acl per interface */
  int msg_size = sizeof (*rmp) + sizeof (rmp->acls[0]);

  rmp = vl_msg_api_alloc (msg_size);
  memset (rmp, 0, msg_size);
  rmp->_vl_msg_id = ntohs (VL_API_MACIP_ACL_INTERFACE_LIST_DETAILS + am->msg_id_base);

  /* fill in the message */
  rmp->context = context;
  rmp->count = 1;
  rmp->sw_if_index = htonl (sw_if_index);
  rmp->acls[0] = htonl (acl_index);

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_macip_acl_interface_list_dump_t_handler (vl_api_macip_acl_interface_list_dump_t *mp)
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
      vec_foreach_index(sw_if_index, am->macip_acl_by_sw_if_index)
        {
          if (~0 != am->macip_acl_by_sw_if_index[sw_if_index])
            {
              send_macip_acl_interface_list_details(am, q,  sw_if_index,
                                                    am->macip_acl_by_sw_if_index[sw_if_index],
                                                    mp->context);
            }
        }
    }
  else
    {
      if (vec_len(am->macip_acl_by_sw_if_index) > sw_if_index)
        {
          send_macip_acl_interface_list_details(am, q, sw_if_index,
                                                am->macip_acl_by_sw_if_index[sw_if_index],
                                                mp->context);
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
acl_set_timeout_sec(int timeout_type, u32 value)
{
  acl_main_t *am = &acl_main;
  clib_time_t *ct = &am->vlib_main->clib_time;

  if (timeout_type < ACL_N_TIMEOUTS) {
    am->session_timeout_sec[timeout_type] = value;
  } else {
    clib_warning("Unknown timeout type %d", timeout_type);
    return;
  }
  am->session_timeout[timeout_type] = (u64)(((f64)value)/ct->seconds_per_clock);
}

static void
acl_set_session_max_entries(u32 value)
{
  acl_main_t *am = &acl_main;
  am->fa_conn_table_max_entries = value;
}

static int
acl_set_skip_ipv6_eh(u32 eh, u32 value)
{
  acl_main_t *am = &acl_main;

  if ((eh < 256) && (value < 2))
    {
      am->fa_ipv6_known_eh_bitmap = clib_bitmap_set(am->fa_ipv6_known_eh_bitmap, eh, value);
      return 1;
    }
  else
    return 0;
}


static clib_error_t *
acl_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  acl_main_t *am = &acl_main;
  if (0 == am->acl_mheap) {
    /* ACL heap is not initialized, so definitely nothing to do. */
    return 0;
  }
  if (0 == is_add) {
    vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
                               ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX, sw_if_index);
    /* also unapply any ACLs in case the users did not do so. */
    macip_acl_interface_del_acl(am, sw_if_index);
    acl_interface_reset_inout_acls (sw_if_index, 0);
    acl_interface_reset_inout_acls (sw_if_index, 1);
  }
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (acl_sw_interface_add_del);



static clib_error_t *
acl_set_aclplugin_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  u32 timeout = 0;
  u32 val = 0;
  u32 eh_val = 0;
  uword memory_size = 0;
  acl_main_t *am = &acl_main;

  if (unformat (input, "skip-ipv6-extension-header %u %u", &eh_val, &val)) {
    if(!acl_set_skip_ipv6_eh(eh_val, val)) {
      error = clib_error_return(0, "expecting eh=0..255, value=0..1");
    }
    goto done;
  }
  if (unformat (input, "use-hash-acl-matching %u", &val))
    {
      am->use_hash_acl_matching = (val !=0);
      goto done;
    }
  if (unformat (input, "l4-match-nonfirst-fragment %u", &val))
    {
      am->l4_match_nonfirst_fragment = (val != 0);
      goto done;
    }
  if (unformat (input, "heap"))
    {
      if (unformat(input, "main"))
        {
          if (unformat(input, "validate %u", &val))
            acl_plugin_acl_set_validate_heap(am, val);
          else if (unformat(input, "trace %u", &val))
            acl_plugin_acl_set_trace_heap(am, val);
          goto done;
        }
      else if (unformat(input, "hash"))
        {
          if (unformat(input, "validate %u", &val))
            acl_plugin_hash_acl_set_validate_heap(am, val);
          else if (unformat(input, "trace %u", &val))
            acl_plugin_hash_acl_set_trace_heap(am, val);
          goto done;
        }
      goto done;
    }
  if (unformat (input, "session")) {
    if (unformat (input, "table")) {
      /* The commands here are for tuning/testing. No user-serviceable parts inside */
      if (unformat (input, "max-entries")) {
	if (!unformat(input, "%u", &val)) {
	  error = clib_error_return(0,
				    "expecting maximum number of entries, got `%U`",
				    format_unformat_error, input);
	  goto done;
	} else {
	  acl_set_session_max_entries(val);
          goto done;
	}
      }
      if (unformat (input, "hash-table-buckets")) {
	if (!unformat(input, "%u", &val)) {
	  error = clib_error_return(0,
				    "expecting maximum number of hash table buckets, got `%U`",
				    format_unformat_error, input);
	  goto done;
	} else {
          am->fa_conn_table_hash_num_buckets = val;
          goto done;
	}
      }
      if (unformat (input, "hash-table-memory")) {
	if (!unformat(input, "%U", unformat_memory_size, &memory_size)) {
	  error = clib_error_return(0,
				    "expecting maximum amount of hash table memory, got `%U`",
				    format_unformat_error, input);
	  goto done;
	} else {
          am->fa_conn_table_hash_memory_size = memory_size;
          goto done;
	}
      }
      goto done;
    }
    if (unformat (input, "timeout")) {
      if (unformat(input, "udp")) {
	if(unformat(input, "idle")) {
	  if (!unformat(input, "%u", &timeout)) {
	    error = clib_error_return(0,
				      "expecting timeout value in seconds, got `%U`",
				      format_unformat_error, input);
	    goto done;
	  } else {
	    acl_set_timeout_sec(ACL_TIMEOUT_UDP_IDLE, timeout);
            goto done;
	  }
	}
      }
      if (unformat(input, "tcp")) {
	if(unformat(input, "idle")) {
	  if (!unformat(input, "%u", &timeout)) {
	    error = clib_error_return(0,
				      "expecting timeout value in seconds, got `%U`",
				      format_unformat_error, input);
	    goto done;
	  } else {
	    acl_set_timeout_sec(ACL_TIMEOUT_TCP_IDLE, timeout);
            goto done;
	  }
	}
	if(unformat(input, "transient")) {
	  if (!unformat(input, "%u", &timeout)) {
	    error = clib_error_return(0,
				      "expecting timeout value in seconds, got `%U`",
				      format_unformat_error, input);
	    goto done;
	  } else {
	    acl_set_timeout_sec(ACL_TIMEOUT_TCP_TRANSIENT, timeout);
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
my_macip_acl_rule_t_pretty_format (u8 *out, va_list *args)
{
  macip_acl_rule_t *a = va_arg (*args, macip_acl_rule_t *);

  out = format(out, "%s action %d ip %U/%d mac %U mask %U",
                     a->is_ipv6 ? "ipv6" : "ipv4", a->is_permit,
                     format_ip46_address, &a->src_ip_addr, IP46_TYPE_ANY,
                     a->src_prefixlen,
                     my_format_mac_address, a->src_mac,
                     my_format_mac_address, a->src_mac_mask);
  return(out);
}

static void
macip_acl_print(acl_main_t *am, u32 macip_acl_index)
{
  vlib_main_t * vm = am->vlib_main;
  int i;

  /* Don't try to print someone else's memory */
  if (macip_acl_index > vec_len(am->macip_acls))
    return;

  macip_acl_list_t *a = vec_elt_at_index(am->macip_acls, macip_acl_index);
  int free_pool_slot = pool_is_free_index(am->macip_acls, macip_acl_index);

  vlib_cli_output(vm, "MACIP acl_index: %d, count: %d (true len %d) tag {%s} is free pool slot: %d\n",
                  macip_acl_index, a->count, vec_len(a->rules), a->tag, free_pool_slot);
  vlib_cli_output(vm, "  ip4_table_index %d, ip6_table_index %d, l2_table_index %d\n",
                  a->ip4_table_index, a->ip6_table_index, a->l2_table_index);
  for(i=0; i<vec_len(a->rules); i++)
    vlib_cli_output(vm, "    rule %d: %U\n", i, my_macip_acl_rule_t_pretty_format,
                    vec_elt_at_index(a->rules, i));

}

static clib_error_t *
acl_show_aclplugin_macip_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;
  int i;
  if (unformat (input, "interface"))
    {
      for(i=0; i < vec_len(am->macip_acl_by_sw_if_index); i++)
        {
          vlib_cli_output(vm, "  sw_if_index %d: %d\n", i, vec_elt(am->macip_acl_by_sw_if_index, i));
        }
    }
  else if (unformat (input, "acl"))
    {
      for(i=0; i < vec_len(am->macip_acls); i++)
        macip_acl_print(am, i);
    }
  return error;
}


static clib_error_t *
acl_show_aclplugin_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;
  u32 *pj;

  vnet_sw_interface_t *swif;

  if (unformat (input, "sessions"))
    {
      u8 * out0 = format(0, "");
      u16 wk;
      u32 show_bihash_verbose = 0;
      u32 show_session_thread_id = ~0;
      u32 show_session_session_index = ~0;
      unformat (input, "thread %u index %u", &show_session_thread_id, &show_session_session_index);
      unformat (input, "verbose %u", &show_bihash_verbose);
      {
        u64 n_adds = am->fa_session_total_adds;
        u64 n_dels = am->fa_session_total_dels;
        out0 = format(out0, "Sessions total: add %lu - del %lu = %lu\n", n_adds, n_dels, n_adds - n_dels);
      }
      out0 = format(out0, "\n\nPer-thread data:\n");
      for (wk = 0; wk < vec_len (am->per_worker_data); wk++) {
        acl_fa_per_worker_data_t *pw = &am->per_worker_data[wk];
	out0 = format(out0, "Thread #%d:\n", wk);
        if (show_session_thread_id == wk && show_session_session_index < pool_len(pw->fa_sessions_pool)) {
	  out0 = format(out0, "  session index %u:\n", show_session_session_index);
          fa_session_t *sess = pw->fa_sessions_pool + show_session_session_index;
          u64 *m =  (u64 *)&sess->info;
          out0 = format(out0, "    info: %016llx %016llx %016llx %016llx %016llx %016llx\n", m[0], m[1], m[2], m[3], m[4], m[5]);
	  out0 = format(out0, "    sw_if_index: %u\n", sess->sw_if_index);
	  out0 = format(out0, "    tcp_flags_seen: %x\n", sess->tcp_flags_seen.as_u16);
	  out0 = format(out0, "    last active time: %lu\n", sess->last_active_time);
	  out0 = format(out0, "    thread index: %u\n", sess->thread_index);
	  out0 = format(out0, "    link enqueue time: %lu\n", sess->link_enqueue_time);
	  out0 = format(out0, "    link next index: %u\n", sess->link_next_idx);
	  out0 = format(out0, "    link prev index: %u\n", sess->link_prev_idx);
	  out0 = format(out0, "    link list id: %u\n", sess->link_list_id);
        }
	out0 = format(out0, "  connection add/del stats:\n", wk);
        pool_foreach (swif, im->sw_interfaces,
        ({
          u32 sw_if_index =  swif->sw_if_index;
          u64 n_adds = sw_if_index < vec_len(pw->fa_session_adds_by_sw_if_index) ? pw->fa_session_adds_by_sw_if_index[sw_if_index] : 0;
          u64 n_dels = sw_if_index < vec_len(pw->fa_session_dels_by_sw_if_index) ? pw->fa_session_dels_by_sw_if_index[sw_if_index] : 0;
          out0 = format(out0, "    sw_if_index %d: add %lu - del %lu = %lu\n", sw_if_index, n_adds, n_dels, n_adds - n_dels);
        }));

	out0 = format(out0, "  connection timeout type lists:\n", wk);
        u8 tt = 0;
        for(tt = 0; tt < ACL_N_TIMEOUTS; tt++) {
          u32 head_session_index = pw->fa_conn_list_head[tt];
          out0 = format(out0, "  fa_conn_list_head[%d]: %d\n", tt, head_session_index);
          if (~0 != head_session_index) {
            fa_session_t *sess = pw->fa_sessions_pool + head_session_index;
	    out0 = format(out0, "    last active time: %lu\n", sess->last_active_time);
	    out0 = format(out0, "    link enqueue time: %lu\n", sess->link_enqueue_time);
          }
        }

	out0 = format(out0, "  Next expiry time: %lu\n", pw->next_expiry_time);
	out0 = format(out0, "  Requeue until time: %lu\n", pw->requeue_until_time);
	out0 = format(out0, "  Current time wait interval: %lu\n", pw->current_time_wait_interval);
	out0 = format(out0, "  Count of deleted sessions: %lu\n", pw->cnt_deleted_sessions);
	out0 = format(out0, "  Delete already deleted: %lu\n", pw->cnt_already_deleted_sessions);
	out0 = format(out0, "  Session timers restarted: %lu\n", pw->cnt_session_timer_restarted);
	out0 = format(out0, "  Swipe until this time: %lu\n", pw->swipe_end_time);
	out0 = format(out0, "  sw_if_index serviced bitmap: %U\n", format_bitmap_hex, pw->serviced_sw_if_index_bitmap);
	out0 = format(out0, "  pending clear intfc bitmap : %U\n", format_bitmap_hex, pw->pending_clear_sw_if_index_bitmap);
	out0 = format(out0, "  clear in progress: %u\n", pw->clear_in_process);
	out0 = format(out0, "  interrupt is pending: %d\n", pw->interrupt_is_pending);
	out0 = format(out0, "  interrupt is needed: %d\n", pw->interrupt_is_needed);
	out0 = format(out0, "  interrupt is unwanted: %d\n", pw->interrupt_is_unwanted);
	out0 = format(out0, "  interrupt generation: %d\n", pw->interrupt_generation);
      }
      out0 = format(out0, "\n\nConn cleaner thread counters:\n");
#define _(cnt, desc) out0 = format(out0, "             %20lu: %s\n", am->cnt, desc);
      foreach_fa_cleaner_counter;
#undef _
      vec_terminate_c_string(out0);
      vlib_cli_output(vm, "\n\n%s\n\n", out0);
      vlib_cli_output(vm, "Interrupt generation: %d\n", am->fa_interrupt_generation);
      vlib_cli_output(vm, "Sessions per interval: min %lu max %lu increment: %f ms current: %f ms",
              am->fa_min_deleted_sessions_per_interval, am->fa_max_deleted_sessions_per_interval,
              am->fa_cleaner_wait_time_increment * 1000.0, ((f64)am->fa_current_cleaner_timer_wait_interval) * 1000.0/(f64)vm->clib_time.clocks_per_second);

      vec_free(out0);
      show_fa_sessions_hash(vm, show_bihash_verbose);
    }
  else if (unformat (input, "interface"))
    {
      u32 sw_if_index = ~0;
      u32 swi;
      u8 * out0 = format(0, "");
      unformat (input, "sw_if_index %u", &sw_if_index);
      for(swi = 0; (swi < vec_len(am->input_acl_vec_by_sw_if_index)) ||
                   (swi < vec_len(am->output_acl_vec_by_sw_if_index)); swi++) {
        out0 = format(out0, "sw_if_index %d:\n", swi);

        if ((swi < vec_len(am->input_acl_vec_by_sw_if_index)) &&
            (vec_len(am->input_acl_vec_by_sw_if_index[swi]) > 0)) {
          out0 = format(out0, "  input acl(s): ");
          vec_foreach(pj, am->input_acl_vec_by_sw_if_index[swi]) {
            out0 = format(out0, "%d ", *pj);
          }
          out0 = format(out0, "\n");
        }

        if ((swi < vec_len(am->output_acl_vec_by_sw_if_index)) &&
            (vec_len(am->output_acl_vec_by_sw_if_index[swi]) > 0)) {
          out0 = format(out0, "  output acl(s): ");
          vec_foreach(pj, am->output_acl_vec_by_sw_if_index[swi]) {
            out0 = format(out0, "%d ", *pj);
          }
          out0 = format(out0, "\n");
        }

      }
      vec_terminate_c_string(out0);
      vlib_cli_output(vm, "\n%s\n", out0);
      vec_free(out0);
    }
  else if (unformat (input, "acl"))
    {
      u32 acl_index = ~0;
      u32 i;
      u8 * out0 = format(0, "");
      unformat (input, "index %u", &acl_index);
      for(i=0; i<vec_len(am->acls); i++) {
        if (acl_is_not_defined(am, i)) {
          /* don't attempt to show the ACLs that do not exist */
          continue;
        }
        if ((acl_index != ~0) && (acl_index != i)) {
          continue;
        }
        out0 = format(out0, "acl-index %u count %u tag {%s}\n", i, am->acls[i].count, am->acls[i].tag);
        acl_rule_t *r;
        int j;
        for(j=0; j<am->acls[i].count; j++) {
          r = &am->acls[i].rules[j];
          out0 = format(out0, "  %4d: %s ", j, r->is_ipv6 ? "ipv6" : "ipv4");
          out0 = format_acl_action(out0, r->is_permit);
          out0 = format(out0, " src %U/%d", format_ip46_address, &r->src, IP46_TYPE_ANY, r->src_prefixlen);
          out0 = format(out0, " dst %U/%d", format_ip46_address, &r->dst, IP46_TYPE_ANY, r->dst_prefixlen);
          out0 = format(out0, " proto %d", r->proto);
          out0 = format(out0, " sport %d", r->src_port_or_type_first);
          if (r->src_port_or_type_first != r->src_port_or_type_last) {
            out0 = format(out0, "-%d", r->src_port_or_type_last);
          }
          out0 = format(out0, " dport %d", r->dst_port_or_code_first);
          if (r->dst_port_or_code_first != r->dst_port_or_code_last) {
            out0 = format(out0, "-%d", r->dst_port_or_code_last);
          }
          if (r->tcp_flags_mask || r->tcp_flags_value) {
            out0 = format(out0, " tcpflags %d mask %d", r->tcp_flags_value, r->tcp_flags_mask);
          }
          out0 = format(out0, "\n");
        }

        if (i<vec_len(am->input_sw_if_index_vec_by_acl)) {
          out0 = format(out0, "  applied inbound on sw_if_index: ");
          vec_foreach(pj, am->input_sw_if_index_vec_by_acl[i]) {
            out0 = format(out0, "%d ", *pj);
          }
          out0 = format(out0, "\n");
        }
        if (i<vec_len(am->output_sw_if_index_vec_by_acl)) {
          out0 = format(out0, "  applied outbound on sw_if_index: ");
          vec_foreach(pj, am->output_sw_if_index_vec_by_acl[i]) {
            out0 = format(out0, "%d ", *pj);
          }
          out0 = format(out0, "\n");
        }
      }
      vec_terminate_c_string(out0);
      vlib_cli_output(vm, "\n%s\n", out0);
      vec_free(out0);
    }
  else if (unformat (input, "memory"))
    {
      vlib_cli_output (vm, "ACL plugin main heap statistics:\n");
      if (am->acl_mheap) {
        vlib_cli_output (vm, " %U\n", format_mheap, am->acl_mheap, 1);
      } else {
        vlib_cli_output (vm, " Not initialized\n");
      }
      vlib_cli_output (vm, "ACL hash lookup support heap statistics:\n");
      if (am->hash_lookup_mheap) {
        vlib_cli_output (vm, " %U\n", format_mheap, am->hash_lookup_mheap, 1);
      } else {
        vlib_cli_output (vm, " Not initialized\n");
      }
    }
  else if (unformat (input, "tables"))
    {
      ace_mask_type_entry_t *mte;
      u32 acl_index = ~0;
      u32 sw_if_index = ~0;
      int show_acl_hash_info = 0;
      int show_applied_info = 0;
      int show_mask_type = 0;
      int show_bihash = 0;
      u32 show_bihash_verbose = 0;

      if (unformat (input, "acl")) {
        show_acl_hash_info = 1;
        /* mask-type is handy to see as well right there */
        show_mask_type = 1;
        unformat (input, "index %u", &acl_index);
      } else if (unformat (input, "applied")) {
        show_applied_info = 1;
        unformat (input, "sw_if_index %u", &sw_if_index);
      } else if (unformat (input, "mask")) {
        show_mask_type = 1;
      } else if (unformat (input, "hash")) {
        show_bihash = 1;
        unformat (input, "verbose %u", &show_bihash_verbose);
      }

      if ( ! (show_mask_type || show_acl_hash_info || show_applied_info || show_bihash) ) {
        /* if no qualifiers specified, show all */
        show_mask_type = 1;
        show_acl_hash_info = 1;
        show_applied_info = 1;
        show_bihash = 1;
      }

      if (show_mask_type) {
        vlib_cli_output(vm, "Mask-type entries:");
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

      if (show_acl_hash_info) {
        u32 i,j;
        u8 * out0 = format(0, "");
        u64 *m;
        out0 = format(out0, "Mask-ready ACL representations\n");
        for (i=0; i< vec_len(am->hash_acl_infos); i++) {
          if ((acl_index != ~0) && (acl_index != i)) {
            continue;
          }
          hash_acl_info_t *ha = &am->hash_acl_infos[i];
          out0 = format(out0, "acl-index %u bitmask-ready layout\n", i);
          out0 = format(out0, "  applied  inbound on sw_if_index list: %U\n", format_vec32, ha->inbound_sw_if_index_list, "%d");
          out0 = format(out0, "  applied outbound on sw_if_index list: %U\n", format_vec32, ha->outbound_sw_if_index_list, "%d");
          out0 = format(out0, "  mask type index bitmap: %U\n", format_bitmap_hex, ha->mask_type_index_bitmap);
          for(j=0; j<vec_len(ha->rules); j++) {
            hash_ace_info_t *pa = &ha->rules[j];
            m = (u64 *)&pa->match;
            out0 = format(out0, "    %4d: %016llx %016llx %016llx %016llx %016llx %016llx mask index %d acl %d rule %d action %d src/dst portrange not ^2: %d,%d\n",
                                j, m[0], m[1], m[2], m[3], m[4], m[5], pa->mask_type_index,
				pa->acl_index, pa->ace_index, pa->action,
                                pa->src_portrange_not_powerof2, pa->dst_portrange_not_powerof2);
          }
        }
        vec_terminate_c_string(out0);
        vlib_cli_output(vm, "\n%s\n", out0);
        vec_free(out0);
      }

      if (show_applied_info) {
        u32 swi, j;
        u8 * out0 = format(0, "");
        out0 = format(out0, "Applied lookup entries for interfaces\n");

        for(swi = 0; (swi < vec_len(am->input_applied_hash_acl_info_by_sw_if_index)) ||
                   (swi < vec_len(am->output_applied_hash_acl_info_by_sw_if_index)) ||
                   (swi < vec_len(am->input_hash_entry_vec_by_sw_if_index)) ||
                   (swi < vec_len(am->output_hash_entry_vec_by_sw_if_index)); swi++) {
          if ((sw_if_index != ~0) && (sw_if_index != swi)) {
            continue;
          }
          out0 = format(out0, "sw_if_index %d:\n", swi);
          if (swi < vec_len(am->input_applied_hash_acl_info_by_sw_if_index)) {
            applied_hash_acl_info_t *pal = &am->input_applied_hash_acl_info_by_sw_if_index[swi];
            out0 = format(out0, "  input lookup mask_type_index_bitmap: %U\n", format_bitmap_hex, pal->mask_type_index_bitmap);
            out0 = format(out0, "  input applied acls: %U\n", format_vec32, pal->applied_acls, "%d");
          }
          if (swi < vec_len(am->input_hash_entry_vec_by_sw_if_index)) {
            out0 = format(out0, "  input lookup applied entries:\n");
            for(j=0; j<vec_len(am->input_hash_entry_vec_by_sw_if_index[swi]); j++) {
              applied_hash_ace_entry_t *pae = &am->input_hash_entry_vec_by_sw_if_index[swi][j];
              out0 = format(out0, "    %4d: acl %d rule %d action %d bitmask-ready rule %d next %d prev %d tail %d hitcount %lld\n",
                                       j, pae->acl_index, pae->ace_index, pae->action, pae->hash_ace_info_index,
                                       pae->next_applied_entry_index, pae->prev_applied_entry_index, pae->tail_applied_entry_index, pae->hitcount);
            }
          }

          if (swi < vec_len(am->output_applied_hash_acl_info_by_sw_if_index)) {
            applied_hash_acl_info_t *pal = &am->output_applied_hash_acl_info_by_sw_if_index[swi];
            out0 = format(out0, "  output lookup mask_type_index_bitmap: %U\n", format_bitmap_hex, pal->mask_type_index_bitmap);
            out0 = format(out0, "  output applied acls: %U\n", format_vec32, pal->applied_acls, "%d");
          }
          if (swi < vec_len(am->output_hash_entry_vec_by_sw_if_index)) {
            out0 = format(out0, "  output lookup applied entries:\n");
            for(j=0; j<vec_len(am->output_hash_entry_vec_by_sw_if_index[swi]); j++) {
              applied_hash_ace_entry_t *pae = &am->output_hash_entry_vec_by_sw_if_index[swi][j];
              out0 = format(out0, "    %4d: acl %d rule %d action %d bitmask-ready rule %d next %d prev %d tail %d hitcount %lld\n",
                                       j, pae->acl_index, pae->ace_index, pae->action, pae->hash_ace_info_index,
                                       pae->next_applied_entry_index, pae->prev_applied_entry_index, pae->tail_applied_entry_index, pae->hitcount);
            }
          }

        }
        vec_terminate_c_string(out0);
        vlib_cli_output(vm, "\n%s\n", out0);
        vec_free(out0);
      }

      if (show_bihash) {
        show_hash_acl_hash(vm, am, show_bihash_verbose);
      }
    }
  return error;
}

static clib_error_t *
acl_clear_aclplugin_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
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

VLIB_CLI_COMMAND (aclplugin_show_command, static) = {
    .path = "show acl-plugin",
    .short_help = "show acl-plugin {sessions|acl|interface|tables}",
    .function = acl_show_aclplugin_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_macip_command, static) = {
    .path = "show acl-plugin macip",
    .short_help = "show acl-plugin macip {acl|interface}",
    .function = acl_show_aclplugin_macip_fn,
};


VLIB_CLI_COMMAND (aclplugin_clear_command, static) = {
    .path = "clear acl-plugin sessions",
    .short_help = "clear acl-plugin sessions",
    .function = acl_clear_aclplugin_fn,
};
/* *INDENT-ON* */



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

  acl_setup_fa_nodes();

  am->session_timeout_sec[ACL_TIMEOUT_TCP_TRANSIENT] = TCP_SESSION_TRANSIENT_TIMEOUT_SEC;
  am->session_timeout_sec[ACL_TIMEOUT_TCP_IDLE] = TCP_SESSION_IDLE_TIMEOUT_SEC;
  am->session_timeout_sec[ACL_TIMEOUT_UDP_IDLE] = UDP_SESSION_IDLE_TIMEOUT_SEC;

  am->fa_conn_table_hash_num_buckets = ACL_FA_CONN_TABLE_DEFAULT_HASH_NUM_BUCKETS;
  am->fa_conn_table_hash_memory_size = ACL_FA_CONN_TABLE_DEFAULT_HASH_MEMORY_SIZE;
  am->fa_conn_table_max_entries = ACL_FA_CONN_TABLE_DEFAULT_MAX_ENTRIES;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vec_validate(am->per_worker_data, tm->n_vlib_mains-1);
  {
    u16 wk;
    u8 tt;
    for (wk = 0; wk < vec_len (am->per_worker_data); wk++) {
      acl_fa_per_worker_data_t *pw = &am->per_worker_data[wk];
      vec_validate(pw->fa_conn_list_head, ACL_N_TIMEOUTS-1);
      vec_validate(pw->fa_conn_list_tail, ACL_N_TIMEOUTS-1);
      for(tt = 0; tt < ACL_N_TIMEOUTS; tt++) {
        pw->fa_conn_list_head[tt] = ~0;
        pw->fa_conn_list_tail[tt] = ~0;
      }
    }
  }

  am->fa_min_deleted_sessions_per_interval = ACL_FA_DEFAULT_MIN_DELETED_SESSIONS_PER_INTERVAL;
  am->fa_max_deleted_sessions_per_interval = ACL_FA_DEFAULT_MAX_DELETED_SESSIONS_PER_INTERVAL;
  am->fa_cleaner_wait_time_increment = ACL_FA_DEFAULT_CLEANER_WAIT_TIME_INCREMENT;

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
