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
#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/classify/in_out_acl.h>
#include <vpp/app/version.h>

#include <vnet/ethernet/ethernet_types_api.h>
#include <vnet/ip/format.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip_types_api.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <acl/acl.api_enum.h>
#include <acl/acl.api_types.h>

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

#include "fa_node.h"
#include "public_inlines.h"

acl_main_t acl_main;

#define REPLY_MSG_ID_BASE am->msg_id_base
#include <vlibapi/api_helper_macros.h>

/*
 * The code for the bihash, used by the session management.
 */
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Access Control Lists (ACL)",
};
/* *INDENT-ON* */

/* methods exported from ACL-as-a-service */
static acl_plugin_methods_t acl_plugin;

/* Format vec16. */
u8 *
format_vec16 (u8 * s, va_list * va)
{
  u16 *v = va_arg (*va, u16 *);
  char *fmt = va_arg (*va, char *);
  uword i;
  for (i = 0; i < vec_len (v); i++)
    {
      if (i > 0)
	s = format (s, ", ");
      s = format (s, fmt, v[i]);
    }
  return s;
}

static void
vl_api_acl_plugin_get_version_t_handler (vl_api_acl_plugin_get_version_t * mp)
{
  acl_main_t *am = &acl_main;
  vl_api_acl_plugin_get_version_reply_t *rmp;
  int msg_size = sizeof (*rmp);
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_ACL_PLUGIN_GET_VERSION_REPLY + am->msg_id_base);
  rmp->context = mp->context;
  rmp->major = htonl (ACL_PLUGIN_VERSION_MAJOR);
  rmp->minor = htonl (ACL_PLUGIN_VERSION_MINOR);

  vl_api_send_msg (reg, (u8 *) rmp);
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

static void
print_clib_warning_and_reset (vlib_main_t * vm, u8 * out0)
{
  clib_warning ("%v", out0);
  vec_reset_length (out0);
}

static void
print_cli_and_reset (vlib_main_t * vm, u8 * out0)
{
  vlib_cli_output (vm, "%v", out0);
  vec_reset_length (out0);
}

typedef void (*acl_vector_print_func_t) (vlib_main_t * vm, u8 * out0);

static inline u8 *
format_acl_action (u8 * s, u8 action)
{
  switch (action)
    {
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
  return (s);
}

static void
acl_print_acl_x (acl_vector_print_func_t vpr, vlib_main_t * vm,
		 acl_main_t * am, int acl_index)
{
  acl_rule_t *r;
  acl_rule_t *acl_rules = am->acls[acl_index].rules;
  u8 *out0 = format (0, "acl-index %u count %u tag {%s}\n", acl_index,
		     vec_len (acl_rules), am->acls[acl_index].tag);
  int j;
  vpr (vm, out0);
  for (j = 0; j < vec_len (acl_rules); j++)
    {
      r = &acl_rules[j];
      out0 = format (out0, "  %9d: %s ", j, r->is_ipv6 ? "ipv6" : "ipv4");
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
      vpr (vm, out0);
    }
}

static void
  vl_api_acl_plugin_get_conn_table_max_entries_t_handler
  (vl_api_acl_plugin_get_conn_table_max_entries_t * mp)
{
  acl_main_t *am = &acl_main;
  vl_api_acl_plugin_get_conn_table_max_entries_reply_t *rmp;
  int msg_size = sizeof (*rmp);
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_ACL_PLUGIN_GET_CONN_TABLE_MAX_ENTRIES_REPLY +
	   am->msg_id_base);
  rmp->context = mp->context;
  rmp->conn_table_max_entries = __bswap_64 (am->fa_conn_table_max_entries);

  vl_api_send_msg (rp, (u8 *) rmp);
}

static void
acl_print_acl (vlib_main_t * vm, acl_main_t * am, int acl_index)
{
  acl_print_acl_x (print_cli_and_reset, vm, am, acl_index);
}

static void
warning_acl_print_acl (vlib_main_t * vm, acl_main_t * am, int acl_index)
{
  acl_print_acl_x (print_clib_warning_and_reset, vm, am, acl_index);
}

static void
increment_policy_epoch (acl_main_t * am, u32 sw_if_index, int is_input)
{

  u32 **ppolicy_epoch_by_swi =
    is_input ? &am->input_policy_epoch_by_sw_if_index :
    &am->output_policy_epoch_by_sw_if_index;
  vec_validate (*ppolicy_epoch_by_swi, sw_if_index);

  u32 *p_epoch = vec_elt_at_index ((*ppolicy_epoch_by_swi), sw_if_index);
  *p_epoch =
    ((1 + *p_epoch) & FA_POLICY_EPOCH_MASK) +
    (is_input * FA_POLICY_EPOCH_IS_INPUT);
}

static void
try_increment_acl_policy_epoch (acl_main_t * am, u32 acl_num, int is_input)
{
  u32 ***p_swi_vec_by_acl = is_input ? &am->input_sw_if_index_vec_by_acl
    : &am->output_sw_if_index_vec_by_acl;
  if (acl_num < vec_len (*p_swi_vec_by_acl))
    {
      u32 *p_swi;
      vec_foreach (p_swi, (*p_swi_vec_by_acl)[acl_num])
      {
	increment_policy_epoch (am, *p_swi, is_input);
      }

    }
}

static void
policy_notify_acl_change (acl_main_t * am, u32 acl_num)
{
  try_increment_acl_policy_epoch (am, acl_num, 0);
  try_increment_acl_policy_epoch (am, acl_num, 1);
}


static void
validate_and_reset_acl_counters (acl_main_t * am, u32 acl_index)
{
  int i;
  /* counters are set as vectors [acl#] pointing to vectors of [acl rule] */
  acl_plugin_counter_lock (am);

  int old_len = vec_len (am->combined_acl_counters);

  vec_validate (am->combined_acl_counters, acl_index);

  for (i = old_len; i < vec_len (am->combined_acl_counters); i++)
    {
      am->combined_acl_counters[i].name = 0;
      /* filled in once only */
      am->combined_acl_counters[i].stat_segment_name = (void *)
	format (0, "/acl/%d/matches%c", i, 0);
      i32 rule_count = vec_len (am->acls[i].rules);
      /* Validate one extra so we always have at least one counter for an ACL */
      vlib_validate_combined_counter (&am->combined_acl_counters[i],
				      rule_count);
      vlib_clear_combined_counters (&am->combined_acl_counters[i]);
    }

  /* (re)validate for the actual ACL that is getting added/updated */
  i32 rule_count = vec_len (am->acls[acl_index].rules);
  /* Validate one extra so we always have at least one counter for an ACL */
  vlib_validate_combined_counter (&am->combined_acl_counters[acl_index],
				  rule_count);
  vlib_clear_combined_counters (&am->combined_acl_counters[acl_index]);
  acl_plugin_counter_unlock (am);
}

static int
acl_api_invalid_prefix (const vl_api_prefix_t * prefix)
{
  ip_prefix_t ip_prefix;
  return ip_prefix_decode2 (prefix, &ip_prefix);
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

  if (am->trace_acl > 255)
    clib_warning ("API dbg: acl_add_list index %d tag %s", *acl_list_index,
		  tag);

  /* check if what they request is consistent */
  for (i = 0; i < count; i++)
    {
      if (acl_api_invalid_prefix (&rules[i].src_prefix))
	return VNET_API_ERROR_INVALID_SRC_ADDRESS;
      if (acl_api_invalid_prefix (&rules[i].dst_prefix))
	return VNET_API_ERROR_INVALID_DST_ADDRESS;
      if (ntohs (rules[i].srcport_or_icmptype_first) >
	  ntohs (rules[i].srcport_or_icmptype_last))
	return VNET_API_ERROR_INVALID_VALUE_2;
      if (ntohs (rules[i].dstport_or_icmpcode_first) >
	  ntohs (rules[i].dstport_or_icmpcode_last))
	return VNET_API_ERROR_INVALID_VALUE_2;
    }

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

  /* Create and populate the rules */
  if (count > 0)
    vec_validate (acl_new_rules, count - 1);

  for (i = 0; i < count; i++)
    {
      r = vec_elt_at_index (acl_new_rules, i);
      clib_memset (r, 0, sizeof (*r));
      r->is_permit = rules[i].is_permit;
      r->is_ipv6 = rules[i].src_prefix.address.af;
      ip_address_decode (&rules[i].src_prefix.address, &r->src);
      ip_address_decode (&rules[i].dst_prefix.address, &r->dst);
      r->src_prefixlen = rules[i].src_prefix.len;
      r->dst_prefixlen = rules[i].dst_prefix.len;
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
      clib_memset (a, 0, sizeof (*a));
      /* Will return the newly allocated ACL index */
      *acl_list_index = a - am->acls;
    }
  else
    {
      a = am->acls + *acl_list_index;
      /* Get rid of the old rules */
      if (a->rules)
	vec_free (a->rules);
    }
  a->rules = acl_new_rules;
  memcpy (a->tag, tag, sizeof (a->tag));
  if (am->trace_acl > 255)
    warning_acl_print_acl (am->vlib_main, am, *acl_list_index);
  if (am->reclassify_sessions)
    {
      /* a change in an ACLs if they are applied may mean a new policy epoch */
      policy_notify_acl_change (am, *acl_list_index);
    }
  validate_and_reset_acl_counters (am, *acl_list_index);
  acl_plugin_lookup_context_notify_acl_change (*acl_list_index);
  return 0;
}

static int
acl_is_used_by (u32 acl_index, u32 ** foo_index_vec_by_acl)
{
  if (acl_index < vec_len (foo_index_vec_by_acl))
    {
      if (vec_len (vec_elt (foo_index_vec_by_acl, acl_index)) > 0)
	{
	  /* ACL is applied somewhere. */
	  return 1;
	}
    }
  return 0;
}

static int
acl_del_list (u32 acl_list_index)
{
  acl_main_t *am = &acl_main;
  acl_list_t *a;
  if (pool_is_free_index (am->acls, acl_list_index))
    {
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
  if (acl_is_used_by (acl_list_index, am->input_sw_if_index_vec_by_acl))
    return VNET_API_ERROR_ACL_IN_USE_INBOUND;
  if (acl_is_used_by (acl_list_index, am->output_sw_if_index_vec_by_acl))
    return VNET_API_ERROR_ACL_IN_USE_OUTBOUND;
  /* lookup contexts cover other cases, not just inbound/outbound, so check that */
  if (acl_is_used_by (acl_list_index, am->lc_index_vec_by_acl))
    return VNET_API_ERROR_ACL_IN_USE_BY_LOOKUP_CONTEXT;

  /* now we can delete the ACL itself */
  a = pool_elt_at_index (am->acls, acl_list_index);
  if (a->rules)
    vec_free (a->rules);
  pool_put (am->acls, a);
  /* acl_list_index is now free, notify the lookup contexts */
  acl_plugin_lookup_context_notify_acl_change (acl_list_index);
  return 0;
}

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

  int ret = vnet_classify_add_del_table (cm, skip_mask_ptr, nbuckets,
					 memory_size, skip, match,
					 next_table_index, miss_next_index,
					 table_index, current_data_flag,
					 current_data_offset, is_add,
					 1 /* delete_chain */ );
  return ret;
}

static int
intf_has_etype_whitelist (acl_main_t * am, u32 sw_if_index, int is_input)
{
  u16 **v = is_input
    ? am->input_etype_whitelist_by_sw_if_index
    : am->output_etype_whitelist_by_sw_if_index;
  u16 *whitelist = (vec_len (v) > sw_if_index) ? vec_elt (v, sw_if_index) : 0;
  return vec_len (whitelist) > 0;
}

static void
acl_clear_sessions (acl_main_t * am, u32 sw_if_index)
{
  vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
			     ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX,
			     sw_if_index);
}


static int
acl_interface_in_enable_disable (acl_main_t * am, u32 sw_if_index,
				 int enable_disable)
{
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (am->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (clib_bitmap_get (am->in_acl_on_sw_if_index, sw_if_index) ==
      enable_disable)
    return 0;

  acl_fa_enable_disable (sw_if_index, 1, enable_disable);

  rv = vnet_l2_feature_enable_disable ("l2-input-ip4", "acl-plugin-in-ip4-l2",
				       sw_if_index, enable_disable, 0, 0);
  if (rv)
    clib_error ("Could not enable on input");
  rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "acl-plugin-in-ip6-l2",
				       sw_if_index, enable_disable, 0, 0);
  if (rv)
    clib_error ("Could not enable on input");

  if (intf_has_etype_whitelist (am, sw_if_index, 1))
    vnet_l2_feature_enable_disable ("l2-input-nonip",
				    "acl-plugin-in-nonip-l2", sw_if_index,
				    enable_disable, 0, 0);
  am->in_acl_on_sw_if_index =
    clib_bitmap_set (am->in_acl_on_sw_if_index, sw_if_index, enable_disable);

  return rv;
}

static int
acl_interface_out_enable_disable (acl_main_t * am, u32 sw_if_index,
				  int enable_disable)
{
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (am->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (clib_bitmap_get (am->out_acl_on_sw_if_index, sw_if_index) ==
      enable_disable)
    return 0;

  acl_fa_enable_disable (sw_if_index, 0, enable_disable);

  rv =
    vnet_l2_feature_enable_disable ("l2-output-ip4", "acl-plugin-out-ip4-l2",
				    sw_if_index, enable_disable, 0, 0);
  if (rv)
    clib_error ("Could not enable on output");
  rv =
    vnet_l2_feature_enable_disable ("l2-output-ip6", "acl-plugin-out-ip6-l2",
				    sw_if_index, enable_disable, 0, 0);
  if (rv)
    clib_error ("Could not enable on output");
  if (intf_has_etype_whitelist (am, sw_if_index, 0))
    vnet_l2_feature_enable_disable ("l2-output-nonip",
				    "acl-plugin-out-nonip-l2", sw_if_index,
				    enable_disable, 0, 0);
  am->out_acl_on_sw_if_index =
    clib_bitmap_set (am->out_acl_on_sw_if_index, sw_if_index, enable_disable);

  return rv;
}

static int
acl_stats_intf_counters_enable_disable (acl_main_t * am, int enable_disable)
{
  int rv = 0;

  am->interface_acl_counters_enabled = enable_disable;

  return rv;
}

static int
acl_interface_inout_enable_disable (acl_main_t * am, u32 sw_if_index,
				    int is_input, int enable_disable)
{
  if (is_input)
    return acl_interface_in_enable_disable (am, sw_if_index, enable_disable);
  else
    return acl_interface_out_enable_disable (am, sw_if_index, enable_disable);
}

static int
acl_is_not_defined (acl_main_t * am, u32 acl_list_index)
{
  return (pool_is_free_index (am->acls, acl_list_index));
}

static int
acl_interface_set_inout_acl_list (acl_main_t * am, u32 sw_if_index,
				  u8 is_input, u32 * vec_acl_list_index,
				  int *may_clear_sessions)
{
  u32 *pacln;
  uword *seen_acl_bitmap = 0;
  uword *old_seen_acl_bitmap = 0;
  uword *change_acl_bitmap = 0;
  int acln;
  int rv = 0;


  if (am->trace_acl > 255)
    clib_warning
      ("API dbg: acl_interface_set_inout_acl_list: sw_if_index %d is_input %d acl_vec: [%U]",
       sw_if_index, is_input, format_vec32, vec_acl_list_index, "%d");

  vec_foreach (pacln, vec_acl_list_index)
  {
    if (acl_is_not_defined (am, *pacln))
      {
	/* ACL is not defined. Can not apply */
	clib_warning ("ERROR: ACL %d not defined", *pacln);
	rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	goto done;
      }
    if (clib_bitmap_get (seen_acl_bitmap, *pacln))
      {
	/* ACL being applied twice within the list. error. */
	clib_warning ("ERROR: ACL %d being applied twice", *pacln);
	rv = VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
	goto done;
      }
    seen_acl_bitmap = clib_bitmap_set (seen_acl_bitmap, *pacln, 1);
  }


  u32 **pinout_lc_index_by_sw_if_index =
    is_input ? &am->input_lc_index_by_sw_if_index : &am->
    output_lc_index_by_sw_if_index;

  u32 ***pinout_acl_vec_by_sw_if_index =
    is_input ? &am->input_acl_vec_by_sw_if_index : &am->
    output_acl_vec_by_sw_if_index;

  u32 ***pinout_sw_if_index_vec_by_acl =
    is_input ? &am->input_sw_if_index_vec_by_acl : &am->
    output_sw_if_index_vec_by_acl;

  vec_validate ((*pinout_acl_vec_by_sw_if_index), sw_if_index);

  clib_bitmap_validate (old_seen_acl_bitmap, 1);

  vec_foreach (pacln, (*pinout_acl_vec_by_sw_if_index)[sw_if_index])
  {
    old_seen_acl_bitmap = clib_bitmap_set (old_seen_acl_bitmap, *pacln, 1);
  }
  change_acl_bitmap =
    clib_bitmap_dup_xor (old_seen_acl_bitmap, seen_acl_bitmap);

  if (am->trace_acl > 255)
    clib_warning ("bitmaps: old seen %U new seen %U changed %U",
		  format_bitmap_hex, old_seen_acl_bitmap, format_bitmap_hex,
		  seen_acl_bitmap, format_bitmap_hex, change_acl_bitmap);

/* *INDENT-OFF* */
  clib_bitmap_foreach(acln, change_acl_bitmap, ({
    if (clib_bitmap_get(old_seen_acl_bitmap, acln)) {
      /* ACL is being removed. */
      if (acln < vec_len((*pinout_sw_if_index_vec_by_acl))) {
        int index = vec_search((*pinout_sw_if_index_vec_by_acl)[acln], sw_if_index);
        vec_del1((*pinout_sw_if_index_vec_by_acl)[acln], index);
      }
    } else {
      /* ACL is being added. */
      vec_validate((*pinout_sw_if_index_vec_by_acl), acln);
      vec_add1((*pinout_sw_if_index_vec_by_acl)[acln], sw_if_index);
    }
  }));
/* *INDENT-ON* */

  vec_free ((*pinout_acl_vec_by_sw_if_index)[sw_if_index]);
  (*pinout_acl_vec_by_sw_if_index)[sw_if_index] =
    vec_dup (vec_acl_list_index);

  if (am->reclassify_sessions)
    {
      /* re-applying ACLs means a new policy epoch */
      increment_policy_epoch (am, sw_if_index, is_input);
    }
  else
    {
      /* if no commonalities between the ACL# - then we should definitely clear the sessions */
      if (may_clear_sessions && *may_clear_sessions
	  && !clib_bitmap_is_zero (change_acl_bitmap))
	{
	  acl_clear_sessions (am, sw_if_index);
	  *may_clear_sessions = 0;
	}
    }

  /*
   * prepare or delete the lookup context if necessary, and if context exists, set ACL list
   */
  vec_validate_init_empty ((*pinout_lc_index_by_sw_if_index), sw_if_index,
			   ~0);
  if (vec_len (vec_acl_list_index) > 0)
    {
      u32 lc_index = (*pinout_lc_index_by_sw_if_index)[sw_if_index];
      if (~0 == lc_index)
	{
	  lc_index =
	    acl_plugin.get_lookup_context_index (am->interface_acl_user_id,
						 sw_if_index, is_input);
	  (*pinout_lc_index_by_sw_if_index)[sw_if_index] = lc_index;
	}
      acl_plugin.set_acl_vec_for_context (lc_index, vec_acl_list_index);
    }
  else
    {
      if (~0 != (*pinout_lc_index_by_sw_if_index)[sw_if_index])
	{
	  acl_plugin.
	    put_lookup_context_index ((*pinout_lc_index_by_sw_if_index)
				      [sw_if_index]);
	  (*pinout_lc_index_by_sw_if_index)[sw_if_index] = ~0;
	}
    }
  /* ensure ACL processing is enabled/disabled as needed */
  acl_interface_inout_enable_disable (am, sw_if_index, is_input,
				      vec_len (vec_acl_list_index) > 0);

done:
  clib_bitmap_free (change_acl_bitmap);
  clib_bitmap_free (seen_acl_bitmap);
  clib_bitmap_free (old_seen_acl_bitmap);
  return rv;
}

static void
acl_interface_reset_inout_acls (u32 sw_if_index, u8 is_input,
				int *may_clear_sessions)
{
  acl_main_t *am = &acl_main;
  acl_interface_set_inout_acl_list (am, sw_if_index, is_input, 0,
				    may_clear_sessions);
}

static int
acl_interface_add_del_inout_acl (u32 sw_if_index, u8 is_add, u8 is_input,
				 u32 acl_list_index)
{

  acl_main_t *am = &acl_main;
  u32 *acl_vec = 0;
  int may_clear_sessions = 1;

  int error_already_applied = is_input ? VNET_API_ERROR_ACL_IN_USE_INBOUND
    : VNET_API_ERROR_ACL_IN_USE_OUTBOUND;

  u32 ***pinout_acl_vec_by_sw_if_index =
    is_input ? &am->input_acl_vec_by_sw_if_index : &am->
    output_acl_vec_by_sw_if_index;
  int rv = 0;
  if (is_add)
    {
      vec_validate ((*pinout_acl_vec_by_sw_if_index), sw_if_index);
      u32 index = vec_search ((*pinout_acl_vec_by_sw_if_index)[sw_if_index],
			      acl_list_index);

      if (~0 != index)
	{
	  rv = error_already_applied;
	  goto done;
	}

      acl_vec = vec_dup ((*pinout_acl_vec_by_sw_if_index)[sw_if_index]);
      vec_add1 (acl_vec, acl_list_index);
    }
  else
    {
      if (sw_if_index >= vec_len (*pinout_acl_vec_by_sw_if_index))
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	  goto done;
	}

      u32 index = vec_search ((*pinout_acl_vec_by_sw_if_index)[sw_if_index],
			      acl_list_index);

      if (~0 == index)
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	  goto done;
	}

      acl_vec = vec_dup ((*pinout_acl_vec_by_sw_if_index)[sw_if_index]);
      vec_del1 (acl_vec, index);
    }

  rv = acl_interface_set_inout_acl_list (am, sw_if_index, is_input, acl_vec,
					 &may_clear_sessions);
done:
  vec_free (acl_vec);
  return rv;
}

static int
acl_set_etype_whitelists (acl_main_t * am, u32 sw_if_index, u16 * vec_in,
			  u16 * vec_out)
{
  vec_validate (am->input_etype_whitelist_by_sw_if_index, sw_if_index);
  vec_validate (am->output_etype_whitelist_by_sw_if_index, sw_if_index);

  vec_free (am->input_etype_whitelist_by_sw_if_index[sw_if_index]);
  vec_free (am->output_etype_whitelist_by_sw_if_index[sw_if_index]);

  am->input_etype_whitelist_by_sw_if_index[sw_if_index] = vec_in;
  am->output_etype_whitelist_by_sw_if_index[sw_if_index] = vec_out;

  /*
   * if there are already inbound/outbound ACLs applied, toggle the
   * enable/disable - this will recreate the necessary tables.
   */

  if (vec_len (am->input_acl_vec_by_sw_if_index) > sw_if_index)
    {
      if (vec_len (am->input_acl_vec_by_sw_if_index[sw_if_index]) > 0)
	{
	  acl_interface_in_enable_disable (am, sw_if_index, 0);
	  acl_interface_in_enable_disable (am, sw_if_index, 1);
	}
    }
  if (vec_len (am->output_acl_vec_by_sw_if_index) > sw_if_index)
    {
      if (vec_len (am->output_acl_vec_by_sw_if_index[sw_if_index]) > 0)
	{
	  acl_interface_out_enable_disable (am, sw_if_index, 0);
	  acl_interface_out_enable_disable (am, sw_if_index, 1);
	}
    }
  return 0;
}


typedef struct
{
  u8 is_ipv6;
  u8 has_egress;
  u8 mac_mask[6];
  u8 prefix_len;
  u32 count;
  u32 table_index;
  u32 arp_table_index;
  u32 dot1q_table_index;
  u32 dot1ad_table_index;
  u32 arp_dot1q_table_index;
  u32 arp_dot1ad_table_index;
  /* egress tables */
  u32 out_table_index;
  u32 out_arp_table_index;
  u32 out_dot1q_table_index;
  u32 out_dot1ad_table_index;
  u32 out_arp_dot1q_table_index;
  u32 out_arp_dot1ad_table_index;
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
get_l3_dst_offset (int is6)
{
  if (is6)
    return (sizeof (ethernet_header_t) +
	    offsetof (ip6_header_t, dst_address));
  else
    return (sizeof (ethernet_header_t) +
	    offsetof (ip4_header_t, dst_address));
}

/*
 * return if the is_permit value also requires to create the egress tables
 * For backwards compatibility, we keep the is_permit = 1 to only
 * create the ingress tables, and the new value of 3 will also
 * create the egress tables based on destination.
 */
static int
macip_permit_also_egress (u8 is_permit)
{
  return (is_permit == 3);
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
  u32 out_last_table;
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
	  mvec[match_type_index].has_egress = 0;
	  mvec[match_type_index].table_index = ~0;
	  mvec[match_type_index].arp_table_index = ~0;
	  mvec[match_type_index].dot1q_table_index = ~0;
	  mvec[match_type_index].dot1ad_table_index = ~0;
	  mvec[match_type_index].arp_dot1q_table_index = ~0;
	  mvec[match_type_index].arp_dot1ad_table_index = ~0;
	  mvec[match_type_index].out_table_index = ~0;
	  mvec[match_type_index].out_arp_table_index = ~0;
	  mvec[match_type_index].out_dot1q_table_index = ~0;
	  mvec[match_type_index].out_dot1ad_table_index = ~0;
	  mvec[match_type_index].out_arp_dot1q_table_index = ~0;
	  mvec[match_type_index].out_arp_dot1ad_table_index = ~0;
	}
      mvec[match_type_index].count++;
      mvec[match_type_index].has_egress |=
	macip_permit_also_egress (a->rules[i].is_permit);
    }
  /* Put the most frequently used tables last in the list so we can create classifier tables in reverse order */
  vec_sort_with_function (mvec, match_type_compare);
  /* Create the classifier tables */
  last_table = ~0;
  out_last_table = ~0;
  /* First add ARP tables */
  vec_foreach (mt, mvec)
  {
    int mask_len;
    int is6 = mt->is_ipv6;
    int tags;
    u32 *last_tag_table;
    u32 *out_last_tag_table;
    u32 l3_offset;

    if (!is6)
      {
	/*
	   0                   1                   2                   3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                      Destination Address                      |
	   +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                               |                               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
	   |                         Source Address                        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |           EtherType           |         Hardware Type         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |         Protocol Type         |  Hw addr len  | Proto addr len|
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |             Opcode            |                               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
	   |                    Sender Hardware Address                    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                    Sender Protocol Address                    |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                    Target Hardware Address                    |
	   +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                               |     TargetProtocolAddress     |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	for (tags = 2; tags >= 0; tags--)
	  {
	    clib_memset (mask, 0, sizeof (mask));
	    /* source MAC address */
	    memcpy (&mask[6], mt->mac_mask, 6);

	    switch (tags)
	      {
	      case 0:
	      default:
		clib_memset (&mask[12], 0xff, 2);	/* ethernet protocol */
		l3_offset = 14;
		last_tag_table = &mt->arp_table_index;
		break;
	      case 1:
		clib_memset (&mask[12], 0xff, 2);	/* VLAN tag1 */
		clib_memset (&mask[16], 0xff, 2);	/* ethernet protocol */
		l3_offset = 18;
		last_tag_table = &mt->arp_dot1q_table_index;
		break;
	      case 2:
		clib_memset (&mask[12], 0xff, 2);	/* VLAN tag1 */
		clib_memset (&mask[16], 0xff, 2);	/* VLAN tag2 */
		clib_memset (&mask[20], 0xff, 2);	/* ethernet protocol */
		l3_offset = 22;
		last_tag_table = &mt->arp_dot1ad_table_index;
		break;
	      }

	    /* sender hardware address within ARP */
	    memcpy (&mask[l3_offset + 8], mt->mac_mask, 6);
	    /* sender protocol address within ARP */
	    for (i = 0; i < (mt->prefix_len / 8); i++)
	      mask[l3_offset + 14 + i] = 0xff;
	    if (mt->prefix_len % 8)
	      mask[l3_offset + 14 + (mt->prefix_len / 8)] =
		0xff - ((1 << (8 - mt->prefix_len % 8)) - 1);

	    mask_len = ((l3_offset + 14 + ((mt->prefix_len + 7) / 8) +
			 (sizeof (u32x4) -
			  1)) / sizeof (u32x4)) * sizeof (u32x4);
	    acl_classify_add_del_table_small (cm, mask, mask_len, last_table,
					      (~0 == last_table) ? 0 : ~0,
					      last_tag_table, 1);
	    last_table = *last_tag_table;
	    if (mt->has_egress)
	      {
		/* egress ARP table */
		clib_memset (mask, 0, sizeof (mask));

		switch (tags)
		  {
		  case 0:
		  default:
		    clib_memset (&mask[12], 0xff, 2);	/* ethernet protocol */
		    l3_offset = 14;
		    out_last_tag_table = &mt->out_arp_table_index;
		    break;
		  case 1:
		    clib_memset (&mask[12], 0xff, 2);	/* VLAN tag1 */
		    clib_memset (&mask[16], 0xff, 2);	/* ethernet protocol */
		    l3_offset = 18;
		    out_last_tag_table = &mt->out_arp_dot1q_table_index;
		    break;
		  case 2:
		    clib_memset (&mask[12], 0xff, 2);	/* VLAN tag1 */
		    clib_memset (&mask[16], 0xff, 2);	/* VLAN tag2 */
		    clib_memset (&mask[20], 0xff, 2);	/* ethernet protocol */
		    l3_offset = 22;
		    out_last_tag_table = &mt->out_arp_dot1ad_table_index;
		    break;
		  }

		/* AYXX: FIXME here - can we tighten the ARP-related table more ? */
		/* mask captures just the destination and the ethertype */
		mask_len = ((l3_offset +
			     (sizeof (u32x4) -
			      1)) / sizeof (u32x4)) * sizeof (u32x4);
		acl_classify_add_del_table_small (cm, mask, mask_len,
						  out_last_table,
						  (~0 ==
						   out_last_table) ? 0 : ~0,
						  out_last_tag_table, 1);
		out_last_table = *out_last_tag_table;
	      }
	  }
      }
  }
  /* Now add IP[46] tables */
  vec_foreach (mt, mvec)
  {
    int mask_len;
    int is6 = mt->is_ipv6;
    int l3_src_offs;
    int l3_dst_offs;
    int tags;
    u32 *last_tag_table;
    u32 *out_last_tag_table;

    /*
     * create chained tables for VLAN (no-tags, dot1q and dot1ad) packets
     */
    for (tags = 2; tags >= 0; tags--)
      {
	clib_memset (mask, 0, sizeof (mask));
	memcpy (&mask[6], mt->mac_mask, 6);
	l3_src_offs = tags * 4 + get_l3_src_offset (is6);
	switch (tags)
	  {
	  case 0:
	  default:
	    clib_memset (&mask[12], 0xff, 2);	/* ethernet protocol */
	    last_tag_table = &mt->table_index;
	    break;
	  case 1:
	    clib_memset (&mask[12], 0xff, 2);	/* VLAN tag1 */
	    clib_memset (&mask[16], 0xff, 2);	/* ethernet protocol */
	    last_tag_table = &mt->dot1q_table_index;
	    break;
	  case 2:
	    clib_memset (&mask[12], 0xff, 2);	/* VLAN tag1 */
	    clib_memset (&mask[16], 0xff, 2);	/* VLAN tag2 */
	    clib_memset (&mask[20], 0xff, 2);	/* ethernet protocol */
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
      }
    if (mt->has_egress)
      {
	for (tags = 2; tags >= 0; tags--)
	  {
	    clib_memset (mask, 0, sizeof (mask));
	    /* MAC destination */
	    memcpy (&mask[0], mt->mac_mask, 6);
	    l3_dst_offs = tags * 4 + get_l3_dst_offset (is6);
	    switch (tags)
	      {
	      case 0:
	      default:
		clib_memset (&mask[12], 0xff, 2);	/* ethernet protocol */
		out_last_tag_table = &mt->out_table_index;
		break;
	      case 1:
		clib_memset (&mask[12], 0xff, 2);	/* VLAN tag1 */
		clib_memset (&mask[16], 0xff, 2);	/* ethernet protocol */
		out_last_tag_table = &mt->out_dot1q_table_index;
		break;
	      case 2:
		clib_memset (&mask[12], 0xff, 2);	/* VLAN tag1 */
		clib_memset (&mask[16], 0xff, 2);	/* VLAN tag2 */
		clib_memset (&mask[20], 0xff, 2);	/* ethernet protocol */
		out_last_tag_table = &mt->out_dot1ad_table_index;
		break;
	      }
	    for (i = 0; i < (mt->prefix_len / 8); i++)
	      {
		mask[l3_dst_offs + i] = 0xff;
	      }
	    if (mt->prefix_len % 8)
	      {
		mask[l3_dst_offs + (mt->prefix_len / 8)] =
		  0xff - ((1 << (8 - mt->prefix_len % 8)) - 1);
	      }
	    /*
	     * Round-up the number of bytes needed to store the prefix,
	     * and round up the number of vectors too
	     */
	    mask_len = ((l3_dst_offs + ((mt->prefix_len + 7) / 8) +
			 (sizeof (u32x4) -
			  1)) / sizeof (u32x4)) * sizeof (u32x4);
	    acl_classify_add_del_table_small (cm, mask, mask_len,
					      out_last_table,
					      (~0 == out_last_table) ? 0 : ~0,
					      out_last_tag_table, 1);
	    out_last_table = *out_last_tag_table;
	  }
      }
  }
  a->ip4_table_index = last_table;
  a->ip6_table_index = last_table;
  a->l2_table_index = last_table;

  a->out_ip4_table_index = out_last_table;
  a->out_ip6_table_index = out_last_table;
  a->out_l2_table_index = out_last_table;

  /* Populate the classifier tables with rules from the MACIP ACL */
  for (i = 0; i < a->count; i++)
    {
      u32 action = 0;
      u32 metadata = 0;
      int is6 = a->rules[i].is_ipv6;
      int l3_src_offs;
      int l3_dst_offs;
      u32 tag_table;
      int tags, eth;

      match_type_index =
	macip_find_match_type (mvec, a->rules[i].src_mac_mask,
			       a->rules[i].src_prefixlen,
			       a->rules[i].is_ipv6);
      ASSERT (match_type_index != ~0);

      for (tags = 2; tags >= 0; tags--)
	{
	  clib_memset (mask, 0, sizeof (mask));
	  l3_src_offs = tags * 4 + get_l3_src_offset (is6);
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
	  clib_memset (&mask[12], 0, sizeof (mask) - 12);
	}

      /* add ARP table entry too */
      if (!is6 && (mvec[match_type_index].arp_table_index != ~0))
	{
	  clib_memset (mask, 0, sizeof (mask));
	  memcpy (&mask[6], a->rules[i].src_mac, 6);

	  for (tags = 2; tags >= 0; tags--)
	    {
	      switch (tags)
		{
		case 0:
		default:
		  tag_table = mvec[match_type_index].arp_table_index;
		  mask[12] = 0x08;
		  mask[13] = 0x06;
		  l3_src_offs = 14;
		  break;
		case 1:
		  tag_table = mvec[match_type_index].arp_dot1q_table_index;
		  mask[12] = 0x81;
		  mask[13] = 0x00;
		  mask[16] = 0x08;
		  mask[17] = 0x06;
		  l3_src_offs = 18;
		  break;
		case 2:
		  tag_table = mvec[match_type_index].arp_dot1ad_table_index;
		  mask[12] = 0x88;
		  mask[13] = 0xa8;
		  mask[16] = 0x81;
		  mask[17] = 0x00;
		  mask[20] = 0x08;
		  mask[21] = 0x06;
		  l3_src_offs = 22;
		  break;
		}

	      memcpy (&mask[l3_src_offs + 8], a->rules[i].src_mac, 6);
	      memcpy (&mask[l3_src_offs + 14], &a->rules[i].src_ip_addr.ip4,
		      4);
	      vnet_classify_add_del_session (cm, tag_table, mask,
					     a->rules[i].is_permit ? ~0 : 0,
					     i, 0, action, metadata, 1);
	    }
	}
      if (macip_permit_also_egress (a->rules[i].is_permit))
	{
	  /* Add the egress entry with destination set */
	  for (tags = 2; tags >= 0; tags--)
	    {
	      clib_memset (mask, 0, sizeof (mask));
	      l3_dst_offs = tags * 4 + get_l3_dst_offset (is6);
	      /* src mac in the other direction becomes dst */
	      memcpy (&mask[0], a->rules[i].src_mac, 6);
	      switch (tags)
		{
		case 0:
		default:
		  tag_table = mvec[match_type_index].out_table_index;
		  eth = 12;
		  break;
		case 1:
		  tag_table = mvec[match_type_index].out_dot1q_table_index;
		  mask[12] = 0x81;
		  mask[13] = 0x00;
		  eth = 16;
		  break;
		case 2:
		  tag_table = mvec[match_type_index].out_dot1ad_table_index;
		  mask[12] = 0x88;
		  mask[13] = 0xa8;
		  mask[16] = 0x81;
		  mask[17] = 0x00;
		  eth = 20;
		  break;
		}
	      if (is6)
		{
		  memcpy (&mask[l3_dst_offs], &a->rules[i].src_ip_addr.ip6,
			  16);
		  mask[eth] = 0x86;
		  mask[eth + 1] = 0xdd;
		}
	      else
		{
		  memcpy (&mask[l3_dst_offs], &a->rules[i].src_ip_addr.ip4,
			  4);
		  mask[eth] = 0x08;
		  mask[eth + 1] = 0x00;
		}

	      /* add session to table mvec[match_type_index].table_index; */
	      vnet_classify_add_del_session (cm, tag_table,
					     mask,
					     a->rules[i].is_permit ? ~0 : 0,
					     i, 0, action, metadata, 1);
	      // clib_memset (&mask[12], 0, sizeof (mask) - 12);
	    }

	  /* add ARP table entry too */
	  if (!is6 && (mvec[match_type_index].out_arp_table_index != ~0))
	    {
	      for (tags = 2; tags >= 0; tags--)
		{
		  clib_memset (mask, 0, sizeof (mask));
		  switch (tags)
		    {
		    case 0:
		    default:
		      tag_table = mvec[match_type_index].out_arp_table_index;
		      mask[12] = 0x08;
		      mask[13] = 0x06;
		      break;
		    case 1:
		      tag_table =
			mvec[match_type_index].out_arp_dot1q_table_index;
		      mask[12] = 0x81;
		      mask[13] = 0x00;
		      mask[16] = 0x08;
		      mask[17] = 0x06;
		      break;
		    case 2:
		      tag_table =
			mvec[match_type_index].out_arp_dot1ad_table_index;
		      mask[12] = 0x88;
		      mask[13] = 0xa8;
		      mask[16] = 0x81;
		      mask[17] = 0x00;
		      mask[20] = 0x08;
		      mask[21] = 0x06;
		      break;
		    }

		  vnet_classify_add_del_session (cm, tag_table,
						 mask,
						 a->rules[i].
						 is_permit ? ~0 : 0, i, 0,
						 action, metadata, 1);
		}
	    }
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
  if (a->out_ip4_table_index != ~0)
    {
      acl_classify_add_del_table_small (cm, 0, ~0, ~0, ~0,
					&a->out_ip4_table_index, 0);
      a->out_ip4_table_index = ~0;
    }
  if (a->out_ip6_table_index != ~0)
    {
      acl_classify_add_del_table_small (cm, 0, ~0, ~0, ~0,
					&a->out_ip6_table_index, 0);
      a->out_ip6_table_index = ~0;
    }
  if (a->out_l2_table_index != ~0)
    {
      acl_classify_add_del_table_small (cm, 0, ~0, ~0, ~0,
					&a->out_l2_table_index, 0);
      a->out_l2_table_index = ~0;
    }
}

static int
macip_maybe_apply_unapply_classifier_tables (acl_main_t * am, u32 acl_index,
					     int is_apply)
{
  int rv = 0;
  int rv0 = 0;
  int i;
  macip_acl_list_t *a = pool_elt_at_index (am->macip_acls, acl_index);

  for (i = 0; i < vec_len (am->macip_acl_by_sw_if_index); i++)
    if (vec_elt (am->macip_acl_by_sw_if_index, i) == acl_index)
      {
	rv0 = vnet_set_input_acl_intfc (am->vlib_main, i, a->ip4_table_index,
					a->ip6_table_index, a->l2_table_index,
					is_apply);
	/* return the first unhappy outcome but make try to plough through. */
	rv = rv || rv0;
	rv0 =
	  vnet_set_output_acl_intfc (am->vlib_main, i, a->out_ip4_table_index,
				     a->out_ip6_table_index,
				     a->out_l2_table_index, is_apply);
	/* return the first unhappy outcome but make try to plough through. */
	rv = rv || rv0;
      }
  return rv;
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
  int rv = 0;

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
  /* if replacing the ACL, unapply the classifier tables first - they will be gone.. */
  if (~0 != *acl_list_index)
    rv = macip_maybe_apply_unapply_classifier_tables (am, *acl_list_index, 0);
  /* Create and populate the rules */
  if (count > 0)
    vec_validate (acl_new_rules, count - 1);

  for (i = 0; i < count; i++)
    {
      r = &acl_new_rules[i];
      r->is_permit = rules[i].is_permit;
      r->is_ipv6 = rules[i].src_prefix.address.af;
      mac_address_decode (rules[i].src_mac, (mac_address_t *) & r->src_mac);
      mac_address_decode (rules[i].src_mac_mask,
			  (mac_address_t *) & r->src_mac_mask);
      ip_address_decode (&rules[i].src_prefix.address, &r->src_ip_addr);
      r->src_prefixlen = rules[i].src_prefix.len;
    }

  if (~0 == *acl_list_index)
    {
      /* Get ACL index */
      pool_get_aligned (am->macip_acls, a, CLIB_CACHE_LINE_BYTES);
      clib_memset (a, 0, sizeof (*a));
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

  /* Create and populate the classifier tables */
  macip_create_classify_tables (am, *acl_list_index);
  /* If the ACL was already applied somewhere, reapply the newly created tables */
  rv = rv
    || macip_maybe_apply_unapply_classifier_tables (am, *acl_list_index, 1);
  return rv;
}

/* No check that sw_if_index denotes a valid interface - the callers
 * were supposed to validate.
 *
 * That said, if sw_if_index corresponds to an interface that exists at all,
 * this function must return errors accordingly if the ACL is not applied.
 */

static int
macip_acl_interface_del_acl (acl_main_t * am, u32 sw_if_index)
{
  int rv;
  u32 macip_acl_index;
  macip_acl_list_t *a;

  /* The vector is too short - MACIP ACL is not applied */
  if (sw_if_index >= vec_len (am->macip_acl_by_sw_if_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  macip_acl_index = am->macip_acl_by_sw_if_index[sw_if_index];
  /* No point in deleting MACIP ACL which is not applied */
  if (~0 == macip_acl_index)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  a = pool_elt_at_index (am->macip_acls, macip_acl_index);
  /* remove the classifier tables off the interface L2 ACL */
  rv =
    vnet_set_input_acl_intfc (am->vlib_main, sw_if_index, a->ip4_table_index,
			      a->ip6_table_index, a->l2_table_index, 0);
  rv |=
    vnet_set_output_acl_intfc (am->vlib_main, sw_if_index,
			       a->out_ip4_table_index, a->out_ip6_table_index,
			       a->out_l2_table_index, 0);
  /* Unset the MACIP ACL index */
  am->macip_acl_by_sw_if_index[sw_if_index] = ~0;
  /* macip_acl_interface_add_acl did a vec_add1() to this previously, so [sw_if_index] should be valid */
  u32 index = vec_search (am->sw_if_index_vec_by_macip_acl[macip_acl_index],
			  sw_if_index);
  if (index != ~0)
    vec_del1 (am->sw_if_index_vec_by_macip_acl[macip_acl_index], index);
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
  a = pool_elt_at_index (am->macip_acls, macip_acl_index);
  vec_validate_init_empty (am->macip_acl_by_sw_if_index, sw_if_index, ~0);
  vec_validate (am->sw_if_index_vec_by_macip_acl, macip_acl_index);
  vec_add1 (am->sw_if_index_vec_by_macip_acl[macip_acl_index], sw_if_index);
  /* If there already a MACIP ACL applied, unapply it */
  if (~0 != am->macip_acl_by_sw_if_index[sw_if_index])
    macip_acl_interface_del_acl (am, sw_if_index);
  am->macip_acl_by_sw_if_index[sw_if_index] = macip_acl_index;

  /* Apply the classifier tables for L2 ACLs */
  rv =
    vnet_set_input_acl_intfc (am->vlib_main, sw_if_index, a->ip4_table_index,
			      a->ip6_table_index, a->l2_table_index, 1);
  rv |=
    vnet_set_output_acl_intfc (am->vlib_main, sw_if_index,
			       a->out_ip4_table_index, a->out_ip6_table_index,
			       a->out_l2_table_index, 1);
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

  /* Now that classifier tables are detached, clean them up */
  macip_destroy_classify_tables (am, acl_list_index);

  /* now we can delete the ACL itself */
  a = pool_elt_at_index (am->macip_acls, acl_list_index);
  if (a->rules)
    {
      vec_free (a->rules);
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
  vl_api_acl_stats_intf_counters_enable_t_handler
  (vl_api_acl_stats_intf_counters_enable_t * mp)
{
  acl_main_t *am = &acl_main;
  vl_api_acl_stats_intf_counters_enable_reply_t *rmp;
  int rv;

  rv = acl_stats_intf_counters_enable_disable (am, mp->enable);

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
      int may_clear_sessions = 1;
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
	  u32 *in_acl_vec = 0;
	  u32 *out_acl_vec = 0;
	  for (i = 0; i < mp->count; i++)
	    if (i < mp->n_input)
	      vec_add1 (in_acl_vec, clib_net_to_host_u32 (mp->acls[i]));
	    else
	      vec_add1 (out_acl_vec, clib_net_to_host_u32 (mp->acls[i]));

	  rv =
	    acl_interface_set_inout_acl_list (am, sw_if_index, 0, out_acl_vec,
					      &may_clear_sessions);
	  rv = rv
	    || acl_interface_set_inout_acl_list (am, sw_if_index, 1,
						 in_acl_vec,
						 &may_clear_sessions);
	  vec_free (in_acl_vec);
	  vec_free (out_acl_vec);
	}
    }

  REPLY_MACRO (VL_API_ACL_INTERFACE_SET_ACL_LIST_REPLY);
}

static void
copy_acl_rule_to_api_rule (vl_api_acl_rule_t * api_rule, acl_rule_t * r)
{
  api_rule->is_permit = r->is_permit;
  ip_address_encode (&r->src, r->is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &api_rule->src_prefix.address);
  ip_address_encode (&r->dst, r->is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
		     &api_rule->dst_prefix.address);
  api_rule->src_prefix.len = r->src_prefixlen;
  api_rule->dst_prefix.len = r->dst_prefixlen;
  api_rule->proto = r->proto;
  api_rule->srcport_or_icmptype_first = htons (r->src_port_or_type_first);
  api_rule->srcport_or_icmptype_last = htons (r->src_port_or_type_last);
  api_rule->dstport_or_icmpcode_first = htons (r->dst_port_or_code_first);
  api_rule->dstport_or_icmpcode_last = htons (r->dst_port_or_code_last);
  api_rule->tcp_flags_mask = r->tcp_flags_mask;
  api_rule->tcp_flags_value = r->tcp_flags_value;
}

static void
send_acl_details (acl_main_t * am, vl_api_registration_t * reg,
		  acl_list_t * acl, u32 context)
{
  vl_api_acl_details_t *mp;
  vl_api_acl_rule_t *rules;
  int i;
  acl_rule_t *acl_rules = acl->rules;
  int msg_size = sizeof (*mp) + sizeof (mp->r[0]) * vec_len (acl_rules);

  mp = vl_msg_api_alloc (msg_size);
  clib_memset (mp, 0, msg_size);
  mp->_vl_msg_id = ntohs (VL_API_ACL_DETAILS + am->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->count = htonl (vec_len (acl_rules));
  mp->acl_index = htonl (acl - am->acls);
  memcpy (mp->tag, acl->tag, sizeof (mp->tag));
  // clib_memcpy (mp->r, acl->rules, acl->count * sizeof(acl->rules[0]));
  rules = mp->r;
  for (i = 0; i < vec_len (acl_rules); i++)
    {
      copy_acl_rule_to_api_rule (&rules[i], &acl_rules[i]);
    }

  vl_api_send_msg (reg, (u8 *) mp);
}


static void
vl_api_acl_dump_t_handler (vl_api_acl_dump_t * mp)
{
  acl_main_t *am = &acl_main;
  u32 acl_index;
  acl_list_t *acl;
  int rv = -1;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->acl_index == ~0)
    {
    /* *INDENT-OFF* */
    /* Just dump all ACLs */
    pool_foreach (acl, am->acls,
    ({
      send_acl_details(am, reg, acl, mp->context);
    }));
    /* *INDENT-ON* */
    }
  else
    {
      acl_index = ntohl (mp->acl_index);
      if (!pool_is_free_index (am->acls, acl_index))
	{
	  acl = pool_elt_at_index (am->acls, acl_index);
	  send_acl_details (am, reg, acl, mp->context);
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
				 vl_api_registration_t * reg,
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
  clib_memset (mp, 0, msg_size);
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
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_acl_interface_list_dump_t_handler (vl_api_acl_interface_list_dump_t *
					  mp)
{
  acl_main_t *am = &acl_main;
  vnet_sw_interface_t *swif;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;

  u32 sw_if_index;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->sw_if_index == ~0)
    {
    /* *INDENT-OFF* */
    pool_foreach (swif, im->sw_interfaces,
    ({
      send_acl_interface_list_details(am, reg, swif->sw_if_index, mp->context);
    }));
    /* *INDENT-ON* */
    }
  else
    {
      sw_if_index = ntohl (mp->sw_if_index);
      if (!pool_is_free_index (im->sw_interfaces, sw_if_index))
	send_acl_interface_list_details (am, reg, sw_if_index, mp->context);
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
send_macip_acl_details (acl_main_t * am, vl_api_registration_t * reg,
			macip_acl_list_t * acl, u32 context)
{
  vl_api_macip_acl_details_t *mp;
  vl_api_macip_acl_rule_t *rules;
  macip_acl_rule_t *r;
  int i;
  int msg_size = sizeof (*mp) + (acl ? sizeof (mp->r[0]) * acl->count : 0);

  mp = vl_msg_api_alloc (msg_size);
  clib_memset (mp, 0, msg_size);
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
	  mac_address_encode ((mac_address_t *) & r->src_mac,
			      rules[i].src_mac);
	  mac_address_encode ((mac_address_t *) & r->src_mac_mask,
			      rules[i].src_mac_mask);
	  ip_address_encode (&r->src_ip_addr,
			     r->is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
			     &rules[i].src_prefix.address);
	  rules[i].src_prefix.len = r->src_prefixlen;
	}
    }
  else
    {
      /* No martini, no party - no ACL applied to this interface. */
      mp->acl_index = ~0;
      mp->count = 0;
    }

  vl_api_send_msg (reg, (u8 *) mp);
}


static void
vl_api_macip_acl_dump_t_handler (vl_api_macip_acl_dump_t * mp)
{
  acl_main_t *am = &acl_main;
  macip_acl_list_t *acl;

  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->acl_index == ~0)
    {
      /* Just dump all ACLs for now, with sw_if_index = ~0 */
      /* *INDENT-OFF* */
      pool_foreach (acl, am->macip_acls,
        ({
          send_macip_acl_details (am, reg, acl, mp->context);
        }));
      /* *INDENT-ON* */
    }
  else
    {
      u32 acl_index = ntohl (mp->acl_index);
      if (!pool_is_free_index (am->macip_acls, acl_index))
	{
	  acl = pool_elt_at_index (am->macip_acls, acl_index);
	  send_macip_acl_details (am, reg, acl, mp->context);
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
  vl_api_registration_t *reg;
  int i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_MACIP_ACL_INTERFACE_GET_REPLY + am->msg_id_base);
  rmp->context = mp->context;
  rmp->count = htonl (count);
  for (i = 0; i < count; i++)
    {
      rmp->acls[i] = htonl (am->macip_acl_by_sw_if_index[i]);
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
send_macip_acl_interface_list_details (acl_main_t * am,
				       vl_api_registration_t * reg,
				       u32 sw_if_index,
				       u32 acl_index, u32 context)
{
  vl_api_macip_acl_interface_list_details_t *rmp;
  /* at this time there is only ever 1 mac ip acl per interface */
  int msg_size = sizeof (*rmp) + sizeof (rmp->acls[0]);

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id =
    ntohs (VL_API_MACIP_ACL_INTERFACE_LIST_DETAILS + am->msg_id_base);

  /* fill in the message */
  rmp->context = context;
  rmp->count = 1;
  rmp->sw_if_index = htonl (sw_if_index);
  rmp->acls[0] = htonl (acl_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
  vl_api_macip_acl_interface_list_dump_t_handler
  (vl_api_macip_acl_interface_list_dump_t * mp)
{
  vl_api_registration_t *reg;
  acl_main_t *am = &acl_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (sw_if_index == ~0)
    {
      vec_foreach_index (sw_if_index, am->macip_acl_by_sw_if_index)
      {
	if (~0 != am->macip_acl_by_sw_if_index[sw_if_index])
	  {
	    send_macip_acl_interface_list_details (am, reg, sw_if_index,
						   am->
						   macip_acl_by_sw_if_index
						   [sw_if_index],
						   mp->context);
	  }
      }
    }
  else
    {
      if (vec_len (am->macip_acl_by_sw_if_index) > sw_if_index)
	{
	  send_macip_acl_interface_list_details (am, reg, sw_if_index,
						 am->macip_acl_by_sw_if_index
						 [sw_if_index], mp->context);
	}
    }
}

static void
  vl_api_acl_interface_set_etype_whitelist_t_handler
  (vl_api_acl_interface_set_etype_whitelist_t * mp)
{
  acl_main_t *am = &acl_main;
  vl_api_acl_interface_set_etype_whitelist_reply_t *rmp;
  int rv = 0;
  int i;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u16 *vec_in = 0, *vec_out = 0;

  if (pool_is_free_index (im->sw_interfaces, sw_if_index))
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  else
    {
      for (i = 0; i < mp->count; i++)
	{
	  if (i < mp->n_input)
	    vec_add1 (vec_in, ntohs (mp->whitelist[i]));
	  else
	    vec_add1 (vec_out, ntohs (mp->whitelist[i]));
	}
      rv = acl_set_etype_whitelists (am, sw_if_index, vec_in, vec_out);
    }

  REPLY_MACRO (VL_API_ACL_INTERFACE_SET_ETYPE_WHITELIST_REPLY);
}

static void
send_acl_interface_etype_whitelist_details (acl_main_t * am,
					    vl_api_registration_t * reg,
					    u32 sw_if_index, u32 context)
{
  vl_api_acl_interface_etype_whitelist_details_t *mp;
  int msg_size;
  int n_input = 0;
  int n_output = 0;
  int count = 0;
  int i = 0;

  u16 *whitelist_in = 0;
  u16 *whitelist_out = 0;

  if (intf_has_etype_whitelist (am, sw_if_index, 0))
    whitelist_out =
      vec_elt (am->output_etype_whitelist_by_sw_if_index, sw_if_index);

  if (intf_has_etype_whitelist (am, sw_if_index, 1))
    whitelist_in =
      vec_elt (am->input_etype_whitelist_by_sw_if_index, sw_if_index);

  if ((0 == whitelist_in) && (0 == whitelist_out))
    return;			/* nothing to do */

  n_input = vec_len (whitelist_in);
  n_output = vec_len (whitelist_out);
  count = n_input + n_output;

  msg_size = sizeof (*mp);
  msg_size += sizeof (mp->whitelist[0]) * count;

  mp = vl_msg_api_alloc (msg_size);
  clib_memset (mp, 0, msg_size);
  mp->_vl_msg_id =
    ntohs (VL_API_ACL_INTERFACE_ETYPE_WHITELIST_DETAILS + am->msg_id_base);

  /* fill in the message */
  mp->context = context;
  mp->sw_if_index = htonl (sw_if_index);
  mp->count = count;
  mp->n_input = n_input;
  for (i = 0; i < n_input; i++)
    {
      mp->whitelist[i] = htons (whitelist_in[i]);
    }
  for (i = 0; i < n_output; i++)
    {
      mp->whitelist[n_input + i] = htons (whitelist_out[i]);
    }
  vl_api_send_msg (reg, (u8 *) mp);
}


static void
  vl_api_acl_interface_etype_whitelist_dump_t_handler
  (vl_api_acl_interface_list_dump_t * mp)
{
  acl_main_t *am = &acl_main;
  vnet_sw_interface_t *swif;
  vnet_interface_main_t *im = &am->vnet_main->interface_main;

  u32 sw_if_index;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->sw_if_index == ~0)
    {
    /* *INDENT-OFF* */
    pool_foreach (swif, im->sw_interfaces,
    ({
      send_acl_interface_etype_whitelist_details(am, reg, swif->sw_if_index, mp->context);
    }));
    /* *INDENT-ON* */
    }
  else
    {
      sw_if_index = ntohl (mp->sw_if_index);
      if (!pool_is_free_index (im->sw_interfaces, sw_if_index))
	send_acl_interface_etype_whitelist_details (am, reg, sw_if_index,
						    mp->context);
    }
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
  if (0 == is_add)
    {
      int may_clear_sessions = 1;
      vlib_process_signal_event (am->vlib_main, am->fa_cleaner_node_index,
				 ACL_FA_CLEANER_DELETE_BY_SW_IF_INDEX,
				 sw_if_index);
      /* also unapply any ACLs in case the users did not do so. */
      macip_acl_interface_del_acl (am, sw_if_index);
      acl_interface_reset_inout_acls (sw_if_index, 0, &may_clear_sessions);
      acl_interface_reset_inout_acls (sw_if_index, 1, &may_clear_sessions);
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
  if (unformat (input, "reclassify-sessions %u", &val))
    {
      am->reclassify_sessions = (val != 0);
      goto done;
    }
  if (unformat (input, "event-trace"))
    {
      if (!unformat (input, "%u", &val))
	{
	  error = clib_error_return (0,
				     "expecting trace level, got `%U`",
				     format_unformat_error, input);
	  goto done;
	}
      else
	{
	  am->trace_acl = val;
	  goto done;
	}
    }
  if (unformat (input, "heap"))
    {
      if (unformat (input, "main"))
	{
	  if (unformat (input, "validate %u", &val))
	    clib_warning ("ACL local heap is deprecated");
	  else if (unformat (input, "trace %u", &val))
	    clib_warning ("ACL local heap is deprecated");
	  goto done;
	}
      else if (unformat (input, "hash"))
	{
	  if (unformat (input, "validate %u", &val))
	    clib_warning ("ACL local heap is deprecated");
	  else if (unformat (input, "trace %u", &val))
	    clib_warning ("ACL local heap is deprecated");
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
	  if (unformat (input, "event-trace"))
	    {
	      if (!unformat (input, "%u", &val))
		{
		  error = clib_error_return (0,
					     "expecting trace level, got `%U`",
					     format_unformat_error, input);
		  goto done;
		}
	      else
		{
		  am->trace_sessions = val;
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
  if (macip_acl_index >= vec_len (am->macip_acls))
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
  vlib_cli_output (vm,
		   "  out_ip4_table_index %d, out_ip6_table_index %d, out_l2_table_index %d\n",
		   a->out_ip4_table_index, a->out_ip6_table_index,
		   a->out_l2_table_index);
  for (i = 0; i < vec_len (a->rules); i++)
    vlib_cli_output (vm, "    rule %d: %U\n", i,
		     my_macip_acl_rule_t_pretty_format,
		     vec_elt_at_index (a->rules, i));

}

static clib_error_t *
acl_set_aclplugin_interface_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index, is_add, is_input, acl_index;

  is_add = is_input = 1;
  acl_index = sw_if_index = ~0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U",
		    unformat_vnet_sw_interface, vnet_get_main (),
		    &sw_if_index))
	;
      else if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "acl %d", &acl_index))
	;
      else if (unformat (line_input, "input"))
	is_input = 1;
      else if (unformat (line_input, "output"))
	is_input = 0;
      else
	break;
    }

  if (~0 == sw_if_index)
    return (clib_error_return (0, "invalid interface"));
  if (~0 == acl_index)
    return (clib_error_return (0, "invalid acl"));

  acl_interface_add_del_inout_acl (sw_if_index, is_add, is_input, acl_index);

  unformat_free (line_input);
  return (NULL);
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

static clib_error_t *
acl_set_aclplugin_acl_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vl_api_acl_rule_t *rules = 0;
  int rv;
  int rule_idx = 0;
  int n_rules_override = -1;
  u32 proto = 0;
  u32 port1 = 0;
  u32 port2 = 0;
  u32 action = 0;
  u32 tcpflags, tcpmask;
  u32 src_prefix_length = 0, dst_prefix_length = 0;
  ip46_address_t src, dst;
  u8 *tag = (u8 *) "cli";

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "permit+reflect"))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  rules[rule_idx].is_permit = 2;
	}
      else if (unformat (line_input, "permit"))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  rules[rule_idx].is_permit = 1;
	}
      else if (unformat (line_input, "deny"))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  rules[rule_idx].is_permit = 0;
	}
      else if (unformat (line_input, "count %d", &n_rules_override))
	{
	  /* we will use this later */
	}
      else if (unformat (line_input, "action %d", &action))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  rules[rule_idx].is_permit = action;
	}
      else if (unformat (line_input, "src %U/%d",
			 unformat_ip46_address, &src, IP46_TYPE_ANY,
			 &src_prefix_length))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  ip_address_encode (&src, IP46_TYPE_ANY,
			     &rules[rule_idx].src_prefix.address);
	  rules[rule_idx].src_prefix.len = src_prefix_length;
	}
      else if (unformat (line_input, "dst %U/%d",
			 unformat_ip46_address, &dst, IP46_TYPE_ANY,
			 &dst_prefix_length))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  ip_address_encode (&dst, IP46_TYPE_ANY,
			     &rules[rule_idx].dst_prefix.address);
	  rules[rule_idx].dst_prefix.len = dst_prefix_length;
	}
      else if (unformat (line_input, "sport %d-%d", &port1, &port2))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  rules[rule_idx].srcport_or_icmptype_first = htons (port1);
	  rules[rule_idx].srcport_or_icmptype_last = htons (port2);
	}
      else if (unformat (line_input, "sport %d", &port1))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  rules[rule_idx].srcport_or_icmptype_first = htons (port1);
	  rules[rule_idx].srcport_or_icmptype_last = htons (port1);
	}
      else if (unformat (line_input, "dport %d-%d", &port1, &port2))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  rules[rule_idx].dstport_or_icmpcode_first = htons (port1);
	  rules[rule_idx].dstport_or_icmpcode_last = htons (port2);
	}
      else if (unformat (line_input, "dport %d", &port1))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  rules[rule_idx].dstport_or_icmpcode_first = htons (port1);
	  rules[rule_idx].dstport_or_icmpcode_last = htons (port1);
	}
      else if (unformat (line_input, "tcpflags %d %d", &tcpflags, &tcpmask))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  rules[rule_idx].tcp_flags_value = tcpflags;
	  rules[rule_idx].tcp_flags_mask = tcpmask;
	}
      else
	if (unformat (line_input, "tcpflags %d mask %d", &tcpflags, &tcpmask))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  rules[rule_idx].tcp_flags_value = tcpflags;
	  rules[rule_idx].tcp_flags_mask = tcpmask;
	}
      else if (unformat (line_input, "proto %d", &proto))
	{
	  vec_validate_acl_rules (rules, rule_idx);
	  rules[rule_idx].proto = proto;
	}
      else if (unformat (line_input, "tag %s", &tag))
	{
	}
      else if (unformat (line_input, ","))
	{
	  rule_idx++;
	  vec_validate_acl_rules (rules, rule_idx);
	}
      else
	break;
    }

  u32 acl_index = ~0;

  rv = acl_add_list (vec_len (rules), rules, &acl_index, tag);

  vec_free (rules);

  if (rv)
    return (clib_error_return (0, "failed"));

  vlib_cli_output (vm, "ACL index:%d", acl_index);

  return (NULL);
}

static clib_error_t *
acl_show_aclplugin_macip_acl_fn (vlib_main_t * vm,
				 unformat_input_t *
				 input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;
  int i;
  u32 acl_index = ~0;

  (void) unformat (input, "index %u", &acl_index);

  for (i = 0; i < vec_len (am->macip_acls); i++)
    {
      /* Don't attempt to show the ACLs that do not exist */
      if (pool_is_free_index (am->macip_acls, i))
	continue;

      if ((acl_index != ~0) && (acl_index != i))
	{
	  continue;
	}

      macip_acl_print (am, i);
      if (i < vec_len (am->sw_if_index_vec_by_macip_acl))
	{
	  vlib_cli_output (vm, "  applied on sw_if_index(s): %U\n",
			   format_vec32,
			   vec_elt (am->sw_if_index_vec_by_macip_acl, i),
			   "%d");
	}
    }

  return error;
}

static clib_error_t *
acl_show_aclplugin_macip_interface_fn (vlib_main_t * vm,
				       unformat_input_t *
				       input, vlib_cli_command_t * cmd)
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
      if (i < vec_len (am->lc_index_vec_by_acl))
	{
	  vlib_cli_output (vm, "  used in lookup context index: %U\n",
			   format_vec32, am->lc_index_vec_by_acl[i], "%d");
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

static clib_error_t *
acl_show_aclplugin_lookup_context_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;

  u32 lc_index = ~0;
  (void) unformat (input, "index %u", &lc_index);

  acl_plugin_show_lookup_context (lc_index);
  return error;
}

static clib_error_t *
acl_show_aclplugin_lookup_user_fn (vlib_main_t * vm,
				   unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;

  u32 lc_index = ~0;
  (void) unformat (input, "index %u", &lc_index);

  acl_plugin_show_lookup_user (lc_index);
  return error;
}


static void
acl_plugin_show_interface (acl_main_t * am, u32 sw_if_index, int show_acl,
			   int detail)
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
      if (swi < vec_len (am->input_policy_epoch_by_sw_if_index))
	vlib_cli_output (vm, "   input policy epoch: %x\n",
			 vec_elt (am->input_policy_epoch_by_sw_if_index,
				  swi));
      if (swi < vec_len (am->output_policy_epoch_by_sw_if_index))
	vlib_cli_output (vm, "   output policy epoch: %x\n",
			 vec_elt (am->output_policy_epoch_by_sw_if_index,
				  swi));


      if (intf_has_etype_whitelist (am, swi, 1))
	{
	  vlib_cli_output (vm, "  input etype whitelist: %U", format_vec16,
			   am->input_etype_whitelist_by_sw_if_index[swi],
			   "%04x");
	}
      if (intf_has_etype_whitelist (am, swi, 0))
	{
	  vlib_cli_output (vm, " output etype whitelist: %U", format_vec16,
			   am->output_etype_whitelist_by_sw_if_index[swi],
			   "%04x");
	}

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
      if (detail && (swi < vec_len (am->input_lc_index_by_sw_if_index)))
	{
	  vlib_cli_output (vm, "   input lookup context index: %d",
			   am->input_lc_index_by_sw_if_index[swi]);
	}
      if (detail && (swi < vec_len (am->output_lc_index_by_sw_if_index)))
	{
	  vlib_cli_output (vm, "  output lookup context index: %d",
			   am->output_lc_index_by_sw_if_index[swi]);
	}
    }

}


static clib_error_t *
acl_show_aclplugin_decode_5tuple_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  u64 five_tuple[6] = { 0, 0, 0, 0, 0, 0 };

  if (unformat
      (input, "%llx %llx %llx %llx %llx %llx", &five_tuple[0], &five_tuple[1],
       &five_tuple[2], &five_tuple[3], &five_tuple[4], &five_tuple[5]))
    vlib_cli_output (vm, "5-tuple structure decode: %U\n\n",
		     format_acl_plugin_5tuple, five_tuple);
  else
    error = clib_error_return (0, "expecting 6 hex integers");
  return error;
}


static clib_error_t *
acl_show_aclplugin_interface_fn (vlib_main_t * vm,
				 unformat_input_t *
				 input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  acl_main_t *am = &acl_main;

  u32 sw_if_index = ~0;
  (void) unformat (input, "sw_if_index %u", &sw_if_index);
  int show_acl = unformat (input, "acl");
  int detail = unformat (input, "detail");

  acl_plugin_show_interface (am, sw_if_index, show_acl, detail);
  return error;
}

static clib_error_t *
acl_show_aclplugin_memory_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  vlib_cli_output (vm, "ACL memory is now part of the main heap");
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
  u64 now = clib_cpu_time_now ();
  u64 clocks_per_second = am->vlib_main->clib_time.clocks_per_second;

  {
    u64 n_adds = am->fa_session_total_adds;
    u64 n_dels = am->fa_session_total_dels;
    u64 n_deact = am->fa_session_total_deactivations;
    vlib_cli_output (vm, "Sessions total: add %lu - del %lu = %lu", n_adds,
		     n_dels, n_adds - n_dels);
    vlib_cli_output (vm, "Sessions active: add %lu - deact %lu = %lu", n_adds,
		     n_deact, n_adds - n_deact);
    vlib_cli_output (vm, "Sessions being purged: deact %lu - del %lu = %lu",
		     n_deact, n_dels, n_deact - n_dels);
  }
  vlib_cli_output (vm, "now: %lu clocks per second: %lu", now,
		   clocks_per_second);
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
      /* *INDENT-OFF* */
      pool_foreach (swif, im->sw_interfaces,
        ({
          u32 sw_if_index = swif->sw_if_index;
          u64 n_adds =
            (sw_if_index < vec_len (pw->fa_session_adds_by_sw_if_index) ?
             pw->fa_session_adds_by_sw_if_index[sw_if_index] :
             0);
          u64 n_dels =
            (sw_if_index < vec_len (pw->fa_session_dels_by_sw_if_index) ?
             pw->fa_session_dels_by_sw_if_index[sw_if_index] :
             0);
          u64 n_epoch_changes =
            (sw_if_index < vec_len (pw->fa_session_epoch_change_by_sw_if_index) ?
             pw->fa_session_epoch_change_by_sw_if_index[sw_if_index] :
             0);
          vlib_cli_output (vm,
                           "    sw_if_index %d: add %lu - del %lu = %lu; epoch chg: %lu",
                           sw_if_index,
                           n_adds,
                           n_dels,
                           n_adds -
                           n_dels,
                           n_epoch_changes);
        }));
      /* *INDENT-ON* */

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
      vlib_cli_output (vm, "  received session change requests: %d",
		       pw->rcvd_session_change_requests);
      vlib_cli_output (vm, "  sent session change requests: %d",
		       pw->sent_session_change_requests);
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
  vlib_cli_output (vm, "Reclassify sessions: %d", am->reclassify_sessions);
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

static clib_error_t *
acl_show_aclplugin_tables_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;

  u32 acl_index = ~0;
  u32 lc_index = ~0;
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
      unformat (input, "lc_index %u", &lc_index);
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
  vlib_cli_output (vm, "Stats counters enabled for interface ACLs: %d",
		   acl_main.interface_acl_counters_enabled);
  if (show_mask_type)
    acl_plugin_show_tables_mask_type ();
  if (show_acl_hash_info)
    acl_plugin_show_tables_acl_hash_info (acl_index);
  if (show_applied_info)
    acl_plugin_show_tables_applied_info (lc_index);
  if (show_bihash)
    acl_plugin_show_tables_bihash (show_bihash_verbose);

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

VLIB_CLI_COMMAND (aclplugin_show_lookup_context_command, static) = {
    .path = "show acl-plugin lookup context",
    .short_help = "show acl-plugin lookup context [index N]",
    .function = acl_show_aclplugin_lookup_context_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_lookup_user_command, static) = {
    .path = "show acl-plugin lookup user",
    .short_help = "show acl-plugin lookup user [index N]",
    .function = acl_show_aclplugin_lookup_user_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_decode_5tuple_command, static) = {
    .path = "show acl-plugin decode 5tuple",
    .short_help = "show acl-plugin decode 5tuple XXXX XXXX XXXX XXXX XXXX XXXX",
    .function = acl_show_aclplugin_decode_5tuple_fn,
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
    .short_help = "show acl-plugin tables [ acl [index N] | applied [ lc_index N ] | mask | hash [verbose N] ]",
    .function = acl_show_aclplugin_tables_fn,
};

VLIB_CLI_COMMAND (aclplugin_show_macip_acl_command, static) = {
    .path = "show acl-plugin macip acl",
    .short_help = "show acl-plugin macip acl [index N]",
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

/*?
 * [un]Apply an ACL to an interface.
 *  The ACL is applied in a given direction, either input or output.
 *  The ACL being applied must already exist.
 *
 * @cliexpar
 * <b><em> set acl-plugin interface <input|output> acl <index> [del]  </b></em>
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (aclplugin_set_interface_command, static) = {
    .path = "set acl-plugin interface",
    .short_help = "set acl-plugin interface <interface> <input|output> <acl INDEX> [del] ",
    .function = acl_set_aclplugin_interface_fn,
};

/*?
 * Create an Access Control List (ACL)
 *  an ACL is composed of more than one Access control element (ACE). Multiple
 *  ACEs can be specified with this command using a comma separated list.
 *
 * Each ACE describes a tuple of src+dst IP prefix, ip protocol, src+dst port ranges.
 * (the ACL plugin also support ICMP types/codes instead of UDP/TCP ports, but
 *  this CLI does not).
 *
 * An ACL can optionally be assigned a 'tag' - which is an identifier understood
 * by the client. VPP does not examine it in any way.
 *
 * @cliexpar
 * <b><em> set acl-plugin acl <permit|deny> src <PREFIX> dst <PREFIX> proto <TCP|UDP> sport <X-Y> dport <X-Y> [tag FOO] </b></em>
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (aclplugin_set_acl_command, static) = {
    .path = "set acl-plugin acl",
    .short_help = "set acl-plugin acl <permit|deny> src <PREFIX> dst <PREFIX> proto X sport X-Y dport X-Y [tag FOO] {use comma separated list for multiple rules}",
    .function = acl_set_aclplugin_acl_fn,
};
/* *INDENT-ON* */

static clib_error_t *
acl_plugin_config (vlib_main_t * vm, unformat_input_t * input)
{
  acl_main_t *am = &acl_main;
  u32 conn_table_hash_buckets;
  uword conn_table_hash_memory_size;
  u32 conn_table_max_entries;
  uword main_heap_size;
  uword hash_heap_size;
  u32 hash_lookup_hash_buckets;
  uword hash_lookup_hash_memory;
  u32 reclassify_sessions;
  u32 use_tuple_merge;
  u32 tuple_merge_split_threshold;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "connection hash buckets %d", &conn_table_hash_buckets))
	am->fa_conn_table_hash_num_buckets = conn_table_hash_buckets;
      else
	if (unformat
	    (input, "connection hash memory %U", unformat_memory_size,
	     &conn_table_hash_memory_size))
	am->fa_conn_table_hash_memory_size = conn_table_hash_memory_size;
      else if (unformat (input, "connection count max %d",
			 &conn_table_max_entries))
	am->fa_conn_table_max_entries = conn_table_max_entries;
      else
	if (unformat
	    (input, "main heap size %U", unformat_memory_size,
	     &main_heap_size))
	clib_warning
	  ("WARNING: ACL heap is now part of the main heap. 'main heap size' is ineffective.");
      else
	if (unformat
	    (input, "hash lookup heap size %U", unformat_memory_size,
	     &hash_heap_size))
	clib_warning
	  ("WARNING: ACL heap is now part of the main heap. 'hash lookup heap size' is ineffective.");
      else
	if (unformat
	    (input, "hash lookup hash buckets %d", &hash_lookup_hash_buckets))
	am->hash_lookup_hash_buckets = hash_lookup_hash_buckets;
      else
	if (unformat
	    (input, "hash lookup hash memory %U", unformat_memory_size,
	     &hash_lookup_hash_memory))
	am->hash_lookup_hash_memory = hash_lookup_hash_memory;
      else if (unformat (input, "use tuple merge %d", &use_tuple_merge))
	am->use_tuple_merge = use_tuple_merge;
      else
	if (unformat
	    (input, "tuple merge split threshold %d",
	     &tuple_merge_split_threshold))
	am->tuple_merge_split_threshold = tuple_merge_split_threshold;

      else if (unformat (input, "reclassify sessions %d",
			 &reclassify_sessions))
	am->reclassify_sessions = reclassify_sessions;

      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (acl_plugin_config, "acl-plugin");

/* Set up the API message handling tables */
#include <vnet/format_fns.h>
#include <acl/acl.api.c>

static clib_error_t *
acl_init (vlib_main_t * vm)
{
  acl_main_t *am = &acl_main;
  clib_error_t *error = 0;
  clib_memset (am, 0, sizeof (*am));
  am->vlib_main = vm;
  am->vnet_main = vnet_get_main ();
  am->log_default = vlib_log_register_class ("acl_plugin", 0);

  /* Ask for a correctly-sized block of API message decode slots */
  am->msg_id_base = setup_message_id_table ();

  error = acl_plugin_exports_init (&acl_plugin);

  if (error)
    return error;

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
  am->reclassify_sessions = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  am->fa_min_deleted_sessions_per_interval =
    ACL_FA_DEFAULT_MIN_DELETED_SESSIONS_PER_INTERVAL;
  am->fa_max_deleted_sessions_per_interval =
    ACL_FA_DEFAULT_MAX_DELETED_SESSIONS_PER_INTERVAL;
  am->fa_cleaner_wait_time_increment =
    ACL_FA_DEFAULT_CLEANER_WAIT_TIME_INCREMENT;

  vec_validate (am->per_worker_data, tm->n_vlib_mains - 1);
  {
    u16 wk;
    for (wk = 0; wk < vec_len (am->per_worker_data); wk++)
      {
	acl_fa_per_worker_data_t *pw = &am->per_worker_data[wk];
	if (tm->n_vlib_mains > 1)
	  {
	    clib_spinlock_init (&pw->pending_session_change_request_lock);
	  }
	vec_validate (pw->expired,
		      ACL_N_TIMEOUTS *
		      am->fa_max_deleted_sessions_per_interval);
	_vec_len (pw->expired) = 0;
	vec_validate_init_empty (pw->fa_conn_list_head, ACL_N_TIMEOUTS - 1,
				 FA_SESSION_BOGUS_INDEX);
	vec_validate_init_empty (pw->fa_conn_list_tail, ACL_N_TIMEOUTS - 1,
				 FA_SESSION_BOGUS_INDEX);
	vec_validate_init_empty (pw->fa_conn_list_head_expiry_time,
				 ACL_N_TIMEOUTS - 1, ~0ULL);
      }
  }

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
  /* use tuplemerge by default */
  am->use_tuple_merge = 1;
  /* Set the default threshold */
  am->tuple_merge_split_threshold = TM_SPLIT_THRESHOLD;

  am->interface_acl_user_id =
    acl_plugin.register_user_module ("interface ACL", "sw_if_index",
				     "is_input");

  am->acl_counter_lock = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
						 CLIB_CACHE_LINE_BYTES);
  am->acl_counter_lock[0] = 0;	/* should be no need */

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
