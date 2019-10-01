/*
 * map.c : MAP support
 *
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

#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_track.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/adj/adj.h>
#include <vppinfra/crc32.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include "map.h"

map_main_t map_main;

/*
 * This code supports the following MAP modes:
 *
 * Algorithmic Shared IPv4 address (ea_bits_len > 0):
 *   ea_bits_len + ip4_prefix > 32
 *   psid_length > 0, ip6_prefix < 64, ip4_prefix <= 32
 * Algorithmic Full IPv4 address (ea_bits_len > 0):
 *   ea_bits_len + ip4_prefix = 32
 *   psid_length = 0, ip6_prefix < 64, ip4_prefix <= 32
 * Algorithmic IPv4 prefix (ea_bits_len > 0):
 *   ea_bits_len + ip4_prefix < 32
 *   psid_length = 0, ip6_prefix < 64, ip4_prefix <= 32
 *
 * Independent Shared IPv4 address (ea_bits_len = 0):
 *   ip4_prefix = 32
 *   psid_length > 0
 *   Rule IPv6 address = 128, Rule PSID Set
 * Independent Full IPv4 address (ea_bits_len = 0):
 *   ip4_prefix = 32
 *   psid_length = 0, ip6_prefix = 128
 * Independent IPv4 prefix (ea_bits_len = 0):
 *   ip4_prefix < 32
 *   psid_length = 0, ip6_prefix = 128
 *
 */

/*
 * This code supports MAP-T:
 *
 * With a DMR prefix length of 64 or 96 (RFC6052).
 *
 */


/*
 * Save user-assigned MAP domain names ("tags") in a vector of
 * extra domain information.
 */
static void
map_save_extras (u32 map_domain_index, u8 * tag)
{
  map_main_t *mm = &map_main;
  map_domain_extra_t *de;

  if (map_domain_index == ~0)
    return;

  vec_validate (mm->domain_extras, map_domain_index);
  de = vec_elt_at_index (mm->domain_extras, map_domain_index);
  clib_memset (de, 0, sizeof (*de));

  if (!tag)
    return;

  de->tag = vec_dup (tag);
}


static void
map_free_extras (u32 map_domain_index)
{
  map_main_t *mm = &map_main;
  map_domain_extra_t *de;
  u8 *tag;

  if (map_domain_index == ~0)
    return;

  de = vec_elt_at_index (mm->domain_extras, map_domain_index);
  tag = de->tag;
  if (!tag)
    return;

  vec_free (tag);
  de->tag = 0;
}


int
map_create_domain (ip4_address_t * ip4_prefix,
		   u8 ip4_prefix_len,
		   ip6_address_t * ip6_prefix,
		   u8 ip6_prefix_len,
		   ip6_address_t * ip6_src,
		   u8 ip6_src_len,
		   u8 ea_bits_len,
		   u8 psid_offset,
		   u8 psid_length,
		   u32 * map_domain_index, u16 mtu, u8 flags, u8 * tag)
{
  u8 suffix_len, suffix_shift;
  map_main_t *mm = &map_main;
  map_domain_t *d;

  /* How many, and which bits to grab from the IPv4 DA */
  if (ip4_prefix_len + ea_bits_len < 32)
    {
      flags |= MAP_DOMAIN_PREFIX;
      suffix_shift = 32 - ip4_prefix_len - ea_bits_len;
      suffix_len = ea_bits_len;
    }
  else
    {
      suffix_shift = 0;
      suffix_len = 32 - ip4_prefix_len;
    }

  /* EA bits must be within the first 64 bits */
  if (ea_bits_len > 0 && ((ip6_prefix_len + ea_bits_len) > 64 ||
			  ip6_prefix_len + suffix_len + psid_length > 64))
    {
      clib_warning
	("Embedded Address bits must be within the first 64 bits of "
	 "the IPv6 prefix");
      return -1;
    }

  /* Get domain index */
  pool_get_aligned (mm->domains, d, CLIB_CACHE_LINE_BYTES);
  clib_memset (d, 0, sizeof (*d));
  *map_domain_index = d - mm->domains;

  /* Init domain struct */
  d->ip4_prefix.as_u32 = ip4_prefix->as_u32;
  d->ip4_prefix_len = ip4_prefix_len;
  d->ip6_prefix = *ip6_prefix;
  d->ip6_prefix_len = ip6_prefix_len;
  d->ip6_src = *ip6_src;
  d->ip6_src_len = ip6_src_len;
  d->ea_bits_len = ea_bits_len;
  d->psid_offset = psid_offset;
  d->psid_length = psid_length;
  d->mtu = mtu;
  d->flags = flags;
  d->suffix_shift = suffix_shift;
  d->suffix_mask = (1 << suffix_len) - 1;

  d->psid_shift = 16 - psid_length - psid_offset;
  d->psid_mask = (1 << d->psid_length) - 1;
  d->ea_shift = 64 - ip6_prefix_len - suffix_len - d->psid_length;

  /* Save a user-assigned MAP domain name if provided. */
  if (tag)
    map_save_extras (*map_domain_index, tag);

  /* MAP longest match lookup table (input feature / FIB) */
  mm->ip4_prefix_tbl->add (mm->ip4_prefix_tbl, &d->ip4_prefix,
			   d->ip4_prefix_len, *map_domain_index);

  /* Really needed? Or always use FIB? */
  mm->ip6_src_prefix_tbl->add (mm->ip6_src_prefix_tbl, &d->ip6_src,
			       d->ip6_src_len, *map_domain_index);

  /* Validate packet/byte counters */
  map_domain_counter_lock (mm);
  int i;
  for (i = 0; i < vec_len (mm->simple_domain_counters); i++)
    {
      vlib_validate_simple_counter (&mm->simple_domain_counters[i],
				    *map_domain_index);
      vlib_zero_simple_counter (&mm->simple_domain_counters[i],
				*map_domain_index);
    }
  for (i = 0; i < vec_len (mm->domain_counters); i++)
    {
      vlib_validate_combined_counter (&mm->domain_counters[i],
				      *map_domain_index);
      vlib_zero_combined_counter (&mm->domain_counters[i], *map_domain_index);
    }
  map_domain_counter_unlock (mm);

  return 0;
}

/*
 * map_delete_domain
 */
int
map_delete_domain (u32 map_domain_index)
{
  map_main_t *mm = &map_main;
  map_domain_t *d;

  if (pool_is_free_index (mm->domains, map_domain_index))
    {
      clib_warning ("MAP domain delete: domain does not exist: %d",
		    map_domain_index);
      return -1;
    }

  d = pool_elt_at_index (mm->domains, map_domain_index);
  mm->ip4_prefix_tbl->delete (mm->ip4_prefix_tbl, &d->ip4_prefix,
			      d->ip4_prefix_len);
  mm->ip6_src_prefix_tbl->delete (mm->ip6_src_prefix_tbl, &d->ip6_src,
				  d->ip6_src_len);

  /* Release user-assigned MAP domain name. */
  map_free_extras (map_domain_index);

  /* Deleting rules */
  if (d->rules)
    clib_mem_free (d->rules);

  pool_put (mm->domains, d);

  return 0;
}

int
map_add_del_psid (u32 map_domain_index, u16 psid, ip6_address_t * tep,
		  bool is_add)
{
  map_domain_t *d;
  map_main_t *mm = &map_main;

  if (pool_is_free_index (mm->domains, map_domain_index))
    {
      clib_warning ("MAP rule: domain does not exist: %d", map_domain_index);
      return -1;
    }
  d = pool_elt_at_index (mm->domains, map_domain_index);

  /* Rules are only used in 1:1 independent case */
  if (d->ea_bits_len > 0)
    return (-1);

  if (!d->rules)
    {
      u32 l = (0x1 << d->psid_length) * sizeof (ip6_address_t);
      d->rules = clib_mem_alloc_aligned (l, CLIB_CACHE_LINE_BYTES);
      if (!d->rules)
	return -1;
      clib_memset (d->rules, 0, l);
    }

  if (psid >= (0x1 << d->psid_length))
    {
      clib_warning ("MAP rule: PSID outside bounds: %d [%d]", psid,
		    0x1 << d->psid_length);
      return -1;
    }

  if (is_add)
    {
      d->rules[psid] = *tep;
    }
  else
    {
      clib_memset (&d->rules[psid], 0, sizeof (ip6_address_t));
    }
  return 0;
}

#ifdef MAP_SKIP_IP6_LOOKUP
/**
 * Pre-resolved per-protocol global next-hops
 */
map_main_pre_resolved_t pre_resolved[FIB_PROTOCOL_MAX];

static void
map_pre_resolve_init (map_main_pre_resolved_t * pr)
{
  pr->fei = FIB_NODE_INDEX_INVALID;
  fib_node_init (&pr->node, FIB_NODE_TYPE_MAP_E);
}

static u8 *
format_map_pre_resolve (u8 * s, va_list * ap)
{
  map_main_pre_resolved_t *pr = va_arg (*ap, map_main_pre_resolved_t *);

  if (FIB_NODE_INDEX_INVALID != pr->fei)
    {
      const fib_prefix_t *pfx;

      pfx = fib_entry_get_prefix (pr->fei);

      return (format (s, "%U (%u)",
		      format_ip46_address, &pfx->fp_addr, IP46_TYPE_ANY,
		      pr->dpo.dpoi_index));
    }
  else
    {
      return (format (s, "un-set"));
    }
}


/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
map_last_lock_gone (fib_node_t * node)
{
  /*
   * The MAP is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

static map_main_pre_resolved_t *
map_from_fib_node (fib_node_t * node)
{
  ASSERT (FIB_NODE_TYPE_MAP_E == node->fn_type);
  return ((map_main_pre_resolved_t *)
	  (((char *) node) -
	   STRUCT_OFFSET_OF (map_main_pre_resolved_t, node)));
}

static void
map_stack (map_main_pre_resolved_t * pr)
{
  const dpo_id_t *dpo;

  dpo = fib_entry_contribute_ip_forwarding (pr->fei);

  dpo_copy (&pr->dpo, dpo);
}

/**
 * Function definition to backwalk a FIB node
 */
static fib_node_back_walk_rc_t
map_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  map_stack (map_from_fib_node (node));

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
map_fib_node_get (fib_node_index_t index)
{
  return (&pre_resolved[index].node);
}

/*
 * Virtual function table registered by MPLS GRE tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t map_vft = {
  .fnv_get = map_fib_node_get,
  .fnv_last_lock = map_last_lock_gone,
  .fnv_back_walk = map_back_walk,
};

static void
map_fib_resolve (map_main_pre_resolved_t * pr,
		 fib_protocol_t proto, u8 len, const ip46_address_t * addr)
{
  fib_prefix_t pfx = {
    .fp_proto = proto,
    .fp_len = len,
    .fp_addr = *addr,
  };

  pr->fei = fib_entry_track (0,	// default fib
			     &pfx, FIB_NODE_TYPE_MAP_E, proto, &pr->sibling);
  map_stack (pr);
}

static void
map_fib_unresolve (map_main_pre_resolved_t * pr,
		   fib_protocol_t proto, u8 len, const ip46_address_t * addr)
{
  if (pr->fei != FIB_NODE_INDEX_INVALID)
    {
      fib_entry_untrack (pr->fei, pr->sibling);

      dpo_reset (&pr->dpo);

      pr->fei = FIB_NODE_INDEX_INVALID;
      pr->sibling = FIB_NODE_INDEX_INVALID;
    }
}

void
map_pre_resolve (ip4_address_t * ip4, ip6_address_t * ip6, bool is_del)
{
  if (ip6 && (ip6->as_u64[0] != 0 || ip6->as_u64[1] != 0))
    {
      ip46_address_t addr = {
	.ip6 = *ip6,
      };
      if (is_del)
	map_fib_unresolve (&pre_resolved[FIB_PROTOCOL_IP6],
			   FIB_PROTOCOL_IP6, 128, &addr);
      else
	map_fib_resolve (&pre_resolved[FIB_PROTOCOL_IP6],
			 FIB_PROTOCOL_IP6, 128, &addr);
    }
  if (ip4 && (ip4->as_u32 != 0))
    {
      ip46_address_t addr = {
	.ip4 = *ip4,
      };
      if (is_del)
	map_fib_unresolve (&pre_resolved[FIB_PROTOCOL_IP4],
			   FIB_PROTOCOL_IP4, 32, &addr);
      else
	map_fib_resolve (&pre_resolved[FIB_PROTOCOL_IP4],
			 FIB_PROTOCOL_IP4, 32, &addr);
    }
}
#endif

static clib_error_t *
map_security_check_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  bool enable = false;
  bool check_frag = false;
  bool saw_enable = false;
  bool saw_frag = false;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	{
	  enable = false;
	  saw_enable = true;
	}
      else if (unformat (line_input, "disable"))
	{
	  enable = true;
	  saw_enable = true;
	}
      else if (unformat (line_input, "fragments on"))
	{
	  check_frag = true;
	  saw_frag = true;
	}
      else if (unformat (line_input, "fragments off"))
	{
	  check_frag = false;
	  saw_frag = true;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!saw_enable)
    {
      error = clib_error_return (0,
				 "Must specify enable 'enable' or 'disable'");
      goto done;
    }

  if (!saw_frag)
    {
      error = clib_error_return (0, "Must specify fragments 'on' or 'off'");
      goto done;
    }

  map_param_set_security_check (enable, check_frag);

done:
  unformat_free (line_input);

  return error;
}


static clib_error_t *
map_add_domain_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t ip4_prefix;
  ip6_address_t ip6_prefix;
  ip6_address_t ip6_src;
  u32 ip6_prefix_len = 0, ip4_prefix_len = 0, map_domain_index, ip6_src_len;
  u32 num_m_args = 0;
  /* Optional arguments */
  u32 ea_bits_len = 0, psid_offset = 0, psid_length = 0;
  u32 mtu = 0;
  u8 flags = 0;
  u8 *tag = 0;
  ip6_src_len = 128;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "ip4-pfx %U/%d", unformat_ip4_address, &ip4_prefix,
	   &ip4_prefix_len))
	num_m_args++;
      else
	if (unformat
	    (line_input, "ip6-pfx %U/%d", unformat_ip6_address, &ip6_prefix,
	     &ip6_prefix_len))
	num_m_args++;
      else
	if (unformat
	    (line_input, "ip6-src %U/%d", unformat_ip6_address, &ip6_src,
	     &ip6_src_len))
	num_m_args++;
      else
	if (unformat
	    (line_input, "ip6-src %U", unformat_ip6_address, &ip6_src))
	num_m_args++;
      else if (unformat (line_input, "ea-bits-len %d", &ea_bits_len))
	num_m_args++;
      else if (unformat (line_input, "psid-offset %d", &psid_offset))
	num_m_args++;
      else if (unformat (line_input, "psid-len %d", &psid_length))
	num_m_args++;
      else if (unformat (line_input, "mtu %d", &mtu))
	num_m_args++;
      else if (unformat (line_input, "tag %v", &tag))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (num_m_args < 3)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      goto done;
    }

  map_create_domain (&ip4_prefix, ip4_prefix_len,
		     &ip6_prefix, ip6_prefix_len, &ip6_src, ip6_src_len,
		     ea_bits_len, psid_offset, psid_length, &map_domain_index,
		     mtu, flags, tag);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
map_del_domain_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 num_m_args = 0;
  u32 map_domain_index;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "index %d", &map_domain_index))
	num_m_args++;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (num_m_args != 1)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      goto done;
    }

  map_delete_domain (map_domain_index);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
map_add_rule_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip6_address_t tep;
  u32 num_m_args = 0;
  u32 psid = 0, map_domain_index;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "index %d", &map_domain_index))
	num_m_args++;
      else if (unformat (line_input, "psid %d", &psid))
	num_m_args++;
      else
	if (unformat (line_input, "ip6-dst %U", unformat_ip6_address, &tep))
	num_m_args++;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (num_m_args != 3)
    {
      error = clib_error_return (0, "mandatory argument(s) missing");
      goto done;
    }

  if (map_add_del_psid (map_domain_index, psid, &tep, 1) != 0)
    {
      error = clib_error_return (0, "Failing to add Mapping Rule");
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

#if MAP_SKIP_IP6_LOOKUP
static clib_error_t *
map_pre_resolve_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t ip4nh, *p_v4 = NULL;
  ip6_address_t ip6nh, *p_v6 = NULL;
  clib_error_t *error = NULL;
  bool is_del = false;

  clib_memset (&ip4nh, 0, sizeof (ip4nh));
  clib_memset (&ip6nh, 0, sizeof (ip6nh));

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "ip4-nh %U", unformat_ip4_address, &ip4nh))
	p_v4 = &ip4nh;
      else
	if (unformat (line_input, "ip6-nh %U", unformat_ip6_address, &ip6nh))
	p_v6 = &ip6nh;
      else if (unformat (line_input, "del"))
	is_del = true;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  map_pre_resolve (p_v4, p_v6, is_del);

done:
  unformat_free (line_input);

  return error;
}
#endif

static clib_error_t *
map_icmp_relay_source_address_command_fn (vlib_main_t * vm,
					  unformat_input_t * input,
					  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t icmp_src_address;
  ip4_address_t *p_icmp_addr = 0;
  map_main_t *mm = &map_main;
  clib_error_t *error = NULL;

  mm->icmp4_src_address.as_u32 = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_ip4_address, &icmp_src_address))
	{
	  mm->icmp4_src_address = icmp_src_address;
	  p_icmp_addr = &icmp_src_address;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  map_param_set_icmp (p_icmp_addr);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
map_icmp_unreachables_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  int num_m_args = 0;
  clib_error_t *error = NULL;
  bool enabled = false;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      num_m_args++;
      if (unformat (line_input, "on"))
	enabled = true;
      else if (unformat (line_input, "off"))
	enabled = false;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }


  if (num_m_args != 1)
    error = clib_error_return (0, "mandatory argument(s) missing");


  map_param_set_icmp6 (enabled);

done:
  unformat_free (line_input);

  return error;
}


static clib_error_t *
map_fragment_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  bool frag_inner = false;
  bool frag_ignore_df = false;
  bool saw_in_out = false;
  bool saw_df = false;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "inner"))
	{
	  frag_inner = true;
	  saw_in_out = true;
	}
      else if (unformat (line_input, "outer"))
	{
	  frag_inner = false;
	  saw_in_out = true;
	}
      else if (unformat (line_input, "ignore-df"))
	{
	  frag_ignore_df = true;
	  saw_df = true;
	}
      else if (unformat (line_input, "honor-df"))
	{
	  frag_ignore_df = false;
	  saw_df = true;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!saw_in_out)
    {
      error = clib_error_return (0, "Must specify 'inner' or 'outer'");
      goto done;
    }

  if (!saw_df)
    {
      error = clib_error_return (0, "Must specify 'ignore-df' or 'honor-df'");
      goto done;
    }

  map_param_set_fragmentation (frag_inner, frag_ignore_df);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
map_traffic_class_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 tc = 0;
  clib_error_t *error = NULL;
  bool tc_copy = false;


  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "copy"))
	tc_copy = true;
      else if (unformat (line_input, "%x", &tc))
	tc = tc & 0xff;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  map_param_set_traffic_class (tc_copy, tc);

done:
  unformat_free (line_input);

  return error;
}

static char *
map_flags_to_string (u32 flags)
{
  if (flags & MAP_DOMAIN_PREFIX)
    return "prefix";
  return "";
}

static u8 *
format_map_domain (u8 * s, va_list * args)
{
  map_domain_t *d = va_arg (*args, map_domain_t *);
  bool counters = va_arg (*args, int);
  map_main_t *mm = &map_main;
  ip6_address_t ip6_prefix;
  u32 map_domain_index = d - mm->domains;
  map_domain_extra_t *de;

  if (d->rules)
    clib_memset (&ip6_prefix, 0, sizeof (ip6_prefix));
  else
    ip6_prefix = d->ip6_prefix;

  de = vec_elt_at_index (mm->domain_extras, map_domain_index);

  s = format (s,
	      "[%d] tag {%v} ip4-pfx %U/%d ip6-pfx %U/%d ip6-src %U/%d "
	      "ea-bits-len %d psid-offset %d psid-len %d mtu %d %s",
	      map_domain_index, de->tag,
	      format_ip4_address, &d->ip4_prefix, d->ip4_prefix_len,
	      format_ip6_address, &ip6_prefix, d->ip6_prefix_len,
	      format_ip6_address, &d->ip6_src, d->ip6_src_len,
	      d->ea_bits_len, d->psid_offset, d->psid_length, d->mtu,
	      map_flags_to_string (d->flags));

  if (counters)
    {
      map_domain_counter_lock (mm);
      vlib_counter_t v;
      vlib_get_combined_counter (&mm->domain_counters[MAP_DOMAIN_COUNTER_TX],
				 map_domain_index, &v);
      s = format (s, "  TX: %lld/%lld", v.packets, v.bytes);
      vlib_get_combined_counter (&mm->domain_counters[MAP_DOMAIN_COUNTER_RX],
				 map_domain_index, &v);
      s = format (s, "  RX: %lld/%lld", v.packets, v.bytes);
      map_domain_counter_unlock (mm);
    }
  s = format (s, "\n");

  if (d->rules)
    {
      int i;
      ip6_address_t dst;
      for (i = 0; i < (0x1 << d->psid_length); i++)
	{
	  dst = d->rules[i];
	  if (dst.as_u64[0] == 0 && dst.as_u64[1] == 0)
	    continue;
	  s = format (s,
		      " rule psid: %d ip6-dst %U\n", i, format_ip6_address,
		      &dst);
	}
    }
  return s;
}

static clib_error_t *
show_map_domain_command_fn (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  map_main_t *mm = &map_main;
  map_domain_t *d;
  bool counters = false;
  u32 map_domain_index = ~0;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "counters"))
	counters = true;
      else if (unformat (line_input, "index %d", &map_domain_index))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (pool_elts (mm->domains) == 0)
    vlib_cli_output (vm, "No MAP domains are configured...");

  if (map_domain_index == ~0)
    {
      /* *INDENT-OFF* */
      pool_foreach(d, mm->domains,
	({vlib_cli_output(vm, "%U", format_map_domain, d, counters);}));
      /* *INDENT-ON* */
    }
  else
    {
      if (pool_is_free_index (mm->domains, map_domain_index))
	{
	  error = clib_error_return (0, "MAP domain does not exists %d",
				     map_domain_index);
	  goto done;
	}

      d = pool_elt_at_index (mm->domains, map_domain_index);
      vlib_cli_output (vm, "%U", format_map_domain, d, counters);
    }

done:
  unformat_free (line_input);

  return error;
}

u64
map_error_counter_get (u32 node_index, map_error_t map_error)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, node_index);
  vlib_error_main_t *em = &vm->error_main;
  vlib_error_t e = error_node->errors[map_error];
  vlib_node_t *n = vlib_get_node (vm, node_index);
  u32 ci;

  ci = vlib_error_get_code (&vm->node_main, e);
  ASSERT (ci < n->n_errors);
  ci += n->error_heap_index;

  return (em->counters[ci]);
}

static clib_error_t *
show_map_stats_command_fn (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  map_main_t *mm = &map_main;
  map_domain_t *d;
  int domains = 0, rules = 0, domaincount = 0, rulecount = 0;
  if (pool_elts (mm->domains) == 0)
    {
      vlib_cli_output (vm, "No MAP domains are configured...");
      return 0;
    }

  /* *INDENT-OFF* */
  pool_foreach(d, mm->domains, ({
    if (d->rules) {
      rulecount+= 0x1 << d->psid_length;
      rules += sizeof(ip6_address_t) * 0x1 << d->psid_length;
    }
    domains += sizeof(*d);
    domaincount++;
  }));
  /* *INDENT-ON* */

  vlib_cli_output (vm, "MAP domains structure: %d\n", sizeof (map_domain_t));
  vlib_cli_output (vm, "MAP domains: %d (%d bytes)\n", domaincount, domains);
  vlib_cli_output (vm, "MAP rules: %d (%d bytes)\n", rulecount, rules);
  vlib_cli_output (vm, "Total: %d bytes)\n", rules + domains);

#if MAP_SKIP_IP6_LOOKUP
  vlib_cli_output (vm,
		   "MAP pre-resolve: IP6 next-hop: %U, IP4 next-hop: %U\n",
		   format_map_pre_resolve, &pre_resolved[FIB_PROTOCOL_IP6],
		   format_map_pre_resolve, &pre_resolved[FIB_PROTOCOL_IP4]);

#endif

  if (mm->tc_copy)
    vlib_cli_output (vm, "MAP traffic-class: copy");
  else
    vlib_cli_output (vm, "MAP traffic-class: %x", mm->tc);

  if (mm->tcp_mss)
    vlib_cli_output (vm, "MAP TCP MSS clamping: %u", mm->tcp_mss);

  vlib_cli_output (vm,
		   "MAP IPv6 inbound security check: %s, fragmented packet security check: %s",
		   mm->sec_check ? "enabled" : "disabled",
		   mm->sec_check_frag ? "enabled" : "disabled");

  vlib_cli_output (vm, "ICMP-relay IPv4 source address: %U\n",
		   format_ip4_address, &mm->icmp4_src_address);
  vlib_cli_output (vm, "ICMP6 unreachables sent for unmatched packets: %s\n",
		   mm->icmp6_enabled ? "enabled" : "disabled");
  vlib_cli_output (vm, "Inner fragmentation: %s\n",
		   mm->frag_inner ? "enabled" : "disabled");
  vlib_cli_output (vm, "Fragment packets regardless of DF flag: %s\n",
		   mm->frag_ignore_df ? "enabled" : "disabled");

  /*
   * Counters
   */
  vlib_combined_counter_main_t *cm = mm->domain_counters;
  u64 total_pkts[MAP_N_DOMAIN_COUNTER];
  u64 total_bytes[MAP_N_DOMAIN_COUNTER];
  int which, i;
  vlib_counter_t v;

  clib_memset (total_pkts, 0, sizeof (total_pkts));
  clib_memset (total_bytes, 0, sizeof (total_bytes));

  map_domain_counter_lock (mm);
  vec_foreach (cm, mm->domain_counters)
  {
    which = cm - mm->domain_counters;

    for (i = 0; i < vlib_combined_counter_n_counters (cm); i++)
      {
	vlib_get_combined_counter (cm, i, &v);
	total_pkts[which] += v.packets;
	total_bytes[which] += v.bytes;
      }
  }
  map_domain_counter_unlock (mm);

  vlib_cli_output (vm, "Encapsulated packets: %lld bytes: %lld\n",
		   total_pkts[MAP_DOMAIN_COUNTER_TX],
		   total_bytes[MAP_DOMAIN_COUNTER_TX]);
  vlib_cli_output (vm, "Decapsulated packets: %lld bytes: %lld\n",
		   total_pkts[MAP_DOMAIN_COUNTER_RX],
		   total_bytes[MAP_DOMAIN_COUNTER_RX]);

  vlib_cli_output (vm, "ICMP relayed packets: %d\n",
		   vlib_get_simple_counter (&mm->icmp_relayed, 0));

  return 0;
}

static clib_error_t *
map_if_command_fn (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  bool is_enable = true, is_translation = false;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_enable = false;
      else if (unformat (line_input, "map-t"))
	is_translation = true;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  unformat_free (line_input);

  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "unknown interface");
      return error;
    }

  int rv = map_if_enable_disable (is_enable, sw_if_index, is_translation);
  if (rv)
    {
      error = clib_error_return (0, "failure enabling MAP on interface");
    }

  return error;
}


/*
 * packet trace format function
 */
u8 *
format_map_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  map_trace_t *t = va_arg (*args, map_trace_t *);
  u32 map_domain_index = t->map_domain_index;
  u16 port = t->port;

  s =
    format (s, "MAP domain index: %d L4 port: %u", map_domain_index,
	    clib_net_to_host_u16 (port));

  return s;
}

static clib_error_t *
map_tcp_mss_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u32 tcp_mss = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%u", &tcp_mss))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (tcp_mss >= (0x1 << 16))
    {
      error = clib_error_return (0, "invalid value `%u'", tcp_mss);
      goto done;
    }

  map_param_set_tcp (tcp_mss);

done:
  unformat_free (line_input);

  return error;
}


/* *INDENT-OFF* */

/*?
 * Set or copy the IP TOS/Traffic Class field
 *
 * @cliexpar
 * @cliexstart{map params traffic-class}
 *
 * This command is used to set the traffic-class field in translated
 * or encapsulated packets. If copy is specifed (the default) then the
 * traffic-class/TOS field is copied from the original packet to the
 * translated / encapsulating header.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_traffic_class_command, static) = {
  .path = "map params traffic-class",
  .short_help = "map params traffic-class {0x0-0xff | copy}",
  .function = map_traffic_class_command_fn,
};

/*?
 * TCP MSS clamping
 *
 * @cliexpar
 * @cliexstart{map params tcp-mss}
 *
 * This command is used to set the TCP MSS in translated
 * or encapsulated packets.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_tcp_mss_command, static) = {
  .path = "map params tcp-mss",
  .short_help = "map params tcp-mss <value>",
  .function = map_tcp_mss_command_fn,
};

/*?
 * Bypass IP4/IP6 lookup
 *
 * @cliexpar
 * @cliexstart{map params pre-resolve}
 *
 * Bypass a second FIB lookup of the translated or encapsulated
 * packet, and forward the packet directly to the specified
 * next-hop. This optimization trades forwarding flexibility for
 * performance.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_pre_resolve_command, static) = {
  .path = "map params pre-resolve",
  .short_help = " map params pre-resolve {ip4-nh <address>} "
                "| {ip6-nh <address>}",
  .function = map_pre_resolve_command_fn,
};

/*?
 * Enable or disable the MAP-E inbound security check
 * Specifiy if the inbound security check should be done on fragments
 *
 * @cliexpar
 * @cliexstart{map params security-check}
 *
 * By default, a decapsulated packet's IPv4 source address will be
 * verified against the outer header's IPv6 source address. Disabling
 * this feature will allow IPv4 source address spoofing.
 *
 * Typically the inbound on-decapsulation security check is only done
 * on the first packet. The packet that contains the L4
 * information. While a security check on every fragment is possible,
 * it has a cost. State must be created on the first fragment.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_security_check_command, static) = {
  .path = "map params security-check",
  .short_help = "map params security-check enable|disable fragments on|off",
  .function = map_security_check_command_fn,
};


/*?
 * Specifiy the IPv4 source address used for relayed ICMP error messages
 *
 * @cliexpar
 * @cliexstart{map params icmp source-address}
 *
 * This command specifies which IPv4 source address (must be local to
 * the system), that is used for relayed received IPv6 ICMP error
 * messages.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_icmp_relay_source_address_command, static) = {
  .path = "map params icmp source-address",
  .short_help = "map params icmp source-address <ip4-address>",
  .function = map_icmp_relay_source_address_command_fn,
};

/*?
 * Send IPv6 ICMP unreachables
 *
 * @cliexpar
 * @cliexstart{map params icmp6 unreachables}
 *
 * Send IPv6 ICMP unreachable messages back if security check fails or
 * no MAP domain exists.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_icmp_unreachables_command, static) = {
  .path = "map params icmp6 unreachables",
  .short_help = "map params icmp6 unreachables {on|off}",
  .function = map_icmp_unreachables_command_fn,
};

/*?
 * Configure MAP fragmentation behaviour
 *
 * @cliexpar
 * @cliexstart{map params fragment}
 *
 * Allows fragmentation of the IPv4 packet even if the DF bit is
 * set. The choice between inner or outer fragmentation of tunnel
 * packets is complicated. The benefit of inner fragmentation is that
 * the ultimate endpoint must reassemble, instead of the tunnel
 * endpoint.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_fragment_command, static) = {
  .path = "map params fragment",
  .short_help = "map params fragment inner|outer ignore-df|honor-df",
  .function = map_fragment_command_fn,
};


/*?
 * Add MAP domain
 *
 * @cliexpar
 * @cliexstart{map add domain}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_add_domain_command, static) = {
  .path = "map add domain",
  .short_help = "map add domain [tag <tag>] ip4-pfx <ip4-pfx> "
      "ip6-pfx <ip6-pfx> "
      "ip6-src <ip6-pfx> ea-bits-len <n> psid-offset <n> psid-len <n> "
      "[map-t] [mtu <mtu>]",
  .function = map_add_domain_command_fn,
};

/*?
 * Add MAP rule to a domain
 *
 * @cliexpar
 * @cliexstart{map add rule}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_add_rule_command, static) = {
  .path = "map add rule",
  .short_help = "map add rule index <domain> psid <psid> ip6-dst <ip6-addr>",
  .function = map_add_rule_command_fn,
};

/*?
 * Delete MAP domain
 *
 * @cliexpar
 * @cliexstart{map del domain}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_del_command, static) = {
  .path = "map del domain",
  .short_help = "map del domain index <domain>",
  .function = map_del_domain_command_fn,
};

/*?
 * Show MAP domains
 *
 * @cliexpar
 * @cliexstart{show map domain}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(show_map_domain_command, static) = {
  .path = "show map domain",
  .short_help = "show map domain index <n> [counters]",
  .function = show_map_domain_command_fn,
};

/*?
 * Show MAP statistics
 *
 * @cliexpar
 * @cliexstart{show map stats}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(show_map_stats_command, static) = {
  .path = "show map stats",
  .short_help = "show map stats",
  .function = show_map_stats_command_fn,
};

/*?
 * Enable MAP processing on interface (input feature)
 *
 ?*/
VLIB_CLI_COMMAND(map_if_command, static) = {
  .path = "map interface",
  .short_help = "map interface <interface-name> [map-t] [del]",
  .function = map_if_command_fn,
};

VLIB_PLUGIN_REGISTER() = {
  .version = VPP_BUILD_VER,
  .description = "Mapping of Address and Port (MAP)",
};

/* *INDENT-ON* */

/*
 * map_init
 */
clib_error_t *
map_init (vlib_main_t * vm)
{
  map_main_t *mm = &map_main;
  clib_error_t *error = 0;

  memset (mm, 0, sizeof (*mm));

  mm->vnet_main = vnet_get_main ();
  mm->vlib_main = vm;

#ifdef MAP_SKIP_IP6_LOOKUP
  fib_protocol_t proto;

  FOR_EACH_FIB_PROTOCOL (proto)
  {
    map_pre_resolve_init (&pre_resolved[proto]);
  }
#endif

  /* traffic class */
  mm->tc = 0;
  mm->tc_copy = true;

  /* Inbound security check */
  mm->sec_check = true;
  mm->sec_check_frag = false;

  /* ICMP6 Type 1, Code 5 for security check failure */
  mm->icmp6_enabled = false;

  /* Inner or outer fragmentation */
  mm->frag_inner = false;
  mm->frag_ignore_df = false;

  vec_validate (mm->domain_counters, MAP_N_DOMAIN_COUNTER - 1);
  mm->domain_counters[MAP_DOMAIN_COUNTER_RX].name = "/map/rx";
  mm->domain_counters[MAP_DOMAIN_COUNTER_TX].name = "/map/tx";

  vlib_validate_simple_counter (&mm->icmp_relayed, 0);
  vlib_zero_simple_counter (&mm->icmp_relayed, 0);
  mm->icmp_relayed.stat_segment_name = "/map/icmp-relayed";

  /* IP6 virtual reassembly */

#ifdef MAP_SKIP_IP6_LOOKUP
  fib_node_register_type (FIB_NODE_TYPE_MAP_E, &map_vft);
#endif

  /* LPM lookup tables */
  mm->ip4_prefix_tbl = lpm_table_init (LPM_TYPE_KEY32);
  mm->ip6_prefix_tbl = lpm_table_init (LPM_TYPE_KEY128);
  mm->ip6_src_prefix_tbl = lpm_table_init (LPM_TYPE_KEY128);

  mm->bm_trans_enabled_by_sw_if = 0;
  mm->bm_encap_enabled_by_sw_if = 0;

  error = map_plugin_api_hookup (vm);

  return error;
}

VLIB_INIT_FUNCTION (map_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
