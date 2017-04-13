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
#include <vnet/fib/ip6_fib.h>
#include <vnet/adj/adj.h>
#include <vnet/map/map_dpo.h>

#include "map.h"

#ifdef __SSE4_2__
static inline u32
crc_u32 (u32 data, u32 value)
{
  __asm__ volatile ("crc32l %[data], %[value];":[value] "+r" (value):[data]
		    "rm" (data));
  return value;
}
#else
#include <vppinfra/xxhash.h>

static inline u32
crc_u32 (u32 data, u32 value)
{
  u64 tmp = ((u64) data << 32) | (u64) value;
  return (u32) clib_xxhash (tmp);
}
#endif


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
 * With DMR prefix length equal to 96.
 *
 */


i32
ip4_get_port (ip4_header_t * ip, map_dir_e dir, u16 buffer_len)
{
  //TODO: use buffer length
  if (ip->ip_version_and_header_length != 0x45 ||
      ip4_get_fragment_offset (ip))
    return -1;

  if (PREDICT_TRUE ((ip->protocol == IP_PROTOCOL_TCP) ||
		    (ip->protocol == IP_PROTOCOL_UDP)))
    {
      udp_header_t *udp = (void *) (ip + 1);
      return (dir == MAP_SENDER) ? udp->src_port : udp->dst_port;
    }
  else if (ip->protocol == IP_PROTOCOL_ICMP)
    {
      icmp46_header_t *icmp = (void *) (ip + 1);
      if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply)
	{
	  return *((u16 *) (icmp + 1));
	}
      else if (clib_net_to_host_u16 (ip->length) >= 64)
	{
	  ip = (ip4_header_t *) (icmp + 2);
	  if (PREDICT_TRUE ((ip->protocol == IP_PROTOCOL_TCP) ||
			    (ip->protocol == IP_PROTOCOL_UDP)))
	    {
	      udp_header_t *udp = (void *) (ip + 1);
	      return (dir == MAP_SENDER) ? udp->dst_port : udp->src_port;
	    }
	  else if (ip->protocol == IP_PROTOCOL_ICMP)
	    {
	      icmp46_header_t *icmp = (void *) (ip + 1);
	      if (icmp->type == ICMP4_echo_request ||
		  icmp->type == ICMP4_echo_reply)
		{
		  return *((u16 *) (icmp + 1));
		}
	    }
	}
    }
  return -1;
}

i32
ip6_get_port (ip6_header_t * ip6, map_dir_e dir, u16 buffer_len)
{
  u8 l4_protocol;
  u16 l4_offset;
  u16 frag_offset;
  u8 *l4;

  if (ip6_parse (ip6, buffer_len, &l4_protocol, &l4_offset, &frag_offset))
    return -1;

  //TODO: Use buffer length

  if (frag_offset &&
      ip6_frag_hdr_offset (((ip6_frag_hdr_t *)
			    u8_ptr_add (ip6, frag_offset))))
    return -1;			//Can't deal with non-first fragment for now

  l4 = u8_ptr_add (ip6, l4_offset);
  if (l4_protocol == IP_PROTOCOL_TCP || l4_protocol == IP_PROTOCOL_UDP)
    {
      return (dir ==
	      MAP_SENDER) ? ((udp_header_t *) (l4))->src_port : ((udp_header_t
								  *)
								 (l4))->dst_port;
    }
  else if (l4_protocol == IP_PROTOCOL_ICMP6)
    {
      icmp46_header_t *icmp = (icmp46_header_t *) (l4);
      if (icmp->type == ICMP6_echo_request)
	{
	  return (dir == MAP_SENDER) ? ((u16 *) (icmp))[2] : -1;
	}
      else if (icmp->type == ICMP6_echo_reply)
	{
	  return (dir == MAP_SENDER) ? -1 : ((u16 *) (icmp))[2];
	}
    }
  return -1;
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
		   u8 psid_length, u32 * map_domain_index, u16 mtu, u8 flags)
{
  u8 suffix_len, suffix_shift;
  map_main_t *mm = &map_main;
  dpo_id_t dpo_v4 = DPO_INVALID;
  dpo_id_t dpo_v6 = DPO_INVALID;
  fib_node_index_t fei;
  map_domain_t *d;

  /* Sanity check on the src prefix length */
  if (flags & MAP_DOMAIN_TRANSLATION)
    {
      if (ip6_src_len != 96)
	{
	  clib_warning ("MAP-T only supports ip6_src_len = 96 for now.");
	  return -1;
	}
    }
  else
    {
      if (ip6_src_len != 128)
	{
	  clib_warning
	    ("MAP-E requires a BR address, not a prefix (ip6_src_len should "
	     "be 128).");
	  return -1;
	}
    }

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
  memset (d, 0, sizeof (*d));
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

  /* MAP data-plane object */
  if (d->flags & MAP_DOMAIN_TRANSLATION)
    map_t_dpo_create (DPO_PROTO_IP4, *map_domain_index, &dpo_v4);
  else
    map_dpo_create (DPO_PROTO_IP4, *map_domain_index, &dpo_v4);

  /* Create ip4 route */
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = d->ip4_prefix_len,
    .fp_addr = {
		.ip4 = d->ip4_prefix,
		}
    ,
  };
  fib_table_entry_special_dpo_add (0, &pfx,
				   FIB_SOURCE_MAP,
				   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo_v4);
  dpo_reset (&dpo_v4);

  /*
   * Multiple MAP domains may share same source IPv6 TEP.
   * In this case the route will exist and be MAP sourced.
   * Find the adj (if any) already contributed and modify it
   */
  fib_prefix_t pfx6 = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = d->ip6_src_len,
    .fp_addr = {
		.ip6 = d->ip6_src,
		}
    ,
  };
  fei = fib_table_lookup_exact_match (0, &pfx6);

  if (FIB_NODE_INDEX_INVALID != fei)
    {
      dpo_id_t dpo = DPO_INVALID;

      if (fib_entry_get_dpo_for_source (fei, FIB_SOURCE_MAP, &dpo))
	{
	  /*
	   * modify the existing MAP to indicate it's shared
	   * skip to route add.
	   */
	  const dpo_id_t *md_dpo;
	  map_dpo_t *md;

	  ASSERT (DPO_LOAD_BALANCE == dpo.dpoi_type);

	  md_dpo = load_balance_get_bucket (dpo.dpoi_index, 0);
	  md = map_dpo_get (md_dpo->dpoi_index);

	  md->md_domain = ~0;
	  dpo_copy (&dpo_v6, md_dpo);
	  dpo_reset (&dpo);

	  goto route_add;
	}
    }

  if (d->flags & MAP_DOMAIN_TRANSLATION)
    map_t_dpo_create (DPO_PROTO_IP6, *map_domain_index, &dpo_v6);
  else
    map_dpo_create (DPO_PROTO_IP6, *map_domain_index, &dpo_v6);

route_add:
  /*
   * Create ip6 route. This is a reference counted add. If the prefix
   * already exists and is MAP sourced, it is now MAP source n+1 times
   * and will need to be removed n+1 times.
   */
  fib_table_entry_special_dpo_add (0, &pfx6,
				   FIB_SOURCE_MAP,
				   FIB_ENTRY_FLAG_EXCLUSIVE, &dpo_v6);
  dpo_reset (&dpo_v6);

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

  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = d->ip4_prefix_len,
    .fp_addr = {
		.ip4 = d->ip4_prefix,
		}
    ,
  };
  fib_table_entry_special_remove (0, &pfx, FIB_SOURCE_MAP);

  fib_prefix_t pfx6 = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = d->ip6_src_len,
    .fp_addr = {
		.ip6 = d->ip6_src,
		}
    ,
  };
  fib_table_entry_special_remove (0, &pfx6, FIB_SOURCE_MAP);

  /* Deleting rules */
  if (d->rules)
    clib_mem_free (d->rules);

  pool_put (mm->domains, d);

  return 0;
}

int
map_add_del_psid (u32 map_domain_index, u16 psid, ip6_address_t * tep,
		  u8 is_add)
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
      memset (d->rules, 0, l);
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
      memset (&d->rules[psid], 0, sizeof (ip6_address_t));
    }
  return 0;
}

#ifdef MAP_SKIP_IP6_LOOKUP
/**
 * Pre-resolvd per-protocol global next-hops
 */
map_main_pre_resolved_t pre_resolved[FIB_PROTOCOL_MAX];

static void
map_pre_resolve_init (map_main_pre_resolved_t * pr)
{
  pr->fei = FIB_NODE_INDEX_INVALID;
  fib_node_init (&pr->node, FIB_NODE_TYPE_MAP_E);
}

static u8 *
format_map_pre_resolve (u8 * s, va_list ap)
{
  map_main_pre_resolved_t *pr = va_arg (ap, map_main_pre_resolved_t *);

  if (FIB_NODE_INDEX_INVALID != pr->fei)
    {
      fib_prefix_t pfx;

      fib_entry_get_prefix (pr->fei, &pfx);

      return (format (s, "%U (%u)",
		      format_ip46_address, &pfx.fp_addr, IP46_TYPE_ANY,
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
#if (CLIB_DEBUG > 0)
  ASSERT (FIB_NODE_TYPE_MAP_E == node->fn_type);
#endif
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

  pr->fei = fib_table_entry_special_add (0,	// default fib
					 &pfx,
					 FIB_SOURCE_RR, FIB_ENTRY_FLAG_NONE);
  pr->sibling = fib_entry_child_add (pr->fei, FIB_NODE_TYPE_MAP_E, proto);
  map_stack (pr);
}

static void
map_fib_unresolve (map_main_pre_resolved_t * pr,
		   fib_protocol_t proto, u8 len, const ip46_address_t * addr)
{
  fib_prefix_t pfx = {
    .fp_proto = proto,
    .fp_len = len,
    .fp_addr = *addr,
  };

  fib_entry_child_remove (pr->fei, pr->sibling);

  fib_table_entry_special_remove (0,	// default fib
				  &pfx, FIB_SOURCE_RR);
  dpo_reset (&pr->dpo);

  pr->fei = FIB_NODE_INDEX_INVALID;
  pr->sibling = FIB_NODE_INDEX_INVALID;
}

static void
map_pre_resolve (ip4_address_t * ip4, ip6_address_t * ip6, int is_del)
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
  map_main_t *mm = &map_main;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "off"))
	mm->sec_check = false;
      else if (unformat (line_input, "on"))
	mm->sec_check = true;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
map_security_check_frag_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  map_main_t *mm = &map_main;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "off"))
	mm->sec_check_frag = false;
      else if (unformat (line_input, "on"))
	mm->sec_check_frag = true;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

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
      else if (unformat (line_input, "map-t"))
	flags |= MAP_DOMAIN_TRANSLATION;
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
		     mtu, flags);

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
  int is_del = 0;

  memset (&ip4nh, 0, sizeof (ip4nh));
  memset (&ip6nh, 0, sizeof (ip6nh));

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
	is_del = 1;
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
	mm->icmp4_src_address = icmp_src_address;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

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
  map_main_t *mm = &map_main;
  int num_m_args = 0;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      num_m_args++;
      if (unformat (line_input, "on"))
	mm->icmp6_enabled = true;
      else if (unformat (line_input, "off"))
	mm->icmp6_enabled = false;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }


  if (num_m_args != 1)
    error = clib_error_return (0, "mandatory argument(s) missing");

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
map_fragment_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  map_main_t *mm = &map_main;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "inner"))
	mm->frag_inner = true;
      else if (unformat (line_input, "outer"))
	mm->frag_inner = false;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
map_fragment_df_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  map_main_t *mm = &map_main;
  clib_error_t *error = NULL;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on"))
	mm->frag_ignore_df = true;
      else if (unformat (line_input, "off"))
	mm->frag_ignore_df = false;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

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
  map_main_t *mm = &map_main;
  u32 tc = 0;
  clib_error_t *error = NULL;

  mm->tc_copy = false;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "copy"))
	mm->tc_copy = true;
      else if (unformat (line_input, "%x", &tc))
	mm->tc = tc & 0xff;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  unformat_free (line_input);

  return error;
}

static u8 *
format_map_domain (u8 * s, va_list * args)
{
  map_domain_t *d = va_arg (*args, map_domain_t *);
  bool counters = va_arg (*args, int);
  map_main_t *mm = &map_main;
  ip6_address_t ip6_prefix;

  if (d->rules)
    memset (&ip6_prefix, 0, sizeof (ip6_prefix));
  else
    ip6_prefix = d->ip6_prefix;

  s = format (s,
	      "[%d] ip4-pfx %U/%d ip6-pfx %U/%d ip6-src %U/%d ea_bits_len %d psid-offset %d psid-len %d mtu %d %s",
	      d - mm->domains,
	      format_ip4_address, &d->ip4_prefix, d->ip4_prefix_len,
	      format_ip6_address, &ip6_prefix, d->ip6_prefix_len,
	      format_ip6_address, &d->ip6_src, d->ip6_src_len,
	      d->ea_bits_len, d->psid_offset, d->psid_length, d->mtu,
	      (d->flags & MAP_DOMAIN_TRANSLATION) ? "map-t" : "");

  if (counters)
    {
      map_domain_counter_lock (mm);
      vlib_counter_t v;
      vlib_get_combined_counter (&mm->domain_counters[MAP_DOMAIN_COUNTER_TX],
				 d - mm->domains, &v);
      s = format (s, "  TX: %lld/%lld", v.packets, v.bytes);
      vlib_get_combined_counter (&mm->domain_counters[MAP_DOMAIN_COUNTER_RX],
				 d - mm->domains, &v);
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

static u8 *
format_map_ip4_reass (u8 * s, va_list * args)
{
  map_main_t *mm = &map_main;
  map_ip4_reass_t *r = va_arg (*args, map_ip4_reass_t *);
  map_ip4_reass_key_t *k = &r->key;
  f64 now = vlib_time_now (mm->vlib_main);
  f64 lifetime = (((f64) mm->ip4_reass_conf_lifetime_ms) / 1000);
  f64 dt = (r->ts + lifetime > now) ? (r->ts + lifetime - now) : -1;
  s = format (s,
	      "ip4-reass src=%U  dst=%U  protocol=%d  identifier=%d  port=%d  lifetime=%.3lf\n",
	      format_ip4_address, &k->src.as_u8, format_ip4_address,
	      &k->dst.as_u8, k->protocol,
	      clib_net_to_host_u16 (k->fragment_id),
	      (r->port >= 0) ? clib_net_to_host_u16 (r->port) : -1, dt);
  return s;
}

static u8 *
format_map_ip6_reass (u8 * s, va_list * args)
{
  map_main_t *mm = &map_main;
  map_ip6_reass_t *r = va_arg (*args, map_ip6_reass_t *);
  map_ip6_reass_key_t *k = &r->key;
  f64 now = vlib_time_now (mm->vlib_main);
  f64 lifetime = (((f64) mm->ip6_reass_conf_lifetime_ms) / 1000);
  f64 dt = (r->ts + lifetime > now) ? (r->ts + lifetime - now) : -1;
  s = format (s,
	      "ip6-reass src=%U  dst=%U  protocol=%d  identifier=%d  lifetime=%.3lf\n",
	      format_ip6_address, &k->src.as_u8, format_ip6_address,
	      &k->dst.as_u8, k->protocol,
	      clib_net_to_host_u32 (k->fragment_id), dt);
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
    pool_foreach(d, mm->domains, ({vlib_cli_output(vm, "%U", format_map_domain, d, counters);}));
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

static clib_error_t *
show_map_fragments_command_fn (vlib_main_t * vm, unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  map_main_t *mm = &map_main;
  map_ip4_reass_t *f4;
  map_ip6_reass_t *f6;

  /* *INDENT-OFF* */
  pool_foreach(f4, mm->ip4_reass_pool, ({vlib_cli_output (vm, "%U", format_map_ip4_reass, f4);}));
  /* *INDENT-ON* */
  /* *INDENT-OFF* */
  pool_foreach(f6, mm->ip6_reass_pool, ({vlib_cli_output (vm, "%U", format_map_ip6_reass, f6);}));
  /* *INDENT-ON* */
  return (0);
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

  ci = vlib_error_get_code (e);
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
    vlib_cli_output (vm, "No MAP domains are configured...");

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

  memset (total_pkts, 0, sizeof (total_pkts));
  memset (total_bytes, 0, sizeof (total_bytes));

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
map_params_reass_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 lifetime = ~0;
  f64 ht_ratio = (MAP_IP4_REASS_CONF_HT_RATIO_MAX + 1);
  u32 pool_size = ~0;
  u64 buffers = ~(0ull);
  u8 ip4 = 0, ip6 = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "lifetime %u", &lifetime))
	;
      else if (unformat (line_input, "ht-ratio %lf", &ht_ratio))
	;
      else if (unformat (line_input, "pool-size %u", &pool_size))
	;
      else if (unformat (line_input, "buffers %llu", &buffers))
	;
      else if (unformat (line_input, "ip4"))
	ip4 = 1;
      else if (unformat (line_input, "ip6"))
	ip6 = 1;
      else
	{
	  unformat_free (line_input);
	  return clib_error_return (0, "invalid input");
	}
    }
  unformat_free (line_input);

  if (!ip4 && !ip6)
    return clib_error_return (0, "must specify ip4 and/or ip6");

  if (ip4)
    {
      if (pool_size != ~0 && pool_size > MAP_IP4_REASS_CONF_POOL_SIZE_MAX)
	return clib_error_return (0, "invalid ip4-reass pool-size ( > %d)",
				  MAP_IP4_REASS_CONF_POOL_SIZE_MAX);
      if (ht_ratio != (MAP_IP4_REASS_CONF_HT_RATIO_MAX + 1)
	  && ht_ratio > MAP_IP4_REASS_CONF_HT_RATIO_MAX)
	return clib_error_return (0, "invalid ip4-reass ht-ratio ( > %d)",
				  MAP_IP4_REASS_CONF_HT_RATIO_MAX);
      if (lifetime != ~0 && lifetime > MAP_IP4_REASS_CONF_LIFETIME_MAX)
	return clib_error_return (0, "invalid ip4-reass lifetime ( > %d)",
				  MAP_IP4_REASS_CONF_LIFETIME_MAX);
      if (buffers != ~(0ull) && buffers > MAP_IP4_REASS_CONF_BUFFERS_MAX)
	return clib_error_return (0, "invalid ip4-reass buffers ( > %ld)",
				  MAP_IP4_REASS_CONF_BUFFERS_MAX);
    }

  if (ip6)
    {
      if (pool_size != ~0 && pool_size > MAP_IP6_REASS_CONF_POOL_SIZE_MAX)
	return clib_error_return (0, "invalid ip6-reass pool-size ( > %d)",
				  MAP_IP6_REASS_CONF_POOL_SIZE_MAX);
      if (ht_ratio != (MAP_IP4_REASS_CONF_HT_RATIO_MAX + 1)
	  && ht_ratio > MAP_IP6_REASS_CONF_HT_RATIO_MAX)
	return clib_error_return (0, "invalid ip6-reass ht-log2len ( > %d)",
				  MAP_IP6_REASS_CONF_HT_RATIO_MAX);
      if (lifetime != ~0 && lifetime > MAP_IP6_REASS_CONF_LIFETIME_MAX)
	return clib_error_return (0, "invalid ip6-reass lifetime ( > %d)",
				  MAP_IP6_REASS_CONF_LIFETIME_MAX);
      if (buffers != ~(0ull) && buffers > MAP_IP6_REASS_CONF_BUFFERS_MAX)
	return clib_error_return (0, "invalid ip6-reass buffers ( > %ld)",
				  MAP_IP6_REASS_CONF_BUFFERS_MAX);
    }

  if (ip4)
    {
      u32 reass = 0, packets = 0;
      if (pool_size != ~0)
	{
	  if (map_ip4_reass_conf_pool_size (pool_size, &reass, &packets))
	    {
	      vlib_cli_output (vm, "Could not set ip4-reass pool-size");
	    }
	  else
	    {
	      vlib_cli_output (vm,
			       "Setting ip4-reass pool-size (destroyed-reassembly=%u , dropped-fragments=%u)",
			       reass, packets);
	    }
	}
      if (ht_ratio != (MAP_IP4_REASS_CONF_HT_RATIO_MAX + 1))
	{
	  if (map_ip4_reass_conf_ht_ratio (ht_ratio, &reass, &packets))
	    {
	      vlib_cli_output (vm, "Could not set ip4-reass ht-log2len");
	    }
	  else
	    {
	      vlib_cli_output (vm,
			       "Setting ip4-reass ht-log2len (destroyed-reassembly=%u , dropped-fragments=%u)",
			       reass, packets);
	    }
	}
      if (lifetime != ~0)
	{
	  if (map_ip4_reass_conf_lifetime (lifetime))
	    vlib_cli_output (vm, "Could not set ip4-reass lifetime");
	  else
	    vlib_cli_output (vm, "Setting ip4-reass lifetime");
	}
      if (buffers != ~(0ull))
	{
	  if (map_ip4_reass_conf_buffers (buffers))
	    vlib_cli_output (vm, "Could not set ip4-reass buffers");
	  else
	    vlib_cli_output (vm, "Setting ip4-reass buffers");
	}

      if (map_main.ip4_reass_conf_buffers >
	  map_main.ip4_reass_conf_pool_size *
	  MAP_IP4_REASS_MAX_FRAGMENTS_PER_REASSEMBLY)
	{
	  vlib_cli_output (vm,
			   "Note: 'ip4-reass buffers' > pool-size * max-fragments-per-reassembly.");
	}
    }

  if (ip6)
    {
      u32 reass = 0, packets = 0;
      if (pool_size != ~0)
	{
	  if (map_ip6_reass_conf_pool_size (pool_size, &reass, &packets))
	    {
	      vlib_cli_output (vm, "Could not set ip6-reass pool-size");
	    }
	  else
	    {
	      vlib_cli_output (vm,
			       "Setting ip6-reass pool-size (destroyed-reassembly=%u , dropped-fragments=%u)",
			       reass, packets);
	    }
	}
      if (ht_ratio != (MAP_IP4_REASS_CONF_HT_RATIO_MAX + 1))
	{
	  if (map_ip6_reass_conf_ht_ratio (ht_ratio, &reass, &packets))
	    {
	      vlib_cli_output (vm, "Could not set ip6-reass ht-log2len");
	    }
	  else
	    {
	      vlib_cli_output (vm,
			       "Setting ip6-reass ht-log2len (destroyed-reassembly=%u , dropped-fragments=%u)",
			       reass, packets);
	    }
	}
      if (lifetime != ~0)
	{
	  if (map_ip6_reass_conf_lifetime (lifetime))
	    vlib_cli_output (vm, "Could not set ip6-reass lifetime");
	  else
	    vlib_cli_output (vm, "Setting ip6-reass lifetime");
	}
      if (buffers != ~(0ull))
	{
	  if (map_ip6_reass_conf_buffers (buffers))
	    vlib_cli_output (vm, "Could not set ip6-reass buffers");
	  else
	    vlib_cli_output (vm, "Setting ip6-reass buffers");
	}

      if (map_main.ip6_reass_conf_buffers >
	  map_main.ip6_reass_conf_pool_size *
	  MAP_IP6_REASS_MAX_FRAGMENTS_PER_REASSEMBLY)
	{
	  vlib_cli_output (vm,
			   "Note: 'ip6-reass buffers' > pool-size * max-fragments-per-reassembly.");
	}
    }

  return 0;
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

static_always_inline map_ip4_reass_t *
map_ip4_reass_lookup (map_ip4_reass_key_t * k, u32 bucket, f64 now)
{
  map_main_t *mm = &map_main;
  u32 ri = mm->ip4_reass_hash_table[bucket];
  while (ri != MAP_REASS_INDEX_NONE)
    {
      map_ip4_reass_t *r = pool_elt_at_index (mm->ip4_reass_pool, ri);
      if (r->key.as_u64[0] == k->as_u64[0] &&
	  r->key.as_u64[1] == k->as_u64[1] &&
	  now < r->ts + (((f64) mm->ip4_reass_conf_lifetime_ms) / 1000))
	{
	  return r;
	}
      ri = r->bucket_next;
    }
  return NULL;
}

#define map_ip4_reass_pool_index(r) (r - map_main.ip4_reass_pool)

void
map_ip4_reass_free (map_ip4_reass_t * r, u32 ** pi_to_drop)
{
  map_main_t *mm = &map_main;
  map_ip4_reass_get_fragments (r, pi_to_drop);

  // Unlink in hash bucket
  map_ip4_reass_t *r2 = NULL;
  u32 r2i = mm->ip4_reass_hash_table[r->bucket];
  while (r2i != map_ip4_reass_pool_index (r))
    {
      ASSERT (r2i != MAP_REASS_INDEX_NONE);
      r2 = pool_elt_at_index (mm->ip4_reass_pool, r2i);
      r2i = r2->bucket_next;
    }
  if (r2)
    {
      r2->bucket_next = r->bucket_next;
    }
  else
    {
      mm->ip4_reass_hash_table[r->bucket] = r->bucket_next;
    }

  // Unlink in list
  if (r->fifo_next == map_ip4_reass_pool_index (r))
    {
      mm->ip4_reass_fifo_last = MAP_REASS_INDEX_NONE;
    }
  else
    {
      if (mm->ip4_reass_fifo_last == map_ip4_reass_pool_index (r))
	mm->ip4_reass_fifo_last = r->fifo_prev;
      pool_elt_at_index (mm->ip4_reass_pool, r->fifo_prev)->fifo_next =
	r->fifo_next;
      pool_elt_at_index (mm->ip4_reass_pool, r->fifo_next)->fifo_prev =
	r->fifo_prev;
    }

  pool_put (mm->ip4_reass_pool, r);
  mm->ip4_reass_allocated--;
}

map_ip4_reass_t *
map_ip4_reass_get (u32 src, u32 dst, u16 fragment_id,
		   u8 protocol, u32 ** pi_to_drop)
{
  map_ip4_reass_t *r;
  map_main_t *mm = &map_main;
  map_ip4_reass_key_t k = {.src.data_u32 = src,
    .dst.data_u32 = dst,
    .fragment_id = fragment_id,
    .protocol = protocol
  };

  u32 h = 0;
  h = crc_u32 (k.as_u32[0], h);
  h = crc_u32 (k.as_u32[1], h);
  h = crc_u32 (k.as_u32[2], h);
  h = crc_u32 (k.as_u32[3], h);
  h = h >> (32 - mm->ip4_reass_ht_log2len);

  f64 now = vlib_time_now (mm->vlib_main);

  //Cache garbage collection
  while (mm->ip4_reass_fifo_last != MAP_REASS_INDEX_NONE)
    {
      map_ip4_reass_t *last =
	pool_elt_at_index (mm->ip4_reass_pool, mm->ip4_reass_fifo_last);
      if (last->ts + (((f64) mm->ip4_reass_conf_lifetime_ms) / 1000) < now)
	map_ip4_reass_free (last, pi_to_drop);
      else
	break;
    }

  if ((r = map_ip4_reass_lookup (&k, h, now)))
    return r;

  if (mm->ip4_reass_allocated >= mm->ip4_reass_conf_pool_size)
    return NULL;

  pool_get (mm->ip4_reass_pool, r);
  mm->ip4_reass_allocated++;
  int i;
  for (i = 0; i < MAP_IP4_REASS_MAX_FRAGMENTS_PER_REASSEMBLY; i++)
    r->fragments[i] = ~0;

  u32 ri = map_ip4_reass_pool_index (r);

  //Link in new bucket
  r->bucket = h;
  r->bucket_next = mm->ip4_reass_hash_table[h];
  mm->ip4_reass_hash_table[h] = ri;

  //Link in fifo
  if (mm->ip4_reass_fifo_last != MAP_REASS_INDEX_NONE)
    {
      r->fifo_next =
	pool_elt_at_index (mm->ip4_reass_pool,
			   mm->ip4_reass_fifo_last)->fifo_next;
      r->fifo_prev = mm->ip4_reass_fifo_last;
      pool_elt_at_index (mm->ip4_reass_pool, r->fifo_prev)->fifo_next = ri;
      pool_elt_at_index (mm->ip4_reass_pool, r->fifo_next)->fifo_prev = ri;
    }
  else
    {
      r->fifo_next = r->fifo_prev = ri;
      mm->ip4_reass_fifo_last = ri;
    }

  //Set other fields
  r->ts = now;
  r->key = k;
  r->port = -1;
#ifdef MAP_IP4_REASS_COUNT_BYTES
  r->expected_total = 0xffff;
  r->forwarded = 0;
#endif

  return r;
}

int
map_ip4_reass_add_fragment (map_ip4_reass_t * r, u32 pi)
{
  if (map_main.ip4_reass_buffered_counter >= map_main.ip4_reass_conf_buffers)
    return -1;

  int i;
  for (i = 0; i < MAP_IP4_REASS_MAX_FRAGMENTS_PER_REASSEMBLY; i++)
    if (r->fragments[i] == ~0)
      {
	r->fragments[i] = pi;
	map_main.ip4_reass_buffered_counter++;
	return 0;
      }
  return -1;
}

static_always_inline map_ip6_reass_t *
map_ip6_reass_lookup (map_ip6_reass_key_t * k, u32 bucket, f64 now)
{
  map_main_t *mm = &map_main;
  u32 ri = mm->ip6_reass_hash_table[bucket];
  while (ri != MAP_REASS_INDEX_NONE)
    {
      map_ip6_reass_t *r = pool_elt_at_index (mm->ip6_reass_pool, ri);
      if (now < r->ts + (((f64) mm->ip6_reass_conf_lifetime_ms) / 1000) &&
	  r->key.as_u64[0] == k->as_u64[0] &&
	  r->key.as_u64[1] == k->as_u64[1] &&
	  r->key.as_u64[2] == k->as_u64[2] &&
	  r->key.as_u64[3] == k->as_u64[3] &&
	  r->key.as_u64[4] == k->as_u64[4])
	return r;
      ri = r->bucket_next;
    }
  return NULL;
}

#define map_ip6_reass_pool_index(r) (r - map_main.ip6_reass_pool)

void
map_ip6_reass_free (map_ip6_reass_t * r, u32 ** pi_to_drop)
{
  map_main_t *mm = &map_main;
  int i;
  for (i = 0; i < MAP_IP6_REASS_MAX_FRAGMENTS_PER_REASSEMBLY; i++)
    if (r->fragments[i].pi != ~0)
      {
	vec_add1 (*pi_to_drop, r->fragments[i].pi);
	r->fragments[i].pi = ~0;
	map_main.ip6_reass_buffered_counter--;
      }

  // Unlink in hash bucket
  map_ip6_reass_t *r2 = NULL;
  u32 r2i = mm->ip6_reass_hash_table[r->bucket];
  while (r2i != map_ip6_reass_pool_index (r))
    {
      ASSERT (r2i != MAP_REASS_INDEX_NONE);
      r2 = pool_elt_at_index (mm->ip6_reass_pool, r2i);
      r2i = r2->bucket_next;
    }
  if (r2)
    {
      r2->bucket_next = r->bucket_next;
    }
  else
    {
      mm->ip6_reass_hash_table[r->bucket] = r->bucket_next;
    }

  // Unlink in list
  if (r->fifo_next == map_ip6_reass_pool_index (r))
    {
      //Single element in the list, list is now empty
      mm->ip6_reass_fifo_last = MAP_REASS_INDEX_NONE;
    }
  else
    {
      if (mm->ip6_reass_fifo_last == map_ip6_reass_pool_index (r))	//First element
	mm->ip6_reass_fifo_last = r->fifo_prev;
      pool_elt_at_index (mm->ip6_reass_pool, r->fifo_prev)->fifo_next =
	r->fifo_next;
      pool_elt_at_index (mm->ip6_reass_pool, r->fifo_next)->fifo_prev =
	r->fifo_prev;
    }

  // Free from pool if necessary
  pool_put (mm->ip6_reass_pool, r);
  mm->ip6_reass_allocated--;
}

map_ip6_reass_t *
map_ip6_reass_get (ip6_address_t * src, ip6_address_t * dst, u32 fragment_id,
		   u8 protocol, u32 ** pi_to_drop)
{
  map_ip6_reass_t *r;
  map_main_t *mm = &map_main;
  map_ip6_reass_key_t k = {
    .src = *src,
    .dst = *dst,
    .fragment_id = fragment_id,
    .protocol = protocol
  };

  u32 h = 0;
  int i;
  for (i = 0; i < 10; i++)
    h = crc_u32 (k.as_u32[i], h);
  h = h >> (32 - mm->ip6_reass_ht_log2len);

  f64 now = vlib_time_now (mm->vlib_main);

  //Cache garbage collection
  while (mm->ip6_reass_fifo_last != MAP_REASS_INDEX_NONE)
    {
      map_ip6_reass_t *last =
	pool_elt_at_index (mm->ip6_reass_pool, mm->ip6_reass_fifo_last);
      if (last->ts + (((f64) mm->ip6_reass_conf_lifetime_ms) / 1000) < now)
	map_ip6_reass_free (last, pi_to_drop);
      else
	break;
    }

  if ((r = map_ip6_reass_lookup (&k, h, now)))
    return r;

  if (mm->ip6_reass_allocated >= mm->ip6_reass_conf_pool_size)
    return NULL;

  pool_get (mm->ip6_reass_pool, r);
  mm->ip6_reass_allocated++;
  for (i = 0; i < MAP_IP6_REASS_MAX_FRAGMENTS_PER_REASSEMBLY; i++)
    {
      r->fragments[i].pi = ~0;
      r->fragments[i].next_data_len = 0;
      r->fragments[i].next_data_offset = 0;
    }

  u32 ri = map_ip6_reass_pool_index (r);

  //Link in new bucket
  r->bucket = h;
  r->bucket_next = mm->ip6_reass_hash_table[h];
  mm->ip6_reass_hash_table[h] = ri;

  //Link in fifo
  if (mm->ip6_reass_fifo_last != MAP_REASS_INDEX_NONE)
    {
      r->fifo_next =
	pool_elt_at_index (mm->ip6_reass_pool,
			   mm->ip6_reass_fifo_last)->fifo_next;
      r->fifo_prev = mm->ip6_reass_fifo_last;
      pool_elt_at_index (mm->ip6_reass_pool, r->fifo_prev)->fifo_next = ri;
      pool_elt_at_index (mm->ip6_reass_pool, r->fifo_next)->fifo_prev = ri;
    }
  else
    {
      r->fifo_next = r->fifo_prev = ri;
      mm->ip6_reass_fifo_last = ri;
    }

  //Set other fields
  r->ts = now;
  r->key = k;
  r->ip4_header.ip_version_and_header_length = 0;
#ifdef MAP_IP6_REASS_COUNT_BYTES
  r->expected_total = 0xffff;
  r->forwarded = 0;
#endif
  return r;
}

int
map_ip6_reass_add_fragment (map_ip6_reass_t * r, u32 pi,
			    u16 data_offset, u16 next_data_offset,
			    u8 * data_start, u16 data_len)
{
  map_ip6_fragment_t *f = NULL, *prev_f = NULL;
  u16 copied_len = (data_len > 20) ? 20 : data_len;

  if (map_main.ip6_reass_buffered_counter >= map_main.ip6_reass_conf_buffers)
    return -1;

  //Lookup for fragments for the current buffer
  //and the one before that
  int i;
  for (i = 0; i < MAP_IP6_REASS_MAX_FRAGMENTS_PER_REASSEMBLY; i++)
    {
      if (data_offset && r->fragments[i].next_data_offset == data_offset)
	{
	  prev_f = &r->fragments[i];	// This is buffer for previous packet
	}
      else if (r->fragments[i].next_data_offset == next_data_offset)
	{
	  f = &r->fragments[i];	// This is a buffer for the current packet
	}
      else if (r->fragments[i].next_data_offset == 0)
	{			//Available
	  if (f == NULL)
	    f = &r->fragments[i];
	  else if (prev_f == NULL)
	    prev_f = &r->fragments[i];
	}
    }

  if (!f || f->pi != ~0)
    return -1;

  if (data_offset)
    {
      if (!prev_f)
	return -1;

      clib_memcpy (prev_f->next_data, data_start, copied_len);
      prev_f->next_data_len = copied_len;
      prev_f->next_data_offset = data_offset;
    }
  else
    {
      if (((ip4_header_t *) data_start)->ip_version_and_header_length != 0x45)
	return -1;

      if (r->ip4_header.ip_version_and_header_length == 0)
	clib_memcpy (&r->ip4_header, data_start, sizeof (ip4_header_t));
    }

  if (data_len > 20)
    {
      f->next_data_offset = next_data_offset;
      f->pi = pi;
      map_main.ip6_reass_buffered_counter++;
    }
  return 0;
}

void
map_ip4_reass_reinit (u32 * trashed_reass, u32 * dropped_packets)
{
  map_main_t *mm = &map_main;
  int i;

  if (dropped_packets)
    *dropped_packets = mm->ip4_reass_buffered_counter;
  if (trashed_reass)
    *trashed_reass = mm->ip4_reass_allocated;
  if (mm->ip4_reass_fifo_last != MAP_REASS_INDEX_NONE)
    {
      u16 ri = mm->ip4_reass_fifo_last;
      do
	{
	  map_ip4_reass_t *r = pool_elt_at_index (mm->ip4_reass_pool, ri);
	  for (i = 0; i < MAP_IP4_REASS_MAX_FRAGMENTS_PER_REASSEMBLY; i++)
	    if (r->fragments[i] != ~0)
	      map_ip4_drop_pi (r->fragments[i]);

	  ri = r->fifo_next;
	  pool_put (mm->ip4_reass_pool, r);
	}
      while (ri != mm->ip4_reass_fifo_last);
    }

  vec_free (mm->ip4_reass_hash_table);
  vec_resize (mm->ip4_reass_hash_table, 1 << mm->ip4_reass_ht_log2len);
  for (i = 0; i < (1 << mm->ip4_reass_ht_log2len); i++)
    mm->ip4_reass_hash_table[i] = MAP_REASS_INDEX_NONE;
  pool_free (mm->ip4_reass_pool);
  pool_alloc (mm->ip4_reass_pool, mm->ip4_reass_conf_pool_size);

  mm->ip4_reass_allocated = 0;
  mm->ip4_reass_fifo_last = MAP_REASS_INDEX_NONE;
  mm->ip4_reass_buffered_counter = 0;
}

u8
map_get_ht_log2len (f32 ht_ratio, u16 pool_size)
{
  u32 desired_size = (u32) (pool_size * ht_ratio);
  u8 i;
  for (i = 1; i < 31; i++)
    if ((1 << i) >= desired_size)
      return i;
  return 4;
}

int
map_ip4_reass_conf_ht_ratio (f32 ht_ratio, u32 * trashed_reass,
			     u32 * dropped_packets)
{
  map_main_t *mm = &map_main;
  if (ht_ratio > MAP_IP4_REASS_CONF_HT_RATIO_MAX)
    return -1;

  map_ip4_reass_lock ();
  mm->ip4_reass_conf_ht_ratio = ht_ratio;
  mm->ip4_reass_ht_log2len =
    map_get_ht_log2len (ht_ratio, mm->ip4_reass_conf_pool_size);
  map_ip4_reass_reinit (trashed_reass, dropped_packets);
  map_ip4_reass_unlock ();
  return 0;
}

int
map_ip4_reass_conf_pool_size (u16 pool_size, u32 * trashed_reass,
			      u32 * dropped_packets)
{
  map_main_t *mm = &map_main;
  if (pool_size > MAP_IP4_REASS_CONF_POOL_SIZE_MAX)
    return -1;

  map_ip4_reass_lock ();
  mm->ip4_reass_conf_pool_size = pool_size;
  map_ip4_reass_reinit (trashed_reass, dropped_packets);
  map_ip4_reass_unlock ();
  return 0;
}

int
map_ip4_reass_conf_lifetime (u16 lifetime_ms)
{
  map_main.ip4_reass_conf_lifetime_ms = lifetime_ms;
  return 0;
}

int
map_ip4_reass_conf_buffers (u32 buffers)
{
  map_main.ip4_reass_conf_buffers = buffers;
  return 0;
}

void
map_ip6_reass_reinit (u32 * trashed_reass, u32 * dropped_packets)
{
  map_main_t *mm = &map_main;
  if (dropped_packets)
    *dropped_packets = mm->ip6_reass_buffered_counter;
  if (trashed_reass)
    *trashed_reass = mm->ip6_reass_allocated;
  int i;
  if (mm->ip6_reass_fifo_last != MAP_REASS_INDEX_NONE)
    {
      u16 ri = mm->ip6_reass_fifo_last;
      do
	{
	  map_ip6_reass_t *r = pool_elt_at_index (mm->ip6_reass_pool, ri);
	  for (i = 0; i < MAP_IP6_REASS_MAX_FRAGMENTS_PER_REASSEMBLY; i++)
	    if (r->fragments[i].pi != ~0)
	      map_ip6_drop_pi (r->fragments[i].pi);

	  ri = r->fifo_next;
	  pool_put (mm->ip6_reass_pool, r);
	}
      while (ri != mm->ip6_reass_fifo_last);
      mm->ip6_reass_fifo_last = MAP_REASS_INDEX_NONE;
    }

  vec_free (mm->ip6_reass_hash_table);
  vec_resize (mm->ip6_reass_hash_table, 1 << mm->ip6_reass_ht_log2len);
  for (i = 0; i < (1 << mm->ip6_reass_ht_log2len); i++)
    mm->ip6_reass_hash_table[i] = MAP_REASS_INDEX_NONE;
  pool_free (mm->ip6_reass_pool);
  pool_alloc (mm->ip6_reass_pool, mm->ip4_reass_conf_pool_size);

  mm->ip6_reass_allocated = 0;
  mm->ip6_reass_buffered_counter = 0;
}

int
map_ip6_reass_conf_ht_ratio (f32 ht_ratio, u32 * trashed_reass,
			     u32 * dropped_packets)
{
  map_main_t *mm = &map_main;
  if (ht_ratio > MAP_IP6_REASS_CONF_HT_RATIO_MAX)
    return -1;

  map_ip6_reass_lock ();
  mm->ip6_reass_conf_ht_ratio = ht_ratio;
  mm->ip6_reass_ht_log2len =
    map_get_ht_log2len (ht_ratio, mm->ip6_reass_conf_pool_size);
  map_ip6_reass_reinit (trashed_reass, dropped_packets);
  map_ip6_reass_unlock ();
  return 0;
}

int
map_ip6_reass_conf_pool_size (u16 pool_size, u32 * trashed_reass,
			      u32 * dropped_packets)
{
  map_main_t *mm = &map_main;
  if (pool_size > MAP_IP6_REASS_CONF_POOL_SIZE_MAX)
    return -1;

  map_ip6_reass_lock ();
  mm->ip6_reass_conf_pool_size = pool_size;
  map_ip6_reass_reinit (trashed_reass, dropped_packets);
  map_ip6_reass_unlock ();
  return 0;
}

int
map_ip6_reass_conf_lifetime (u16 lifetime_ms)
{
  map_main.ip6_reass_conf_lifetime_ms = lifetime_ms;
  return 0;
}

int
map_ip6_reass_conf_buffers (u32 buffers)
{
  map_main.ip6_reass_conf_buffers = buffers;
  return 0;
}

/* *INDENT-OFF* */

/*?
 * Configure MAP reassembly behaviour
 *
 * @cliexpar
 * @cliexstart{map params reassembly}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ip4_reass_lifetime_command, static) = {
  .path = "map params reassembly",
  .short_help = "map params reassembly [ip4 | ip6] [lifetime <lifetime-ms>] "
                "[pool-size <pool-size>] [buffers <buffers>] "
                "[ht-ratio <ht-ratio>]",
  .function = map_params_reass_command_fn,
};

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
 *
 * @cliexpar
 * @cliexstart{map params security-check}
 *
 * By default, a decapsulated packet's IPv4 source address will be
 * verified against the outer header's IPv6 source address. Disabling
 * this feature will allow IPv4 source address spoofing.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_security_check_command, static) = {
  .path = "map params security-check",
  .short_help = "map params security-check on|off",
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
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_fragment_command, static) = {
  .path = "map params fragment",
  .short_help = "map params fragment inner|outer",
  .function = map_fragment_command_fn,
};

/*?
 * Ignore the IPv4 Don't fragment bit
 *
 * @cliexpar
 * @cliexstart{map params fragment ignore-df}
 *
 * Allows fragmentation of the IPv4 packet even if the DF bit is
 * set. The choice between inner or outer fragmentation of tunnel
 * packets is complicated. The benefit of inner fragmentation is that
 * the ultimate endpoint must reassemble, instead of the tunnel
 * endpoint.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_fragment_df_command, static) = {
  .path = "map params fragment ignore-df",
  .short_help = "map params fragment ignore-df on|off",
  .function = map_fragment_df_command_fn,
};

/*?
 * Specifiy if the inbound security check should be done on fragments
 *
 * @cliexpar
 * @cliexstart{map params security-check fragments}
 *
 * Typically the inbound on-decapsulation security check is only done
 * on the first packet. The packet that contains the L4
 * information. While a security check on every fragment is possible,
 * it has a cost. State must be created on the first fragment.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_security_check_frag_command, static) = {
  .path = "map params security-check fragments",
  .short_help = "map params security-check fragments on|off",
  .function = map_security_check_frag_command_fn,
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
  .short_help = "map add domain ip4-pfx <ip4-pfx> ip6-pfx <ip6-pfx> "
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
 * Show MAP fragmentation information
 *
 * @cliexpar
 * @cliexstart{show map fragments}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(show_map_fragments_command, static) = {
  .path = "show map fragments",
  .short_help = "show map fragments",
  .function = show_map_fragments_command_fn,
};
/* *INDENT-ON* */

/*
 * map_init
 */
clib_error_t *
map_init (vlib_main_t * vm)
{
  map_main_t *mm = &map_main;
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
  mm->domain_counters[MAP_DOMAIN_COUNTER_RX].name = "rx";
  mm->domain_counters[MAP_DOMAIN_COUNTER_TX].name = "tx";

  vlib_validate_simple_counter (&mm->icmp_relayed, 0);
  vlib_zero_simple_counter (&mm->icmp_relayed, 0);

  /* IP4 virtual reassembly */
  mm->ip4_reass_hash_table = 0;
  mm->ip4_reass_pool = 0;
  mm->ip4_reass_lock =
    clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES, CLIB_CACHE_LINE_BYTES);
  mm->ip4_reass_conf_ht_ratio = MAP_IP4_REASS_HT_RATIO_DEFAULT;
  mm->ip4_reass_conf_lifetime_ms = MAP_IP4_REASS_LIFETIME_DEFAULT;
  mm->ip4_reass_conf_pool_size = MAP_IP4_REASS_POOL_SIZE_DEFAULT;
  mm->ip4_reass_conf_buffers = MAP_IP4_REASS_BUFFERS_DEFAULT;
  mm->ip4_reass_ht_log2len =
    map_get_ht_log2len (mm->ip4_reass_conf_ht_ratio,
			mm->ip4_reass_conf_pool_size);
  mm->ip4_reass_fifo_last = MAP_REASS_INDEX_NONE;
  map_ip4_reass_reinit (NULL, NULL);

  /* IP6 virtual reassembly */
  mm->ip6_reass_hash_table = 0;
  mm->ip6_reass_pool = 0;
  mm->ip6_reass_lock =
    clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES, CLIB_CACHE_LINE_BYTES);
  mm->ip6_reass_conf_ht_ratio = MAP_IP6_REASS_HT_RATIO_DEFAULT;
  mm->ip6_reass_conf_lifetime_ms = MAP_IP6_REASS_LIFETIME_DEFAULT;
  mm->ip6_reass_conf_pool_size = MAP_IP6_REASS_POOL_SIZE_DEFAULT;
  mm->ip6_reass_conf_buffers = MAP_IP6_REASS_BUFFERS_DEFAULT;
  mm->ip6_reass_ht_log2len =
    map_get_ht_log2len (mm->ip6_reass_conf_ht_ratio,
			mm->ip6_reass_conf_pool_size);
  mm->ip6_reass_fifo_last = MAP_REASS_INDEX_NONE;
  map_ip6_reass_reinit (NULL, NULL);

#ifdef MAP_SKIP_IP6_LOOKUP
  fib_node_register_type (FIB_NODE_TYPE_MAP_E, &map_vft);
#endif
  map_dpo_module_init ();

  return 0;
}

VLIB_INIT_FUNCTION (map_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
