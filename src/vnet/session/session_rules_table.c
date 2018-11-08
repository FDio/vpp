/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vnet/session/mma_16.h>
#include <vnet/session/mma_template.c>
#include <vnet/session/mma_40.h>
#include <vnet/session/mma_template.c>
#include <vnet/session/session_rules_table.h>
#include <vnet/session/transport.h>

u32
session_rule_tag_key_index (u32 ri, u8 is_ip4)
{
  return ((ri << 1) | is_ip4);
}

void
session_rule_tag_key_index_parse (u32 rti_key, u32 * ri, u8 * is_ip4)
{
  *is_ip4 = rti_key & 1;
  *ri = rti_key >> 1;
}

u8 *
session_rules_table_rule_tag (session_rules_table_t * srt, u32 ri, u8 is_ip4)
{
  uword *tip;
  session_rule_tag_t *rt;

  tip =
    hash_get (srt->tags_by_rules, session_rule_tag_key_index (ri, is_ip4));
  if (tip)
    {
      rt = pool_elt_at_index (srt->rule_tags, *tip);
      return rt->tag;
    }
  return 0;
}

void
session_rules_table_del_tag (session_rules_table_t * srt, u8 * tag, u8 is_ip4)
{
  uword *rip, *rtip;
  session_rule_tag_t *rt;
  u32 rti_key;

  if (tag == 0)
    return;
  rip = hash_get_mem (srt->rules_by_tag, tag);
  if (!rip)
    {
      clib_warning ("tag has no rule associated");
      return;
    }
  rti_key = session_rule_tag_key_index (*rip, is_ip4);
  rtip = hash_get (srt->tags_by_rules, rti_key);
  if (!rtip)
    {
      clib_warning ("rule has no tag associated");
      return;
    }
  rt = pool_elt_at_index (srt->rule_tags, *rtip);
  ASSERT (rt);
  hash_unset_mem (srt->rules_by_tag, tag);
  hash_unset (srt->tags_by_rules, rti_key);
  pool_put (srt->rule_tags, rt);
}

void
session_rules_table_add_tag (session_rules_table_t * srt, u8 * tag,
			     u32 rule_index, u8 is_ip4)
{
  uword *rip;
  session_rule_tag_t *rt;
  u32 rti_key;

  if (tag == 0)
    return;
  rip = hash_get_mem (srt->rules_by_tag, tag);
  if (rip)
    session_rules_table_del_tag (srt, tag, is_ip4);
  pool_get (srt->rule_tags, rt);
  rt->tag = vec_dup (tag);
  hash_set_mem (srt->rules_by_tag, rt->tag, rule_index);
  rti_key = session_rule_tag_key_index (rule_index, is_ip4);
  hash_set (srt->tags_by_rules, rti_key, rt - srt->rule_tags);
}

u32
session_rules_table_rule_for_tag (session_rules_table_t * srt, u8 * tag)
{
  uword *rp;
  if (tag == 0)
    return SESSION_RULES_TABLE_INVALID_INDEX;
  rp = hash_get_mem (srt->rules_by_tag, tag);
  return (rp == 0 ? SESSION_RULES_TABLE_INVALID_INDEX : *rp);
}

static void
fib_pref_normalize (fib_prefix_t * pref)
{
  if (pref->fp_proto == FIB_PROTOCOL_IP4)
    ip4_address_normalize (&pref->fp_addr.ip4, pref->fp_len);
  else
    ip6_address_normalize (&pref->fp_addr.ip6, pref->fp_len);
}

u8 *
format_session_rule4 (u8 * s, va_list * args)
{
  session_rules_table_t *srt = va_arg (*args, session_rules_table_t *);
  mma_rule_16_t *sr = va_arg (*args, mma_rule_16_t *);
  session_mask_or_match_4_t *mask, *match;
  mma_rules_table_16_t *srt4;
  u8 *tag = 0, *null_tag = format (0, "none");
  u32 ri;
  int i;

  srt4 = &srt->session_rules_tables_16;
  ri = mma_rules_table_rule_index_16 (srt4, sr);
  tag = session_rules_table_rule_tag (srt, ri, 1);
  match = (session_mask_or_match_4_t *) & sr->match;
  mask = (session_mask_or_match_4_t *) & sr->mask;

  s = format (s, "[%d] rule: %U/%d %d %U/%d %d action: %d tag: %v", ri,
	      format_ip4_address, &match->lcl_ip,
	      ip4_mask_to_preflen (&mask->lcl_ip),
	      clib_net_to_host_u16 (match->lcl_port), format_ip4_address,
	      &match->rmt_ip, ip4_mask_to_preflen (&mask->rmt_ip),
	      clib_net_to_host_u16 (match->rmt_port), sr->action_index,
	      tag ? tag : null_tag);
  if (vec_len (sr->next_indices))
    {
      s = format (s, "\n    children: ");
      for (i = 0; i < vec_len (sr->next_indices); i++)
	s = format (s, "%d ", sr->next_indices[i]);
    }
  vec_free (null_tag);
  return s;
}

u8 *
format_session_rule6 (u8 * s, va_list * args)
{
  session_rules_table_t *srt = va_arg (*args, session_rules_table_t *);
  mma_rule_40_t *sr = va_arg (*args, mma_rule_40_t *);
  session_mask_or_match_6_t *mask, *match;
  mma_rules_table_40_t *srt6;
  u8 *tag = 0, *null_tag = format (0, "none");
  u32 ri;
  int i;

  srt6 = &srt->session_rules_tables_40;
  ri = mma_rules_table_rule_index_40 (srt6, sr);
  tag = session_rules_table_rule_tag (srt, ri, 0);
  match = (session_mask_or_match_6_t *) & sr->match;
  mask = (session_mask_or_match_6_t *) & sr->mask;

  s = format (s, "[%d] rule: %U/%d %d %U/%d %d action: %d tag: %v", ri,
	      format_ip6_address, &match->lcl_ip,
	      ip6_mask_to_preflen (&mask->lcl_ip),
	      clib_net_to_host_u16 (match->lcl_port), format_ip6_address,
	      &match->rmt_ip, ip6_mask_to_preflen (&mask->rmt_ip),
	      clib_net_to_host_u16 (match->rmt_port), sr->action_index,
	      tag ? tag : null_tag);
  if (vec_len (sr->next_indices))
    {
      s = format (s, "\n    children: ");
      for (i = 0; i < vec_len (sr->next_indices); i++)
	s = format (s, "%d ", sr->next_indices[i]);
    }
  vec_free (null_tag);
  return s;
}

void *
session_rules_table_get (session_rules_table_t * srt, u8 fib_proto)
{
  if (fib_proto == FIB_PROTOCOL_IP4)
    return &srt->session_rules_tables_16;
  else if (fib_proto == FIB_PROTOCOL_IP6)
    return &srt->session_rules_tables_40;
  return 0;
}

int
rule_cmp_16 (mma_rule_16_t * rule1, mma_rule_16_t * rule2)
{
  session_mask_or_match_4_t *m1, *m2;

  m1 = (session_mask_or_match_4_t *) & rule1->max_match;
  m2 = (session_mask_or_match_4_t *) & rule2->max_match;
  if (m1->rmt_ip.as_u32 != m2->rmt_ip.as_u32)
    return (m1->rmt_ip.as_u32 < m2->rmt_ip.as_u32 ? -1 : 1);
  if (m1->lcl_ip.as_u32 != m2->lcl_ip.as_u32)
    return (m1->lcl_ip.as_u32 < m2->lcl_ip.as_u32 ? -1 : 1);
  if (m1->rmt_port != m2->rmt_port)
    return (m1->rmt_port < m2->rmt_port ? -1 : 1);
  if (m1->lcl_port != m2->lcl_port)
    return (m1->lcl_port < m2->lcl_port ? -1 : 1);
  return 0;
}

int
rule_cmp_40 (mma_rule_40_t * rule1, mma_rule_40_t * rule2)
{
  session_mask_or_match_6_t *r1, *r2;
  r1 = (session_mask_or_match_6_t *) & rule1->max_match;
  r2 = (session_mask_or_match_6_t *) & rule2->max_match;
  if (r1->rmt_ip.as_u64[0] != r2->rmt_ip.as_u64[0])
    return (r1->rmt_ip.as_u64[0] < r2->rmt_ip.as_u64[0] ? -1 : 1);
  if (r1->rmt_ip.as_u64[1] != r2->rmt_ip.as_u64[1])
    return (r1->rmt_ip.as_u64[1] < r2->rmt_ip.as_u64[1] ? -1 : 1);
  if (r1->lcl_ip.as_u64[0] != r2->lcl_ip.as_u64[0])
    return (r1->lcl_ip.as_u64[0] < r2->lcl_ip.as_u64[0] ? -1 : 1);
  if (r1->lcl_ip.as_u64[1] != r2->lcl_ip.as_u64[1])
    return (r1->lcl_ip.as_u64[1] < r2->lcl_ip.as_u64[1]) ? -1 : 1;
  if (r1->rmt_port != r2->rmt_port)
    return (r1->rmt_port < r2->rmt_port ? -1 : 1);
  if (r1->lcl_port != r2->lcl_port)
    return (r1->lcl_port < r2->lcl_port ? -1 : 1);
  return 0;
}

void
session_rules_table_init_rule_16 (mma_rule_16_t * rule,
				  fib_prefix_t * lcl, u16 lcl_port,
				  fib_prefix_t * rmt, u16 rmt_port)
{
  session_mask_or_match_4_t *match, *mask, *max_match;
  fib_pref_normalize (lcl);
  fib_pref_normalize (rmt);
  match = (session_mask_or_match_4_t *) & rule->match;
  match->lcl_ip.as_u32 = lcl->fp_addr.ip4.as_u32;
  match->rmt_ip.as_u32 = rmt->fp_addr.ip4.as_u32;
  match->lcl_port = lcl_port;
  match->rmt_port = rmt_port;
  mask = (session_mask_or_match_4_t *) & rule->mask;
  ip4_preflen_to_mask (lcl->fp_len, &mask->lcl_ip);
  ip4_preflen_to_mask (rmt->fp_len, &mask->rmt_ip);
  mask->lcl_port = lcl_port == 0 ? 0 : (u16) ~ 0;
  mask->rmt_port = rmt_port == 0 ? 0 : (u16) ~ 0;
  max_match = (session_mask_or_match_4_t *) & rule->max_match;
  ip4_prefix_max_address_host_order (&rmt->fp_addr.ip4, rmt->fp_len,
				     &max_match->rmt_ip);
  ip4_prefix_max_address_host_order (&lcl->fp_addr.ip4, lcl->fp_len,
				     &max_match->lcl_ip);
  max_match->lcl_port = lcl_port == 0 ? (u16) ~ 0 : lcl_port;
  max_match->rmt_port = rmt_port == 0 ? (u16) ~ 0 : rmt_port;
}

void
session_rules_table_init_rule_40 (mma_rule_40_t * rule,
				  fib_prefix_t * lcl, u16 lcl_port,
				  fib_prefix_t * rmt, u16 rmt_port)
{
  session_mask_or_match_6_t *match, *mask, *max_match;
  fib_pref_normalize (lcl);
  fib_pref_normalize (rmt);
  match = (session_mask_or_match_6_t *) & rule->match;
  clib_memcpy (&match->lcl_ip, &lcl->fp_addr.ip6, sizeof (match->lcl_ip));
  clib_memcpy (&match->rmt_ip, &rmt->fp_addr.ip6, sizeof (match->rmt_ip));
  match->lcl_port = lcl_port;
  match->rmt_port = rmt_port;
  mask = (session_mask_or_match_6_t *) & rule->mask;
  ip6_preflen_to_mask (lcl->fp_len, &mask->lcl_ip);
  ip6_preflen_to_mask (rmt->fp_len, &mask->rmt_ip);
  mask->lcl_port = lcl_port == 0 ? 0 : (u16) ~ 0;
  mask->rmt_port = rmt_port == 0 ? 0 : (u16) ~ 0;
  max_match = (session_mask_or_match_6_t *) & rule->max_match;
  ip6_prefix_max_address_host_order (&rmt->fp_addr.ip6, rmt->fp_len,
				     &max_match->rmt_ip);
  ip6_prefix_max_address_host_order (&lcl->fp_addr.ip6, lcl->fp_len,
				     &max_match->lcl_ip);
  max_match->lcl_port = lcl_port == 0 ? (u16) ~ 0 : lcl_port;
  max_match->rmt_port = rmt_port == 0 ? (u16) ~ 0 : rmt_port;
}

mma_rule_16_t *
session_rules_table_alloc_rule_16 (mma_rules_table_16_t * srt,
				   fib_prefix_t * lcl, u16 lcl_port,
				   fib_prefix_t * rmt, u16 rmt_port)
{
  mma_rule_16_t *rule = 0;
  rule = mma_rules_table_rule_alloc_16 (srt);
  session_rules_table_init_rule_16 (rule, lcl, lcl_port, rmt, rmt_port);
  return rule;
}

mma_rule_40_t *
session_rules_table_alloc_rule_40 (mma_rules_table_40_t * srt,
				   fib_prefix_t * lcl, u16 lcl_port,
				   fib_prefix_t * rmt, u16 rmt_port)
{
  mma_rule_40_t *rule;
  rule = mma_rules_table_rule_alloc_40 (srt);
  session_rules_table_init_rule_40 (rule, lcl, lcl_port, rmt, rmt_port);
  return rule;
}

u32
session_rules_table_lookup_rule4 (session_rules_table_t * srt,
				  ip4_address_t * lcl_ip,
				  ip4_address_t * rmt_ip, u16 lcl_port,
				  u16 rmt_port)
{
  mma_rules_table_16_t *srt4 = &srt->session_rules_tables_16;
  session_mask_or_match_4_t key = {
    .lcl_ip.as_u32 = lcl_ip->as_u32,
    .rmt_ip.as_u32 = rmt_ip->as_u32,
    .lcl_port = lcl_port,
    .rmt_port = rmt_port,
  };
  return mma_rules_table_lookup_rule_16 (srt4,
					 (mma_mask_or_match_16_t *) & key,
					 srt4->root_index);
}

u32
session_rules_table_lookup4 (session_rules_table_t * srt,
			     ip4_address_t * lcl_ip, ip4_address_t * rmt_ip,
			     u16 lcl_port, u16 rmt_port)
{
  mma_rules_table_16_t *srt4 = &srt->session_rules_tables_16;
  session_mask_or_match_4_t key = {
    .lcl_ip.as_u32 = lcl_ip->as_u32,
    .rmt_ip.as_u32 = rmt_ip->as_u32,
    .lcl_port = lcl_port,
    .rmt_port = rmt_port,
  };
  return mma_rules_table_lookup_16 (srt4, (mma_mask_or_match_16_t *) & key,
				    srt4->root_index);
}

u32
session_rules_table_lookup_rule6 (session_rules_table_t * srt,
				  ip6_address_t * lcl_ip,
				  ip6_address_t * rmt_ip, u16 lcl_port,
				  u16 rmt_port)
{
  mma_rules_table_40_t *srt6 = &srt->session_rules_tables_40;
  session_mask_or_match_6_t key = {
    .lcl_port = lcl_port,
    .rmt_port = rmt_port,
  };
  clib_memcpy (&key.lcl_ip, lcl_ip, sizeof (*lcl_ip));
  clib_memcpy (&key.rmt_ip, rmt_ip, sizeof (*rmt_ip));
  return mma_rules_table_lookup_rule_40 (srt6,
					 (mma_mask_or_match_40_t *) & key,
					 srt6->root_index);
}

u32
session_rules_table_lookup6 (session_rules_table_t * srt,
			     ip6_address_t * lcl_ip, ip6_address_t * rmt_ip,
			     u16 lcl_port, u16 rmt_port)
{
  mma_rules_table_40_t *srt6 = &srt->session_rules_tables_40;
  session_mask_or_match_6_t key = {
    .lcl_port = lcl_port,
    .rmt_port = rmt_port,
  };
  clib_memcpy (&key.lcl_ip, lcl_ip, sizeof (*lcl_ip));
  clib_memcpy (&key.rmt_ip, rmt_ip, sizeof (*rmt_ip));
  return mma_rules_table_lookup_40 (srt6, (mma_mask_or_match_40_t *) & key,
				    srt6->root_index);
}

/**
 * Add/delete session rule
 *
 * @param srt table where rule should be added
 * @param args rule arguments
 *
 * @return 0 if success, clib_error_t error otherwise
 */
clib_error_t *
session_rules_table_add_del (session_rules_table_t * srt,
			     session_rule_table_add_del_args_t * args)
{
  u8 fib_proto = args->rmt.fp_proto, *rt;
  u32 ri_from_tag, ri;
  int rv;

  ri_from_tag = session_rules_table_rule_for_tag (srt, args->tag);
  if (args->is_add && ri_from_tag != SESSION_RULES_TABLE_INVALID_INDEX)
    return clib_error_return_code (0, VNET_API_ERROR_INVALID_VALUE, 0,
				   "tag exists");

  if (fib_proto == FIB_PROTOCOL_IP4)
    {
      mma_rules_table_16_t *srt4;
      srt4 = &srt->session_rules_tables_16;
      if (args->is_add)
	{
	  mma_rule_16_t *rule4;
	  rule4 = session_rules_table_alloc_rule_16 (srt4, &args->lcl,
						     args->lcl_port,
						     &args->rmt,
						     args->rmt_port);
	  rule4->action_index = args->action_index;
	  rv = mma_rules_table_add_rule_16 (srt4, rule4);
	  if (!rv)
	    {
	      ri = mma_rules_table_rule_index_16 (srt4, rule4);
	      session_rules_table_add_tag (srt, args->tag, ri, 1);
	    }
	  else
	    {
	      ri = session_rules_table_lookup_rule4 (srt,
						     &args->lcl.fp_addr.ip4,
						     &args->rmt.fp_addr.ip4,
						     args->lcl_port,
						     args->rmt_port);
	      if (ri != SESSION_RULES_TABLE_INVALID_INDEX)
		{
		  rt = session_rules_table_rule_tag (srt, ri, 1);
		  session_rules_table_del_tag (srt, rt, 1);
		  session_rules_table_add_tag (srt, args->tag, ri, 1);
		}
	    }
	}
      else
	{
	  mma_rule_16_t *rule;
	  if (ri_from_tag != SESSION_RULES_TABLE_INVALID_INDEX)
	    {
	      rule = mma_rules_table_get_rule_16 (srt4, ri_from_tag);
	      mma_rules_table_del_rule_16 (srt4, rule, srt4->root_index);
	      session_rules_table_del_tag (srt, args->tag, 1);
	    }
	  else
	    {
	      mma_rule_16_t _rule;
	      rule = &_rule;
	      memset (rule, 0, sizeof (*rule));
	      session_rules_table_init_rule_16 (rule, &args->lcl,
						args->lcl_port, &args->rmt,
						args->rmt_port);
	      mma_rules_table_del_rule_16 (srt4, rule, srt4->root_index);
	    }
	}
    }
  else if (fib_proto == FIB_PROTOCOL_IP6)
    {
      mma_rules_table_40_t *srt6;
      mma_rule_40_t *rule6;
      srt6 = &srt->session_rules_tables_40;
      if (args->is_add)
	{
	  rule6 = session_rules_table_alloc_rule_40 (srt6, &args->lcl,
						     args->lcl_port,
						     &args->rmt,
						     args->rmt_port);
	  rule6->action_index = args->action_index;
	  rv = mma_rules_table_add_rule_40 (srt6, rule6);
	  if (!rv)
	    {
	      ri = mma_rules_table_rule_index_40 (srt6, rule6);
	      session_rules_table_add_tag (srt, args->tag, ri, 0);
	    }
	  else
	    {
	      ri = session_rules_table_lookup_rule6 (srt,
						     &args->lcl.fp_addr.ip6,
						     &args->rmt.fp_addr.ip6,
						     args->lcl_port,
						     args->rmt_port);
	      if (ri != SESSION_RULES_TABLE_INVALID_INDEX)
		{
		  rt = session_rules_table_rule_tag (srt, ri, 0);
		  session_rules_table_del_tag (srt, rt, 1);
		  session_rules_table_add_tag (srt, args->tag, ri, 0);
		}
	    }
	}
      else
	{
	  mma_rule_40_t *rule;
	  if (ri_from_tag != SESSION_RULES_TABLE_INVALID_INDEX)
	    {
	      rule = mma_rules_table_get_rule_40 (srt6, ri_from_tag);
	      mma_rules_table_del_rule_40 (srt6, rule, srt6->root_index);
	      session_rules_table_del_tag (srt, args->tag, 0);
	    }
	  else
	    {
	      mma_rule_40_t _rule;
	      rule = &_rule;
	      memset (rule, 0, sizeof (*rule));
	      session_rules_table_init_rule_40 (rule, &args->lcl,
						args->lcl_port, &args->rmt,
						args->rmt_port);
	      mma_rules_table_del_rule_40 (srt6, rule, srt6->root_index);
	    }
	}
    }
  else
    return clib_error_return_code (0, VNET_API_ERROR_INVALID_VALUE_2, 0,
				   "invalid fib proto");
  return 0;
}

void
session_rules_table_init (session_rules_table_t * srt)
{
  mma_rules_table_16_t *srt4;
  mma_rules_table_40_t *srt6;
  mma_rule_16_t *rule4;
  mma_rule_40_t *rule6;
  fib_prefix_t null_prefix;

  memset (&null_prefix, 0, sizeof (null_prefix));

  srt4 = &srt->session_rules_tables_16;
  rule4 = session_rules_table_alloc_rule_16 (srt4, &null_prefix, 0,
					     &null_prefix, 0);
  rule4->action_index = SESSION_RULES_TABLE_INVALID_INDEX;
  srt4->root_index = mma_rules_table_rule_index_16 (srt4, rule4);
  srt4->rule_cmp_fn = rule_cmp_16;

  srt6 = &srt->session_rules_tables_40;
  rule6 = session_rules_table_alloc_rule_40 (srt6, &null_prefix, 0,
					     &null_prefix, 0);
  rule6->action_index = SESSION_RULES_TABLE_INVALID_INDEX;
  srt6->root_index = mma_rules_table_rule_index_40 (srt6, rule6);
  srt6->rule_cmp_fn = rule_cmp_40;

  srt->rules_by_tag = hash_create_vec (0, sizeof (u8), sizeof (uword));
  srt->tags_by_rules = hash_create (0, sizeof (uword));
}

void
session_rules_table_show_rule (vlib_main_t * vm, session_rules_table_t * srt,
			       ip46_address_t * lcl_ip, u16 lcl_port,
			       ip46_address_t * rmt_ip, u16 rmt_port,
			       u8 is_ip4)
{
  mma_rules_table_16_t *srt4;
  mma_rules_table_40_t *srt6;
  mma_rule_16_t *sr4;
  mma_rule_40_t *sr6;
  u32 ri;

  if (is_ip4)
    {
      srt4 = session_rules_table_get (srt, FIB_PROTOCOL_IP4);
      session_mask_or_match_4_t key = {
	.lcl_ip.as_u32 = lcl_ip->ip4.as_u32,
	.rmt_ip.as_u32 = rmt_ip->ip4.as_u32,
	.lcl_port = lcl_port,
	.rmt_port = rmt_port,
      };
      ri =
	mma_rules_table_lookup_rule_16 (srt4,
					(mma_mask_or_match_16_t *) & key,
					srt4->root_index);
      sr4 = mma_rules_table_get_rule_16 (srt4, ri);
      vlib_cli_output (vm, "%U", format_session_rule4, srt, sr4);
    }
  else
    {
      srt6 = session_rules_table_get (srt, FIB_PROTOCOL_IP6);
      session_mask_or_match_6_t key = {
	.lcl_port = lcl_port,
	.rmt_port = rmt_port,
      };
      clib_memcpy (&key.lcl_ip, &lcl_ip->ip6, sizeof (lcl_ip->ip6));
      clib_memcpy (&key.rmt_ip, &rmt_ip->ip6, sizeof (rmt_ip->ip6));
      ri = mma_rules_table_lookup_rule_40 (srt6,
					   (mma_mask_or_match_40_t *) & key,
					   srt6->root_index);
      sr6 = mma_rules_table_get_rule_40 (srt6, ri);
      vlib_cli_output (vm, "%U", format_session_rule6, srt, sr6);
    }
}

void
session_rules_table_cli_dump (vlib_main_t * vm, session_rules_table_t * srt,
			      u8 fib_proto)
{
  if (fib_proto == FIB_PROTOCOL_IP4)
    {
      mma_rules_table_16_t *srt4;
      mma_rule_16_t *sr4;
      srt4 = &srt->session_rules_tables_16;
      vlib_cli_output (vm, "IP4 rules");

      /* *INDENT-OFF* */
      pool_foreach(sr4, srt4->rules, ({
	vlib_cli_output (vm, "%U", format_session_rule4, srt, sr4);
      }));
      /* *INDENT-ON* */

    }
  else if (fib_proto == FIB_PROTOCOL_IP6)
    {
      mma_rules_table_40_t *srt6;
      mma_rule_40_t *sr6;
      srt6 = &srt->session_rules_tables_40;
      vlib_cli_output (vm, "IP6 rules");

      /* *INDENT-OFF* */
      pool_foreach(sr6, srt6->rules, ({
        vlib_cli_output (vm, "%U", format_session_rule6, srt, sr6);
      }));
      /* *INDENT-ON* */

    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
