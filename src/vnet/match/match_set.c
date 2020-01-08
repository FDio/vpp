/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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


#include <vnet/match/match_set.h>
#include <vnet/match/match_set_dp.h>
#include <vnet/match/match_engine.h>

match_set_t *match_set_pool;
match_set_entry_t *match_set_entry_pool;

static index_t
match_set_entry_get_index (const match_set_entry_t * mse)
{
  return (mse - match_set_entry_pool);
}

static void *
match_set_set_heap (const match_set_t * ms)
{
  return (clib_mem_set_heap (ms->ms_heap));
}

i16
match_set_get_l2_offset (vnet_link_t linkt, match_set_tag_flags_t flag)
{
  /*
   * the link layer at which the match is performed
   * hence the layer at which the packet's get_current() will point
   */
  switch (linkt)
    {
    case VNET_LINK_IP4:
    case VNET_LINK_IP6:
    case VNET_LINK_ARP:
      /* the rule applie to ip4 over ethernet packets
       * rewind to the ehternet header  */
      if (flag == MATCH_SET_TAG_FLAG_0_TAG)
	return -((i16) sizeof (ethernet_header_t));
      if (flag == MATCH_SET_TAG_FLAG_1_TAG)
	return -((i16) (sizeof (ethernet_header_t) +
			sizeof (ethernet_vlan_header_t)));
      if (flag == MATCH_SET_TAG_FLAG_2_TAG)
	return -((i16) (sizeof (ethernet_header_t) +
			sizeof (ethernet_vlan_header_t) +
			sizeof (ethernet_vlan_header_t)));
      break;
    case VNET_LINK_ETHERNET:
      return (0);
    default:
      ASSERT (0);
    }
  ASSERT (0);
  return (0);
}

/**
 *  determine how many VLAN tags will be present on the interface
 */
match_set_tag_flags_t
match_set_get_itf_tag_flags (u32 sw_if_index)
{
  const vnet_sw_interface_t *si;
  match_set_tag_flags_t flags;

  flags = MATCH_SET_TAG_FLAG_NONE;
  si = vnet_get_sw_interface (vnet_get_main (), sw_if_index);

  if (si->type == VNET_SW_INTERFACE_TYPE_SUB)
    {
      if (si->sub.eth.flags.exact_match)
	{
	  /* If the interface is exact match mode, then it
	   * will only see packets with the specified number
	   * of tags */
	  if (si->sub.eth.flags.no_tags)
	    flags = MATCH_SET_TAG_FLAG_0_TAG;
	  else if (si->sub.eth.flags.one_tag)
	    flags = MATCH_SET_TAG_FLAG_1_TAG;
	  else if (si->sub.eth.flags.two_tags)
	    flags = MATCH_SET_TAG_FLAG_2_TAG;
	  else
	    ASSERT (0);
	}
      else
	{
	  /* If the interface is not exact match, it can get
	   * packets with more than than number of tags specified
	   * (because it is the 'best' match) */
	  if (si->sub.eth.flags.no_tags)
	    flags |= MATCH_SET_TAG_FLAG_0_TAG;
	  if (si->sub.eth.flags.one_tag)
	    flags |= MATCH_SET_TAG_FLAG_1_TAG;
	  if (si->sub.eth.flags.two_tags)
	    flags |= MATCH_SET_TAG_FLAG_2_TAG;
	}
    }
  else
    {
      /* no subinterface means no tags */
      flags = MATCH_SET_TAG_FLAG_0_TAG;
    }

  return (flags);
}

u8 *
format_match_set_pos (u8 * s, va_list * args)
{
  match_set_pos_t *msp = va_arg (*args, match_set_pos_t *);

  s = format (s, "list:%d, rule:%d",
	      msp->msp_list_index, msp->msp_rule_index);

  return (s);
}

u8 *
format_match_set_result (u8 * s, va_list * args)
{
  match_set_result_t *msr = va_arg (*args, match_set_result_t *);

  s = format (s, "[%U], user:%llx",
	      format_match_set_pos, &msr->msr_pos, msr->msr_user_ctx);

  return (s);
}

u8 *
format_match_semantic (u8 * s, va_list * args)
{
  match_semantic_t ms = va_arg (*args, match_semantic_t);

  switch (ms)
    {
    case MATCH_SEMANTIC_ANY:
      return (format (s, "any"));
    case MATCH_SEMANTIC_FIRST:
      return (format (s, "first"));
    }

  return (format (s, "unknown-semantic"));
}

u8 *
format_match_set (u8 * s, va_list * args)
{
  index_t msi = va_arg (*args, index_t);
  match_set_entry_t *mse;
  match_set_t *ms;
  index_t *msei;

  ms = match_set_get (msi);

  s = format (s, "match-set: %v, locks:%d", ms->ms_tag, ms->ms_locks);

  vec_foreach (msei, ms->ms_entries)
  {
    mse = match_set_entry_get (*msei);
    s = format (s, "\n  priority:%d", mse->mse_priority);
    s = format (s, "\n  list:%U", format_match_list, &mse->mse_list, 4);
  }

  match_semantic_t msem;
  vnet_link_t linkt;

  s = format (s, "\n  applications:");

  FOR_EACH_VNET_LINK (linkt)
  {
    for (msem = MATCH_SEMANTIC_ANY; msem < MATCH_N_SEMANTICS; msem++)
      {
	if (0 != ms->ms_apps[msem][linkt].msar_locks)
	  {
	    s = format (s, "\n   %U, %U locks:%d",
			format_vnet_link, linkt,
			format_match_semantic, msem,
			ms->ms_apps[msem][linkt].msar_locks);
	    s =
	      format (s, "\n%U",
		      match_engine_get (msem, ms->ms_type)->mev_format,
		      ms->ms_apps[msem][linkt].msar_app, 4);
	  }
      }
  }

  return (s);
}

index_t
match_set_create_and_lock (const u8 * name, void *heap)
{
  match_set_t *ms;

  pool_get_zero (match_set_pool, ms);

  ms->ms_tag = vec_dup ((u8 *) name);

  match_set_lock (match_set_get_index (ms));

  if (NULL == heap)
    heap = clib_mem_get_heap ();

  ms->ms_heap = heap;

  return (match_set_get_index (ms));
}

void
match_set_lock (index_t msi)
{
  match_set_t *ms;

  ms = match_set_get (msi);

  ms->ms_locks++;
}

static void
match_set_destroy (match_set_t * ms)
{
  match_set_entry_t *mse;
  index_t *msei;
  void *heap;

  heap = match_set_set_heap (ms);

  vec_foreach (msei, ms->ms_entries)
  {
    mse = match_set_entry_get (*msei);
    match_list_free (&mse->mse_list);
  }

  clib_mem_set_heap (heap);

  vec_free (ms->ms_tag);
  pool_put (match_set_pool, ms);
}

void
match_set_unlock (index_t * msi)
{
  match_set_t *ms;

  ms = match_set_get (*msi);

  ms->ms_locks--;

  if (0 == ms->ms_locks)
    {
      match_set_destroy (ms);
    }
  *msi = INDEX_INVALID;
}

/**
 * Update.
 *  for each application of this set, inform the negine that the set has changed.
 */
static void
match_set_update (match_set_t * ms)
{
  match_semantic_t msem;
  vnet_link_t linkt;

  FOR_EACH_VNET_LINK (linkt)
  {
    for (msem = MATCH_SEMANTIC_ANY; msem < MATCH_N_SEMANTICS; msem++)
      {
	if (ms->ms_apps[msem][linkt].msar_locks)
	  {
	    match_engine_get (msem, ms->ms_type)->mev_update
	      (ms, ms->ms_apps[msem][linkt].msar_app,
	       linkt, ms->ms_apps[msem][linkt].msar_flags);
	  }
      }
  }
}

static int
match_set_entry_cmp (void *a1, void *a2)
{
  match_set_entry_t *mse1 = a1, *mse2 = a2;

  return (mse1->mse_priority - mse2->mse_priority);
}

static void
match_set_entry_init (match_set_t * ms,
		      match_set_entry_t * mse,
		      const match_list_t * ml, u16 priority, void *data)
{
  u32 i;

  mse->mse_priority = priority;
  mse->mse_usr_ctxt = data;
  match_list_copy (&mse->mse_list, ml);

  vec_foreach_index (i, mse->mse_list.ml_rules)
    mse->mse_list.ml_rules[i].mr_index = i;
}

void
match_set_list_replace (index_t msi,
			match_handle_t mh,
			const match_list_t * ml, u16 priority, void *data)
{
  match_set_entry_t *mse;
  match_set_t *ms;
  void *heap;

  ms = match_set_get (msi);
  heap = match_set_set_heap (ms);

  mse = pool_elt_at_index (match_set_entry_pool, mh);

  match_set_entry_init (ms, mse, ml, priority, data);

  vec_sort_with_function (ms->ms_entries, match_set_entry_cmp);

  match_set_update (ms);

  clib_mem_set_heap (heap);
}

match_handle_t
match_set_list_add (index_t msi,
		    const match_list_t * ml, u16 priority, void *data)
{
  match_set_entry_t *mse;
  match_set_t *ms;
  void *heap;

  ms = match_set_get (msi);
  heap = match_set_set_heap (ms);

  pool_get_zero (match_set_entry_pool, mse);

  match_set_entry_init (ms, mse, ml, priority, data);

  vec_add1 (ms->ms_entries, match_set_entry_get_index (mse));
  vec_sort_with_function (ms->ms_entries, match_set_entry_cmp);

  match_set_update (ms);

  clib_mem_set_heap (heap);

  return (match_set_entry_get_index (mse));
}

void *
match_set_list_del (index_t msi, match_handle_t * mh)
{
  match_set_entry_t *mse;
  void *heap, *user_ctx;
  match_set_t *ms;

  ms = match_set_get (msi);
  heap = match_set_set_heap (ms);
  mse = match_set_entry_get (*mh);

  user_ctx = mse->mse_usr_ctxt;

  u32 pos = vec_search (ms->ms_entries, *mh);

  if (~0 != pos)
    {
      vec_del1 (ms->ms_entries, pos);
      vec_sort_with_function (ms->ms_entries, match_set_entry_cmp);
      match_set_update (ms);

      pool_put (match_set_entry_pool, mse);
    }

  match_set_update (ms);

  clib_mem_set_heap (heap);

  *mh = MATCH_HANDLE_INVALID;

  return (user_ctx);
}

void
match_set_entry_walk_rules (const match_set_entry_t * mse,
			    match_set_rule_walk_t fn, void *ctx)
{
  const match_rule_t *mr;

  vec_foreach (mr, mse->mse_list.ml_rules)
  {
    if (WALK_STOP == fn (mr, ctx))
      return;
  }
}

void
match_set_walk_entries (const match_set_t * ms,
			match_set_entry_walk_t fn, void *ctx)
{
  const match_set_entry_t *mse;
  u32 index;

  vec_foreach_index (index, ms->ms_entries)
  {
    mse = match_set_entry_get (ms->ms_entries[index]);

    if (WALK_STOP == fn (mse, index, ctx))
      return;
  }
}

typedef struct match_set_hardest_match_ctx_t_
{
  match_type_t type;
} match_set_hardest_match_ctx_t;

static walk_rc_t
match_set_hardest_match_rule (const match_rule_t * mr, void *data)
{
  match_set_hardest_match_ctx_t *ctx = data;

  ctx->type = clib_max (ctx->type, mr->mr_type);

  return (WALK_CONTINUE);
}

static walk_rc_t
match_set_hardest_match_entry (const match_set_entry_t * mse, u32 index,
			       void *data)
{
  match_set_entry_walk_rules (mse, match_set_hardest_match_rule, data);

  return (WALK_CONTINUE);
}

static match_type_t
match_set_hardest_match (const match_set_t * ms)
{
  match_set_hardest_match_ctx_t ctx = {
    .type = MATCH_TYPE_EASIEST,
  };

  match_set_walk_entries (ms, match_set_hardest_match_entry, &ctx);

  return (ctx.type);
}

match_set_app_t
match_set_apply (index_t msi,
		 match_semantic_t sem,
		 vnet_link_t linkt, match_set_tag_flags_t flags)
{
  match_set_app_t app;
  match_set_t *ms;
  void *heap;

  ms = match_set_get (msi);

  if (0 == vec_len (ms->ms_entries))
    return (MATCH_SET_APP_INVALID);
  heap = match_set_set_heap (ms);

  ms->ms_type = match_set_hardest_match (ms);

  if (0 == ms->ms_apps[sem][linkt].msar_locks)
    {
      ms->ms_apps[sem][linkt].msar_app =
	match_engine_get (sem, ms->ms_type)->mev_apply (ms, linkt, flags);
      ms->ms_apps[sem][linkt].msar_flags = flags;
    }

  ASSERT (flags == ms->ms_apps[sem][linkt].msar_flags);
  ms->ms_apps[sem][linkt].msar_locks++;

  app = ms->ms_apps[sem][linkt].msar_app;

  clib_mem_set_heap (heap);

  return (app);
}

void
match_set_unapply (index_t msi, match_set_app_t * msb)
{
  match_semantic_t msem;
  vnet_link_t linkt;
  match_set_t *ms;
  void *heap;

  if (MATCH_SET_APP_INVALID == *msb)
    return;

  ms = match_set_get (msi);
  heap = match_set_set_heap (ms);

  FOR_EACH_VNET_LINK (linkt)
  {
    for (msem = MATCH_SEMANTIC_ANY; msem < MATCH_N_SEMANTICS; msem++)
      {
	if (*msb == ms->ms_apps[msem][linkt].msar_app &&
	    ms->ms_apps[msem][linkt].msar_locks)
	  {
	    ms->ms_apps[msem][linkt].msar_locks--;

	    if (0 == ms->ms_apps[msem][linkt].msar_locks)
	      {
		match_engine_get (msem, ms->ms_type)->mev_unapply
		  (ms, ms->ms_apps[msem][linkt].msar_app);
		ms->ms_apps[msem][linkt].msar_app = MATCH_SET_APP_INVALID;
	      }
	    goto done;
	  }
      }
  }
done:
  *msb = MATCH_SET_APP_INVALID;
  clib_mem_set_heap (heap);
}

static clib_error_t *
match_init (vlib_main_t * vm)
{
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (match_init);
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
