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

#include <vnet/ethernet/ethernet.h>

match_set_t *match_set_pool;
match_set_entry_t *match_set_entry_pool;

u8 *
format_match_tag_flags (u8 * s, va_list * args)
{
  match_set_tag_flags_t tf = va_arg (*args, match_set_tag_flags_t);

  if (MATCH_SET_TAG_FLAG_NONE == tf)
    s = format (s, "none ");
  if (MATCH_SET_TAG_FLAG_0_TAG & tf)
    s = format (s, "0-tag ");
  if (MATCH_SET_TAG_FLAG_1_TAG & tf)
    s = format (s, "1-tag ");
  if (MATCH_SET_TAG_FLAG_2_TAG & tf)
    s = format (s, "2-tag ");

  return (s);
}

void
match_set_pos_copy (const match_set_pos_t * msp1, match_set_pos_t * msp2)
{
  msp2->msp_list_index = msp1->msp_list_index;
  msp2->msp_rule_index = msp1->msp_rule_index;
}

static index_t
match_set_entry_get_index (const match_set_entry_t * mse)
{
  return (mse - match_set_entry_pool);
}

bool
match_set_index_is_valid (index_t msi)
{
  return (!pool_is_free_index (match_set_pool, msi));
}

static void *
match_set_set_heap (const match_set_t * ms)
{
  ASSERT (ms->ms_heap);
  return (clib_mem_set_heap (ms->ms_heap));
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

bool
match_set_app_is_valid (const match_set_app_t * msa)
{
  return (msa->msa_index != INDEX_INVALID && msa->msa_match != NULL);
}

bool
match_set_app_is_equal (const match_set_app_t * msa1,
			const match_set_app_t * msa2)
{
  return (msa1->msa_index == msa2->msa_index);
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

uword
unformat_match_semantic (unformat_input_t * input, va_list * args)
{
  match_semantic_t *msem = va_arg (*args, match_semantic_t *);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "any"))
	{
	  *msem = MATCH_SEMANTIC_ANY;
	  return (1);
	}
      else if (unformat (input, "first"))
	{
	  *msem = MATCH_SEMANTIC_FIRST;
	  return (1);
	}
      else
	return (0);
    }

  return (0);
}


u8 *
format_match_set (u8 * s, va_list * args)
{
  index_t msi = va_arg (*args, index_t);
  match_set_entry_t *mse;
  match_semantic_t msem;
  match_set_t *ms;
  index_t *msei;

  ms = match_set_get (msi);

  s = format (s, "[%d] match-set: %v, %U %U %U locks:%d",
	      msi, ms->ms_tag,
	      format_match_type, ms->ms_type,
	      format_match_orientation, ms->ms_orientation,
	      format_ethernet_type, ms->ms_eth_type, ms->ms_locks);

  vec_foreach (msei, ms->ms_entries)
  {
    mse = match_set_entry_get (*msei);
    s = format (s, "\n  [%d] priority:%d %U",
		*msei, mse->mse_priority,
		format_match_list, &mse->mse_list, 4);
  }

  s = format (s, "\n  applications:");

  FOR_EACH_MATCH_SEMANTIC (msem)
  {
    match_set_app_ref_t *msar = &ms->ms_apps[msem];

    if (0 != msar->msar_locks)
      {
	s = format (s, "\n   %U %U %U locks:%d",
		    format_match_semantic, msem,
		    format_match_type, ms->ms_type,
		    format_match_orientation, ms->ms_orientation,
		    msar->msar_locks);
	s = format (s, "\n%U",
		    msar->msar_engine->mev_format,
		    msar->msar_app.msa_index, 4);
      }
  }

  return (s);
}

ip_address_family_t
match_set_get_af (index_t msi)
{
  match_set_entry_t *mse;
  match_set_t *ms;

  ms = pool_elt_at_index (match_set_pool, msi);
  mse = pool_elt_at_index (match_set_entry_pool, ms->ms_entries[0]);

  return (match_rule_get_af (&mse->mse_list.ml_rules[0]));
}

u32
match_set_size (const match_set_t * ms)
{
  match_set_entry_t *mse;
  index_t *msei;
  u32 size;

  size = 0;

  vec_foreach (msei, ms->ms_entries)
  {
    mse = match_set_entry_get (*msei);
    size += match_list_length (&mse->mse_list);
  }

  return (size);
}

index_t
match_set_create_and_lock (const u8 * name,
			   match_type_t rtype,
			   match_orientation_t mo,
			   ethernet_type_t etype, void *heap)
{
  match_set_t *ms;

  pool_get_zero (match_set_pool, ms);

  ms->ms_tag = vec_dup ((u8 *) name);
  ms->ms_type = rtype;
  ms->ms_orientation = mo;
  ms->ms_eth_type = etype;

  match_set_lock (match_set_get_index (ms));

  if (NULL == heap)
    heap = clib_mem_get_heap ();

  ASSERT (heap);
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

static const match_engine_vft_t *
match_set_engine_get (const match_set_t * ms, match_semantic_t semantic)
{
  return match_engine_get (semantic, ms->ms_type, match_set_size (ms));
}

/**
 * Update.
 *  for each application of this set, inform the negine that the set has changed.
 */
static void
match_set_update (match_set_t * ms)
{
  match_semantic_t msem;

  FOR_EACH_MATCH_SEMANTIC (msem)
  {
    if (ms->ms_apps[msem].msar_locks)
      {
	const match_engine_vft_t *me;
	match_set_app_ref_t *msar;
	match_set_app_t *msa;

	me = match_set_engine_get (ms, msem);
	msar = &ms->ms_apps[msem];
	msa = &ms->ms_apps[msem].msar_app;

	/*
	 * if th eengine has changed as a result of the update
	 * unapply with the old and apply with the new, else update
	 */
	if (me->mev_apply == msar->msar_engine->mev_apply)
	  msar->msar_engine->mev_update (ms, msa);
	else
	  {
	    msar->msar_engine->mev_unapply (ms, msa);
	    msar->msar_engine = me;
	    msar->msar_engine->mev_apply (ms, msem, msar->msar_flags, msa);
	  }
      }
  }
}

static void
match_set_list_update (match_set_t * ms, index_t msei)
{
  match_semantic_t msem;

  FOR_EACH_MATCH_SEMANTIC (msem)
  {
    if (ms->ms_apps[msem].msar_locks)
      {
	const match_engine_vft_t *me;
	match_set_app_ref_t *msar;
	match_set_app_t *msa;

	me = match_set_engine_get (ms, msem);
	msar = &ms->ms_apps[msem];
	msa = &ms->ms_apps[msem].msar_app;

	/*
	 * if the eengine has changed as a result of the update
	 * unapply with the old and apply with the new, else update
	 */
	if (me->mev_apply == msar->msar_engine->mev_apply)
	  msar->msar_engine->mev_list_update (ms, msei, msa);
	else
	  {
	    msar->msar_engine->mev_unapply (ms, msa);
	    msar->msar_engine = me;
	    msar->msar_engine->mev_apply (ms, msem, msar->msar_flags, msa);
	  }
      }
  }
}

static int
match_set_entry_cmp (void *a1, void *a2)
{
  index_t *i1 = a1, *i2 = a2;
  match_set_entry_t *mse1, *mse2;

  mse1 = pool_elt_at_index (match_set_entry_pool, *i1);
  mse2 = pool_elt_at_index (match_set_entry_pool, *i2);

  return (mse1->mse_priority - mse2->mse_priority);
}

static void
match_set_entry_init (match_set_t * ms,
		      match_set_entry_t * mse,
		      const match_list_t * ml, u16 priority)
{
  u32 i;

  mse->mse_priority = priority;

  match_list_copy (&mse->mse_list, ml);

  vec_foreach_index (i, mse->mse_list.ml_rules)
    mse->mse_list.ml_rules[i].mr_index = i;
}

void
match_set_list_replace (index_t msi,
			match_handle_t mh,
			const match_list_t * ml, u16 priority)
{
  match_set_entry_t *mse;
  match_set_t *ms;
  void *heap;

  ms = match_set_get (msi);
  heap = match_set_set_heap (ms);

  mse = pool_elt_at_index (match_set_entry_pool, mh);

  match_set_entry_init (ms, mse, ml, priority);

  vec_sort_with_function (ms->ms_entries, match_set_entry_cmp);

  match_set_list_update (ms, mh);

  clib_mem_set_heap (heap);
}

match_handle_t
match_set_list_add (index_t msi, const match_list_t * ml, u16 priority)
{
  match_set_entry_t *mse;
  match_set_t *ms;
  void *heap;

  ms = match_set_get (msi);
  heap = match_set_set_heap (ms);

  pool_get_zero (match_set_entry_pool, mse);

  match_set_entry_init (ms, mse, ml, priority);

  vec_add1 (ms->ms_entries, match_set_entry_get_index (mse));
  vec_sort_with_function (ms->ms_entries, match_set_entry_cmp);

  match_set_update (ms);

  clib_mem_set_heap (heap);

  return (match_set_entry_get_index (mse));
}

void
match_set_list_del (index_t msi, match_handle_t * mh)
{
  match_set_entry_t *mse;
  match_set_t *ms;
  void *heap;

  ms = match_set_get (msi);
  heap = match_set_set_heap (ms);
  mse = match_set_entry_get (*mh);

  u32 pos = vec_search (ms->ms_entries, *mh);

  if (~0 != pos)
    {
      vec_del1 (ms->ms_entries, pos);
      vec_sort_with_function (ms->ms_entries, match_set_entry_cmp);
      match_set_update (ms);

      pool_put (match_set_entry_pool, mse);
    }

  clib_mem_set_heap (heap);

  *mh = MATCH_HANDLE_INVALID;
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

void
match_set_apply (index_t msi,
		 match_semantic_t msem,
		 match_set_tag_flags_t flags, match_set_app_t * app)
{
  match_set_app_ref_t *msar;
  match_set_app_t *msa;
  match_set_t *ms;
  void *heap;

  ms = match_set_get (msi);

  heap = match_set_set_heap (ms);

  msar = &ms->ms_apps[msem];

  if (0 == msar->msar_locks)
    {
      msa = &ms->ms_apps[msem].msar_app;
      msar->msar_engine = match_set_engine_get (ms, msem);
      msar->msar_engine->mev_apply (ms, msem, flags, msa);
      msar->msar_flags = flags;
    }

  ASSERT (flags == msar->msar_flags);
  msar->msar_locks++;

  *app = msar->msar_app;

  clib_mem_set_heap (heap);
}

void
match_set_unapply (index_t msi, match_set_app_t * msb)
{
  match_set_app_ref_t *msar;
  match_semantic_t msem;
  match_set_app_t *msa;
  match_set_t *ms;
  void *heap;

  if (!match_set_app_is_valid (msb))
    return;

  ms = match_set_get (msi);
  heap = match_set_set_heap (ms);

  FOR_EACH_MATCH_SEMANTIC (msem)
  {
    msar = &ms->ms_apps[msem];
    msa = &msar->msar_app;

    if (match_set_app_is_equal (msb, msa) && msar->msar_locks)
      {
	msar->msar_locks--;

	if (0 == msar->msar_locks)
	  {
	    msar->msar_engine->mev_unapply (ms, msa);
	    *msa = MATCH_SET_APP_INVALID;
	  }
	goto done;
      }
  }
done:
  *msb = MATCH_SET_APP_INVALID;
  clib_mem_set_heap (heap);
}

void
match_sets_walk (match_set_walk_cb_t fn, void *arg)
{
  index_t msi;

  /* *INDENT-OFF* */
  pool_foreach_index(msi, match_set_pool,
  ({
    if (WALK_STOP == fn (msi, arg))
      break;
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
match_set_show (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error;
  index_t msi;

  error = NULL;
  msi = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &msi))
	;
    }

  if (INDEX_INVALID == msi)
    {
      /* *INDENT-OFF* */
      pool_foreach_index (msi, match_set_pool,
      ({
        vlib_cli_output (vm, "%U", format_match_set, msi, 0);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if (match_set_index_is_valid (msi))
	vlib_cli_output (vm, "%U", format_match_set, msi, 0);
      else
	error = clib_error_return (0, "invalid match set:%d", msi);
    }

  return (error);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(match_set_show_cmd) =
{
  .path = "show match set",
  .short_help = "show match set",
  .function = match_set_show,
};
/* *INDENT-ON* */

static clib_error_t *
match_init (vlib_main_t * vm)
{
  return (NULL);
}

VLIB_INIT_FUNCTION (match_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
