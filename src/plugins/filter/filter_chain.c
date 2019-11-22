/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <filter/filter_chain.h>
#include <filter/filter_table.h>
#include <filter/filter_rule.h>
#include <filter/filter_target_jump.h>
#include <filter/filter_target_return.h>
#include <filter/filter_target_accept.h>
#include <filter/filter_target_drop.h>

#include <vnet/dpo/drop_dpo.h>
#include <vnet/fib/fib_walk.h>

/**
 * type for linkage into the object graph
 */
static fib_node_type_t filter_chain_node_type;

/* filter chain packet/byte counters */
vlib_combined_counter_main_t filter_chain_counters = {
  .name = "filter-chain",
  .stat_segment_name = "/net/filter/chain",
};

static filter_chain_t *filter_chain_pool;

u32
filter_chain_n_elts (void)
{
  return (pool_elts (filter_chain_pool));
}

filter_chain_t *
filter_chain_get (index_t fci)
{
  return (pool_elt_at_index (filter_chain_pool, fci));
}

static void
filter_chain_update_terminator (filter_chain_t * fc)
{
  /*
   * setup the chain's terminator based on policy
   */
  switch (fc->fc_policy)
    {
    case FILTER_CHAIN_POLICY_RETURN:
      filter_target_return_add_and_lock (fc->fc_proto, &fc->fc_terminator);
      break;
    case FILTER_CHAIN_POLICY_ACCEPT:
      if (INDEX_INVALID == fc->fc_next)
	/* last chain does accept */
	filter_target_accept_add_and_lock (fc->fc_table,
					   fc->fc_proto, &fc->fc_terminator);
      else
	filter_target_return_add_and_lock (fc->fc_proto, &fc->fc_terminator);
      break;
    case FILTER_CHAIN_POLICY_DROP:
      filter_target_drop_add_and_lock (fc->fc_proto, &fc->fc_terminator);
      break;
    }
}

/*
 * invokded when the prev's next rule is updated
 */
static void
filter_chain_update_prev (index_t fci, index_t prev, index_t next, void *ctx)
{
  const dpo_id_t *match = ctx;

  filter_rule_update_next (prev, match);
}

/*
 * invoked when the first rule in the chain is changed
 */
static void
filter_chain_update_front (index_t fci, index_t front, void *ctx)
{
  /* just update/added the first rule, restack any targets that point at us */
  fib_node_back_walk_ctx_t bw_ctx = {
    .fnbw_reason = FIB_NODE_BW_REASON_FLAG_RESOLVE,
  };

  fib_walk_sync (filter_chain_node_type, fci, &bw_ctx);
}

static void
filter_chain_update_back (index_t fci, index_t back, void *ctx)
{
  filter_chain_t *fc;

  if (INDEX_INVALID != back)
    {
      fc = filter_chain_get (fci);

      filter_rule_update_next (back, &fc->fc_terminator);
    }
  /* else, last rule removed */
}

const static filter_list_vft_t filter_chain_list_vft = {
  .flv_front = filter_chain_update_front,
  .flv_back = filter_chain_update_back,
  .flv_prev = filter_chain_update_prev,
  .flv_sort = NULL,
  .flv_format = format_filter_rule,
};

index_t
filter_chain_create_and_lock (index_t fti,
			      const u8 * name,
			      dpo_proto_t dproto,
			      filter_hook_type_t fht,
			      filter_chain_policy_t fcp, u32 precedence)
{
  filter_chain_t *fc;
  index_t fci;

  pool_get_zero (filter_chain_pool, fc);

  fci = fc - filter_chain_pool;

  fib_node_init (&fc->fc_node.fn_node, filter_chain_node_type);
  fib_node_lock (&fc->fc_node.fn_node);

  fc->fc_proto = dproto;
  fc->fc_name = vec_dup ((u8 *) name);
  fc->fc_precedence = precedence;
  fc->fc_hook = fht;
  fc->fc_policy = fcp;
  fc->fc_table = fti;
  fc->fc_next = INDEX_INVALID;
  fc->fc_db = hash_create_string (0, sizeof (index_t));
  fc->fc_rules = filter_list_create (fci, &filter_chain_list_vft);

  vlib_validate_combined_counter (&filter_chain_counters, fci);
  vlib_zero_combined_counter (&filter_chain_counters, fci);

  filter_chain_update_terminator (fc);

  /*
   * Then create a jump that jumps to this chain
   */
  filter_target_jump_add_and_lock (fc->fc_proto,
				   fc - filter_chain_pool, &fc->fc_jump);

  return (fci);
}

void
filter_chain_delete (index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  dpo_reset (&fc->fc_jump);

  fib_node_unlock (&fc->fc_node.fn_node);
}

static void
filter_chain_unlock (index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  fib_node_unlock (&fc->fc_node.fn_node);
}

static void
filter_chain_lock (index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  fib_node_lock (&fc->fc_node.fn_node);
}

void
filter_chain_update_next_chain (index_t fci, index_t fci_next)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  if (INDEX_INVALID != fc->fc_next)
    filter_chain_unlock (fc->fc_next);
  if (INDEX_INVALID != fci_next)
    filter_chain_lock (fci_next);

  fc->fc_next = fci_next;

  filter_chain_update_terminator (fc);
  filter_target_jump_stack (fc->fc_jump.dpoi_index);
}

u32
filter_chain_precedence_get (index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  return (fc->fc_precedence);
}

filter_hook_type_t
filter_chain_hook_type_get (index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  return (fc->fc_hook);
}

u8 *
format_filter_chain (u8 * s, va_list * args)
{
  vlib_counter_t count;
  filter_chain_t *fc;
  index_t fci;
  int indent;

  fci = va_arg (*args, index_t);
  indent = va_arg (*args, int);

  fc = filter_chain_get (fci);

  vlib_get_combined_counter (&filter_chain_counters, fci, &count);

  s = format (s, "%U[%d] %s: hook:%U precedence:%d to:[%Ld:%Ld]",
	      format_white_space, indent,
	      fci, fc->fc_name,
	      format_filter_hook_type, fc->fc_hook,
	      fc->fc_precedence, count.packets, count.bytes);

  s = filter_list_format (s, indent + 2, fc->fc_rules);

  s = format (s, "\n%Uend:%U",
	      format_white_space, indent,
	      format_dpo_id, &fc->fc_terminator, indent + 2);

  return (s);
}

filter_hook_type_t
filter_chain_get_hook (index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  return (fc->fc_hook);
}

const dpo_id_t *
filter_chain_push_dpo_get (index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  if (INDEX_INVALID == fc->fc_next)
    {
      return (filter_table_push_dpo_get (fc->fc_table, fc->fc_hook));
    }
  else
    {
      return (filter_chain_jump_dpo_get (fc->fc_next));
    }
}

const dpo_id_t *
filter_chain_rule_dpo_get (index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  /*
   * Return a DPO that a preceeding chain can stack on
   */
  if (0 == filter_list_get_length (fc->fc_rules))
    {
      return (&fc->fc_terminator);
    }
  else
    {
      return filter_rule_dpo_get (filter_list_get_front (fc->fc_rules));
    }
}

const dpo_id_t *
filter_chain_jump_dpo_get (index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  return (&fc->fc_jump);
}

void
filter_chain_jump_dpo_update (index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  filter_target_jump_stack (fc->fc_jump.dpoi_index);
}

static index_t
filter_chain_rule_db_find (filter_chain_t * fc, const u8 * name)
{
  uword *p;

  p = hash_get_mem (fc->fc_db, name);

  if (p)
    return (p[0]);

  return (INDEX_INVALID);
}

index_t
filter_chain_rule_find (index_t fci, const u8 * rule)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  return (filter_chain_rule_db_find (fc, rule));
}

static void
filter_chain_rule_db_insert (filter_chain_t * fc, index_t fri)
{
  filter_rule_t *fr;

  fr = filter_rule_get (fri);

  hash_set_mem (fc->fc_db, fr->fr_name, fri);
}

static void
filter_chain_rule_db_remove (filter_chain_t * fc, index_t fri)
{
  filter_rule_t *fr;

  fr = filter_rule_get (fri);

  hash_unset_mem (fc->fc_db, fr->fr_name);
}

index_t
filter_chain_rule_append (index_t fci,
			  const u8 * name,
			  const dpo_id_t * match, const dpo_id_t * target)
{
  filter_chain_t *fc;
  index_t fri;

  fc = filter_chain_get (fci);
  fri = filter_chain_rule_db_find (fc, name);

  /* we are appending this rule to the end of the chain,
   * so the next DPO is the chain's terminator */
  if (INDEX_INVALID == fri)
    {
      fri = filter_rule_create_and_lock (name, match, target,
					 &fc->fc_terminator);

      /* Add to the back of the chain of rules */
      filter_chain_rule_db_insert (fc, fri);

      filter_list_insert (fc->fc_rules, fri, (void *) match);
    }
  else
    filter_rule_update (fri, match, target, &fc->fc_terminator);

  return (fri);
}

int
filter_chain_rule_delete (index_t fci, const u8 * name)
{
  filter_chain_t *fc;
  index_t fri;

  fc = filter_chain_get (fci);
  fri = filter_chain_rule_db_find (fc, name);

  if (INDEX_INVALID == fri)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  /* remove the rule */
  filter_list_remove (fc->fc_rules, fri, NULL);
  filter_chain_rule_db_remove (fc, fri);
  filter_rule_unlock (fri);

  return (0);
}

void
filter_chain_child_add (index_t fci, index_t child_index, filter_node_t * fn)
{
  fn->fn_sibling = fib_node_child_add (filter_chain_node_type,
				       fci, fn->fn_node.fn_type, child_index);
}

void
filter_chain_child_remove (index_t fci, filter_node_t * fn)
{
  fib_node_child_remove (filter_chain_node_type, fci, fn->fn_sibling);
  fn->fn_sibling = ~0;
}

static fib_node_t *
filter_chain_get_node (index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  return (&fc->fc_node.fn_node);
}

static filter_chain_t *
filter_chain_from_fib_node (fib_node_t * node)
{
  return ((filter_chain_t *) (((char *) node) -
			      STRUCT_OFFSET_OF (filter_chain_t, fc_node)));
}

static void
filter_chain_last_lock_gone (fib_node_t * node)
{
  filter_chain_t *fc;

  fc = filter_chain_from_fib_node (node);

  ASSERT (filter_list_get_length (fc->fc_rules) == 0);

  if (INDEX_INVALID != fc->fc_next)
    filter_chain_unlock (fc->fc_next);
  filter_list_destroy (&fc->fc_rules);
  hash_free (fc->fc_db);
  dpo_reset (&fc->fc_terminator);
  pool_put (filter_chain_pool, fc);
}

static fib_node_back_walk_rc_t
filter_chain_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  ASSERT (0);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/* *INDENT-OFF* */
static fib_node_vft_t fc_vft = {
  .fnv_get = filter_chain_get_node,
  .fnv_last_lock = filter_chain_last_lock_gone,
  .fnv_back_walk = filter_chain_back_walk,
  .fnv_format = format_filter_chain,
  .fnv_mem_show = NULL,
};
/* *INDENT-ON* */

static clib_error_t *
filter_chain_init (vlib_main_t * vm)
{
  filter_chain_node_type = fib_node_register_new_type (&fc_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_chain_init) =
{
    .runs_after = VLIB_INITS("fib_module_init"),
};
/* *INDENT-ON* */



static clib_error_t *
filter_chain_cli (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  filter_chain_policy_t fcp;
  u8 *tname, *cname, add;
  filter_hook_type_t fht;
  u32 dproto, precedence;
  int rv;

  add = 1;
  dproto = DPO_PROTO_NONE;
  fht = FILTER_HOOK_BRANCH;
  cname = tname = NULL;
  precedence = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "%U", unformat_dpo_proto, &dproto))
	;
      else if (unformat (line_input, "%U", unformat_filter_hook_type, &fht))
	;
      else
	if (unformat (line_input, "%U", unformat_filter_chain_policy, &fcp))
	;
      else if (unformat (line_input, "%d", &precedence))
	;
      else if (unformat (line_input, "table %s", &tname))
	;
      else if (unformat (line_input, "%s", &cname))
	;
      else
	break;
    }
  unformat_free (line_input);

  if (DPO_PROTO_NONE == dproto)
    return clib_error_return (0, "specify protocol");

  if (add)
    {
      index_t fti, fci;

      fti = filter_table_find (tname, dproto);

      if (INDEX_INVALID == fti)
	return clib_error_return (0, "unknown filter table: %v", tname);

      if (NULL == cname)
	return clib_error_return (0, "specify chain name:");

      rv = filter_table_chain_add (fti, cname, fht, precedence, fcp, &fci);

      if (rv)
	return clib_error_return (0, "filter chain create failed: %d", rv);
      else
	vlib_cli_output (vm, "%d\n", fci);
    }
  else
    {
      return clib_error_return (0, "TODO");
    }

  vec_free (cname);
  vec_free (tname);

  return (NULL);
}

/*?
 * Configure a filter table on IP address
 *
 * @cliexpar
 * @cliexstart{filter chain add table <name> ip <name>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_chain_cli_node, static) = {
  .path = "filter chain",
  .short_help = "filter chain add table <name> ip <name>",
  .function = filter_chain_cli,
};
/* *INDENT-ON* */

static clib_error_t *
filter_chain_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t fci;

  fci = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &fci))
	;
    }

  if (INDEX_INVALID == fci)
    {
      vlib_cli_output (vm, "Filter Chains:");

      /* *INDENT-OFF* */
      pool_foreach_index (fci, filter_chain_pool,
        ({
          vlib_cli_output (vm, "%U", format_filter_chain, fci, 2);
        }));
      /* *INDENT-ON* */
    }
  else
    {
      if (!pool_is_free_index (filter_chain_pool, fci))
	vlib_cli_output (vm, "%U", format_filter_chain, fci, 2);
      else
	vlib_cli_output (vm, "no such filter chain");
    }

  return (NULL);
}

/*?
 * show filter chain
 *
 * @cliexpar
 * @cliexstart{filter chain}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_chain_show_node, static) = {
  .path = "show filter chain",
  .short_help = "show filter chain [name]",
  .function = filter_chain_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
