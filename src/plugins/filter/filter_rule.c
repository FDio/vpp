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

#include <filter/filter_rule.h>
#include <filter/filter_table.h>
#include <filter/filter_match.h>
#include <filter/filter_target_jump.h>

/**
 * type for linkage into the object graph
 */
static fib_node_type_t filter_rule_node_type;

/**
 * Pool of filter rules
 */
static filter_rule_t *filter_rule_pool;

/* filter chain packet/byte counters */
vlib_combined_counter_main_t filter_rule_counters = {
  .name = "filter-rule",
  .stat_segment_name = "/net/filter/rule",
};

u32
filter_rule_n_elts (void)
{
  return (pool_elts (filter_rule_pool));
}

filter_rule_t *
filter_rule_get (index_t fri)
{
  return (pool_elt_at_index (filter_rule_pool, fri));
}

void
filter_rule_update (index_t fri,
		    const dpo_id_t * match,
		    const dpo_id_t * target, const dpo_id_t * next)
{
  filter_rule_t *fr;

  fr = filter_rule_get (fri);

  dpo_copy (&fr->fr_match, match);
  dpo_copy (&fr->fr_target, target);
  dpo_copy (&fr->fr_next, next);

  filter_match_stack (&fr->fr_match, fri, &fr->fr_target, &fr->fr_next);
  filter_target_rule_update (&fr->fr_target, fri);
}

void
filter_rule_update_next (index_t fri, const dpo_id_t * next)
{
  filter_rule_t *fr;

  fr = filter_rule_get (fri);

  dpo_copy (&fr->fr_next, next);

  filter_match_stack (&fr->fr_match, fri, &fr->fr_target, &fr->fr_next);
  filter_target_rule_update (&fr->fr_target, fri);
}

index_t
filter_rule_create_and_lock (const u8 * name,
			     const dpo_id_t * match,
			     const dpo_id_t * target, const dpo_id_t * next)
{
  filter_rule_t *fr;
  index_t fri;

  pool_get_zero (filter_rule_pool, fr);

  fib_node_init (&fr->fr_node.fn_node, filter_rule_node_type);
  fib_node_lock (&fr->fr_node.fn_node);

  fr->fr_name = vec_dup ((u8 *) name);

  fri = fr - filter_rule_pool;

  vlib_validate_combined_counter (&filter_rule_counters, fri);
  vlib_zero_combined_counter (&filter_rule_counters, fri);

  filter_rule_update (fri, match, target, next);

  return (fri);
}

void
filter_rule_unlock (index_t fri)
{
  filter_rule_t *fr;

  fr = filter_rule_get (fri);

  fib_node_unlock (&fr->fr_node.fn_node);
}

const dpo_id_t *
filter_rule_dpo_get (index_t fri)
{
  filter_rule_t *fr;

  fr = filter_rule_get (fri);

  return (&fr->fr_match);
}

u8 *
format_filter_rule (u8 * s, va_list * args)
{
  vlib_counter_t count;
  filter_rule_t *fr;
  index_t fri;
  int indent;

  fri = va_arg (*args, index_t);
  indent = va_arg (*args, int);

  fr = filter_rule_get (fri);

  vlib_get_combined_counter (&filter_rule_counters, fri, &count);

  s = format (s, "%U[%d] %s: to:[%Ld:%Ld]",
	      format_white_space, indent,
	      fri, fr->fr_name, count.packets, count.bytes);
  s = format (s, "\n%U%U",
	      format_white_space, indent + 2,
	      format_dpo_id, &fr->fr_match, indent + 4);
  s = format (s, "\n%U%U",
	      format_white_space, indent + 4,
	      format_dpo_id, &fr->fr_target, indent + 6);
  s = format (s, "\n%U%U",
	      format_white_space, indent + 4,
	      format_dpo_id, &fr->fr_next, indent + 6);

  return (s);
}

void
filter_rule_child_add (index_t fri, index_t child_index, filter_node_t * fn)
{
  fn->fn_sibling = fib_node_child_add (filter_rule_node_type,
				       fri, fn->fn_node.fn_type, child_index);
}

void
filter_rule_child_remove (index_t fri, filter_node_t * fn)
{
  fib_node_child_remove (filter_rule_node_type, fri, fn->fn_sibling);
  fn->fn_sibling = ~0;
}

static fib_node_t *
filter_rule_get_node (index_t fri)
{
  filter_rule_t *fr;

  fr = filter_rule_get (fri);

  return (&fr->fr_node.fn_node);
}

static filter_rule_t *
filter_rule_from_fib_node (fib_node_t * node)
{
  return ((filter_rule_t *) (((char *) node) -
			     STRUCT_OFFSET_OF (filter_rule_t, fr_node)));
}

static void
filter_rule_last_lock_gone (fib_node_t * node)
{
  filter_rule_t *fr;

  fr = filter_rule_from_fib_node (node);

  filter_match_unstack (&fr->fr_match);
  filter_target_rule_update (&fr->fr_target, INDEX_INVALID);

  dpo_reset (&fr->fr_match);
  dpo_reset (&fr->fr_target);
  dpo_reset (&fr->fr_next);

  pool_put (filter_rule_pool, fr);
}

static fib_node_back_walk_rc_t
filter_rule_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  ASSERT (0);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/* *INDENT-OFF* */
static fib_node_vft_t fr_vft = {
  .fnv_get = filter_rule_get_node,
  .fnv_last_lock = filter_rule_last_lock_gone,
  .fnv_back_walk = filter_rule_back_walk,
  .fnv_format = format_filter_rule,
  .fnv_mem_show = NULL,
};
/* *INDENT-ON* */

static clib_error_t *
filter_rule_init (vlib_main_t * vm)
{
  filter_rule_node_type = fib_node_register_new_type (&fr_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_rule_init) =
{
    .runs_after = VLIB_INITS("fib_module_init"),
};
/* *INDENT-ON* */


static clib_error_t *
filter_rule_cli (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpo_id_t match_dpo = DPO_INVALID, target_dpo = DPO_INVALID;
  u8 *tname, *cname, *rname, add;
  index_t fti, fri;
  u32 dproto;
  int rv;

  add = 1;
  dproto = DPO_PROTO_NONE;
  cname = tname = rname = NULL;

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
      else if (unformat (line_input, "match %U",
			 unformat_filter_match, &match_dpo, dproto))
	;
      else if (unformat (line_input, "target %U",
			 unformat_filter_target, &target_dpo, dproto))
	;
      else if (unformat (line_input, "table %s", &tname))
	;
      else if (unformat (line_input, "chain %s", &cname))
	;
      else if (unformat (line_input, "%s", &rname))
	;
      else
	break;
    }
  unformat_free (line_input);

  if (DPO_PROTO_NONE == dproto)
    return clib_error_return (0, "specify protocol");
  if (!tname || !cname || !rname)
    return clib_error_return (0, "specify table, chain and rule name");

  fti = filter_table_find (tname, dproto);

  if (INDEX_INVALID == fti)
    return clib_error_return (0, "unknown filter table: %v", tname);

  if (add)
    {
      if (!dpo_id_is_valid (&match_dpo))
	return clib_error_return (0, "specify match DPO");
      if (!dpo_id_is_valid (&target_dpo))
	return clib_error_return (0, "specify target DPO");

      rv = filter_table_rule_append (fti, cname, rname, &match_dpo,
				     &target_dpo, &fri);

      if (rv)
	return clib_error_return (0, "filter rule create failed: %d", rv);
      else
	vlib_cli_output (vm, "%d\n", fri);
    }
  else
    {
      filter_table_rule_delete (fti, cname, rname);
    }

  vec_free (cname);
  vec_free (tname);

  return (NULL);
}

/*?
 * Configure a filter table on IP address
 *
 * @cliexpar
 * @cliexstart{filter rule add table <name> ip <name>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_rule_cli_node, static) = {
  .path = "filter rule",
  .short_help = "filter rule add table <name> chain <name> ip <name>",
  .function = filter_rule_cli,
};
/* *INDENT-ON* */

static clib_error_t *
filter_rule_show (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t fri;

  fri = INDEX_INVALID;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%d", &fri))
	;
    }

  if (INDEX_INVALID == fri)
    {
      vlib_cli_output (vm, "Filter Rules:");

      /* *INDENT-OFF* */
      pool_foreach_index (fri, filter_rule_pool,
        ({
          vlib_cli_output (vm, "%U", format_filter_rule, fri, 2);
        }));
      /* *INDENT-ON* */
    }
  else
    {
      if (!pool_is_free_index (filter_rule_pool, fri))
	vlib_cli_output (vm, "%U", format_filter_rule, fri, 2);
      else
	vlib_cli_output (vm, "no such filter rule");
    }

  return (NULL);
}

/*?
 * show filter rule
 *
 * @cliexpar
 * @cliexstart{filter rule}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_rule_show_node, static) = {
  .path = "show filter rule",
  .short_help = "show filter rule [name]",
  .function = filter_rule_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
