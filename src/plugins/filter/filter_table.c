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

#include <filter/filter_table.h>
#include <filter/filter_chain.h>
#include <filter/filter_hook.h>
#include <filter/filter_target_accept.h>
#include <filter/filter_target_jump.h>
#include <filter/filter_target_drop.h>
#include <filter/filter_target_terminate.h>

#include <vnet/dpo/drop_dpo.h>
#include <vnet/fib/fib_walk.h>

static filter_table_t *filter_table_pool;

static uword *filter_table_db[DPO_PROTO_NUM];

/**
 * type for linkage into the object graph
 */
static fib_node_type_t filter_table_node_type;

/**
 * Precedence sorted order vector of tables
 */
static index_t *filter_tables[DPO_PROTO_NUM][FILTER_N_BASE_HOOKS];

u32
filter_table_n_elts (void)
{
  return (pool_elts (filter_table_pool));
}

filter_table_t *
filter_table_get (index_t fti)
{
  return (pool_elt_at_index (filter_table_pool, fti));
}

index_t
filter_table_get_index (filter_table_t * ft)
{
  return (ft - filter_table_pool);
}

index_t
filter_table_find (const u8 * name, dpo_proto_t dproto)
{
  uword *p;

  p = hash_get_mem (filter_table_db[dproto], name);

  if (p)
    return p[0];

  return (INDEX_INVALID);
}

int
filter_table_cmp_for_sort (void *v1, void *v2)
{
  index_t *fti1 = v1, *fti2 = v2;
  filter_table_t *ft1, *ft2;

  ft1 = filter_table_get (*fti1);
  ft2 = filter_table_get (*fti2);

  return (ft1->ft_precedence - ft2->ft_precedence);
}

static void
filter_table_db_insert (filter_table_t * ft)
{
  hash_set_mem (filter_table_db[ft->ft_proto], ft->ft_name,
		ft - filter_table_pool);
}

static void
filter_table_db_remove (filter_table_t * ft)
{
  hash_unset_mem (filter_table_db[ft->ft_proto], ft->ft_name);
}

int
filter_table_delete (const u8 * name, dpo_proto_t dproto)
{
  index_t fti;

  fti = filter_table_find (name, dproto);

  if (INDEX_INVALID == fti)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  return (filter_table_delete_index (fti));
}

int
filter_table_delete_index (index_t fti)
{
  filter_table_t *ft;

  ft = filter_table_get (fti);

  fib_node_unlock (&ft->ft_node.fn_node);

  return (0);
}

/*
 * invokded when the prev's next rule is updated
 */
static void
filter_table_update_prev (index_t fti, index_t prev, index_t next, void *ctx)
{
  filter_chain_update_next_chain (prev, next);
}

/*
 * invoked when the first rule in the table is changed
 */
static void
filter_table_update_front (index_t fti, index_t front, void *ctx)
{
  filter_hook_type_t *fht = ctx;
  filter_table_t *ft;

  if (INDEX_INVALID != front)
    {
      ft = filter_table_get (fti);
      /* poke the hook to restack */
      filter_hook_update (ft->ft_proto, *fht);
    }

  /* just update/added the first rule, restack any targets that point at us */
  fib_node_back_walk_ctx_t bw_ctx = {
    .fnbw_reason = *fht,
  };

  fib_walk_sync (filter_table_node_type, fti, &bw_ctx);
}

static void
filter_table_update_back (index_t fti, index_t back, void *ctx)
{
}

static int
filter_table_chain_sort (index_t * i1, index_t * i2)
{
  return (filter_chain_precedence_get (*i2) -
	  filter_chain_precedence_get (*i1));
}

const static filter_list_vft_t filter_table_list_vft = {
  .flv_front = filter_table_update_front,
  .flv_back = filter_table_update_back,
  .flv_prev = filter_table_update_prev,
  .flv_this = filter_table_update_prev,
  .flv_sort = filter_table_chain_sort,
  .flv_format = format_filter_chain,
};

/**
 * Create or update an filter Table
 *
 * @return error code
 */
int
filter_table_update (const u8 * name,
		     dpo_proto_t dproto, u32 precedence, index_t * fti_out)
{
  filter_hook_type_t fht;
  filter_table_t *ft;
  index_t fti;

  fti = filter_table_find (name, dproto);

  if (INDEX_INVALID == fti)
    {
      pool_get_zero (filter_table_pool, ft);

      fib_node_init (&ft->ft_node.fn_node, filter_table_node_type);
      fib_node_lock (&ft->ft_node.fn_node);
      fti = ft - filter_table_pool;
      ft->ft_name = vec_dup ((u8 *) name);
      ft->ft_precedence = precedence;
      ft->ft_proto = dproto;

      FOREACH_FILTER_HOOK_BASE_TYPE (fht)
      {
	ft->ft_hooks[fht] = filter_list_create (fti, &filter_table_list_vft);
	ft->ft_nexts[fht].ftn_index = INDEX_INVALID;
      }
      ft->ft_db = hash_create_string (0, sizeof (index_t));

      filter_table_db_insert (ft);
    }
  else
    {
      ft = filter_table_get (fti);

      ft->ft_precedence = precedence;

      FOREACH_FILTER_HOOK_BASE_TYPE (fht)
      {
	vec_sort_with_function (filter_tables[ft->ft_proto][fht],
				filter_table_cmp_for_sort);
      }
    }

  *fti_out = fti;

  return (0);
}

u32
filter_table_child_add_i (index_t fti, index_t child_index)
{
  return (fib_node_child_add (filter_table_node_type,
			      fti, filter_table_node_type, child_index));
}

void
filter_table_child_remove_i (index_t fti, u32 sibling)
{
  fib_node_child_remove (filter_table_node_type, fti, sibling);
}

void
filter_table_child_add (index_t fti, index_t child_index, filter_node_t * fn)
{
  fn->fn_sibling = fib_node_child_add (filter_table_node_type,
				       fti, fn->fn_node.fn_type, child_index);
}

void
filter_table_child_remove (index_t fti, filter_node_t * fn)
{
  fib_node_child_remove (filter_table_node_type, fti, fn->fn_sibling);
  fn->fn_sibling = ~0;
}

static void
filter_table_restack_jump (filter_table_t * ft, filter_hook_type_t fht)
{
  index_t fci;

  /* restack the jump dpo of the first chain -
     this is the jump used in the hook */
  fci = filter_list_get_front (ft->ft_hooks[fht]);

  if (INDEX_INVALID != fci)
    filter_chain_jump_dpo_update (fci);
}

void
filter_table_update_next (index_t fti, index_t next, filter_hook_type_t fht)
{
  filter_table_t *ft;

  ft = filter_table_get (fti);

  if (INDEX_INVALID != ft->ft_nexts[fht].ftn_index)
    filter_table_child_remove_i (next, ft->ft_nexts[fht].ftn_sibling);

  ft->ft_nexts[fht].ftn_index = next;

  if (INDEX_INVALID != ft->ft_nexts[fht].ftn_index)
    ft->ft_nexts[fht].ftn_sibling =
      filter_table_child_add_i (ft->ft_nexts[fht].ftn_index, fti);

  filter_table_restack_jump (ft, fht);
}

static index_t
filter_table_chain_db_find (filter_table_t * ft, const u8 * name)
{
  uword *p;

  p = hash_get_mem (ft->ft_db, name);

  if (p)
    return p[0];

  return (INDEX_INVALID);
}

index_t
filter_table_chain_find (index_t fti, const u8 * cname)
{
  return (filter_table_chain_db_find (filter_table_get (fti), cname));
}

static void
filter_table_chain_db_insert (filter_table_t * ft, index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  hash_set_mem (ft->ft_db, fc->fc_name, fci);
}

static void
filter_table_chain_db_remove (filter_table_t * ft, index_t fci)
{
  filter_chain_t *fc;

  fc = filter_chain_get (fci);

  hash_unset_mem (ft->ft_db, fc->fc_name);
}

int
filter_table_chain_add (index_t fti,
			const u8 * name,
			filter_hook_type_t fht,
			filter_chain_policy_t policy,
			u32 precedence, index_t * fci_out)
{
  filter_table_t *ft;
  index_t fci;

  ft = filter_table_get (fti);
  fci = filter_table_chain_db_find (ft, name);

  if (INDEX_INVALID != fci)
    return (VNET_API_ERROR_VALUE_EXIST);

  fci = filter_chain_create_and_lock (fti, name, ft->ft_proto, fht,
				      policy, precedence);

  /*
   * If the chain is rooted from a valid hook insert it in precedence order
   */
  if (FILTER_HOOK_IS_BASE (fht))
    {
      if (0 == filter_list_get_length (ft->ft_hooks[fht]))
	/* first chain at this hook */
	filter_hook_table_add (ft->ft_proto, fht, fti);

      filter_list_insert (ft->ft_hooks[fht], fci, &fht);
    }

  filter_table_chain_db_insert (ft, fci);

  *fci_out = fci;

  return (0);
}

int
filter_table_chain_delete (index_t fti, const u8 * chain)
{
  filter_hook_type_t fht;
  filter_table_t *ft;
  index_t fci;

  ft = filter_table_get (fti);
  fci = filter_table_chain_db_find (ft, chain);

  if (INDEX_INVALID == fci)
    return (VNET_API_ERROR_VALUE_EXIST);

  fht = filter_chain_hook_type_get (fci);

  if (FILTER_HOOK_IS_BASE (fht))
    {
      filter_list_remove (ft->ft_hooks[fht], fci, &fht);
      if (0 == filter_list_get_length (ft->ft_hooks[fht]))
	/* last chain removed at this hook */
	filter_hook_table_remove (ft->ft_proto, fht, fti);
    }
  filter_table_chain_db_remove (ft, fci);
  filter_chain_delete (fci);

  return (0);
}

int
filter_table_rule_append (index_t fti,
			  const u8 * chain,
			  const u8 * rule,
			  const dpo_id_t * match,
			  const dpo_id_t * target, index_t * fri)
{
  filter_table_t *ft;
  index_t fci;

  ft = filter_table_get (fti);
  fci = filter_table_chain_db_find (ft, chain);

  if (INDEX_INVALID == fci)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  *fri = filter_chain_rule_append (fci, rule, match, target);

  return (0);
}

int
filter_table_rule_delete (index_t fti, const u8 * chain, const u8 * rule)
{
  filter_table_t *ft;
  index_t fci;

  ft = filter_table_get (fti);
  fci = filter_table_chain_db_find (ft, chain);

  if (INDEX_INVALID == fci)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  filter_chain_rule_delete (fci, rule);

  return (0);
}

u32
filter_table_precedence_get (index_t fti)
{
  filter_table_t *ft;

  ft = filter_table_get (fti);

  return (ft->ft_precedence);
}

const dpo_id_t *
filter_table_jump_dpo_get (index_t fti, filter_hook_type_t fht)
{
  filter_table_t *ft;
  index_t fci;

  ft = filter_table_get (fti);
  fci = filter_list_get_front (ft->ft_hooks[fht]);

  if (INDEX_INVALID != fci)
    return (filter_chain_jump_dpo_get (fci));
  return (filter_target_terminate_get (ft->ft_proto, fht));
}

const dpo_id_t *
filter_table_push_dpo_get (index_t fti, filter_hook_type_t fht)
{
  filter_table_t *ft;

  ft = filter_table_get (fti);

  if (INDEX_INVALID != ft->ft_nexts[fht].ftn_index)
    return (filter_table_jump_dpo_get (ft->ft_nexts[fht].ftn_index, fht));
  return (filter_target_terminate_get (ft->ft_proto, fht));
}

u8 *
format_filter_table (u8 * s, va_list * args)
{
  filter_table_t *ft;
  index_t fti, fci;
  int indent;
  u8 *name;

  fti = va_arg (*args, index_t);
  indent = va_arg (*args, int);

  ft = filter_table_get (fti);

  s = format (s, "%U[%d] %s: precedence:%d",
	      format_white_space, indent, fti, ft->ft_name,
	      ft->ft_precedence);

  /* *INDENT-OFF* */
  hash_foreach(name, fci, ft->ft_db,
  ({
    s = format (s, "\n%U:", format_filter_chain, fci, indent + 2);
  }));
  /* *INDENT-ON* */

  return (s);
}

static fib_node_t *
filter_table_get_node (index_t fci)
{
  filter_table_t *fc;

  fc = filter_table_get (fci);

  return (&fc->ft_node.fn_node);
}

static filter_table_t *
filter_table_from_fib_node (fib_node_t * node)
{
  return ((filter_table_t *) (((char *) node) -
			      STRUCT_OFFSET_OF (filter_table_t, ft_node)));
}

static void
filter_table_last_lock_gone (fib_node_t * node)
{
  filter_hook_type_t fht;
  filter_table_t *ft;

  ft = filter_table_from_fib_node (node);

  FOREACH_FILTER_HOOK_BASE_TYPE (fht)
    filter_list_destroy (&ft->ft_hooks[fht]);
  hash_free (ft->ft_db);
  filter_table_db_remove (ft);
  pool_put (filter_table_pool, ft);
}

static fib_node_back_walk_rc_t
filter_table_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  filter_table_t *ft;

  ft = filter_table_from_fib_node (node);

  filter_table_restack_jump (ft, ctx->fnbw_reason);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/* *INDENT-OFF* */
static fib_node_vft_t fc_vft = {
  .fnv_get = filter_table_get_node,
  .fnv_last_lock = filter_table_last_lock_gone,
  .fnv_back_walk = filter_table_back_walk,
  .fnv_format = format_filter_table,
  .fnv_mem_show = NULL,
};
/* *INDENT-ON* */

static clib_error_t *
filter_table_init (vlib_main_t * vm)
{
  dpo_proto_t dproto;

  FOR_EACH_DPO_PROTO (dproto)
  {
    filter_table_db[dproto] = hash_create_string (0, sizeof (index_t));
  }
  filter_table_node_type = fib_node_register_new_type (&fc_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_table_init) =
{
    .runs_after = VLIB_INITS("fib_module_init"),
};
/* *INDENT-ON* */


static clib_error_t *
filter_table_cli (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 precedence, dproto;
  u8 *name, add;
  int rv;

  add = 1;
  name = NULL;
  precedence = 1;
  dproto = DPO_PROTO_NONE;

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
      else if (unformat (line_input, "precedence %d", &precedence))
	;
      else if (unformat (line_input, "%s", &name))
	;
      else
	break;
    }
  unformat_free (line_input);

  if (DPO_PROTO_NONE == dproto)
    return clib_error_return (0, "specify protocol");

  if (add)
    {
      index_t fti;

      rv = filter_table_update (name, dproto, precedence, &fti);

      if (rv)
	return clib_error_return (0, "filter table create failed: %d", rv);
      else
	vlib_cli_output (vm, "%d\n", fti);
    }
  else
    {
      return clib_error_return (0, "TODO");
    }

  vec_free (name);

  return (NULL);
}

/*?
 * Configure a filter table
 *
 * @cliexpar
 * @cliexstart{filter table <proto>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_table_cli_node, static) = {
  .path = "filter table",
  .short_help = "filter table <proto>",
  .function = filter_table_cli,
};
/* *INDENT-ON* */

static clib_error_t *
filter_table_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t fti;

  vlib_cli_output (vm, "Filter Tables:");

  /* *INDENT-OFF* */
  pool_foreach_index (fti, filter_table_pool,
    ({
      vlib_cli_output (vm, " %U", format_filter_table, fti, 2);
    }));
  /* *INDENT-ON* */

  return (NULL);
}

/*?
 * show filter table
 *
 * @cliexpar
 * @cliexstart{filter table}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_table_show_node, static) = {
  .path = "show filter table",
  .short_help = "show filter table [name]",
  .function = filter_table_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
