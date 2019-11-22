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


#include <filter/filter_target_jump.h>
#include <filter/filter_chain.h>
#include <filter/filter_table.h>
#include <filter/filter_rule.h>

#include <vnet/dpo/drop_dpo.h>

filter_target_jump_t *filter_target_jump_pool;

static dpo_type_t filter_target_jump_dpo_type;
static fib_node_type_t filter_target_jump_node_type;

static index_t
filter_target_jump_get_index (const filter_target_jump_t * ftj)
{
  return (ftj - filter_target_jump_pool);
}

static void
filter_target_jump_stack_i (filter_target_jump_t * ftj)
{
  /* from our chain get the DPO we will jump to */
  dpo_stack (filter_target_jump_dpo_type,
	     ftj->ftj_proto,
	     &ftj->ftj_next, filter_chain_rule_dpo_get (ftj->ftj_chain));

  /*
   * Determine the DPO we'll push onto the stack
   */
  ftj->ftj_hook = filter_chain_get_hook (ftj->ftj_chain);

  if (FILTER_HOOK_IS_BASE (ftj->ftj_hook))
    {
      /* stack on the chain's next chain's jump */
      dpo_stack (filter_target_jump_dpo_type,
		 ftj->ftj_proto,
		 &ftj->ftj_push, filter_chain_push_dpo_get (ftj->ftj_chain));
    }
  else
    {
      /* stack on the rule's next */
      if (INDEX_INVALID != ftj->ftj_rule)
	dpo_stack (filter_target_jump_dpo_type,
		   ftj->ftj_proto,
		   &ftj->ftj_push, filter_rule_dpo_get (ftj->ftj_rule));
      else
	dpo_stack (filter_target_jump_dpo_type,
		   ftj->ftj_proto,
		   &ftj->ftj_push, drop_dpo_get (ftj->ftj_proto));
    }
}

void
filter_target_jump_stack (index_t ftji)
{
  filter_target_jump_t *ftj;

  ftj = filter_target_jump_get (ftji);

  filter_target_jump_stack_i (ftj);
}

static void
filter_target_jump_unstack (filter_target_jump_t * ftj)
{
  dpo_reset (&ftj->ftj_next);
  dpo_reset (&ftj->ftj_push);
}

int
filter_target_jump_add_and_lock (dpo_proto_t proto,
				 index_t fci, dpo_id_t * dpo)
{
  filter_target_jump_t *ftj;

  pool_get_aligned_zero (filter_target_jump_pool, ftj, CLIB_CACHE_LINE_BYTES);

  fib_node_init (&ftj->ftj_node.fn_node, filter_target_jump_node_type);

  ftj->ftj_chain = fci;
  ftj->ftj_rule = INDEX_INVALID;
  ftj->ftj_proto = proto;

  /*
   * become a child of the chain we jump to
   */
  filter_chain_child_add (fci, filter_target_jump_get_index (ftj),
			  &ftj->ftj_node);

  filter_target_jump_stack_i (ftj);

  /* return ourself as the DPO */
  dpo_set (dpo, filter_target_jump_dpo_type,
	   ftj->ftj_proto, ftj - filter_target_jump_pool);

  return (0);
}

static void
filter_target_jump_rule_update (const dpo_id_t * dpo, index_t fri)
{
  filter_target_jump_t *ftj;

  ASSERT (dpo->dpoi_type == filter_target_jump_dpo_type);

  ftj = filter_target_jump_get (dpo->dpoi_index);

  ftj->ftj_rule = fri;

  filter_target_jump_stack_i (ftj);
}

static void
filter_target_jump_lock (dpo_id_t * dpo)
{
  filter_target_jump_t *ftj;

  ftj = filter_target_jump_get (dpo->dpoi_index);

  fib_node_lock (&ftj->ftj_node.fn_node);
}

static void
filter_target_jump_unlock (dpo_id_t * dpo)
{
  filter_target_jump_t *ftj;

  ftj = filter_target_jump_get (dpo->dpoi_index);

  fib_node_unlock (&ftj->ftj_node.fn_node);
}

u8 *
format_filter_target_jump (u8 * s, va_list * args)
{
  index_t ftji = va_arg (*args, index_t);
  filter_target_jump_t *ftj;
  filter_chain_t *fc;
  int indent;

  ftj = filter_target_jump_get (ftji);
  indent = va_arg (*args, int);

  fc = filter_chain_get (ftj->ftj_chain);

  s = format (s, "[%d] jump:[%U rule:%d to:%s]",
	      ftji, format_dpo_proto, ftj->ftj_proto,
	      ftj->ftj_rule, fc->fc_name);
  s = format (s, "\n%U%U",
	      format_white_space, indent + 2,
	      format_dpo_id, &ftj->ftj_next, indent + 4);
  s = format (s, "\n%U%U",
	      format_white_space, indent + 2,
	      format_dpo_id, &ftj->ftj_push, indent + 4);

  return (s);
}

void
filter_target_jump_walk (filter_target_walk_cb_t cb, void *ctx)
{
  index_t ftji;

  /* *INDENT-OFF* */
  pool_foreach_index (ftji, filter_target_jump_pool,
    ({
      cb(ftji, ctx);
    }));
  /* *INDENT-ON* */
}

const static dpo_vft_t filter_target_jump_dpo_vft = {
  .dv_lock = filter_target_jump_lock,
  .dv_unlock = filter_target_jump_unlock,
  .dv_format = format_filter_target_jump,
};

const static char *const filter_target_jump_ip4_nodes[] = {
  "filter-target-jump-ip4",
  NULL,
};

const static char *const filter_target_jump_ip6_nodes[] = {
  "filter-target-jump-ip6",
  NULL,
};

const static char *const *const filter_target_jump_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = filter_target_jump_ip4_nodes,
  [DPO_PROTO_IP6] = filter_target_jump_ip6_nodes,
};

static uword
unformat_filter_target_jump (unformat_input_t * input, va_list * args)
{
  dpo_proto_t dproto;
  u8 *tname, *cname;
  index_t fti, fci;
  dpo_id_t *dpo;

  dpo = va_arg (args, dpo_id_t *);
  dproto = va_arg (args, int);
  cname = tname = NULL;

  if (unformat (input, "jump table %s chain %s", &tname, &cname))
    ;
  else
    return (0);

  fti = filter_table_find (tname, dproto);

  if (INDEX_INVALID == fti)
    return (0);

  fci = filter_table_chain_find (fti, cname);

  if (INDEX_INVALID == fci)
    return (0);

  filter_target_jump_add_and_lock (dproto, fci, dpo);

  return (1);
}

static filter_target_vft_t ftj_vft = {
  .ftv_unformat = unformat_filter_target_jump,
  .ftv_rule_update = filter_target_jump_rule_update,
};

static fib_node_t *
filter_target_jump_get_node (index_t fci)
{
  filter_target_jump_t *fc;

  fc = filter_target_jump_get (fci);

  return (&fc->ftj_node.fn_node);
}

static filter_target_jump_t *
filter_target_jump_from_fib_node (fib_node_t * node)
{
  return ((filter_target_jump_t *) (((char *) node) -
				    STRUCT_OFFSET_OF (filter_target_jump_t,
						      ftj_node)));
}

static void
filter_target_jump_last_lock_gone (fib_node_t * node)
{
  filter_target_jump_t *ftj;

  ftj = filter_target_jump_from_fib_node (node);

  filter_chain_child_remove (ftj->ftj_chain, &ftj->ftj_node);
  filter_target_jump_unstack (ftj);
  dpo_reset (&ftj->ftj_push);
  pool_put (filter_target_jump_pool, ftj);
}

static fib_node_back_walk_rc_t
filter_target_jump_back_walk (fib_node_t * node,
			      fib_node_back_walk_ctx_t * ctx)
{
  filter_target_jump_t *ftj;

  ftj = filter_target_jump_from_fib_node (node);

  filter_target_jump_stack_i (ftj);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/* *INDENT-OFF* */
static fib_node_vft_t ftj_node_vft = {
  .fnv_get = filter_target_jump_get_node,
  .fnv_last_lock = filter_target_jump_last_lock_gone,
  .fnv_back_walk = filter_target_jump_back_walk,
  .fnv_format = format_filter_target_jump,
  .fnv_mem_show = NULL,
};
/* *INDENT-ON* */

static clib_error_t *
filter_target_jump_init (vlib_main_t * vm)
{
  filter_target_jump_dpo_type =
    dpo_register_new_type (&filter_target_jump_dpo_vft,
			   filter_target_jump_nodes);

  filter_target_jump_node_type = fib_node_register_new_type (&ftj_node_vft);

  filter_target_register (filter_target_jump_dpo_type, &ftj_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_target_jump_init) =
{
    .runs_after = VLIB_INITS("fib_module_init"),
};
/* *INDENT-ON* */

static clib_error_t *
filter_target_jump_show (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t ftji;

  vlib_cli_output (vm, "Filter Target Jump:");

  /* *INDENT-OFF* */
  pool_foreach_index (ftji, filter_target_jump_pool,
    ({
      vlib_cli_output (vm, " %U", format_filter_target_jump, ftji, 0);
    }));
  /* *INDENT-ON* */

  return (NULL);
}

/*?
 * show filter target jump
 *
 * @cliexpar
 * @cliexstart{filter target ip <direction> <IP>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_target_jump_show_node, static) = {
  .path = "show filter target jump",
  .short_help = "show filter target jump [ip|ip6]>",
  .function = filter_target_jump_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
