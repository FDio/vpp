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


#include <filter/filter_target_goto.h>
#include <filter/filter_chain.h>
#include <filter/filter_table.h>
#include <filter/filter_rule.h>

#include <vnet/dpo/drop_dpo.h>

filter_target_goto_t *filter_target_goto_pool;

static dpo_type_t filter_target_goto_dpo_type;
static fib_node_type_t filter_target_goto_node_type;

static index_t
filter_target_goto_get_index (const filter_target_goto_t * ftg)
{
  return (ftg - filter_target_goto_pool);
}

static void
filter_target_goto_stack_i (filter_target_goto_t * ftg)
{
  /* from our chain get the DPO we will goto to */
  dpo_stack (filter_target_goto_dpo_type,
	     ftg->ftg_proto,
	     &ftg->ftg_next, filter_chain_rule_dpo_get (ftg->ftg_chain));
}

void
filter_target_goto_stack (index_t ftgi)
{
  filter_target_goto_t *ftg;

  ftg = filter_target_goto_get (ftgi);

  filter_target_goto_stack_i (ftg);
}

static void
filter_target_goto_unstack (filter_target_goto_t * ftg)
{
  dpo_reset (&ftg->ftg_next);
}

int
filter_target_goto_add_and_lock (dpo_proto_t proto,
				 index_t fci, dpo_id_t * dpo)
{
  filter_target_goto_t *ftg;

  pool_get_aligned_zero (filter_target_goto_pool, ftg, CLIB_CACHE_LINE_BYTES);

  fib_node_init (&ftg->ftg_node.fn_node, filter_target_goto_node_type);

  ftg->ftg_chain = fci;
  ftg->ftg_rule = INDEX_INVALID;
  ftg->ftg_proto = proto;

  /*
   * become a child of the chain we goto to
   */
  filter_chain_child_add (fci, filter_target_goto_get_index (ftg),
			  &ftg->ftg_node);

  filter_target_goto_stack_i (ftg);

  /* return ourself as the DPO */
  dpo_set (dpo, filter_target_goto_dpo_type,
	   ftg->ftg_proto, ftg - filter_target_goto_pool);

  return (0);
}

static void
filter_target_goto_rule_update (const dpo_id_t * dpo, index_t fri)
{
  filter_target_goto_t *ftg;

  ASSERT (dpo->dpoi_type == filter_target_goto_dpo_type);

  ftg = filter_target_goto_get (dpo->dpoi_index);

  ftg->ftg_rule = fri;

  filter_target_goto_stack_i (ftg);
}

static void
filter_target_goto_lock (dpo_id_t * dpo)
{
  filter_target_goto_t *ftg;

  ftg = filter_target_goto_get (dpo->dpoi_index);

  fib_node_lock (&ftg->ftg_node.fn_node);
}

static void
filter_target_goto_unlock (dpo_id_t * dpo)
{
  filter_target_goto_t *ftg;

  ftg = filter_target_goto_get (dpo->dpoi_index);

  fib_node_unlock (&ftg->ftg_node.fn_node);
}

u8 *
format_filter_target_goto (u8 * s, va_list * args)
{
  index_t ftgi = va_arg (*args, index_t);
  filter_target_goto_t *ftg;
  filter_chain_t *fc;
  int indent;

  ftg = filter_target_goto_get (ftgi);
  indent = va_arg (*args, int);

  fc = filter_chain_get (ftg->ftg_chain);

  s = format (s, "[%d] goto:[%U rule:%d to:%s]",
	      ftgi, format_dpo_proto, ftg->ftg_proto,
	      ftg->ftg_rule, fc->fc_name);
  s = format (s, "\n%U%U",
	      format_white_space, indent + 2,
	      format_dpo_id, &ftg->ftg_next, indent + 4);

  return (s);
}

void
filter_target_goto_walk (filter_target_walk_cb_t cb, void *ctx)
{
  index_t ftgi;

  /* *INDENT-OFF* */
  pool_foreach_index (ftgi, filter_target_goto_pool,
    ({
      cb(ftgi, ctx);
    }));
  /* *INDENT-ON* */
}

const static dpo_vft_t filter_target_goto_dpo_vft = {
  .dv_lock = filter_target_goto_lock,
  .dv_unlock = filter_target_goto_unlock,
  .dv_format = format_filter_target_goto,
};

const static char *const filter_target_goto_ip4_nodes[] = {
  "filter-target-goto-ip4",
  NULL,
};

const static char *const filter_target_goto_ip6_nodes[] = {
  "filter-target-goto-ip6",
  NULL,
};

const static char *const *const filter_target_goto_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = filter_target_goto_ip4_nodes,
  [DPO_PROTO_IP6] = filter_target_goto_ip6_nodes,
};

static uword
unformat_filter_target_goto (unformat_input_t * input, va_list * args)
{
  dpo_proto_t dproto;
  u8 *tname, *cname;
  index_t fti, fci;
  dpo_id_t *dpo;

  dpo = va_arg (args, dpo_id_t *);
  dproto = va_arg (args, int);
  cname = tname = NULL;

  if (unformat (input, "goto table %s chain %s", &tname, &cname))
    ;
  else
    return (0);

  fti = filter_table_find (tname, dproto);

  if (INDEX_INVALID == fti)
    return (0);

  fci = filter_table_chain_find (fti, cname);

  if (INDEX_INVALID == fci)
    return (0);

  filter_target_goto_add_and_lock (dproto, fci, dpo);

  return (1);
}

static filter_target_vft_t ftg_vft = {
  .ftv_unformat = unformat_filter_target_goto,
  .ftv_rule_update = filter_target_goto_rule_update,
};

static fib_node_t *
filter_target_goto_get_node (index_t fci)
{
  filter_target_goto_t *fc;

  fc = filter_target_goto_get (fci);

  return (&fc->ftg_node.fn_node);
}

static filter_target_goto_t *
filter_target_goto_from_fib_node (fib_node_t * node)
{
  return ((filter_target_goto_t *) (((char *) node) -
				    STRUCT_OFFSET_OF (filter_target_goto_t,
						      ftg_node)));
}

static void
filter_target_goto_last_lock_gone (fib_node_t * node)
{
  filter_target_goto_t *ftg;

  ftg = filter_target_goto_from_fib_node (node);

  filter_chain_child_remove (ftg->ftg_chain, &ftg->ftg_node);
  filter_target_goto_unstack (ftg);
  pool_put (filter_target_goto_pool, ftg);
}

static fib_node_back_walk_rc_t
filter_target_goto_back_walk (fib_node_t * node,
			      fib_node_back_walk_ctx_t * ctx)
{
  filter_target_goto_t *ftg;

  ftg = filter_target_goto_from_fib_node (node);

  filter_target_goto_stack_i (ftg);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/* *INDENT-OFF* */
static fib_node_vft_t ftg_node_vft = {
  .fnv_get = filter_target_goto_get_node,
  .fnv_last_lock = filter_target_goto_last_lock_gone,
  .fnv_back_walk = filter_target_goto_back_walk,
  .fnv_format = format_filter_target_goto,
  .fnv_mem_show = NULL,
};
/* *INDENT-ON* */

static clib_error_t *
filter_target_goto_init (vlib_main_t * vm)
{
  filter_target_goto_dpo_type =
    dpo_register_new_type (&filter_target_goto_dpo_vft,
			   filter_target_goto_nodes);

  filter_target_goto_node_type = fib_node_register_new_type (&ftg_node_vft);

  filter_target_register (filter_target_goto_dpo_type, &ftg_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_target_goto_init) =
{
    .runs_after = VLIB_INITS("fib_module_init"),
};
/* *INDENT-ON* */

static clib_error_t *
filter_target_goto_show (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t ftgi;

  vlib_cli_output (vm, "Filter Target Goto:");

  /* *INDENT-OFF* */
  pool_foreach_index (ftgi, filter_target_goto_pool,
    ({
      vlib_cli_output (vm, " %U", format_filter_target_goto, ftgi, 0);
    }));
  /* *INDENT-ON* */

  return (NULL);
}

/*?
 * show filter target goto
 *
 * @cliexpar
 * @cliexstart{filter target ip <direction> <IP>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_target_goto_show_node, static) = {
  .path = "show filter target goto",
  .short_help = "show filter target goto [ip|ip6]>",
  .function = filter_target_goto_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
