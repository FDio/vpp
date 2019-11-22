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

#include <filter/filter_target_accept.h>
#include <filter/filter_table.h>

filter_target_accept_t *filter_target_accept_pool;

static dpo_type_t filter_target_accept_dpo_type;
static fib_node_type_t filter_target_accept_node_type;

bool
filter_target_is_accept (const dpo_id_t * dpo)
{
  return (dpo->dpoi_type == filter_target_accept_dpo_type);
}

static void
filter_target_accept_stack (filter_target_accept_t * fta)
{
  filter_hook_type_t fht;

  FOREACH_FILTER_HOOK_BASE_TYPE (fht)
  {
    dpo_stack (filter_target_accept_dpo_type,
	       fta->fta_proto,
	       &fta->fta_next[fht],
	       filter_table_push_dpo_get (fta->fta_table, fht));
  }
}

static void
filter_target_accept_unstack (filter_target_accept_t * fta)
{
  filter_hook_type_t fht;

  FOREACH_FILTER_HOOK_BASE_TYPE (fht)
  {
    dpo_reset (&fta->fta_next[fht]);
  }
}

int
filter_target_accept_add_and_lock (index_t fti,
				   dpo_proto_t proto, dpo_id_t * dpo)
{
  filter_target_accept_t *fta;
  index_t ftai;

  pool_get_aligned_zero (filter_target_accept_pool, fta,
			 CLIB_CACHE_LINE_BYTES);
  ftai = fta - filter_target_accept_pool;

  fib_node_init (&fta->fta_node.fn_node, filter_target_accept_node_type);

  fta->fta_table = fti;
  fta->fta_proto = proto;

  /* become a child of the table, so we get updates */
  filter_table_child_add (fta->fta_table, ftai, &fta->fta_node);

  /* then stack on its jump dpo */
  filter_target_accept_stack (fta);

  /* return ourselves as a DPO */
  dpo_set (dpo, filter_target_accept_dpo_type, fta->fta_proto, ftai);

  return (0);
}

static void
filter_target_accept_lock (dpo_id_t * dpo)
{
  filter_target_accept_t *fta;

  fta = filter_target_accept_get (dpo->dpoi_index);

  fib_node_lock (&fta->fta_node.fn_node);
}

static void
filter_target_accept_unlock (dpo_id_t * dpo)
{
  filter_target_accept_t *fta;

  fta = filter_target_accept_get (dpo->dpoi_index);

  fib_node_unlock (&fta->fta_node.fn_node);
}

u8 *
format_filter_target_accept (u8 * s, va_list * args)
{
  filter_target_accept_t *fta;
  CLIB_UNUSED (int) indent;
  index_t fti;

  fti = va_arg (*args, index_t);
  indent = va_arg (*args, int);

  fta = filter_target_accept_get (fti);

  s = format (s, "[%d] accept:[%U]", fti, format_dpo_proto, fta->fta_proto);

  return (s);
}

static uword
unformat_filter_target_accept (unformat_input_t * input, va_list * args)
{
  dpo_proto_t dproto;
  dpo_id_t *dpo;
  index_t fti;
  u8 *tname;

  dpo = va_arg (args, dpo_id_t *);
  dproto = va_arg (args, int);
  tname = NULL;

  if (unformat (input, "accept table %s", &tname))
    ;
  else
    return (0);

  fti = filter_table_find (tname, dproto);

  if (INDEX_INVALID == fti)
    return (0);

  filter_target_accept_add_and_lock (fti, dproto, dpo);

  return (1);
}

static filter_target_vft_t fta_vft = {
  .ftv_unformat = unformat_filter_target_accept,
};

static fib_node_t *
filter_target_accept_get_node (index_t fci)
{
  filter_target_accept_t *fc;

  fc = filter_target_accept_get (fci);

  return (&fc->fta_node.fn_node);
}

static filter_target_accept_t *
filter_target_accept_from_fib_node (fib_node_t * node)
{
  return ((filter_target_accept_t *) (((char *) node) -
				      STRUCT_OFFSET_OF
				      (filter_target_accept_t, fta_node)));
}

static void
filter_target_accept_last_lock_gone (fib_node_t * node)
{
  filter_target_accept_t *fta;

  fta = filter_target_accept_from_fib_node (node);

  filter_table_child_remove (fta->fta_table, &fta->fta_node);
  filter_target_accept_unstack (fta);
  pool_put (filter_target_accept_pool, fta);
}

static fib_node_back_walk_rc_t
filter_target_accept_back_walk (fib_node_t * node,
				fib_node_back_walk_ctx_t * ctx)
{
  filter_target_accept_t *fta;

  fta = filter_target_accept_from_fib_node (node);

  filter_target_accept_stack (fta);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}


/* *INDENT-OFF* */
const static dpo_vft_t filter_target_accept_vft = {
  .dv_lock = filter_target_accept_lock,
  .dv_unlock = filter_target_accept_unlock,
  .dv_format = format_filter_target_accept,
};

const static char *const filter_target_accept_ip4_nodes[] = {
  "filter-target-accept-ip4",
  NULL,
};

const static char *const filter_target_accept_ip6_nodes[] = {
  "filter-target-accept-ip6",
  NULL,
};

static fib_node_vft_t fta_node_vft = {
  .fnv_get = filter_target_accept_get_node,
  .fnv_last_lock = filter_target_accept_last_lock_gone,
  .fnv_back_walk = filter_target_accept_back_walk,
  .fnv_format = format_filter_target_accept,
  .fnv_mem_show = NULL,
};

const static char *const *const filter_target_accept_nodes[DPO_PROTO_NUM] = {
    [DPO_PROTO_IP4] = filter_target_accept_ip4_nodes,
    [DPO_PROTO_IP6] = filter_target_accept_ip6_nodes,
};
/* *INDENT-ON* */

static clib_error_t *
filter_target_accept_init (vlib_main_t * vm)
{
  filter_target_accept_node_type = fib_node_register_new_type (&fta_node_vft);

  filter_target_accept_dpo_type =
    dpo_register_new_type (&filter_target_accept_vft,
			   filter_target_accept_nodes);

  filter_target_register (filter_target_accept_dpo_type, &fta_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_target_accept_init) =
{
    .runs_after = VLIB_INITS("fib_module_init"),
};
/* *INDENT-ON* */


static clib_error_t *
filter_target_accept_show (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  filter_target_accept_t *fta;

  vlib_cli_output (vm, "Filter Target Accept:");

  /* *INDENT-OFF* */
  pool_foreach (fta, filter_target_accept_pool,
    ({
      vlib_cli_output (vm, " %U %U",
                       format_filter_target_accept,
                       fta - filter_target_accept_pool, 0);
    }));
  /* *INDENT-ON* */

  return (NULL);
}

/*?
 * show filter target accept
 *
 * @cliexpar
 * @cliexstart{filter target ip <direction> <IP>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_target_accept_show_node, static) = {
  .path = "show filter target accept",
  .short_help = "show filter target accept [ip|ip6]>",
  .function = filter_target_accept_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
