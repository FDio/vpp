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

#include <filter/filter_hook.h>
#include <filter/filter_table.h>
#include <filter/filter_target_terminate.h>

filter_hook_t *filter_hook_pool;
index_t filter_hooks[DPO_PROTO_NUM][FILTER_N_BASE_HOOKS];
dpo_id_t filter_hook_roots[DPO_PROTO_NUM][FILTER_N_BASE_HOOKS];

/* *INDENT-OFF* */
static const char *filter_feature_nodes[DPO_PROTO_NUM][FILTER_N_BASE_HOOKS] = {
  [DPO_PROTO_IP4] = {
    [FILTER_HOOK_INPUT] = "filter-feature-input-ip4",
    [FILTER_HOOK_OUTPUT] = "filter-feature-output-ip4",
  },
  [DPO_PROTO_IP6] = {
    [FILTER_HOOK_INPUT] = "filter-feature-input-ip6",
    [FILTER_HOOK_OUTPUT] = "filter-feature-output-ip6",
  },
};
/* *INDENT-ON* */

static filter_hook_t *
filter_hook_get (index_t fhi)
{
  return (pool_elt_at_index (filter_hook_pool, fhi));
}

static void
filter_hook_stack (filter_hook_type_t fht, const dpo_id_t * dpo)
{
  vlib_node_t *node;

  node = vlib_get_node_by_name (vlib_get_main (),
				(u8 *)
				filter_feature_nodes[dpo->dpoi_proto][fht]);

  if (node)
    dpo_stack_from_node (node->index,
			 &filter_hook_roots[dpo->dpoi_proto][fht], dpo);
}

void
filter_hook_update (dpo_proto_t dproto, filter_hook_type_t fht)
{
  filter_hook_t *fh;
  index_t fhi;

  fhi = filter_hooks[dproto][fht];

  ASSERT (INDEX_INVALID != fhi);

  fh = filter_hook_get (fhi);

  /* get the jump target from the best table's best chain */
  filter_hook_stack (fht, filter_table_jump_dpo_get
		     (filter_list_get_front (fh->fh_tables1), fht));
}

typedef struct filter_hook_upd_ctx_t_
{
  dpo_proto_t dproto;
  filter_hook_type_t fht;
} filter_hook_upd_ctx_t;

static void
filter_hook_update_i (index_t fhi, index_t fti, void *ctx)
{
  filter_hook_upd_ctx_t *uctx = ctx;

  /* get the jump target from the best table's best chain */
  if (INDEX_INVALID == fti)
    filter_hook_stack (uctx->fht,
		       filter_target_terminate_get (uctx->dproto, uctx->fht));
  else
    filter_hook_stack (uctx->fht, filter_table_jump_dpo_get (fti, uctx->fht));
}

static void
filter_hook_update_prev (index_t fhi, index_t fti, index_t next, void *ctx)
{
  filter_hook_upd_ctx_t *uctx = ctx;

  filter_table_update_next (fti, next, uctx->fht);
  filter_hook_stack (uctx->fht, filter_table_jump_dpo_get (fti, uctx->fht));
}

u8 *
format_filter_table_index (u8 * s, va_list * args)
{
  CLIB_UNUSED (int) indent;
  index_t fti;

  fti = va_arg (*args, index_t);
  indent = va_arg (*args, int);

  s = format (s, "%d", fti);

  return (s);
}


static int
filter_hook_table_sort (index_t * fti1, index_t * fti2)
{
  return (filter_table_precedence_get (*fti1) -
	  filter_table_precedence_get (*fti2));
}

const static filter_list_vft_t filter_hook_list_vft = {
  .flv_front = filter_hook_update_i,
  .flv_prev = filter_hook_update_prev,
  .flv_sort = filter_hook_table_sort,
  .flv_format = format_filter_table_index,
};

void
filter_hook_table_add (dpo_proto_t dproto,
		       filter_hook_type_t fht, index_t fti)
{
  filter_hook_t *fh;
  index_t fhi;

  fhi = filter_hooks[dproto][fht];

  if (INDEX_INVALID == fhi)
    {
      pool_get (filter_hook_pool, fh);
      fhi = filter_hooks[dproto][fht] = fh - filter_hook_pool;

      fh->fh_tables1 = filter_list_create (fhi, &filter_hook_list_vft);
    }
  else
    fh = pool_elt_at_index (filter_hook_pool, fhi);

  filter_hook_upd_ctx_t uctx = {
    .dproto = dproto,
    .fht = fht,
  };
  filter_list_insert (fh->fh_tables1, fti, &uctx);
}

void
filter_hook_table_remove (dpo_proto_t dproto,
			  filter_hook_type_t fht, index_t fti)
{
  filter_hook_t *fh;
  index_t fhi;

  fhi = filter_hooks[dproto][fht];

  ASSERT (INDEX_INVALID != fhi);

  fh = pool_elt_at_index (filter_hook_pool, fhi);

  filter_list_remove (fh->fh_tables1, fti, &fht);
}

u8 *
format_filter_hook (u8 * s, va_list * args)
{
  filter_hook_t *fh;
  index_t fhi;
  int indent;

  fhi = va_arg (*args, index_t);
  indent = va_arg (*args, int);

  fh = filter_hook_get (fhi);

  s = format (s, "%U[%d] hook:[%U %U]:",
	      format_white_space, indent,
	      fhi, format_filter_hook_type, fh->fh_hook,
	      format_dpo_proto, fh->fh_proto);
  s = format (s, "%Utables:[", format_white_space, indent + 2);

  s = filter_list_format (s, indent + 2, fh->fh_tables1);
  s = format (s, "]");

  return (s);
}

static clib_error_t *
filter_hook_show (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t fhi;

  vlib_cli_output (vm, "Filter Hooks:");

  /* *INDENT-OFF* */
  pool_foreach_index (fhi, filter_hook_pool,
    ({
      vlib_cli_output (vm, " %U", format_filter_hook, fhi, 2);
    }));
  /* *INDENT-ON* */

  {
    filter_hook_type_t fht;
    dpo_proto_t dproto;

    vlib_cli_output (vm, " Start Nodes:");

    FOR_EACH_DPO_PROTO (dproto)
    {
      FOREACH_FILTER_HOOK_BASE_TYPE (fht)
      {
	if (dpo_id_is_valid (&filter_hook_roots[dproto][fht]))
	  vlib_cli_output (vm, " %U, %U:\n %U",
			   format_dpo_proto, dproto,
			   format_filter_hook_type, fht,
			   format_dpo_id, &filter_hook_roots[dproto][fht], 2);
      }
    }

    return (NULL);
  }
}

/*?
 * show filter hook
 *
 * @cliexpar
 * @cliexstart{filter hook}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_hook_show_node, static) = {
  .path = "show filter hook",
  .short_help = "show filter hook [name]",
  .function = filter_hook_show,
};
/* *INDENT-ON* */

static clib_error_t *
filter_hook_init (vlib_main_t * vm)
{
  filter_hook_type_t fht;
  dpo_proto_t dproto;

  FOR_EACH_DPO_PROTO (dproto)
  {
    FOREACH_FILTER_HOOK_BASE_TYPE (fht)
    {
      filter_hook_stack (fht, filter_target_terminate_get (dproto, fht));

      filter_hooks[dproto][fht] = INDEX_INVALID;
    }
  }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_hook_init) =
{
  .runs_after = VLIB_INITS ("fib_module_init", "filter_target_terminate_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
