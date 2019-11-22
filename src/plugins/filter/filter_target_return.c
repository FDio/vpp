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


#include <filter/filter_target_return.h>
#include <filter/filter_chain.h>
#include <filter/filter_table.h>

filter_target_return_t *filter_target_return_pool;

static dpo_type_t filter_target_return_type;

bool
filter_target_is_return (const dpo_id_t * dpo)
{
  return (dpo->dpoi_type == filter_target_return_type);
}

int
filter_target_return_add_and_lock (dpo_proto_t proto, dpo_id_t * dpo)
{
  filter_target_return_t *ftr;

  pool_get_aligned_zero (filter_target_return_pool, ftr,
			 CLIB_CACHE_LINE_BYTES);

  ftr->ftr_proto = proto;

  dpo_set (dpo, filter_target_return_type,
	   ftr->ftr_proto, ftr - filter_target_return_pool);

  return (0);
}

static void
filter_target_return_lock (dpo_id_t * dpo)
{
  filter_target_return_t *ftr;

  ftr = filter_target_return_get (dpo->dpoi_index);

  ftr->ftr_locks++;
}

static void
filter_target_return_unlock (dpo_id_t * dpo)
{
  filter_target_return_t *ftr;

  ftr = filter_target_return_get (dpo->dpoi_index);

  ftr->ftr_locks--;

  if (0 == ftr->ftr_locks)
    {
      pool_put (filter_target_return_pool, ftr);
    }
}

u8 *
format_filter_target_return (u8 * s, va_list * args)
{
  index_t ftri = va_arg (*args, index_t);
  filter_target_return_t *ftr;
  CLIB_UNUSED (int) indent;

  ftr = filter_target_return_get (ftri);
  indent = va_arg (*args, int);

  s = format (s, "[%d] return:[%U]", ftri, format_dpo_proto, ftr->ftr_proto);

  return (s);
}

void
filter_target_return_walk (filter_target_walk_cb_t cb, void *ctx)
{
  index_t ftri;

  /* *INDENT-OFF* */
  pool_foreach_index (ftri, filter_target_return_pool,
    ({
      cb(ftri, ctx);
    }));
  /* *INDENT-ON* */
}

const static dpo_vft_t filter_target_return_vft = {
  .dv_lock = filter_target_return_lock,
  .dv_unlock = filter_target_return_unlock,
  .dv_format = format_filter_target_return,
};

const static char *const filter_target_return_ip4_nodes[] = {
  "filter-target-return-ip4",
  NULL,
};

const static char *const filter_target_return_ip6_nodes[] = {
  "filter-target-return-ip6",
  NULL,
};

const static char *const *const filter_target_return_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = filter_target_return_ip4_nodes,
  [DPO_PROTO_IP6] = filter_target_return_ip6_nodes,
};

static uword
unformat_filter_target_return (unformat_input_t * input, va_list * args)
{
  dpo_proto_t dproto;
  dpo_id_t *dpo;
  index_t fti;
  u8 *tname;

  dpo = va_arg (args, dpo_id_t *);
  dproto = va_arg (args, int);
  tname = NULL;

  if (unformat (input, "return table %s", &tname))
    ;
  else
    return (0);

  fti = filter_table_find (tname, dproto);

  if (INDEX_INVALID == fti)
    return (0);

  filter_target_return_add_and_lock (dproto, dpo);

  return (1);
}

static filter_target_vft_t ftr_vft = {
  .ftv_unformat = unformat_filter_target_return,
};

static clib_error_t *
filter_target_return_init (vlib_main_t * vm)
{
  filter_target_return_type =
    dpo_register_new_type (&filter_target_return_vft,
			   filter_target_return_nodes);

  filter_target_register (filter_target_return_type, &ftr_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_target_return_init) =
{
    .runs_after = VLIB_INITS("fib_module_init"),
};
/* *INDENT-ON* */

static clib_error_t *
filter_target_return_show (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  filter_target_return_t *ftr;

  vlib_cli_output (vm, "Filter Target Return:");

  /* *INDENT-OFF* */
  pool_foreach (ftr, filter_target_return_pool,
    ({
      vlib_cli_output (vm, " %U",
                       format_filter_target_return,
                       ftr - filter_target_return_pool, 0);

    }));
  /* *INDENT-ON* */

  return (NULL);
}

/*?
 * show filter target return
 *
 * @cliexpar
 * @cliexstart{filter target ip <direction> <IP>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_target_return_show_node, static) = {
  .path = "show filter target return",
  .short_help = "show filter target return [ip|ip6]>",
  .function = filter_target_return_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
