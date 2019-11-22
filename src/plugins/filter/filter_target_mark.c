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


#include <filter/filter_target_mark.h>
#include <filter/filter_rule.h>
#include <filter/filter_table.h>
#include <vnet/dpo/drop_dpo.h>

filter_target_mark_t *filter_target_mark_pool;

static dpo_type_t filter_target_mark_type;

static void
filter_target_mark_stack (filter_target_mark_t * ftm)
{
  /* stack on the rule's next */
  if (INDEX_INVALID != ftm->ftm_rule)
    dpo_stack (filter_target_mark_type,
	       ftm->ftm_proto,
	       &ftm->ftm_next, filter_rule_dpo_get (ftm->ftm_rule));
  else
    dpo_stack (filter_target_mark_type,
	       ftm->ftm_proto, &ftm->ftm_next, drop_dpo_get (ftm->ftm_proto));
}

int
filter_target_mark_add_and_lock (dpo_proto_t proto,
				 bool xor, u32 mask, u32 bits, dpo_id_t * dpo)
{
  filter_target_mark_t *ftm;

  pool_get_aligned_zero (filter_target_mark_pool, ftm, CLIB_CACHE_LINE_BYTES);

  ftm->ftm_proto = proto;
  ftm->ftm_mask = mask;
  ftm->ftm_bits = bits;
  ftm->ftm_proto = proto;
  ftm->ftm_rule = INDEX_INVALID;

  filter_target_mark_stack (ftm);

  dpo_set (dpo, filter_target_mark_type,
	   ftm->ftm_proto, ftm - filter_target_mark_pool);

  return (0);
}

static void
filter_target_mark_lock (dpo_id_t * dpo)
{
  filter_target_mark_t *ftm;

  ftm = filter_target_mark_get (dpo->dpoi_index);

  ftm->ftm_locks++;
}

static void
filter_target_mark_unlock (dpo_id_t * dpo)
{
  filter_target_mark_t *ftm;

  ftm = filter_target_mark_get (dpo->dpoi_index);

  ftm->ftm_locks--;

  if (0 == ftm->ftm_locks)
    {
      dpo_reset (&ftm->ftm_next);
      pool_put (filter_target_mark_pool, ftm);
    }
}

u8 *
format_filter_target_mark (u8 * s, va_list * args)
{
  index_t ftmi = va_arg (*args, index_t);
  filter_target_mark_t *ftm;
  int indent;

  ftm = filter_target_mark_get (ftmi);
  indent = va_arg (*args, int);

  s = format (s, "[%d] mark:[%U rule:%d]",
	      ftmi, format_dpo_proto, ftm->ftm_proto, ftm->ftm_rule);
  s = format (s, "\n%U%U",
	      format_white_space, indent + 2,
	      format_dpo_id, &ftm->ftm_next, indent + 4);

  return (s);
}

void
filter_target_mark_walk (filter_target_walk_cb_t cb, void *ctx)
{
  index_t ftmi;

  /* *INDENT-OFF* */
  pool_foreach_index (ftmi, filter_target_mark_pool,
    ({
      cb(ftmi, ctx);
    }));
  /* *INDENT-ON* */
}

/* *INDENT-OFF* */
const static dpo_vft_t filter_target_mark_vft = {
  .dv_lock = filter_target_mark_lock,
  .dv_unlock = filter_target_mark_unlock,
  .dv_format = format_filter_target_mark,
};

const static char *const filter_target_mark_ip4_nodes[] = {
  "filter-target-mark-ip4",
  NULL,
};

const static char *const filter_target_mark_ip6_nodes[] = {
  "filter-target-mark-ip6",
  NULL,
};

const static char *const *const filter_target_mark_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = filter_target_mark_ip4_nodes,
  [DPO_PROTO_IP6] = filter_target_mark_ip6_nodes,
};
/* *INDENT-ON* */

static uword
unformat_filter_target_mark (unformat_input_t * input, va_list * args)
{
  dpo_proto_t dproto;
  u32 bits, mask;
  dpo_id_t *dpo;
  u8 xor;

  dpo = va_arg (args, dpo_id_t *);
  dproto = va_arg (args, int);
  mask = 0;
  xor = 0;

  if (unformat (input, "mark %x/%x", &bits, &mask))
    ;
  else if (unformat (input, "mark xor %x/%x", &bits, &mask))
    xor = 1;
  if (unformat (input, "mark %x", &bits, &mask))
    ;
  else if (unformat (input, "mark xor %x/%x", &bits, &mask))
    xor = 1;
  else
    return (0);

  filter_target_mark_add_and_lock (dproto, xor, mask, bits, dpo);

  return (1);
}

static void
filter_target_mark_rule_update (const dpo_id_t * dpo, index_t fri)
{
  filter_target_mark_t *ftm;

  ASSERT (dpo->dpoi_type == filter_target_mark_type);

  ftm = filter_target_mark_get (dpo->dpoi_index);

  ftm->ftm_rule = fri;

  filter_target_mark_stack (ftm);
}

static filter_target_vft_t ftm_vft = {
  .ftv_unformat = unformat_filter_target_mark,
  .ftv_rule_update = filter_target_mark_rule_update,
};

static clib_error_t *
filter_target_mark_init (vlib_main_t * vm)
{
  filter_target_mark_type = dpo_register_new_type (&filter_target_mark_vft,
						   filter_target_mark_nodes);

  filter_target_register (filter_target_mark_type, &ftm_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_target_mark_init) =
{
    .runs_after = VLIB_INITS("fib_module_init"),
};
/* *INDENT-ON* */


static clib_error_t *
filter_target_mark_show (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  filter_target_mark_t *ftm;

  vlib_cli_output (vm, "Filter Target Mark:");

  /* *INDENT-OFF* */
  pool_foreach (ftm, filter_target_mark_pool,
    ({
      vlib_cli_output (vm, " %U", format_filter_target_mark,
                       ftm - filter_target_mark_pool, 0);

    }));
  /* *INDENT-ON* */

  return (NULL);
}

/*?
 * show filter target mark
 *
 * @cliexpar
 * @cliexstart{filter target ip <direction> <IP>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_target_mark_show_node, static) = {
  .path = "show filter target mark",
  .short_help = "show filter target mark [ip|ip6]>",
  .function = filter_target_mark_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
