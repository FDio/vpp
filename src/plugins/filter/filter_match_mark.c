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


#include <filter/filter_match_mark.h>
#include <vnet/ip/ip.h>

filter_match_mark_t *filter_match_mark_pool;

static dpo_type_t filter_match_mark_type;

int
filter_match_mark_add_and_lock (dpo_proto_t proto,
				u32 bits, u32 mask, dpo_id_t * dpo)
{
  filter_match_mark_t *fmm;

  pool_get_aligned_zero (filter_match_mark_pool, fmm, CLIB_CACHE_LINE_BYTES);

  fmm->fmm_base.fm_base.dpoi_type = filter_match_mark_type;
  fmm->fmm_base.fm_base.dpoi_proto = proto;

  fmm->fmm_mask = mask;
  fmm->fmm_bits = bits;

  dpo_set (dpo, filter_match_mark_type,
	   fmm->fmm_base.fm_base.dpoi_proto, fmm - filter_match_mark_pool);

  return (0);
}

static void
filter_match_mark_lock (dpo_id_t * dpo)
{
  filter_match_mark_t *fmm;

  fmm = filter_match_mark_get (dpo->dpoi_index);

  fmm->fmm_locks++;
}

static void
filter_match_mark_unlock (dpo_id_t * dpo)
{
  filter_match_mark_t *fmm;

  fmm = filter_match_mark_get (dpo->dpoi_index);

  fmm->fmm_locks--;

  if (0 == fmm->fmm_locks)
    {
      pool_put (filter_match_mark_pool, fmm);
    }
}

u8 *
format_filter_match_mark (u8 * s, va_list * args)
{
  filter_match_mark_t *fmm;
  index_t fmmi;
  int indent;

  fmmi = va_arg (*args, index_t);
  indent = va_arg (*args, int);

  fmm = filter_match_mark_get (fmmi);

  s = format (s, "match:[mark 0x%x/0x%x]", fmm->fmm_mask, fmm->fmm_bits);
  s = format (s, "%U", format_filter_match, &fmm->fmm_base, indent + 2);

  return (s);
}

const static dpo_vft_t filter_match_mark_vft = {
  .dv_lock = filter_match_mark_lock,
  .dv_unlock = filter_match_mark_unlock,
  .dv_format = format_filter_match_mark,
};

const static char *const filter_match_mark_ip4_nodes[] = {
  "filter-match-mark-ip4",
  NULL,
};

const static char *const filter_match_mark_ip6_nodes[] = {
  "filter-match-mark-ip6",
  NULL,
};

const static char *const *const filter_match_mark_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = filter_match_mark_ip4_nodes,
  [DPO_PROTO_IP6] = filter_match_mark_ip6_nodes,
};

static filter_match_t *
filter_match_mark_get_base (const dpo_id_t * match)
{
  filter_match_mark_t *fmm;

  fmm = filter_match_mark_get (match->dpoi_index);

  return (&(fmm->fmm_base));
}

const static filter_match_vft_t match_vft = {
  .fmv_get_base = filter_match_mark_get_base,
};

static clib_error_t *
filter_match_mark_init (vlib_main_t * vm)
{
  filter_match_mark_type = dpo_register_new_type (&filter_match_mark_vft,
						  filter_match_mark_nodes);

  filter_match_register (filter_match_mark_type, &match_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_match_mark_init) =
{
    .runs_after = VLIB_INITS("dpo_module_init"),
};
/* *INDENT-ON* */


static clib_error_t *
filter_match_mark_cli (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int rv, dproto;
  u32 bits, mask;
  dpo_id_t dpo;
  u8 add;

  bits = 0;
  add = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	add = 1;
      else if (unformat (input, "del"))
	add = 0;
      else if (unformat (input, "%x/%x", &bits, &mask))
	;
      else if (unformat (input, "%x", &bits))
	mask = 0xffffffff;
      else if (unformat (input, "%U", unformat_dpo_proto, &dproto))
	;
      else
	break;
    }

  if (!bits)
    return clib_error_return (0, "specify bits to mark");

  if (add)
    {
      rv = filter_match_mark_add_and_lock (dproto, mask, bits, &dpo);

      if (rv)
	return clib_error_return (0, "filter match create failed: %d", rv);
      else
	vlib_cli_output (vm, "%U\n", format_dpo_id_handle, &dpo);
    }
  else
    {
      return clib_error_return (0, "TODO");
    }


  return (NULL);
}

/*?
 * Configure a filter match on IP address
 *
 * @cliexpar
 * @cliexstart{filter match ip <direction> <IP>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_match_mark_cli_node, static) = {
  .path = "filter match mark",
  .short_help = "filter match mark <proto> <mask/bits>",
  .function = filter_match_mark_cli,
};
/* *INDENT-ON* */

static clib_error_t *
filter_match_mark_show (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t fmmi;

  vlib_cli_output (vm, "Filter Match Mark:");

  /* *INDENT-OFF* */
  pool_foreach_index (fmmi, filter_match_mark_pool,
    ({
      vlib_cli_output (vm, " %U handle:[%d, %d]",
                       format_filter_match_mark, fmmi, 0,
                       filter_match_mark_type, fmmi);
    }));
  /* *INDENT-ON* */

  return (NULL);
}

/*?
 * show filter target drop
 *
 * @cliexpar
 * @cliexstart{filter target ip <direction> <IP>}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_match_mark_show_node, static) = {
  .path = "show filter match mark",
  .short_help = "show filter match mark",
  .function = filter_match_mark_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
