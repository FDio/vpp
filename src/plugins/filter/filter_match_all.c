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

#include <filter/filter_match_all.h>

filter_match_all_t *filter_match_all_pool;

static dpo_type_t filter_match_all_type;

int
filter_match_all_add_and_lock (dpo_proto_t proto, dpo_id_t * dpo)
{
  filter_match_all_t *fma;

  pool_get_aligned_zero (filter_match_all_pool, fma, CLIB_CACHE_LINE_BYTES);

  fma->fma_base.fm_base.dpoi_type = filter_match_all_type;
  fma->fma_base.fm_base.dpoi_proto = proto;

  dpo_set (dpo, filter_match_all_type,
	   fma->fma_base.fm_base.dpoi_proto, fma - filter_match_all_pool);

  return (0);
}

static void
filter_match_all_lock (dpo_id_t * dpo)
{
  filter_match_all_t *fma;

  fma = filter_match_all_get (dpo->dpoi_index);

  fma->fma_locks++;
}

static void
filter_match_all_unlock (dpo_id_t * dpo)
{
  filter_match_all_t *fma;

  fma = filter_match_all_get (dpo->dpoi_index);

  fma->fma_locks--;

  if (0 == fma->fma_locks)
    {
      pool_put (filter_match_all_pool, fma);
    }
}

u8 *
format_filter_match_all (u8 * s, va_list * args)
{
  filter_match_all_t *fma;
  index_t fmai;
  int indent;

  fmai = va_arg (*args, index_t);
  indent = va_arg (*args, int);

  fma = filter_match_all_get (fmai);

  s = format (s, "match:[all]");
  s = format (s, "%U", format_filter_match, &fma->fma_base, indent + 2);

  return (s);
}

const static dpo_vft_t filter_match_all_vft = {
  .dv_lock = filter_match_all_lock,
  .dv_unlock = filter_match_all_unlock,
  .dv_format = format_filter_match_all,
};

const static char *const filter_match_all_ip4_nodes[] = {
  "filter-match-all-ip4",
  NULL,
};

const static char *const filter_match_all_ip6_nodes[] = {
  "filter-match-all-ip6",
  NULL,
};

const static char *const *const filter_match_all_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = filter_match_all_ip4_nodes,
  [DPO_PROTO_IP6] = filter_match_all_ip6_nodes,
};

static filter_match_t *
filter_match_all_get_base (const dpo_id_t * match)
{
  filter_match_all_t *fma;

  fma = filter_match_all_get (match->dpoi_index);

  return (&(fma->fma_base));
}

const static filter_match_vft_t match_vft = {
  .fmv_get_base = filter_match_all_get_base,
};

static clib_error_t *
filter_match_all_init (vlib_main_t * vm)
{
  filter_match_all_type = dpo_register_new_type (&filter_match_all_vft,
						 filter_match_all_nodes);

  filter_match_register (filter_match_all_type, &match_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_match_all_init) =
{
    .runs_after = VLIB_INITS("dpo_module_init"),
};
/* *INDENT-ON* */


static clib_error_t *
filter_match_all_cli (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  dpo_id_t dpo;
  u8 add = 1;
  int rv, dproto;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	add = 1;
      else if (unformat (input, "del"))
	add = 0;
      else if (unformat (input, "%U", unformat_dpo_proto, &dproto))
	;
      else
	break;
    }

  if (add)
    {
      rv = filter_match_all_add_and_lock (dproto, &dpo);

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
 * Configure a filter match all
 *
 * @cliexpar
 * @cliexstart{filter match all}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_match_all_cli_node, static) = {
  .path = "filter match all",
  .short_help = "filter match all",
  .function = filter_match_all_cli,
};
/* *INDENT-ON* */

static clib_error_t *
filter_match_all_show (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t fmai;

  vlib_cli_output (vm, "Filter Match All:");

  /* *INDENT-OFF* */
  pool_foreach_index (fmai, filter_match_all_pool,
    ({
      vlib_cli_output (vm, " %U handle:[%d, %d]",
                       format_filter_match_all, fmai, 0,
                       filter_match_all_type, fmai);
    }));
  /* *INDENT-ON* */

  return (NULL);
}

/*?
 * show filter target drop
 *
 * @cliexpar
 * @cliexstart{filter match all}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_match_all_show_node, static) = {
  .path = "show filter match all",
  .short_help = "show filter match all",
  .function = filter_match_all_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
