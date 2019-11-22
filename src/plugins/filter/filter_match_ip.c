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


#include <filter/filter_match_ip.h>
#include <vnet/ip/ip.h>

filter_match_ip_t *filter_match_ip_pool;

static dpo_type_t filter_match_ip_type;

int
filter_match_ip_add_and_lock (dpo_proto_t proto,
			      filter_match_dir_t dir,
			      const ip46_address_t * ip, dpo_id_t * dpo)
{
  filter_match_ip_t *fmi;

  pool_get_aligned_zero (filter_match_ip_pool, fmi, CLIB_CACHE_LINE_BYTES);

  fmi->fmi_base.fm_base.dpoi_type = filter_match_ip_type;
  fmi->fmi_base.fm_base.dpoi_proto = proto;

  fmi->fmi_dir = dir;
  fmi->fmi_ip = *ip;

  dpo_set (dpo, filter_match_ip_type,
	   fmi->fmi_base.fm_base.dpoi_proto, fmi - filter_match_ip_pool);

  return (0);
}

static void
filter_match_ip_lock (dpo_id_t * dpo)
{
  filter_match_ip_t *fmi;

  fmi = filter_match_ip_get (dpo->dpoi_index);

  fmi->fmi_locks++;
}

static void
filter_match_ip_unlock (dpo_id_t * dpo)
{
  filter_match_ip_t *fmi;

  fmi = filter_match_ip_get (dpo->dpoi_index);

  fmi->fmi_locks--;

  if (0 == fmi->fmi_locks)
    {
      pool_put (filter_match_ip_pool, fmi);
    }
}

u8 *
format_filter_match_ip (u8 * s, va_list * args)
{
  filter_match_ip_t *fmi;
  index_t fmii;
  int indent;

  fmii = va_arg (*args, index_t);
  indent = va_arg (*args, int);

  fmi = filter_match_ip_get (fmii);

  s = format (s, "[%d] match:[%U ip %U]",
	      fmii, format_filter_match_dir, fmi->fmi_dir,
	      format_ip46_address, &fmi->fmi_ip, IP46_TYPE_ANY);
  s = format (s, "%U", format_filter_match, &fmi->fmi_base, indent + 2);

  return (s);
}

const static dpo_vft_t filter_match_ip_vft = {
  .dv_lock = filter_match_ip_lock,
  .dv_unlock = filter_match_ip_unlock,
  .dv_format = format_filter_match_ip,
};

const static char *const filter_match_ip_ip4_nodes[] = {
  "filter-match-ip-ip4",
  NULL,
};

const static char *const filter_match_ip_ip6_nodes[] = {
  "filter-match-ip-ip6",
  NULL,
};

const static char *const *const filter_match_ip_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = filter_match_ip_ip4_nodes,
  [DPO_PROTO_IP6] = filter_match_ip_ip6_nodes,
};

static filter_match_t *
filter_match_ip_get_base (const dpo_id_t * match)
{
  filter_match_ip_t *fmi;

  fmi = filter_match_ip_get (match->dpoi_index);

  return (&(fmi->fmi_base));
}

static uword
unformat_filter_match_ip (unformat_input_t * input, va_list * args)
{
  ip46_address_t ip = ip46_address_initializer;
  filter_match_dir_t fd;
  dpo_proto_t dproto;
  dpo_id_t *dpo;

  dpo = va_arg (*args, dpo_id_t *);
  dproto = va_arg (args, int);

  if (unformat (input, "%U %U",
		unformat_filter_match_dir, &fd,
		unformat_ip46_address, &ip, IP46_TYPE_ANY))
    ;
  else
    return (0);

  filter_match_ip_add_and_lock (dproto, fd, &ip, dpo);

  return (1);
}

const static filter_match_vft_t match_vft = {
  .fmv_get_base = filter_match_ip_get_base,
  .fmv_unformat = unformat_filter_match_ip,
};

static clib_error_t *
filter_match_ip_init (vlib_main_t * vm)
{
  filter_match_ip_type = dpo_register_new_type (&filter_match_ip_vft,
						filter_match_ip_nodes);

  filter_match_register (filter_match_ip_type, &match_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_match_ip_init) =
{
    .runs_after = VLIB_INITS("dpo_module_init"),
};
/* *INDENT-ON* */



static clib_error_t *
filter_match_ip_show (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t fmii;

  vlib_cli_output (vm, "Filter Match IP:");

  /* *INDENT-OFF* */
  pool_foreach_index (fmii, filter_match_ip_pool,
    ({
      vlib_cli_output (vm, " %U", format_filter_match_ip, fmii, 0);
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
VLIB_CLI_COMMAND (filter_match_ip_show_node, static) = {
  .path = "show filter match ip",
  .short_help = "show filter match ip",
  .function = filter_match_ip_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
