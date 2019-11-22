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


#include <filter/filter_match_l4.h>
#include <vnet/ip/ip.h>

filter_match_l4_t *filter_match_l4_pool;

static dpo_type_t filter_match_l4_type;

int
filter_match_l4_add_and_lock (dpo_proto_t proto,
			      filter_match_dir_t dir,
			      ip_protocol_t ip_proto,
			      u16 port, dpo_id_t * dpo)
{
  filter_match_l4_t *fml;

  pool_get_aligned_zero (filter_match_l4_pool, fml, CLIB_CACHE_LINE_BYTES);

  fml->fml_base.fm_base.dpoi_type = filter_match_l4_type;
  fml->fml_base.fm_base.dpoi_proto = proto;

  fml->fml_dir = dir;
  fml->fml_port = clib_host_to_net_u16 (port);
  fml->fml_iproto = ip_proto;

  dpo_set (dpo, filter_match_l4_type,
	   fml->fml_base.fm_base.dpoi_proto, fml - filter_match_l4_pool);

  return (0);
}

static void
filter_match_l4_lock (dpo_id_t * dpo)
{
  filter_match_l4_t *fml;

  fml = filter_match_l4_get (dpo->dpoi_index);

  fml->fml_locks++;
}

static void
filter_match_l4_unlock (dpo_id_t * dpo)
{
  filter_match_l4_t *fml;

  fml = filter_match_l4_get (dpo->dpoi_index);

  fml->fml_locks--;

  if (0 == fml->fml_locks)
    {
      pool_put (filter_match_l4_pool, fml);
    }
}

u8 *
format_filter_match_l4 (u8 * s, va_list * args)
{
  filter_match_l4_t *fml;
  index_t fmli;
  int indent;

  fmli = va_arg (*args, index_t);
  indent = va_arg (*args, int);

  fml = filter_match_l4_get (fmli);

  s = format (s, "[%d] match:[%U %U %d]",
	      fmli, format_filter_match_dir, fml->fml_dir,
	      format_ip_protocol, fml->fml_iproto,
	      clib_host_to_net_u16 (fml->fml_port));
  s = format (s, "%U", format_filter_match, &fml->fml_base, indent + 2);

  return (s);
}

const static dpo_vft_t filter_match_l4_vft = {
  .dv_lock = filter_match_l4_lock,
  .dv_unlock = filter_match_l4_unlock,
  .dv_format = format_filter_match_l4,
};

const static char *const filter_match_l4_ip4_nodes[] = {
  "filter-match-ip-ip4",
  NULL,
};

const static char *const filter_match_l4_ip6_nodes[] = {
  "filter-match-ip-ip6",
  NULL,
};

const static char *const *const filter_match_l4_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = filter_match_l4_ip4_nodes,
  [DPO_PROTO_IP6] = filter_match_l4_ip6_nodes,
};

static filter_match_t *
filter_match_l4_get_base (const dpo_id_t * match)
{
  filter_match_l4_t *fml;

  fml = filter_match_l4_get (match->dpoi_index);

  return (&(fml->fml_base));
}

static uword
unformat_filter_match_l4 (unformat_input_t * input, va_list * args)
{
  ip_protocol_t ip_proto;
  filter_match_dir_t fd;
  dpo_proto_t dproto;
  dpo_id_t *dpo;
  int port;

  dpo = va_arg (*args, dpo_id_t *);
  dproto = va_arg (args, int);

  if (unformat (input, "%U %U %d",
		unformat_ip_protocol, &ip_proto,
		unformat_filter_match_dir, &fd, &port))
    ;
  else
    return (0);

  filter_match_l4_add_and_lock (dproto, fd, ip_proto, port, dpo);

  return (0);
}

const static filter_match_vft_t match_vft = {
  .fmv_get_base = filter_match_l4_get_base,
  .fmv_unformat = unformat_filter_match_l4
};

static clib_error_t *
filter_match_l4_init (vlib_main_t * vm)
{
  filter_match_l4_type = dpo_register_new_type (&filter_match_l4_vft,
						filter_match_l4_nodes);

  filter_match_register (filter_match_l4_type, &match_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_match_l4_init) =
{
    .runs_after = VLIB_INITS("dpo_module_init"),
};
/* *INDENT-ON* */


static clib_error_t *
filter_match_l4_show (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t fmli;

  vlib_cli_output (vm, "Filter Match IP:");

  /* *INDENT-OFF* */
  pool_foreach_index (fmli, filter_match_l4_pool,
    ({
      vlib_cli_output (vm, " %U handle:[%d, %d]",
                       format_filter_match_l4, fmli, 0,
                       filter_match_l4_type, fmli);
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
VLIB_CLI_COMMAND (filter_match_l4_show_node, static) = {
  .path = "show filter match l4",
  .short_help = "show filter match l4",
  .function = filter_match_l4_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
