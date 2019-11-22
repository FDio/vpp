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


#include <filter/filter_target_drop.h>
#include <vnet/ip/ip.h>

filter_target_drop_t *filter_target_drop_pool;

static dpo_type_t filter_target_drop_type;

/* there only needs to be one drop target instance per-proto */
static index_t filter_target_drop_db[DPO_PROTO_NUM] = {
  INDEX_INVALID,
};

int
filter_target_drop_add_and_lock (dpo_proto_t proto, dpo_id_t * dpo)
{
  filter_target_drop_t *ftd;
  index_t ftdi;

  ftdi = filter_target_drop_db[proto];

  if (INDEX_INVALID == ftdi)
    {
      pool_get_aligned_zero (filter_target_drop_pool, ftd,
			     CLIB_CACHE_LINE_BYTES);
      ftdi = ftd - filter_target_drop_pool;
      filter_target_drop_db[proto] = ftdi;

      ftd->ftd_proto = proto;
    }
  else
    ftd = pool_elt_at_index (filter_target_drop_pool, ftdi);

  dpo_set (dpo, filter_target_drop_type, ftd->ftd_proto, ftdi);

  return (0);
}

static void
filter_target_drop_lock (dpo_id_t * dpo)
{
  filter_target_drop_t *ftd;

  ftd = filter_target_drop_get (dpo->dpoi_index);

  ftd->ftd_locks++;
}

static void
filter_target_drop_unlock (dpo_id_t * dpo)
{
  filter_target_drop_t *ftd;

  ftd = filter_target_drop_get (dpo->dpoi_index);

  ftd->ftd_locks--;

  if (0 == ftd->ftd_locks)
    {
      filter_target_drop_db[ftd->ftd_proto] = INDEX_INVALID;
      pool_put (filter_target_drop_pool, ftd);
    }
}

u8 *
format_filter_target_drop (u8 * s, va_list * args)
{
  filter_target_drop_t *ftd;
  index_t ftdi;
  CLIB_UNUSED (int) indent;

  ftdi = va_arg (*args, index_t);
  indent = va_arg (*args, int);

  ftd = filter_target_drop_get (ftdi);

  s = format (s, "[%d] drop:[%U]", ftdi, format_dpo_proto, ftd->ftd_proto);

  return (s);
}

const static dpo_vft_t filter_target_drop_vft = {
  .dv_lock = filter_target_drop_lock,
  .dv_unlock = filter_target_drop_unlock,
  .dv_format = format_filter_target_drop,
};

const static char *const filter_target_drop_ip4_nodes[] = {
  "ip4-drop",
  NULL,
};

const static char *const filter_target_drop_ip6_nodes[] = {
  "ip6-drop",
  NULL,
};

const static char *const *const filter_target_drop_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = filter_target_drop_ip4_nodes,
  [DPO_PROTO_IP6] = filter_target_drop_ip6_nodes,
};

static uword
unformat_filter_target_drop (unformat_input_t * input, va_list * args)
{
  dpo_proto_t dproto;
  dpo_id_t *dpo;

  dpo = va_arg (args, dpo_id_t *);
  dproto = va_arg (args, int);

  if (unformat (input, "drop"))
    ;
  else
    return (0);

  filter_target_drop_add_and_lock (dproto, dpo);

  return (1);
}

static filter_target_vft_t ftd_vft = {
  .ftv_unformat = unformat_filter_target_drop,
};

static clib_error_t *
filter_target_drop_init (vlib_main_t * vm)
{
  filter_target_drop_type = dpo_register_new_type (&filter_target_drop_vft,
						   filter_target_drop_nodes);

  filter_target_register (filter_target_drop_type, &ftd_vft);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (filter_target_drop_init) =
{
    .runs_after = VLIB_INITS("fib_module_init"),
};
/* *INDENT-ON* */



static clib_error_t *
filter_target_drop_show (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  index_t ftdi;

  vlib_cli_output (vm, "Filter Target Drop:");

/* *INDENT-OFF* */
  pool_foreach_index (ftdi, filter_target_drop_pool,
    ({
      vlib_cli_output (vm, " %U", format_filter_target_drop, ftdi);
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
VLIB_CLI_COMMAND (filter_target_drop_show_node, static) = {
  .path = "show filter target drop",
  .short_help = "show filter target drop [ip|ip6]>",
  .function = filter_target_drop_show,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
