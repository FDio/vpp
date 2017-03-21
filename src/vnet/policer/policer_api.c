/*
 *------------------------------------------------------------------
 * policer_api.c - policer api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/policer/policer.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                             \
_(POLICER_ADD_DEL, policer_add_del)                     \
_(POLICER_DUMP, policer_dump)

static void
vl_api_policer_add_del_t_handler (vl_api_policer_add_del_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_policer_add_del_reply_t *rmp;
  int rv = 0;
  u8 *name = NULL;
  sse2_qos_pol_cfg_params_st cfg;
  clib_error_t *error;
  u32 policer_index;

  name = format (0, "%s", mp->name);

  memset (&cfg, 0, sizeof (cfg));
  cfg.rfc = mp->type;
  cfg.rnd_type = mp->round_type;
  cfg.rate_type = mp->rate_type;
  cfg.rb.kbps.cir_kbps = mp->cir;
  cfg.rb.kbps.eir_kbps = mp->eir;
  cfg.rb.kbps.cb_bytes = mp->cb;
  cfg.rb.kbps.eb_bytes = mp->eb;
  cfg.conform_action.action_type = mp->conform_action_type;
  cfg.conform_action.dscp = mp->conform_dscp;
  cfg.exceed_action.action_type = mp->exceed_action_type;
  cfg.exceed_action.dscp = mp->exceed_dscp;
  cfg.violate_action.action_type = mp->violate_action_type;
  cfg.violate_action.dscp = mp->violate_dscp;
  cfg.color_aware = mp->color_aware;

  error = policer_add_del (vm, name, &cfg, &policer_index, mp->is_add);

  if (error)
    rv = VNET_API_ERROR_UNSPECIFIED;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_POLICER_ADD_DEL_REPLY,
  ({
    if (rv == 0 &&  mp->is_add)
      rmp->policer_index = ntohl(policer_index);
    else
      rmp->policer_index = ~0;
  }));
  /* *INDENT-ON* */
}

static void
send_policer_details (u8 * name,
		      sse2_qos_pol_cfg_params_st * config,
		      policer_read_response_type_st * templ,
		      unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_policer_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_POLICER_DETAILS);
  mp->context = context;
  mp->cir = htonl (config->rb.kbps.cir_kbps);
  mp->eir = htonl (config->rb.kbps.eir_kbps);
  mp->cb = clib_host_to_net_u64 (config->rb.kbps.cb_bytes);
  mp->eb = clib_host_to_net_u64 (config->rb.kbps.eb_bytes);
  mp->rate_type = config->rate_type;
  mp->round_type = config->rnd_type;
  mp->type = config->rfc;
  mp->conform_action_type = config->conform_action.action_type;
  mp->conform_dscp = config->conform_action.dscp;
  mp->exceed_action_type = config->exceed_action.action_type;
  mp->exceed_dscp = config->exceed_action.dscp;
  mp->violate_action_type = config->violate_action.action_type;
  mp->violate_dscp = config->violate_action.dscp;
  mp->single_rate = templ->single_rate ? 1 : 0;
  mp->color_aware = templ->color_aware ? 1 : 0;
  mp->scale = htonl (templ->scale);
  mp->cir_tokens_per_period = htonl (templ->cir_tokens_per_period);
  mp->pir_tokens_per_period = htonl (templ->pir_tokens_per_period);
  mp->current_limit = htonl (templ->current_limit);
  mp->current_bucket = htonl (templ->current_bucket);
  mp->extended_limit = htonl (templ->extended_limit);
  mp->extended_bucket = htonl (templ->extended_bucket);
  mp->last_update_time = clib_host_to_net_u64 (templ->last_update_time);

  strncpy ((char *) mp->name, (char *) name, ARRAY_LEN (mp->name) - 1);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_policer_dump_t_handler (vl_api_policer_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  vnet_policer_main_t *pm = &vnet_policer_main;
  hash_pair_t *hp;
  uword *p;
  u32 pool_index;
  u8 *match_name = 0;
  u8 *name;
  sse2_qos_pol_cfg_params_st *config;
  policer_read_response_type_st *templ;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  if (mp->match_name_valid)
    {
      match_name = format (0, "%s%c", mp->match_name, 0);
    }

  if (mp->match_name_valid)
    {
      p = hash_get_mem (pm->policer_config_by_name, match_name);
      if (p)
	{
	  pool_index = p[0];
	  config = pool_elt_at_index (pm->configs, pool_index);
	  templ = pool_elt_at_index (pm->policer_templates, pool_index);
	  send_policer_details (match_name, config, templ, q, mp->context);
	}
    }
  else
    {
      /* *INDENT-OFF* */
      hash_foreach_pair (hp, pm->policer_config_by_name,
      ({
        name = (u8 *) hp->key;
        pool_index = hp->value[0];
        config = pool_elt_at_index (pm->configs, pool_index);
        templ = pool_elt_at_index (pm->policer_templates, pool_index);
        send_policer_details(name, config, templ, q, mp->context);
      }));
      /* *INDENT-ON* */
    }
}

/*
 * policer_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_policer;
#undef _
}

static clib_error_t *
policer_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (policer_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
