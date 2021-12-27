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

#include <vnet/format_fns.h>
#include <vnet/policer/policer.api_enum.h>
#include <vnet/policer/policer.api_types.h>

#define REPLY_MSG_ID_BASE vnet_policer_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_policer_add_del_t_handler (vl_api_policer_add_del_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_policer_add_del_reply_t *rmp;
  int rv = 0;
  u8 *name = NULL;
  qos_pol_cfg_params_st cfg;
  clib_error_t *error;
  u32 policer_index;

  name = format (0, "%s", mp->name);
  vec_terminate_c_string (name);

  clib_memset (&cfg, 0, sizeof (cfg));
  cfg.rfc = (qos_policer_type_en) mp->type;
  cfg.rnd_type = (qos_round_type_en) mp->round_type;
  cfg.rate_type = (qos_rate_type_en) mp->rate_type;
  cfg.rb.kbps.cir_kbps = ntohl (mp->cir);
  cfg.rb.kbps.eir_kbps = ntohl (mp->eir);
  cfg.rb.kbps.cb_bytes = clib_net_to_host_u64 (mp->cb);
  cfg.rb.kbps.eb_bytes = clib_net_to_host_u64 (mp->eb);
  cfg.conform_action.action_type =
    (qos_action_type_en) mp->conform_action.type;
  cfg.conform_action.dscp = mp->conform_action.dscp;
  cfg.exceed_action.action_type = (qos_action_type_en) mp->exceed_action.type;
  cfg.exceed_action.dscp = mp->exceed_action.dscp;
  cfg.violate_action.action_type =
    (qos_action_type_en) mp->violate_action.type;
  cfg.violate_action.dscp = mp->violate_action.dscp;

  cfg.color_aware = mp->color_aware;

  error = policer_add_del (vm, name, &cfg, &policer_index, mp->is_add);

  if (error)
    {
      rv = VNET_API_ERROR_UNSPECIFIED;
      clib_error_free (error);
    }

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
vl_api_policer_bind_t_handler (vl_api_policer_bind_t *mp)
{
  vl_api_policer_bind_reply_t *rmp;
  u8 *name;
  u32 worker_index;
  u8 bind_enable;
  int rv;

  name = format (0, "%s", mp->name);
  vec_terminate_c_string (name);

  worker_index = ntohl (mp->worker_index);
  bind_enable = mp->bind_enable;

  rv = policer_bind_worker (name, worker_index, bind_enable);
  vec_free (name);
  REPLY_MACRO (VL_API_POLICER_BIND_REPLY);
}

static void
vl_api_policer_input_t_handler (vl_api_policer_input_t *mp)
{
  vl_api_policer_bind_reply_t *rmp;
  u8 *name;
  u32 sw_if_index;
  u8 apply;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  name = format (0, "%s", mp->name);
  vec_terminate_c_string (name);

  sw_if_index = ntohl (mp->sw_if_index);
  apply = mp->apply;

  rv = policer_input (name, sw_if_index, apply);
  vec_free (name);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_POLICER_INPUT_REPLY);
}

static void
send_policer_details (u8 *name, qos_pol_cfg_params_st *config,
		      policer_t *templ, vl_api_registration_t *reg,
		      u32 context)
{
  vl_api_policer_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_POLICER_DETAILS);
  mp->context = context;
  mp->cir = htonl (config->rb.kbps.cir_kbps);
  mp->eir = htonl (config->rb.kbps.eir_kbps);
  mp->cb = clib_host_to_net_u64 (config->rb.kbps.cb_bytes);
  mp->eb = clib_host_to_net_u64 (config->rb.kbps.eb_bytes);
  mp->rate_type = (vl_api_sse2_qos_rate_type_t) config->rate_type;
  mp->round_type = (vl_api_sse2_qos_round_type_t) config->rnd_type;
  mp->type = (vl_api_sse2_qos_policer_type_t) config->rfc;
  mp->conform_action.type =
    (vl_api_sse2_qos_action_type_t) config->conform_action.action_type;
  mp->conform_action.dscp = config->conform_action.dscp;
  mp->exceed_action.type =
    (vl_api_sse2_qos_action_type_t) config->exceed_action.action_type;
  mp->exceed_action.dscp = config->exceed_action.dscp;
  mp->violate_action.type =
    (vl_api_sse2_qos_action_type_t) config->violate_action.action_type;
  mp->violate_action.dscp = config->violate_action.dscp;
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

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_policer_dump_t_handler (vl_api_policer_dump_t * mp)
{
  vl_api_registration_t *reg;
  vnet_policer_main_t *pm = &vnet_policer_main;
  hash_pair_t *hp;
  uword *p;
  u32 pool_index;
  u8 *match_name = 0;
  u8 *name;
  qos_pol_cfg_params_st *config;
  policer_t *templ;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->match_name_valid)
    {
      match_name = format (0, "%s%c", mp->match_name, 0);
      vec_terminate_c_string (match_name);
    }

  if (mp->match_name_valid)
    {
      p = hash_get_mem (pm->policer_config_by_name, match_name);
      if (p)
	{
	  pool_index = p[0];
	  config = pool_elt_at_index (pm->configs, pool_index);
	  templ = pool_elt_at_index (pm->policer_templates, pool_index);
	  send_policer_details (match_name, config, templ, reg, mp->context);
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
        send_policer_details(name, config, templ, reg, mp->context);
      }));
      /* *INDENT-ON* */
    }
}

#include <vnet/policer/policer.api.c>
static clib_error_t *
policer_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

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
