/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <policer/internal.h>
#include <policer/policer_op.h>
#include <policer/ip_punt.h>

#include <vnet/format_fns.h>
#include <policer/policer.api_enum.h>
#include <policer/policer.api_types.h>

#define REPLY_MSG_ID_BASE policer_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_policer_add_del_t_handler (vl_api_policer_add_del_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  policer_main_t *pm = &policer_main;
  vl_api_policer_add_del_reply_t *rmp;
  int rv = 0;
  uword *p;
  char name[sizeof (mp->name) + 1];
  qos_pol_cfg_params_st cfg;
  u32 policer_index;

  snprintf (name, sizeof (name), "%s", mp->name);

  if (mp->is_add)
    {
      clib_memset (&cfg, 0, sizeof (cfg));
      cfg.rfc = (qos_policer_type_en) mp->type;
      cfg.rnd_type = (qos_round_type_en) mp->round_type;
      cfg.rate_type = (qos_rate_type_en) mp->rate_type;
      cfg.rb.kbps.cir_kbps = ntohl (mp->cir);
      cfg.rb.kbps.eir_kbps = ntohl (mp->eir);
      cfg.rb.kbps.cb_bytes = clib_net_to_host_u64 (mp->cb);
      cfg.rb.kbps.eb_bytes = clib_net_to_host_u64 (mp->eb);
      cfg.conform_action.action_type = (qos_action_type_en) mp->conform_action.type;
      cfg.conform_action.dscp = mp->conform_action.dscp;
      cfg.exceed_action.action_type = (qos_action_type_en) mp->exceed_action.type;
      cfg.exceed_action.dscp = mp->exceed_action.dscp;
      cfg.violate_action.action_type = (qos_action_type_en) mp->violate_action.type;
      cfg.violate_action.dscp = mp->violate_action.dscp;
      cfg.color_aware = mp->color_aware;

      rv = policer_add (vm, (u8 *) name, &cfg, &policer_index);
    }
  else
    {
      p = hash_get_mem (pm->policer_index_by_name, name);

      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      if (p != NULL)
	rv = policer_del (vm, p[0]);
    }

  REPLY_MACRO2 (VL_API_POLICER_ADD_DEL_REPLY, ({
		  if (rv == 0 && mp->is_add)
		    rmp->policer_index = htonl (policer_index);
		  else
		    rmp->policer_index = ~0;
		}));
}

static_always_inline void
policer_set_configuration (qos_pol_cfg_params_st *cfg, vl_api_policer_config_t *infos)
{
  clib_memset (cfg, 0, sizeof (*cfg));
  cfg->rfc = (qos_policer_type_en) infos->type;
  cfg->rnd_type = (qos_round_type_en) infos->round_type;
  cfg->rate_type = (qos_rate_type_en) infos->rate_type;
  cfg->rb.kbps.cir_kbps = ntohl (infos->cir);
  cfg->rb.kbps.eir_kbps = ntohl (infos->eir);
  cfg->rb.kbps.cb_bytes = clib_net_to_host_u64 (infos->cb);
  cfg->rb.kbps.eb_bytes = clib_net_to_host_u64 (infos->eb);
  cfg->conform_action.action_type = (qos_action_type_en) infos->conform_action.type;
  cfg->conform_action.dscp = infos->conform_action.dscp;
  cfg->exceed_action.action_type = (qos_action_type_en) infos->exceed_action.type;
  cfg->exceed_action.dscp = infos->exceed_action.dscp;
  cfg->violate_action.action_type = (qos_action_type_en) infos->violate_action.type;
  cfg->violate_action.dscp = infos->violate_action.dscp;
  cfg->color_aware = infos->color_aware;
}

static void
vl_api_policer_add_t_handler (vl_api_policer_add_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_policer_add_reply_t *rmp;
  int rv = 0;
  char name[sizeof (mp->name) + 1];
  qos_pol_cfg_params_st cfg;
  u32 policer_index;

  snprintf (name, sizeof (name), "%s", mp->name);

  policer_set_configuration (&cfg, &mp->infos);

  rv = policer_add (vm, (u8 *) name, &cfg, &policer_index);

  REPLY_MACRO2 (VL_API_POLICER_ADD_REPLY, ({
		  if (rv == 0)
		    rmp->policer_index = htonl (policer_index);
		  else
		    rmp->policer_index = ~0;
		}));
}

static void
vl_api_policer_del_t_handler (vl_api_policer_del_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_policer_del_reply_t *rmp;
  u32 policer_index;
  int rv = 0;

  policer_index = ntohl (mp->policer_index);
  rv = policer_del (vm, policer_index);

  REPLY_MACRO (VL_API_POLICER_DEL_REPLY);
}

static void
vl_api_policer_update_t_handler (vl_api_policer_update_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_policer_update_reply_t *rmp;
  int rv = 0;
  qos_pol_cfg_params_st cfg;
  u32 policer_index;

  policer_set_configuration (&cfg, &mp->infos);

  policer_index = ntohl (mp->policer_index);
  rv = policer_update (vm, policer_index, &cfg);

  REPLY_MACRO (VL_API_POLICER_UPDATE_REPLY);
}

static void
vl_api_policer_reset_t_handler (vl_api_policer_reset_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_policer_reset_reply_t *rmp;
  u32 policer_index;
  int rv = 0;

  policer_index = ntohl (mp->policer_index);
  rv = policer_reset (vm, policer_index);

  REPLY_MACRO (VL_API_POLICER_RESET_REPLY);
}

static void
vl_api_policer_bind_t_handler (vl_api_policer_bind_t *mp)
{
  vl_api_policer_bind_reply_t *rmp;
  policer_main_t *pm = &policer_main;
  char name[sizeof (mp->name) + 1];
  uword *p;
  u32 worker_index;
  u8 bind_enable;
  int rv;

  snprintf (name, sizeof (name), "%s", mp->name);

  worker_index = ntohl (mp->worker_index);
  bind_enable = mp->bind_enable;

  p = hash_get_mem (pm->policer_index_by_name, name);

  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  if (p != NULL)
    rv = policer_bind_worker (p[0], worker_index, bind_enable);

  REPLY_MACRO (VL_API_POLICER_BIND_REPLY);
}

static void
vl_api_policer_bind_v2_t_handler (vl_api_policer_bind_v2_t *mp)
{
  vl_api_policer_bind_v2_reply_t *rmp;
  u32 policer_index;
  u32 worker_index;
  u8 bind_enable;
  int rv;

  policer_index = ntohl (mp->policer_index);
  worker_index = ntohl (mp->worker_index);
  bind_enable = mp->bind_enable;

  rv = policer_bind_worker (policer_index, worker_index, bind_enable);

  REPLY_MACRO (VL_API_POLICER_BIND_V2_REPLY);
}

static void
vl_api_policer_input_t_handler (vl_api_policer_input_t *mp)
{
  vl_api_policer_input_reply_t *rmp;
  policer_main_t *pm = &policer_main;
  char name[sizeof (mp->name) + 1];
  uword *p;
  u32 sw_if_index;
  u8 apply;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  snprintf (name, sizeof (name), "%s", mp->name);

  sw_if_index = ntohl (mp->sw_if_index);
  apply = mp->apply;

  p = hash_get_mem (pm->policer_index_by_name, name);

  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  if (p != NULL)
    rv = policer_input (p[0], sw_if_index, VLIB_RX, apply);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_POLICER_INPUT_REPLY);
}

static void
vl_api_policer_input_v2_t_handler (vl_api_policer_input_v2_t *mp)
{
  vl_api_policer_input_v2_reply_t *rmp;
  u32 policer_index;
  u32 sw_if_index;
  u8 apply;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  policer_index = ntohl (mp->policer_index);
  sw_if_index = ntohl (mp->sw_if_index);
  apply = mp->apply;

  rv = policer_input (policer_index, sw_if_index, VLIB_RX, apply);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_POLICER_INPUT_REPLY);
}

static void
vl_api_policer_output_t_handler (vl_api_policer_output_t *mp)
{
  vl_api_policer_output_reply_t *rmp;
  policer_main_t *pm = &policer_main;
  char name[sizeof (mp->name) + 1];
  uword *p;
  u32 sw_if_index;
  u8 apply;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  snprintf (name, sizeof (name), "%s", mp->name);

  sw_if_index = ntohl (mp->sw_if_index);
  apply = mp->apply;

  p = hash_get_mem (pm->policer_index_by_name, name);

  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  if (p != NULL)
    rv = policer_input (p[0], sw_if_index, VLIB_TX, apply);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_POLICER_OUTPUT_REPLY);
}

static void
vl_api_policer_output_v2_t_handler (vl_api_policer_output_v2_t *mp)
{
  vl_api_policer_output_reply_t *rmp;
  u32 policer_index;
  u32 sw_if_index;
  u8 apply;
  int rv;

  VALIDATE_SW_IF_INDEX (mp);

  policer_index = ntohl (mp->policer_index);
  sw_if_index = ntohl (mp->sw_if_index);
  apply = mp->apply;

  rv = policer_input (policer_index, sw_if_index, VLIB_TX, apply);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_POLICER_OUTPUT_REPLY);
}

static void
send_policer_details (qos_pol_cfg_params_st *config, policer_t *policer, vl_api_registration_t *reg,
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
  mp->conform_action.type = (vl_api_sse2_qos_action_type_t) policer->action[POLICE_CONFORM];
  mp->conform_action.dscp = policer->mark_dscp[POLICE_CONFORM];
  mp->exceed_action.type = (vl_api_sse2_qos_action_type_t) policer->action[POLICE_EXCEED];
  mp->exceed_action.dscp = policer->mark_dscp[POLICE_EXCEED];
  mp->violate_action.type = (vl_api_sse2_qos_action_type_t) policer->action[POLICE_VIOLATE];
  mp->violate_action.dscp = policer->mark_dscp[POLICE_VIOLATE];
  mp->single_rate = policer->single_rate ? 1 : 0;
  mp->color_aware = policer->color_aware ? 1 : 0;
  mp->scale = htonl (policer->scale);
  mp->cir_tokens_per_period = htonl (policer->cir_tokens_per_period);
  mp->pir_tokens_per_period = htonl (policer->pir_tokens_per_period);
  mp->current_limit = htonl (policer->current_limit);
  mp->current_bucket = htonl (policer->current_bucket);
  mp->extended_limit = htonl (policer->extended_limit);
  mp->extended_bucket = htonl (policer->extended_bucket);
  mp->last_update_time = clib_host_to_net_u64 (policer->last_update_time);

  strncpy ((char *) mp->name, (char *) policer->name, ARRAY_LEN (mp->name) - 1);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_policer_dump_t_handler (vl_api_policer_dump_t *mp)
{
  vl_api_registration_t *reg;
  policer_main_t *pm = &policer_main;
  uword *p, *pi;
  u32 pool_index, policer_index;
  u8 *match_name = 0;
  qos_pol_cfg_params_st *config;
  policer_t *policer;

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
      pi = hash_get_mem (pm->policer_index_by_name, match_name);
      if (0 == p || 0 == pi)
	return;

      pool_index = p[0];
      policer_index = pi[0];
      config = pool_elt_at_index (pm->configs, pool_index);
      policer = pool_elt_at_index (pm->policers, policer_index);
      send_policer_details (config, policer, reg, mp->context);
    }
  else
    {
      pool_foreach (policer, pm->policers)
	{
	  p = hash_get_mem (pm->policer_config_by_name, policer->name);
	  if (0 == p)
	    continue;

	  pool_index = p[0];
	  config = pool_elt_at_index (pm->configs, pool_index);
	  send_policer_details (config, policer, reg, mp->context);
	};
    }
}

static void
vl_api_policer_dump_v2_t_handler (vl_api_policer_dump_v2_t *mp)
{
  vl_api_registration_t *reg;
  policer_main_t *pm = &policer_main;
  qos_pol_cfg_params_st *config;
  u32 policer_index, pool_index;
  policer_t *policer;
  uword *p;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  policer_index = ntohl (mp->policer_index);

  if (~0 == policer_index)
    {
      pool_foreach (policer, pm->policers)
	{
	  p = hash_get_mem (pm->policer_config_by_name, policer->name);
	  pool_index = p[0];
	  config = pool_elt_at_index (pm->configs, pool_index);
	  send_policer_details (config, policer, reg, mp->context);
	};
    }
  else
    {
      if (pool_is_free_index (pm->policers, policer_index))
	return;

      policer = &pm->policers[policer_index];
      p = hash_get_mem (pm->policer_config_by_name, policer->name);
      pool_index = p[0];
      config = pool_elt_at_index (pm->configs, pool_index);
      send_policer_details (config, policer, reg, mp->context);
    }
}

static void
vl_api_ip_punt_police_t_handler (vl_api_ip_punt_police_t *mp, vlib_main_t *vm)
{
  vl_api_ip_punt_police_reply_t *rmp;
  int rv = 0;

  if (mp->is_ip6)
    ip6_punt_policer_add_del (mp->is_add, ntohl (mp->policer_index));
  else
    ip4_punt_policer_add_del (mp->is_add, ntohl (mp->policer_index));

  REPLY_MACRO (VL_API_IP_PUNT_POLICE_REPLY);
}

#include <policer/policer.api.c>
static clib_error_t *
policer_api_hookup (vlib_main_t *vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (policer_api_hookup);
