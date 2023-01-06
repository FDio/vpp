/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __included_policer_h__
#define __included_policer_h__

#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <vnet/policer/xlate.h>
#include <vnet/policer/police.h>

typedef struct
{
  /* policer pool, aligned */
  policer_t *policers;

  /* config + template h/w policer instance parallel pools */
  qos_pol_cfg_params_st *configs;
  policer_t *policer_templates;

  /* Config by policer name hash */
  uword *policer_config_by_name;

  /* Policer by name hash */
  uword *policer_index_by_name;

  /* Policer by sw_if_index vector */
  u32 *policer_index_by_sw_if_index[VLIB_N_RX_TX];

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  vlib_log_class_t log_class;

  /* frame queue for thread handoff */
  u32 fq_index[VLIB_N_RX_TX];

  u16 msg_id_base;
} vnet_policer_main_t;

extern vnet_policer_main_t vnet_policer_main;

extern vlib_combined_counter_main_t policer_counters[];

extern vlib_node_registration_t policer_input_node;
extern vlib_node_registration_t policer_output_node;

typedef enum
{
  VNET_POLICER_NEXT_DROP,
  VNET_POLICER_NEXT_HANDOFF,
  VNET_POLICER_N_NEXT,
} vnet_policer_next_t;

u8 *format_policer_instance (u8 * s, va_list * va);
int policer_add (vlib_main_t *vm, const u8 *name,
		 const qos_pol_cfg_params_st *cfg, u32 *policer_index);

int policer_update (vlib_main_t *vm, u32 policer_index,
		    const qos_pol_cfg_params_st *cfg);
int policer_del (vlib_main_t *vm, u32 policer_index);
int policer_reset (vlib_main_t *vm, u32 policer_index);
int policer_bind_worker (u32 policer_index, u32 worker, bool bind);
int policer_input (u32 policer_index, u32 sw_if_index, vlib_dir_t dir,
		   bool apply);

#endif /* __included_policer_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
