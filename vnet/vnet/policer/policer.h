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

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <vnet/policer/xlate.h>
#include <vnet/policer/police.h>

typedef struct {
  /* policer pool, aligned */
  policer_read_response_type_st  * policers;

  /* config + template h/w policer instance parallel pools */
  sse2_qos_pol_cfg_params_st * configs;
  policer_read_response_type_st * policer_templates;
  
  /* Config by name hash */
  uword * policer_config_by_name;

  /* Policer by sw_if_index vector */
  u32 * policer_index_by_sw_if_index;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} vnet_policer_main_t;

vnet_policer_main_t vnet_policer_main;

typedef enum {
  VNET_POLICER_INDEX_BY_SW_IF_INDEX,
  VNET_POLICER_INDEX_BY_OPAQUE,
  VNET_POLICER_INDEX_BY_EITHER,
} vnet_policer_index_t;

typedef 
enum {
  VNET_POLICER_NEXT_TRANSMIT,
  VNET_POLICER_NEXT_DROP,
  VNET_POLICER_N_NEXT,
} vnet_policer_next_t;

u8 * format_policer_instance (u8 * s, va_list * va);
clib_error_t * policer_add_del (vlib_main_t *vm,
                                u8 * name, sse2_qos_pol_cfg_params_st * cfg,
                                u8 is_add);

#endif /* __included_policer_h__ */
