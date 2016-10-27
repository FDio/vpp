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

typedef struct
{
  /* policer pool, aligned */
  policer_read_response_type_st *policers;

  /* config + template h/w policer instance parallel pools */
  sse2_qos_pol_cfg_params_st *configs;
  policer_read_response_type_st *policer_templates;

  /* Config by name hash */
  uword *policer_config_by_name;

  /* Policer by name hash */
  uword *policer_index_by_name;

  /* Policer by sw_if_index vector */
  u32 *policer_index_by_sw_if_index;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} vnet_policer_main_t;

vnet_policer_main_t vnet_policer_main;

typedef enum
{
  VNET_POLICER_INDEX_BY_SW_IF_INDEX,
  VNET_POLICER_INDEX_BY_OPAQUE,
  VNET_POLICER_INDEX_BY_EITHER,
} vnet_policer_index_t;

typedef enum
{
  VNET_POLICER_NEXT_TRANSMIT,
  VNET_POLICER_NEXT_DROP,
  VNET_POLICER_N_NEXT,
} vnet_policer_next_t;

#define foreach_vnet_dscp \
  _(0 , CS0,  "CS0")  \
  _(8 , CS1,  "CS1")  \
  _(10, AF11, "AF11") \
  _(12, AF12, "AF12") \
  _(14, AF13, "AF13") \
  _(16, CS2,  "CS2")  \
  _(18, AF21, "AF21") \
  _(20, AF22, "AF22") \
  _(22, AF23, "AF23") \
  _(24, CS3,  "CS3")  \
  _(26, AF31, "AF31") \
  _(28, AF32, "AF32") \
  _(30, AF33, "AF33") \
  _(32, CS4,  "CS4")  \
  _(34, AF41, "AF41") \
  _(36, AF42, "AF42") \
  _(38, AF43, "AF43") \
  _(40, CS5,  "CS5")  \
  _(46, EF,   "EF")   \
  _(48, CS6,  "CS6")  \
  _(50, CS7,  "CS7")

typedef enum
{
#define _(v,f,str) VNET_DSCP_##f = v,
  foreach_vnet_dscp
#undef _
} vnet_dscp_t;

u8 *format_policer_instance (u8 * s, va_list * va);
clib_error_t *policer_add_del (vlib_main_t * vm,
			       u8 * name,
			       sse2_qos_pol_cfg_params_st * cfg,
			       u32 * policer_index, u8 is_add);

#endif /* __included_policer_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
