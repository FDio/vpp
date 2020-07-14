/*
 * Copyright (c) 2016,2020 Cisco and/or its affiliates.
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

#ifndef __vnet_adl_h__
#define __vnet_adl_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

typedef enum {
  VNET_ADL_IP4,
  VNET_ADL_IP6,
  VNET_ADL_DEFAULT,
  VNET_N_ADLS,
} vnet_adl_t;

typedef enum {
  /* First check src address against allowlist */
  IP4_RX_ADL_ALLOWLIST,
  IP6_RX_ADL_ALLOWLIST,
  DEFAULT_RX_ADL_ALLOWLIST,

  /* Pkts not otherwise dropped go to xxx-input */
  IP4_RX_ADL_INPUT,
  IP6_RX_ADL_INPUT,
  DEFAULT_RX_ADL_INPUT,

  /* Going, going, gone... */
  RX_ADL_DROP,

  ADL_RX_N_FEATURES,
} adl_feature_type_t;

typedef struct {
  vnet_config_main_t config_main;
  u32 * config_index_by_sw_if_index;
} adl_config_main_t;

typedef struct {
  u32 fib_index;
} adl_config_data_t;

typedef struct {
  adl_config_main_t adl_config_mains[VNET_N_ADLS];

  u16 msg_id_base;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} adl_main_t;

extern adl_main_t adl_main;

extern vlib_node_registration_t adl_input_node;

int adl_interface_enable_disable (u32 sw_if_index, int enable_disable);

typedef struct {
  u32 sw_if_index;
  u8 ip4;
  u8 ip6;
  u8 default_adl;
  u32 fib_id;
} adl_allowlist_enable_disable_args_t;

int adl_allowlist_enable_disable (adl_allowlist_enable_disable_args_t *a);

/* Plugin private opaque union type */
typedef struct {
    /* MUST be in sync with .../src/vnet/buffer.h */
    u32 sw_if_index[VLIB_N_RX_TX];
    i16 l2_hdr_offset;
    i16 l3_hdr_offset;
    i16 l4_hdr_offset;
    u8 feature_arc_index;
    u8 dont_waste_me;
    /* end of must be in sync with .../src/vnet/buffer.h */
    union
    {
        /* COP - configurable junk filter(s) */
        struct
        {
            /* Current configuration index. */
            u32 current_config_index;
        } adl;
    };
} adl_buffer_opaque_t;

#define adl_buffer(b) ((adl_buffer_opaque_t *) (b)->opaque)

#endif /* __vnet_adl_h__ */
