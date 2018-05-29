/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef SRC_PLUGINS_SNORT_SNORT_H_
#define SRC_PLUGINS_SNORT_SNORT_H_

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_48_8.h>

/* *INDENT-OFF* */
/* 16 octets */
typedef CLIB_PACKED (struct {
  union
    {
      struct
	{
	  ip4_address_t src;
	  ip4_address_t dst;
	  u16 src_port;
	  u16 dst_port;
	  /* align by making this 4 octets even though its a 1-bit field
	   * NOTE: avoid key overlap with other transports that use 5 tuples for
	   * session identification.
	   */
	  u32 proto;
	};
      u64 as_u64[2];
    };
}) v4_flow_key_t;

typedef struct snort_interface_add_del_args_
{
  u32 sw_if_index;
  u8 is_add;
} snort_interface_add_del_args_t;

typedef CLIB_PACKED (struct {
  union
    {
      struct
        {
          /* 48 octets */
          ip6_address_t src;
          ip6_address_t dst;
          u16 src_port;
          u16 dst_port;
          u32 proto;
          u64 unused;
        };
      u64 as_u64[6];
    };
}) v6_flow_key_t;
/* *INDENT-ON* */

typedef struct snort_flow_id_
{
  union
  {
    v4_flow_key_t v4;
    v6_flow_key_t v6;
  };
  u8 is_ip4;
} snort_flow_id_t;

typedef enum snort_action_
{
  SNORT_ACTION_INSPECT,
  SNORT_ACTION_DROP,
  SNORT_ACTION_FWD,
} snort_action_t;

typedef struct snort_flow_
{
  snort_action_t action;
  snort_flow_id_t id;
} snort_flow_t;

typedef struct snort_interface_
{
  snort_flow_t *flows;
  u32 sw_if_index;
} snort_interface_t;

typedef struct snort_interface_flow_add_del_args_
{
  u32 sw_if_index;
  snort_flow_id_t flow_id;
  u8 action;
  u8 is_add;
} snort_interface_flow_add_del_args_t;

typedef struct snort_main_
{
  snort_interface_t *interfaces;	/**< pool of interfaces */
  u32 *snort_iface_by_sw_if_index;	/**< snort iface by sw_if_index */
  u32 sw_if_index;			/**< snort iface sw_if_index */

  clib_bihash_16_8_t v4_flow_hash;	/**< v4 flow lookup table */
  clib_bihash_48_8_t v6_flow_hash;	/**< v6 flow lookup table */

  u32 msg_id_base;			/**< api msg id base */
  u8 is_enabled;			/**< set if plugin is enabled */
} snort_main_t;

typedef struct snort_enable_disable_args_
{
  u32 sw_if_index;
  u8 is_en;
} snort_enable_disable_args_t;

u32 snort_interface_index (snort_interface_t *sif);
snort_interface_t *snort_interface_lookup (u32 sw_if_index);
snort_interface_t *snort_interface_alloc (void);
void snort_interface_free (snort_interface_t *sif);

int snort_create_memif_interface (void);

clib_error_t *snort_interface_add_del (snort_interface_add_del_args_t *a);
clib_error_t *snort_interface_flow_add_del (snort_interface_flow_add_del_args_t *a);

snort_main_t *snort_get_main (void);
clib_error_t *snort_plugin_api_hookup (vlib_main_t *vm);
clib_error_t *snort_enable_disable (snort_enable_disable_args_t *a);

#endif /* SRC_PLUGINS_SNORT_SNORT_H_ */
