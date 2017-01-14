/*
 *------------------------------------------------------------------
 * tuntap.h - kernel stack (reverse) punt/inject path
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief Call from VLIB_INIT_FUNCTION to set the Linux kernel inject node name.
 */
void register_tuntap_inject_node_name (char *name);

/** arguments structure for vnet_tap_connect, vnet_tap_connect_renumber, etc.
 */

typedef struct
{
  /** Interface name */
  u8 *intfc_name;
  /** Mac address */
  u8 *hwaddr_arg;
  /** Please set the indicated ip4 address/mask on the interface */
  u8 ip4_address_set;
  /** Please set the indicated ip4 address/mask on the interface */
  u8 ip6_address_set;
  /** Renumber the (existing) interface */
  u8 renumber;
  /** (optional) ip4 address to set */
  ip4_address_t *ip4_address;
  /** (optional) ip4 mask width to set */
  u32 ip4_mask_width;
  /** (optional) ip6 address to set */
  ip6_address_t *ip6_address;
  /** (optional) ip6 mask width to set */
  u32 ip6_mask_width;
  /** Output parameter: result sw_if_index */
  u32 *sw_if_indexp;
  /** Custom device instance */
  u32 custom_dev_instance;
  /** original sw_if_index (renumber) */
  u32 orig_sw_if_index;
} vnet_tap_connect_args_t;

/** Connect a tap interface */
int vnet_tap_connect (vlib_main_t * vm, vnet_tap_connect_args_t *args);

/** Connect / renumber a tap interface */
int vnet_tap_connect_renumber (vlib_main_t * vm,
                               vnet_tap_connect_args_t *args);

/** Modify a tap interface */
int vnet_tap_modify (vlib_main_t * vm, vnet_tap_connect_args_t *args);

/** delete a tap interface */
int vnet_tap_delete(vlib_main_t *vm, u32 sw_if_index);


