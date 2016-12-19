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

int vnet_tap_connect (vlib_main_t * vm, u8 * intfc_name,
                      u8 *hwaddr_arg, u32 * sw_if_indexp);
int vnet_tap_connect_renumber (vlib_main_t * vm, u8 * intfc_name,
                      u8 *hwaddr_arg, u32 * sw_if_indexp,
                      u8 renumber, u32 custom_dev_instance);

int vnet_tap_delete(vlib_main_t *vm, u32 sw_if_index);

int vnet_tap_modify (vlib_main_t * vm, u32 orig_sw_if_index,
                     u8 * intfc_name, u8 *hwaddr_arg,
                     u32 * sw_if_indexp,
                     u8 renumber, u32 custom_dev_instance);
