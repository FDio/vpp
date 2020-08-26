/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vppinfra/bitmap.h>
#include <cnat/cnat_types.h>
#include <cnat/cnat_inline.h>

typedef struct calico_main_
{
  /* Bitmaps for interfaces with SNAT enabled */
  clib_bitmap_t *ip4_snat_interfaces;
  clib_bitmap_t *ip6_snat_interfaces;
  cnat_main_t *cnat_main;
  int (*cnat_search_snat_prefix) (ip46_address_t *, ip_address_family_t);
  int (*cnat_allocate_port) (u16 *sport, ip_protocol_t iproto);
  int (*register_vip_src_policy) (void *);
  cnat_main_t * (*cnat_get_main) (void);
} calico_main_t;

extern calico_main_t calico_main;

int calico_enable_disable_snat (u32 sw_if_index, u8 is_ip6, u8 enable);

always_inline int
calico_interface_snat_enabled (u32 sw_if_index, u8 is_ip6)
{
  calico_main_t *cm = &calico_main;
  if (is_ip6)
    {
      return clib_bitmap_get (cm->ip6_snat_interfaces, sw_if_index);
    }
  else
    {
      return clib_bitmap_get (cm->ip4_snat_interfaces, sw_if_index);
    }
}
