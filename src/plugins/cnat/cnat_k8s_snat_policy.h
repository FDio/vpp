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

typedef struct cnat_k8s_main_
{
  /* Bitmaps for interfaces with SNAT enabled */
  clib_bitmap_t *ip4_snat_interfaces;
  clib_bitmap_t *ip6_snat_interfaces;
  clib_bitmap_t *pod_interfaces;

  /* vec of pod cidrs */
  ip_prefix_t *pod_cidrs;
} cnat_k8s_main_t;

extern cnat_k8s_main_t cnat_k8s_main;

int cnat_k8s_enable_disable_snat (u32 sw_if_index, u8 is_ip6, u8 enable);
int cnat_k8s_register_pod_interface (u32 sw_if_index, u8 is_add);
int cnat_k8s_add_del_pod_cidr (ip_prefix_t *pfx, u8 is_add);

void cnat_k8s_snat_policy (vlib_main_t *vm, vlib_buffer_t *b,
			   cnat_session_t *session, cnat_node_ctx_t *ctx,
			   u8 *do_snat);

always_inline int
cnat_k8s_interface_snat_enabled (u32 sw_if_index, u8 is_ip6)
{
  cnat_k8s_main_t *cm = &cnat_k8s_main;
  if (is_ip6)
    {
      return clib_bitmap_get (cm->ip6_snat_interfaces, sw_if_index);
    }
  else
    {
      return clib_bitmap_get (cm->ip4_snat_interfaces, sw_if_index);
    }
}
