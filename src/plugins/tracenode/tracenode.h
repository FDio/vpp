/*
 * Copyright (c) 2023 Cisco and/or its affiliates.
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
#ifndef _TRACENODE_H_
#define _TRACENODE_H_
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <stdbool.h>

typedef struct
{
  vnet_main_t *vnet_main;
  uword *feature_enabled_by_sw_if;
  u16 msg_id_base;
} tracenode_main_t;

extern tracenode_main_t tracenode_main;

clib_error_t *tracenode_plugin_api_hookup (vlib_main_t *vm);

int vnet_enable_disable_tracenode_feature (u32 sw_if_index, bool is_pcap,
					   bool enable);

#endif /* _TRACENODE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
