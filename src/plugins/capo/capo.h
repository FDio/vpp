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

#ifndef included_capo_h
#define included_capo_h

#include <vnet/ip/ip.h>
#include <vnet/ip/ip_types_api.h>
#include <acl/public_inlines.h>
#include <capo/bihash_8_24.h>

#include <capo/capo.api_enum.h>
#include <capo/capo.api_types.h>
#include <capo/capo_interface.h>

#define CAPO_INVALID_INDEX ((u32)~0)

typedef struct
{
  u16 start;
  u16 end;
} capo_port_range_t;

typedef struct
{
  clib_bihash_8_24_t if_config;	/* sw_if_index -> capo_interface_config */

  u32 calico_acl_user_id;
  acl_plugin_methods_t acl_plugin;

  /* API message ID base */
  u16 msg_id_base;

} capo_main_t;


extern capo_main_t capo_main;

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
