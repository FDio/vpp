/*
 * mss_clamp.h - TCP MSS clamping plug-in header file
 *
 * Copyright (c) 2018 Cisco and/or its affiliates
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

#ifndef __included_mss_clamp_h__
#define __included_mss_clamp_h__

#include <stdbool.h> /* for bool in .api */
#include <vnet/vnet.h>

extern int mssc_enable_disable (u32 sw_if_index, u8 dir4, u8 dir6, u16 mss4,
				u16 mss6);
extern int mssc_get_mss (u32 sw_if_index, u8 *dir4, u8 *dir6, u16 *mss4,
			 u16 *mss6);

typedef struct
{
  /* Maximum segment size per interface for IPv4/IPv6 */
  u16 *max_mss4;
  u16 *max_mss6;

  /* Direction the feature is enabled for IPv4/IPv6 (rx, tx, both) */
  u8 *dir_enabled4;
  u8 *dir_enabled6;

  /* API message ID base */
  u16 msg_id_base;
} mssc_main_t;

extern mssc_main_t mssc_main;

#define MSS_CLAMP_UNSET 0xffff

#endif /* __included_mss_clamp_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
