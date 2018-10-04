/*
 * tmc.h - skeleton vpp engine plug-in header file
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

#ifndef __included_tmc_h__
#define __included_tmc_h__

#include <stdbool.h>  /* for bool in .api */
#include <vnet/vnet.h>

extern int tmc_enable (u32 sw_if_index, u16 mss);
extern int tmc_disable (u32 sw_if_index);

/*
 * expose the DB for the data-plane node
 */
extern u16 *tmc_db;

#endif /* __included_tmc_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
