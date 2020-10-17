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

#ifndef __NULL_H__
#define __NULL_H__

#include <vnet/interface.h>

/**
 * Create a new null interface
 *
 * @param user_instance The user's desired instance, ~0 = don't care
 * @param sw_if_index OUT the created parent interface
 */
extern int null_interface_add (u32 user_instance, u32 * parent_sw_if_index);
extern int null_interface_delete (u32 parent_sw_if_index);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
