/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef included_vnet_msg_enum_h
#define included_vnet_msg_enum_h

#include <vppinfra/byte_order.h>

#define vl_msg_id(n,h) n,
typedef enum
{
  VL_ILLEGAL_MESSAGE_ID = 0,
#include <vnet/vnet_all_api_h.h>
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

#endif /* included_vnet_msg_enum_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
