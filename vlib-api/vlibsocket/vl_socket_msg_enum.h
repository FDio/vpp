/*
 *------------------------------------------------------------------
 * vl_msg_enum.h - Our view of how to number API messages
 * Clients have their own view, which has to agree with ours.
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

#ifndef __VL_MSG_ENUM_H__
#define __VL_MSG_ENUM_H__

#include <vppinfra/byte_order.h>

#define vl_msg_id(n,h) n,
typedef enum
{
  VL_ILLEGAL_MESSAGE_ID = 0,
#include <vlibsocket/vl_socket_api_h.h>
} vl_msg_id_t;
#undef vl_msg_id

#endif /* __VL_MSG_ENUM_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
