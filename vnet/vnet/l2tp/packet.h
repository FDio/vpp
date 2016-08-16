/*
 * packet.h : L2TPv3 packet header format
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#ifndef __included_l2tp_packet_h__
#define __included_l2tp_packet_h__

/*
 * See RFC4719 for packet format.
 * Note: the l2_specific_sublayer is present in current Linux l2tpv3
 * tunnels. It is not present in IOS XR l2tpv3 tunnels.
 * The Linux implementation is almost certainly wrong.
 */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
{
  u32 session_id;
  u64 cookie; u32
  l2_specific_sublayer;	/* set to 0 (if present) */
}) l2tpv3_header_t;
/* *INDENT-ON* */

#endif /* __included_l2tp_packet_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
