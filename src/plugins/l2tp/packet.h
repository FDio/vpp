/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2013 Cisco and/or its affiliates.
 */

/* packet.h : L2TPv3 packet header format */

#ifndef __included_l2tp_packet_h__
#define __included_l2tp_packet_h__

/*
 * See RFC4719 for packet format.
 * Note: the l2_specific_sublayer is present in current Linux l2tpv3
 * tunnels. It is not present in IOS XR l2tpv3 tunnels.
 * The Linux implementation is almost certainly wrong.
 */
typedef CLIB_PACKED (struct
{
  u32 session_id;
  u64 cookie; u32
  l2_specific_sublayer;	/* set to 0 (if present) */
}) l2tpv3_header_t;

#endif /* __included_l2tp_packet_h__ */
