/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef __included_vnet_bonding_lacp_protocol_h__
#define __included_vnet_bonding_lacp_protocol_h__

#include <vnet/ethernet/ethernet.h>

#define LACP_FAST_PERIODIC_TIMER        1.0
#define LACP_SHORT_TIMOUT_TIME          (LACP_FAST_PERIODIC_TIMER * 3)
#define LACP_SLOW_PERIODIC_TIMER        30.0
#define LACP_LONG_TIMOUT_TIME           (LACP_SLOW_PERIODIC_TIMER * 3)
#define LACP_CHURN_DETECTION_TIME       60
#define LACP_AGGREGATE_WAIT_TIME        2.0

#define LACP_SUBTYPE                    1
#define LACP_ACTOR_LACP_VERSION         1

#define foreach_lacp_tlv        \
  _ (TERMINATOR_INFORMATION, 0) \
  _ (ACTOR_INFORMATION, 1)      \
  _ (PARTNER_INFORMATION , 2)   \
  _ (COLLECTOR_INFORMATION, 3)

typedef enum
{
#define _(f,n) LACP_##f = (n),
  foreach_lacp_tlv
#undef _
} lacp_tlv_t;

#define foreach_lacp_port  \
  _ (UNSELECTED, 0)        \
  _ (SELECTED, 1)          \
  _ (STANDBY, 2)

typedef enum
{
#define _(f,n) LACP_PORT_##f = (n),
  foreach_lacp_port
#undef _
} lacp_port_t;

/* Port state */
#define foreach_lacp_state	     	     \
  _(0, LACP_ACTIVITY, "activity")	     \
  _(1, LACP_TIMEOUT, "lacp timeout")         \
  _(2, AGGREGATION, "aggregation")           \
  _(3, SYNCHRONIZATION, "synchronization")   \
  _(4, COLLECTING, "collecting")            \
  _(5, DISTRIBUTING, "distributing")         \
  _(6, DEFAULTED, "defaulted")               \
  _(7, EXPIRED, "expired")

typedef enum
{
#define _(a, b, c) LACP_STATE_##b = (1 << a),
  foreach_lacp_state
#undef _
} lacp_state_t;

#define foreach_lacp_state_flag	     	                \
  _(0, LACP_STATE_LACP_ACTIViTY, "activity")	        \
  _(1, LACP_STATE_LACP_TIMEOUT, "lacp timeout")         \
  _(2, LACP_STATE_AGGREGATION, "aggregation")           \
  _(3, LACP_STATE_SYNCHRONIZATION, "synchronization")   \
  _(4, LACP_STATE_COLLECTIING, "collecting")            \
  _(5, LACP_STATE_DISTRIBUTING, "distributing")         \
  _(6, LACP_STATE_DEFAULTED, "defaulted")               \
  _(7, LACP_STATE_EXPIRED, "expired")

typedef struct
{
  u8 bit;
  char *str;
} lacp_state_struct;

typedef struct
{
  u8 bit;
  char *str;
} lacp_event_struct;

#define LACP_MAX_TX_IN_SECOND           3
#define LACP_DEFAULT_PORT_PRIORITY      0x00ff
#define LACP_DEFAULT_SYSTEM_PRIORITY    0xffff

typedef CLIB_PACKED (struct
		     {
		     u16 system_priority;
		     u8 system[6];
		     u16 key; u16 port_priority; u16 port_number;
		     u8 state;
		     }) lacp_port_info_t;

typedef CLIB_PACKED (struct
		     {
		     u8 tlv_type;
		     u8 tlv_length;
		     lacp_port_info_t port_info; u8 reserved[3];
		     }) lacp_actor_partner_t;

typedef CLIB_PACKED (struct
		     {
		     u8 tlv_type; u8 tlv_length; u16 max_delay;
		     u8 reserved[12];
		     }) lacp_collector_t;

typedef CLIB_PACKED (struct
		     {
		     u8 tlv_type; u8 tlv_length;
		     u8 pad[50];
		     }) lacp_terminator_t;

typedef CLIB_PACKED (struct
		     {
		     u8 subtype; u8 version_number;
		     lacp_actor_partner_t actor; lacp_actor_partner_t partner;
		     lacp_collector_t collector; lacp_terminator_t terminator;
		     }) lacp_pdu_t;

typedef CLIB_PACKED (struct
		     {
		     ethernet_header_t ethernet; lacp_pdu_t lacp;
		     }) ethernet_lacp_pdu_t;

#define MARKER_SUBTYPE                  2
#define MARKER_PROTOCOL_VERSION         1

#define foreach_marker_tlv      \
  _ (TERMINATOR_INFORMATION, 0) \
  _ (INFORMATION, 1)            \
  _ (RESPONSE_INFORMATION , 2)

typedef enum
{
#define _(f,n) MARKER_##f = (n),
  foreach_marker_tlv
#undef _
} marker_tlv_t;

typedef CLIB_PACKED (struct
		     {
		     u8 tlv_type; u8 tlv_length;
		     u8 reserved[90];
		     }) marker_terminator_t;

typedef CLIB_PACKED (struct
		     {
		     u8 tlv_type;
		     u8 tlv_length;
		     u16 requester_port; u8 requester_system[6];
		     u32 requester_transaction_id; u8 pad[2];
		     }) marker_information_t;

typedef CLIB_PACKED (struct
		     {
		     u8 subtype;
		     u8 version_number;
		     marker_information_t marker_info;
		     marker_terminator_t terminator;
		     }) marker_pdu_t;

typedef CLIB_PACKED (struct
		     {
		     ethernet_header_t ethernet; marker_pdu_t marker;
		     }) ethernet_marker_pdu_t;

#endif /* __included_vnet_bonding_lacp_protocol_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
