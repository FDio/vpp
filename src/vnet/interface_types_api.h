/* Hey Emacs use -*- mode: C -*- */
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

typedef u32 interface_index;

enum if_status_flags
{
  IF_STATUS_API_FLAG_ADMIN_UP = 1,
  IF_STATUS_API_FLAG_LINK_UP = 2,
};

/* Per protocol MTU */
enum mtu_proto
{
  MTU_PROTO_API_L3,		/* Default payload MTU (without L2 headers) */
  MTU_PROTO_API_IP4,		/* Per-protocol MTUs overriding default */
  MTU_PROTO_API_IP6,
  MTU_PROTO_API_MPLS,
  MTU_PROTO_API_N,
};

enum link_duplex
{
  LINK_DUPLEX_API_UNKNOWN = 0,
  LINK_DUPLEX_API_HALF = 1,
  LINK_DUPLEX_API_FULL = 2,
};

enum sub_if_flags
{
  SUB_IF_API_FLAG_NO_TAGS = 1,
  SUB_IF_API_FLAG_ONE_TAG = 2,
  SUB_IF_API_FLAG_TWO_TAGS = 4,
  SUB_IF_API_FLAG_DOT1AD = 8,
  SUB_IF_API_FLAG_EXACT_MATCH = 16,
  SUB_IF_API_FLAG_DEFAULT = 32,
  SUB_IF_API_FLAG_OUTER_VLAN_ID_ANY = 64,
  SUB_IF_API_FLAG_INNER_VLAN_ID_ANY = 128,
  SUB_IF_API_FLAG_MASK_VNET = 254,	/* use with vnet_sub_interface_t raw_flags */
  SUB_IF_API_FLAG_DOT1AH = 256,
};

enum rx_mode
{
  RX_MODE_API_UNKNOWN = 0,
  RX_MODE_API_POLLING,
  RX_MODE_API_INTERRUPT,
  RX_MODE_API_ADAPTIVE,
  RX_MODE_API_DEFAULT,
};

enum if_type
{
  /* A hw interface. */
  IF_API_TYPE_HARDWARE,

  /* A sub-interface. */
  IF_API_TYPE_SUB,
  IF_API_TYPE_P2P,
  IF_API_TYPE_PIPE,
};

enum direction:u8
{
  DIRECTION_RX,
  DIRECTION_TX,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
