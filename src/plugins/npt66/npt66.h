// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2023 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/ip/ip6_packet.h>

typedef struct
{
  u32 sw_if_index;
  ip6_address_t internal;
  ip6_address_t external;
  u8 internal_plen;
  u8 external_plen;
  uword delta;
} npt66_binding_t;
typedef struct
{
  u32 *interface_by_sw_if_index;
  npt66_binding_t *bindings;
  u16 msg_id_base;
} npt66_main_t;

extern npt66_main_t npt66_main;

int npt66_binding_add_del (u32 sw_if_index, ip6_address_t *internal,
			   int internal_plen, ip6_address_t *external,
			   int external_plen, bool is_add);
npt66_binding_t *npt66_interface_by_sw_if_index (u32 sw_if_index);
