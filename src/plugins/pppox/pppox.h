/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2017 RaydoNetworks.
 * Copyright (c) 2026 Hi-Jiajun.
 */

#ifndef _PPPOX_H
#define _PPPOX_H

#include <vnet/plugin/plugin.h>
#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_table.h>
#include <vlib/vlib.h>
#include <vppinfra/bihash_8_8.h>

typedef struct
{
  u32 len;
} pppox_vnet_buffer_opaque_t;

STATIC_ASSERT (sizeof (pppox_vnet_buffer_opaque_t) <= VNET_BUFFER_OPAQUE_SIZE,
	       "pppox_vnet_buffer_opaque_t too large");

#define pppox_buffer(b) ((pppox_vnet_buffer_opaque_t *) vnet_buffer_get_opaque (b))

typedef enum
{
#define pppox_error(n, s) PPPOX_ERROR_##n,
#include <pppox/pppox_error.def>
#undef pppox_error
  PPPOX_N_ERROR,
} pppox_error_t;

#define foreach_pppox_input_next _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) PPPOX_INPUT_NEXT_##s,
  foreach_pppox_input_next
#undef _
    PPPOX_INPUT_N_NEXT,
} pppox_input_next_t;

#define foreach_pppox_output_next _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) PPPOX_OUTPUT_NEXT_##s,
  foreach_pppox_output_next
#undef _
    PPPOX_OUTPUT_N_NEXT,
} pppox_output_next_t;

typedef struct
{
  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /* record pppoe client index */
  // TODO: if we wan to support real pppoX, we should make
  // a type here to detect underly encapsulation.
  u32 pppoe_client_index;
  /* record pppoe session status */
  u8 pppoe_session_allocated;

  /* record allocated address. */
  u32 our_addr;
  u32 his_addr;
  /* IPv6 addresses */
  ip6_address_t our_ipv6;
  ip6_address_t his_ipv6;

  /* IPCP options derived from the PPPoE client CLI. */
  u8 add_default_route4; /* add IPv4 default route via peer */
  u8 add_default_route6; /* add IPv6 default route via peer */
  u8 use_peer_dns;
} pppox_virtual_interface_t;

typedef struct
{
  /* vector of pppox interfaces. */
  pppox_virtual_interface_t *virtual_interfaces;

  /* Free vlib hw_if_indices */
  u32 *free_pppox_hw_if_indices;

  /* Mapping from sw_if_index to session index */
  u32 *virtual_interface_index_by_sw_if_index;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} pppox_main_t;

extern pppox_main_t pppox_main;

extern vlib_node_registration_t pppox_input_node;
extern vlib_node_registration_t pppox_output_node;

int consume_pppox_ctrl_pkt (u32, vlib_buffer_t *);

u32 pppox_allocate_interface (u32);

void pppox_free_interface (u32);

void pppox_lower_up (u32);

int pppox_set_auth (u32, u8 *, u8 *);
int pppox_set_add_default_route (u32, u8);  /* sets both IPv4 and IPv6 */
int pppox_set_add_default_route4 (u32, u8); /* IPv4 only */
int pppox_set_add_default_route6 (u32, u8); /* IPv6 only */
int pppox_set_use_peer_dns (u32, u8);
void pppox_set_interface_mtu (int, int);

#endif /* _PPPOX_H */

/*
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
