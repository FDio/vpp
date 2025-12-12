/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2024 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ppp.h: types/functions for ppp. */

#ifndef included_ppp_h
#define included_ppp_h

#include <vnet/vnet.h>
#include <ppp/packet.h>

extern vnet_hw_interface_class_t ppp_hw_interface_class;

typedef enum
{
#define ppp_error(n,s) PPP_ERROR_##n,
#include <ppp/error.def>
#undef ppp_error
  PPP_N_ERROR,
} ppp_error_t;

typedef struct
{
  /* Name (a c string). */
  char *name;

  /* PPP protocol type in host byte order. */
  ppp_protocol_t protocol;

  /* Node which handles this type. */
  u32 node_index;

  /* Next index for this type. */
  u32 next_index;
} ppp_protocol_info_t;

typedef struct
{
  vlib_main_t *vlib_main;

  ppp_protocol_info_t *protocol_infos;

  /* Hash tables mapping name/protocol to protocol info index. */
  uword *protocol_info_by_name, *protocol_info_by_protocol;
} ppp_main_t;

always_inline ppp_protocol_info_t *
ppp_get_protocol_info (ppp_main_t * em, ppp_protocol_t protocol)
{
  uword *p = hash_get (em->protocol_info_by_protocol, protocol);
  return p ? vec_elt_at_index (em->protocol_infos, p[0]) : 0;
}

extern ppp_main_t ppp_main;

/* Register given node index to take input for given ppp type. */
void
ppp_register_input_type (vlib_main_t * vm,
			 ppp_protocol_t protocol, u32 node_index);

format_function_t format_ppp_protocol;
format_function_t format_ppp_header;
format_function_t format_ppp_header_with_length;

/* Parse ppp protocol as 0xXXXX or protocol name.
   In either host or network byte order. */
unformat_function_t unformat_ppp_protocol_host_byte_order;
unformat_function_t unformat_ppp_protocol_net_byte_order;

/* Parse ppp header. */
unformat_function_t unformat_ppp_header;
unformat_function_t unformat_pg_ppp_header;

__clib_export void ppp_register_input_protocol (vlib_main_t *vm,
						ppp_protocol_t protocol,
						u32 node_index);

#endif /* included_ppp_h */
