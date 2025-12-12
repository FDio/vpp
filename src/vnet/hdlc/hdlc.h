/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* hdlc.h: types/functions for hdlc. */

#ifndef included_hdlc_h
#define included_hdlc_h

#include <vnet/vnet.h>
#include <vnet/hdlc/packet.h>

extern vnet_hw_interface_class_t hdlc_hw_interface_class;

typedef enum
{
#define hdlc_error(n,s) HDLC_ERROR_##n,
#include <vnet/hdlc/error.def>
#undef hdlc_error
  HDLC_N_ERROR,
} hdlc_error_t;

typedef struct
{
  /* Name (a c string). */
  char *name;

  /* HDLC protocol type in host byte order. */
  hdlc_protocol_t protocol;

  /* Node which handles this type. */
  u32 node_index;

  /* Next index for this type. */
  u32 next_index;
} hdlc_protocol_info_t;

typedef struct
{
  vlib_main_t *vlib_main;

  hdlc_protocol_info_t *protocol_infos;

  /* Hash tables mapping name/protocol to protocol info index. */
  uword *protocol_info_by_name, *protocol_info_by_protocol;
} hdlc_main_t;

always_inline hdlc_protocol_info_t *
hdlc_get_protocol_info (hdlc_main_t * em, hdlc_protocol_t protocol)
{
  uword *p = hash_get (em->protocol_info_by_protocol, protocol);
  return p ? vec_elt_at_index (em->protocol_infos, p[0]) : 0;
}

extern hdlc_main_t hdlc_main;

/* Register given node index to take input for given hdlc type. */
void
hdlc_register_input_type (vlib_main_t * vm,
			  hdlc_protocol_t protocol, u32 node_index);

format_function_t format_hdlc_protocol;
format_function_t format_hdlc_header;
format_function_t format_hdlc_header_with_length;

/* Parse hdlc protocol as 0xXXXX or protocol name.
   In either host or network byte order. */
unformat_function_t unformat_hdlc_protocol_host_byte_order;
unformat_function_t unformat_hdlc_protocol_net_byte_order;

/* Parse hdlc header. */
unformat_function_t unformat_hdlc_header;
unformat_function_t unformat_pg_hdlc_header;

void
hdlc_register_input_protocol (vlib_main_t * vm,
			      hdlc_protocol_t protocol, u32 node_index);

#endif /* included_hdlc_h */
