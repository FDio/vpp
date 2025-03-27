/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* llc.h: LLC definitions */

#ifndef included_llc_h
#define included_llc_h

#include <vnet/vnet.h>

/* Protocol (SSAP/DSAP) types. */
#define foreach_llc_protocol			\
  _ (null, 0x0)					\
  _ (sublayer, 0x2)				\
  _ (sna_path_control, 0x4)			\
  _ (ip4, 0x6)					\
  _ (sna1, 0x8)					\
  _ (sna2, 0xc)					\
  _ (sna3, 0x40)				\
  _ (proway_lan, 0x0e)				\
  _ (netware1, 0x10)				\
  _ (netware2, 0xe0)				\
  _ (osi_layer1, 0x14)				\
  _ (osi_layer2, 0x20)				\
  _ (osi_layer3, 0x34)				\
  _ (osi_layer4, 0x54)				\
  _ (osi_layer5, 0xfe)				\
  _ (bpdu, 0x42)				\
  _ (arp, 0x98)					\
  _ (snap, 0xaa)				\
  _ (vines1, 0xba)				\
  _ (vines2, 0xbc)				\
  _ (netbios, 0xf0)				\
  _ (global_dsap, 0xff)

typedef enum
{
#define _(f,n) LLC_PROTOCOL_##f = n,
  foreach_llc_protocol
#undef _
} llc_protocol_t;

typedef struct
{
#define LLC_DST_SAP_IS_GROUP (1 << 0)
#define LLC_SRC_SAP_IS_RESPONSE (1 << 0)
  u8 dst_sap, src_sap;

  /* Control byte.
     [0] 1 => supervisory 0 => information
     [1] unnumbered frame. */
  u8 control;

  /* Only present if (control & 3) != 3. */
  u8 extended_control[0];
} llc_header_t;

always_inline u16
llc_header_get_control (llc_header_t * h)
{
  u16 r = h->control;
  return r | ((((r & 3) != 3) ? h->extended_control[0] : 0) << 8);
}

always_inline u8
llc_header_length (llc_header_t * h)
{
  return ((h->control & 3) != 3 ? 4 : 3);
}

typedef struct
{
  /* Name (a c string). */
  char *name;

  /* LLC protocol (SAP type). */
  llc_protocol_t protocol;

  /* Node which handles this type. */
  u32 node_index;

  /* Next index for this type. */
  u32 next_index;
} llc_protocol_info_t;

#define foreach_llc_error			\
  _ (NONE, "no error")				\
  _ (UNKNOWN_PROTOCOL, "unknown llc ssap/dsap")	\
  _ (UNKNOWN_CONTROL, "control != 0x3")

typedef enum
{
#define _(f,s) LLC_ERROR_##f,
  foreach_llc_error
#undef _
    LLC_N_ERROR,
} llc_error_t;

typedef struct
{
  vlib_main_t *vlib_main;

  llc_protocol_info_t *protocol_infos;

  /* Hash tables mapping name/protocol to protocol info index. */
  uword *protocol_info_by_name, *protocol_info_by_protocol;

  /* llc-input next index indexed by protocol. */
  u8 input_next_by_protocol[256];
} llc_main_t;

always_inline llc_protocol_info_t *
llc_get_protocol_info (llc_main_t * m, llc_protocol_t protocol)
{
  uword *p = hash_get (m->protocol_info_by_protocol, protocol);
  return p ? vec_elt_at_index (m->protocol_infos, p[0]) : 0;
}

extern llc_main_t llc_main;

/* Register given node index to take input for given llc type. */
void
llc_register_input_protocol (vlib_main_t * vm,
			     llc_protocol_t protocol, u32 node_index);

format_function_t format_llc_protocol;
format_function_t format_llc_header;
format_function_t format_llc_header_with_length;

/* Parse llc protocol as 0xXXXX or protocol name. */
unformat_function_t unformat_llc_protocol;

/* Parse llc header. */
unformat_function_t unformat_llc_header;
unformat_function_t unformat_pg_llc_header;

extern vlib_node_registration_t llc_input_node;

#endif /* included_llc_h */
