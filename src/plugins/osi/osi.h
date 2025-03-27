/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* osi.h: OSI definitions */

#ifndef included_osi_h
#define included_osi_h

#include <vnet/vnet.h>

#define foreach_osi_protocol			\
  _ (null, 0x0)					\
  _ (x_29, 0x01)				\
  _ (x_633, 0x03)				\
  _ (q_931, 0x08)				\
  _ (q_933, 0x08)				\
  _ (q_2931, 0x09)				\
  _ (q_2119, 0x0c)				\
  _ (snap, 0x80)				\
  _ (clnp, 0x81)				\
  _ (esis, 0x82)				\
  _ (isis, 0x83)				\
  _ (idrp, 0x85)				\
  _ (x25_esis, 0x8a)				\
  _ (iso10030, 0x8c)				\
  _ (iso11577, 0x8d)				\
  _ (ip6, 0x8e)					\
  _ (compressed, 0xb0)				\
  _ (sndcf, 0xc1)				\
  _ (ip4, 0xcc)					\
  _ (ppp, 0xcf)

typedef enum
{
#define _(f,n) OSI_PROTOCOL_##f = n,
  foreach_osi_protocol
#undef _
} osi_protocol_t;

typedef struct
{
  u8 protocol;

  u8 payload[0];
} osi_header_t;

typedef struct
{
  /* Name (a c string). */
  char *name;

  /* OSI protocol (SAP type). */
  osi_protocol_t protocol;

  /* Node which handles this type. */
  u32 node_index;

  /* Next index for this type. */
  u32 next_index;
} osi_protocol_info_t;

#define foreach_osi_error			\
  _ (NONE, "no error")				\
  _ (UNKNOWN_PROTOCOL, "unknown osi protocol")

typedef enum
{
#define _(f,s) OSI_ERROR_##f,
  foreach_osi_error
#undef _
    OSI_N_ERROR,
} osi_error_t;

typedef struct
{
  vlib_main_t *vlib_main;

  osi_protocol_info_t *protocol_infos;

  /* Hash tables mapping name/protocol to protocol info index. */
  uword *protocol_info_by_name, *protocol_info_by_protocol;

  /* osi-input next index indexed by protocol. */
  u8 input_next_by_protocol[256];
} osi_main_t;

always_inline osi_protocol_info_t *
osi_get_protocol_info (osi_main_t * m, osi_protocol_t protocol)
{
  uword *p = hash_get (m->protocol_info_by_protocol, protocol);
  return p ? vec_elt_at_index (m->protocol_infos, p[0]) : 0;
}

extern osi_main_t osi_main;

/* Register given node index to take input for given osi type. */
int osi_register_input_protocol (osi_protocol_t protocol, u32 node_index);

format_function_t format_osi_protocol;
format_function_t format_osi_header;
format_function_t format_osi_header_with_length;

/* Parse osi protocol as 0xXXXX or protocol name. */
unformat_function_t unformat_osi_protocol;

/* Parse osi header. */
unformat_function_t unformat_osi_header;
unformat_function_t unformat_pg_osi_header;

format_function_t format_osi_header;

#endif /* included_osi_h */
