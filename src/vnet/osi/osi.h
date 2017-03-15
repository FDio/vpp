/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * osi.h: OSI definitions
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_osi_h
#define included_osi_h

#include <vnet/vnet.h>
#include <vnet/pg/pg.h>

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
void osi_register_input_protocol (osi_protocol_t protocol, u32 node_index);

format_function_t format_osi_protocol;
format_function_t format_osi_header;
format_function_t format_osi_header_with_length;

/* Parse osi protocol as 0xXXXX or protocol name. */
unformat_function_t unformat_osi_protocol;

/* Parse osi header. */
unformat_function_t unformat_osi_header;
unformat_function_t unformat_pg_osi_header;

always_inline void
osi_setup_node (vlib_main_t * vm, u32 node_index)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  pg_node_t *pn = pg_get_node (node_index);

  n->format_buffer = format_osi_header_with_length;
  n->unformat_buffer = unformat_osi_header;
  pn->unformat_edit = unformat_pg_osi_header;
}

void osi_register_input_protocol (osi_protocol_t protocol, u32 node_index);

format_function_t format_osi_header;

#endif /* included_osi_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
