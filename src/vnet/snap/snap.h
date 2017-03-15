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
 * snap.h: SNAP definitions
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

#ifndef included_snap_h
#define included_snap_h

#include <vnet/vnet.h>
#include <vnet/pg/pg.h>

#define foreach_ieee_oui			\
  _ (0x000000, ethernet)			\
  _ (0x00000c, cisco)

typedef enum
{
#define _(n,f) IEEE_OUI_##f = n,
  foreach_ieee_oui
#undef _
} ieee_oui_t;

#define foreach_snap_cisco_protocol		\
  _ (0x0102, drip)				\
  _ (0x0104, port_aggregation_protocol)		\
  _ (0x0105, mls_hello)				\
  _ (0x010b, per_vlan_spanning_tree)		\
  _ (0x010c, vlan_bridge)			\
  _ (0x0111, unidirectional_link_detection)	\
  _ (0x2000, cdp)				\
  _ (0x2001, cgmp)				\
  _ (0x2003, vtp)				\
  _ (0x2004, dtp)				\
  _ (0x200a, stp_uplink_fast)

typedef enum
{
#define _(n,f) SNAP_cisco_##f = n,
  foreach_snap_cisco_protocol
#undef _
} snap_cisco_protocol_t;

typedef union
{
  /* *INDENT-OFF* */
  CLIB_PACKED (struct {
    /* OUI: organization unique identifier. */
    u8 oui[3];

    /* Per-OUI protocol. */
    u16 protocol;
  });
  /* *INDENT-ON* */

  u8 as_u8[5];
} snap_header_t;

typedef struct
{
  u32 oui;
  u32 protocol;
} snap_oui_and_protocol_t;

typedef struct
{
  /* Name vector string. */
  u8 *name;

  snap_oui_and_protocol_t oui_and_protocol;

  /* Node which handles this type. */
  u32 node_index;

  /* snap-input next index for this type. */
  u32 next_index;
} snap_protocol_info_t;

always_inline void
snap_header_set_protocol (snap_header_t * h, snap_oui_and_protocol_t * p)
{
  u16 protocol = p->protocol;
  u32 oui = p->oui;
  h->protocol = clib_host_to_net_u16 (protocol);
  h->oui[0] = (oui >> 16) & 0xff;
  h->oui[1] = (oui >> 8) & 0xff;
  h->oui[2] = (oui >> 0) & 0xff;
}

#define foreach_snap_error			\
  _ (NONE, "no error")				\
  _ (UNKNOWN_PROTOCOL, "unknown oui/snap protocol")

typedef enum
{
#define _(f,s) SNAP_ERROR_##f,
  foreach_snap_error
#undef _
    SNAP_N_ERROR,
} snap_error_t;

typedef struct
{
  vlib_main_t *vlib_main;

  /* Vector of known SNAP oui/protocol pairs. */
  snap_protocol_info_t *protocols;

  /* Hash table mapping oui/protocol to protocol index. */
  mhash_t protocol_hash;

  /* Hash table mapping protocol by name. */
  uword *protocol_info_by_name;
} snap_main_t;

always_inline u32
snap_header_get_oui (snap_header_t * h)
{
  return (h->oui[0] << 16) | (h->oui[1] << 8) | h->oui[2];
}

always_inline snap_protocol_info_t *
snap_get_protocol_info (snap_main_t * sm, snap_header_t * h)
{
  snap_oui_and_protocol_t key;
  uword *p;

  key.oui = snap_header_get_oui (h);
  key.protocol = h->protocol;

  p = mhash_get (&sm->protocol_hash, &key);
  return p ? vec_elt_at_index (sm->protocols, p[0]) : 0;
}

snap_main_t snap_main;

/* Register given node index to take input for given snap type. */
void
snap_register_input_protocol (vlib_main_t * vm,
			      char *name,
			      u32 ieee_oui, u16 protocol, u32 node_index);

format_function_t format_snap_protocol;
format_function_t format_snap_header;
format_function_t format_snap_header_with_length;

/* Parse snap protocol as 0xXXXX or protocol name. */
unformat_function_t unformat_snap_protocol;

/* Parse snap header. */
unformat_function_t unformat_snap_header;
unformat_function_t unformat_pg_snap_header;

always_inline void
snap_setup_node (vlib_main_t * vm, u32 node_index)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  pg_node_t *pn = pg_get_node (node_index);

  n->format_buffer = format_snap_header_with_length;
  n->unformat_buffer = unformat_snap_header;
  pn->unformat_edit = unformat_pg_snap_header;
}

#endif /* included_snap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
