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
 * hdlc.h: types/functions for hdlc.
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

#ifndef included_hdlc_h
#define included_hdlc_h

#include <vnet/vnet.h>
#include <vnet/hdlc/packet.h>
#include <vnet/pg/pg.h>

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

always_inline void
hdlc_setup_node (vlib_main_t * vm, u32 node_index)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  pg_node_t *pn = pg_get_node (node_index);

  n->format_buffer = format_hdlc_header_with_length;
  n->unformat_buffer = unformat_hdlc_header;
  pn->unformat_edit = unformat_pg_hdlc_header;
}

void
hdlc_register_input_protocol (vlib_main_t * vm,
			      hdlc_protocol_t protocol, u32 node_index);

#endif /* included_hdlc_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
