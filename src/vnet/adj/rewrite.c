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
 * rewrite.c: packet rewrite
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

#include <vnet/vnet.h>
#include <vnet/ip/lookup.h>

void
vnet_rewrite_copy_slow_path (vnet_rewrite_data_t * p0,
			     vnet_rewrite_data_t * rw0,
			     word n_left, uword most_likely_size)
{
  uword n_done =
    round_pow2 (most_likely_size, sizeof (rw0[0])) / sizeof (rw0[0]);

  p0 -= n_done;
  rw0 -= n_done;

  /* As we enter the cleanup loop, p0 and rw0 point to the last chunk written
     by the fast path. Hence, the constant 1, which the
     vnet_rewrite_copy_one macro renders as p0[-1] = rw0[-1]. */

  while (n_left > 0)
    {
      vnet_rewrite_copy_one (p0, rw0, 1);
      p0--;
      rw0--;
      n_left--;
    }
}

u8 *
format_vnet_rewrite (u8 * s, va_list * args)
{
  vnet_rewrite_header_t *rw = va_arg (*args, vnet_rewrite_header_t *);
  u32 max_data_bytes = va_arg (*args, u32);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);
  vnet_main_t *vnm = vnet_get_main ();

  if (rw->sw_if_index != ~0)
    {
      vnet_sw_interface_t *si;
      si = vnet_get_sw_interface_safe (vnm, rw->sw_if_index);
      if (NULL != si)
	s = format (s, "%U: ", format_vnet_sw_interface_name, vnm, si);
      else
	s = format (s, "DELETED:%d", rw->sw_if_index);
    }

  /* Format rewrite string. */
  if (rw->data_bytes > 0)

    s = format (s, "%U",
		format_hex_bytes,
		rw->data + max_data_bytes - rw->data_bytes, rw->data_bytes);

  return s;
}

u32
vnet_tx_node_index_for_sw_interface (vnet_main_t * vnm, u32 sw_if_index)
{
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  return (hw->output_node_index);
}

void
vnet_rewrite_init (vnet_main_t * vnm,
		   u32 sw_if_index,
		   u32 this_node, u32 next_node, vnet_rewrite_header_t * rw)
{
  rw->sw_if_index = sw_if_index;
  rw->next_index = vlib_node_add_next (vnm->vlib_main, this_node, next_node);
  rw->max_l3_packet_bytes =
    vnet_sw_interface_get_mtu (vnm, sw_if_index, VLIB_TX);
}

void
vnet_rewrite_for_sw_interface (vnet_main_t * vnm,
			       vnet_link_t link_type,
			       u32 sw_if_index,
			       u32 node_index,
			       void *dst_address,
			       vnet_rewrite_header_t * rw,
			       u32 max_rewrite_bytes)
{

  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  vnet_hw_interface_class_t *hc =
    vnet_get_hw_interface_class (vnm, hw->hw_class_index);
  u8 *rewrite = NULL;

  vnet_rewrite_init (vnm, sw_if_index, node_index,
		     vnet_tx_node_index_for_sw_interface (vnm, sw_if_index),
		     rw);

  ASSERT (hc->build_rewrite);
  rewrite = hc->build_rewrite (vnm, sw_if_index, link_type, dst_address);

  ASSERT (vec_len (rewrite) < max_rewrite_bytes);
  vnet_rewrite_set_data_internal (rw, max_rewrite_bytes, rewrite,
				  vec_len (rewrite));
  vec_free (rewrite);
}

void
vnet_rewrite_for_tunnel (vnet_main_t * vnm,
			 u32 tx_sw_if_index,
			 u32 rewrite_node_index,
			 u32 post_rewrite_node_index,
			 vnet_rewrite_header_t * rw,
			 u8 * rewrite_data, u32 rewrite_length)
{
  ip_adjacency_t *adj = 0;
  /*
   * Installed into vnet_buffer(b)->sw_if_index[VLIB_TX] e.g.
   * by ip4_rewrite_inline. If the post-rewrite node injects into
   * ipX-forward, this will be interpreted as a FIB number.
   */
  rw->sw_if_index = tx_sw_if_index;
  rw->next_index = vlib_node_add_next (vnm->vlib_main, rewrite_node_index,
				       post_rewrite_node_index);
  rw->max_l3_packet_bytes = (u16) ~ 0;	/* we can't know at this point */

  ASSERT (rewrite_length < sizeof (adj->rewrite_data));
  /* Leave room for ethernet + VLAN tag */
  vnet_rewrite_set_data_internal (rw, sizeof (adj->rewrite_data),
				  rewrite_data, rewrite_length);
}

void
serialize_vnet_rewrite (serialize_main_t * m, va_list * va)
{
  vnet_rewrite_header_t *rw = va_arg (*va, vnet_rewrite_header_t *);
  u32 max_data_bytes = va_arg (*va, u32);
  u8 *p;

  serialize_integer (m, rw->sw_if_index, sizeof (rw->sw_if_index));
  serialize_integer (m, rw->data_bytes, sizeof (rw->data_bytes));
  serialize_integer (m, rw->max_l3_packet_bytes,
		     sizeof (rw->max_l3_packet_bytes));
  p = serialize_get (m, rw->data_bytes);
  clib_memcpy (p, vnet_rewrite_get_data_internal (rw, max_data_bytes),
	       rw->data_bytes);
}

void
unserialize_vnet_rewrite (serialize_main_t * m, va_list * va)
{
  vnet_rewrite_header_t *rw = va_arg (*va, vnet_rewrite_header_t *);
  u32 max_data_bytes = va_arg (*va, u32);
  u8 *p;

  /* It is up to user to fill these in. */
  rw->next_index = ~0;

  unserialize_integer (m, &rw->sw_if_index, sizeof (rw->sw_if_index));
  unserialize_integer (m, &rw->data_bytes, sizeof (rw->data_bytes));
  unserialize_integer (m, &rw->max_l3_packet_bytes,
		       sizeof (rw->max_l3_packet_bytes));
  p = unserialize_get (m, rw->data_bytes);
  clib_memcpy (vnet_rewrite_get_data_internal (rw, max_data_bytes), p,
	       rw->data_bytes);
}

u8 *
vnet_build_rewrite_for_sw_interface (vnet_main_t * vnm,
				     u32 sw_if_index,
				     vnet_link_t link_type,
				     const void *dst_address)
{
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  vnet_hw_interface_class_t *hc =
    vnet_get_hw_interface_class (vnm, hw->hw_class_index);

  ASSERT (hc->build_rewrite);
  return (hc->build_rewrite (vnm, sw_if_index, link_type, dst_address));
}


void
vnet_update_adjacency_for_sw_interface (vnet_main_t * vnm,
					u32 sw_if_index, u32 ai)
{
  vnet_hw_interface_t *hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  vnet_hw_interface_class_t *hc =
    vnet_get_hw_interface_class (vnm, hw->hw_class_index);

  ASSERT (hc->update_adjacency);
  hc->update_adjacency (vnm, sw_if_index, ai);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
