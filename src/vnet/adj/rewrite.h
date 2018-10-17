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
 * rewrite.h: packet rewrite
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

#ifndef included_vnet_rewrite_h
#define included_vnet_rewrite_h

#include <vlib/vlib.h>
#include <vnet/l3_types.h>

/* Consider using vector types for speed? */
typedef uword vnet_rewrite_data_t;

/**
 * Flags associated with the rewrite/adjacency
 */
typedef enum vnet_rewrite_flags_t_
{
  /**
   * This adjacency/interface has output features configured
   */
  VNET_REWRITE_HAS_FEATURES = (1 << 0),
} __attribute__ ((packed)) vnet_rewrite_flags_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  /* Interface to mark re-written packets with. */
  u32 sw_if_index;

  /* Next node to feed after packet rewrite is done. */
  u16 next_index;

  /* Number of bytes in rewrite data. */
  u16 data_bytes;

  /* Max packet size layer 3 (MTU) for output interface.
     Used for MTU check after packet rewrite. */
  u16 max_l3_packet_bytes;

  /* Data-plane flags on the adjacency/rewrite */
  vnet_rewrite_flags_t flags;

  /* When dynamically writing a multicast destination L2 addresss
   * this is the offset from the IP address at which to write in the
   * IP->MAC address translation.
   */
  u8 dst_mcast_offset;

  /* Rewrite string starting at end and going backwards. */
  u8 data[0];
}) vnet_rewrite_header_t;
/* *INDENT-ON* */

/**
 * At 16 bytes of rewrite herader we have enought space left for a IPv6
 * (40 bytes) + LISP-GPE (8 bytes) in the cache line
 */
STATIC_ASSERT (sizeof (vnet_rewrite_header_t) <= 16,
	       "Rewrite header too big");

/*
  Helper macro for declaring rewrite string w/ given max-size.

  Typical usage:
    typedef struct {
      //
      int a, b;

      // Total adjacency is 64 bytes.
      vnet_rewrite_declare(64 - 2*sizeof(int)) rw;
    } my_adjacency_t;
*/
#define vnet_declare_rewrite(total_bytes)				\
struct {								\
  vnet_rewrite_header_t rewrite_header;  			        \
									\
  u8 rewrite_data[(total_bytes) - sizeof (vnet_rewrite_header_t)];	\
}

always_inline void
vnet_rewrite_clear_data_internal (vnet_rewrite_header_t * rw, int max_size)
{
  /* Sanity check values carefully for this clib_memset operation */
  ASSERT ((max_size > 0) && (max_size < VLIB_BUFFER_PRE_DATA_SIZE));

  rw->data_bytes = 0;
  clib_memset (rw->data, 0xfe, max_size);
}

always_inline void
vnet_rewrite_set_data_internal (vnet_rewrite_header_t * rw,
				int max_size, void *data, int data_bytes)
{
  /* Sanity check values carefully for this clib_memset operation */
  ASSERT ((max_size > 0) && (max_size < VLIB_BUFFER_PRE_DATA_SIZE));
  ASSERT ((data_bytes >= 0) && (data_bytes < max_size));

  rw->data_bytes = data_bytes;
  clib_memcpy (rw->data + max_size - data_bytes, data, data_bytes);
  clib_memset (rw->data, 0xfe, max_size - data_bytes);
}

#define vnet_rewrite_set_data(rw,data,data_bytes)		\
  vnet_rewrite_set_data_internal (&((rw).rewrite_header),	\
				  sizeof ((rw).rewrite_data),	\
				  (data),			\
				  (data_bytes))

always_inline void *
vnet_rewrite_get_data_internal (vnet_rewrite_header_t * rw, int max_size)
{
  ASSERT (rw->data_bytes <= max_size);
  return rw->data + max_size - rw->data_bytes;
}

#define vnet_rewrite_get_data(rw) \
  vnet_rewrite_get_data_internal (&((rw).rewrite_header), sizeof ((rw).rewrite_data))

always_inline void
vnet_rewrite_copy_one (vnet_rewrite_data_t * p0, vnet_rewrite_data_t * rw0,
		       int i)
{
  p0[-i] = rw0[-i];
}

void vnet_rewrite_copy_slow_path (vnet_rewrite_data_t * p0,
				  vnet_rewrite_data_t * rw0,
				  word n_left, uword most_likely_size);

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u64 a;
  u32 b;
  u16 c;
}) eh_copy_t;
/* *INDENT-ON* */

always_inline void
_vnet_rewrite_one_header (vnet_rewrite_header_t * h0,
			  void *packet0, int max_size, int most_likely_size)
{
  vnet_rewrite_data_t *p0 = packet0;
  vnet_rewrite_data_t *rw0 = (vnet_rewrite_data_t *) (h0->data + max_size);
  word n_left0;

  /* 0xfefe => poisoned adjacency => crash */
  ASSERT (h0->data_bytes != 0xfefe);

  if (PREDICT_TRUE (h0->data_bytes == sizeof (eh_copy_t)))
    {
      eh_copy_t *s, *d;
      s = (eh_copy_t *) (h0->data + max_size - sizeof (eh_copy_t));
      d = (eh_copy_t *) (((u8 *) packet0) - sizeof (eh_copy_t));
      clib_memcpy (d, s, sizeof (eh_copy_t));
      return;
    }


#define _(i)								\
  do {									\
    if (most_likely_size > ((i)-1)*sizeof (vnet_rewrite_data_t))	\
      vnet_rewrite_copy_one (p0, rw0, (i));				\
  } while (0)

  _(4);
  _(3);
  _(2);
  _(1);

#undef _

  n_left0 = (int)
    (((int) h0->data_bytes - most_likely_size) + (sizeof (rw0[0]) - 1))
    / (int) sizeof (rw0[0]);
  if (PREDICT_FALSE (n_left0 > 0))
    vnet_rewrite_copy_slow_path (p0, rw0, n_left0, most_likely_size);
}

always_inline void
_vnet_rewrite_two_headers (vnet_rewrite_header_t * h0,
			   vnet_rewrite_header_t * h1,
			   void *packet0,
			   void *packet1, int max_size, int most_likely_size)
{
  vnet_rewrite_data_t *p0 = packet0;
  vnet_rewrite_data_t *p1 = packet1;
  vnet_rewrite_data_t *rw0 = (vnet_rewrite_data_t *) (h0->data + max_size);
  vnet_rewrite_data_t *rw1 = (vnet_rewrite_data_t *) (h1->data + max_size);
  word n_left0, n_left1;
  int slow_path;

  /* 0xfefe => poisoned adjacency => crash */
  ASSERT (h0->data_bytes != 0xfefe);
  ASSERT (h1->data_bytes != 0xfefe);

  /* Arithmetic calculation: bytes0 == bytes1 == 14 */
  slow_path = h0->data_bytes ^ h1->data_bytes;
  slow_path += h0->data_bytes ^ sizeof (eh_copy_t);

  if (PREDICT_TRUE (slow_path == 0))
    {
      eh_copy_t *s0, *d0, *s1, *d1;
      s0 = (eh_copy_t *) (h0->data + max_size - sizeof (eh_copy_t));
      d0 = (eh_copy_t *) (((u8 *) packet0) - sizeof (eh_copy_t));
      clib_memcpy (d0, s0, sizeof (eh_copy_t));
      s1 = (eh_copy_t *) (h1->data + max_size - sizeof (eh_copy_t));
      d1 = (eh_copy_t *) (((u8 *) packet1) - sizeof (eh_copy_t));
      clib_memcpy (d1, s1, sizeof (eh_copy_t));
      return;
    }

#define _(i)								\
  do {									\
    if (most_likely_size > ((i)-1)*sizeof (vnet_rewrite_data_t))	\
      {									\
	vnet_rewrite_copy_one (p0, rw0, (i));				\
	vnet_rewrite_copy_one (p1, rw1, (i));				\
      }									\
  } while (0)

  _(4);
  _(3);
  _(2);
  _(1);

#undef _

  n_left0 = (int)
    (((int) h0->data_bytes - most_likely_size) + (sizeof (rw0[0]) - 1))
    / (int) sizeof (rw0[0]);
  n_left1 = (int)
    (((int) h1->data_bytes - most_likely_size) + (sizeof (rw1[0]) - 1))
    / (int) sizeof (rw1[0]);

  if (PREDICT_FALSE (n_left0 > 0 || n_left1 > 0))
    {
      vnet_rewrite_copy_slow_path (p0, rw0, n_left0, most_likely_size);
      vnet_rewrite_copy_slow_path (p1, rw1, n_left1, most_likely_size);
    }
}

#define vnet_rewrite_one_header(rw0,p0,most_likely_size)	\
  _vnet_rewrite_one_header (&((rw0).rewrite_header), (p0),	\
			    sizeof ((rw0).rewrite_data),	\
			    (most_likely_size))

#define vnet_rewrite_two_headers(rw0,rw1,p0,p1,most_likely_size)	\
  _vnet_rewrite_two_headers (&((rw0).rewrite_header), &((rw1).rewrite_header), \
			     (p0), (p1),				\
			     sizeof ((rw0).rewrite_data),		\
			     (most_likely_size))

always_inline void
vnet_ip_mcast_fixup_header (u32 dst_mcast_mask,
			    u32 dst_mcast_offset, u32 * addr, u8 * packet0)
{
  if (PREDICT_TRUE (0 != dst_mcast_offset))
    {
      /* location to write to in the packet */
      u8 *p0 = packet0 - dst_mcast_offset;
      u32 *p1 = (u32 *) p0;

      *p1 |= (*addr & dst_mcast_mask);
    }
}

#define VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST ((void *) 0)
/** Deprecated */
void vnet_rewrite_for_sw_interface (struct vnet_main_t *vnm,
				    vnet_link_t packet_type,
				    u32 sw_if_index,
				    u32 node_index,
				    void *dst_address,
				    vnet_rewrite_header_t * rw,
				    u32 max_rewrite_bytes);

u32 vnet_tx_node_index_for_sw_interface (struct vnet_main_t *vnm,
					 u32 sw_if_index);

void vnet_rewrite_init (struct vnet_main_t *vnm,
			u32 sw_if_index,
			vnet_link_t linkt,
			u32 this_node,
			u32 next_node, vnet_rewrite_header_t * rw);

void vnet_rewrite_update_mtu (struct vnet_main_t *vnm,
			      vnet_link_t linkt, vnet_rewrite_header_t * rw);

u8 *vnet_build_rewrite_for_sw_interface (struct vnet_main_t *vnm,
					 u32 sw_if_index,
					 vnet_link_t packet_type,
					 const void *dst_address);
void vnet_update_adjacency_for_sw_interface (struct vnet_main_t *vnm,
					     u32 sw_if_index, u32 ai);

format_function_t format_vnet_rewrite;

serialize_function_t serialize_vnet_rewrite, unserialize_vnet_rewrite;

#endif /* included_vnet_rewrite_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
