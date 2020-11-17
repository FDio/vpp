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

  /**
   * this adj performs IP4 over IP4 fixup
   */
  VNET_REWRITE_FIXUP_IP4_O_4 = (1 << 1),

  /**
   * this adj performs the flow hash fixup
   */
  VNET_REWRITE_FIXUP_FLOW_HASH = (1 << 2),
} __attribute__ ((packed)) vnet_rewrite_flags_t;

typedef struct vnet_rewrite_header_t_
{
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
} __clib_packed vnet_rewrite_header_t;

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
#define VNET_DECLARE_REWRITE                         \
  struct                                             \
  {                                                  \
    vnet_rewrite_header_t rewrite_header;            \
                                                     \
    u8 rewrite_data[(VNET_REWRITE_TOTAL_BYTES) -     \
                    sizeof (vnet_rewrite_header_t)]; \
  }

typedef struct __rewrite_unused_t__
{
  VNET_DECLARE_REWRITE;
} __rewrite_unused_t;

STATIC_ASSERT_SIZEOF (__rewrite_unused_t, 128);

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
  clib_memcpy_fast (rw->data, data, data_bytes);
  clib_memset (rw->data + data_bytes, 0xfe, max_size - data_bytes);
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
  return rw->data;
}

#define vnet_rewrite_get_data(rw) \
  vnet_rewrite_get_data_internal (&((rw).rewrite_header), sizeof ((rw).rewrite_data))

always_inline void
_vnet_rewrite_one_header (const vnet_rewrite_header_t * h0,
			  void *packet0, int most_likely_size)
{
  /* 0xfefe => poisoned adjacency => crash */
  ASSERT (h0->data_bytes != 0xfefe);
  if (PREDICT_TRUE (most_likely_size == h0->data_bytes))
    {
      clib_memcpy_fast ((u8 *) packet0 - most_likely_size,
			h0->data, most_likely_size);
    }
  else
    {
      clib_memcpy_fast ((u8 *) packet0 - h0->data_bytes,
			h0->data, h0->data_bytes);
    }
}

always_inline void
_vnet_rewrite_two_headers (const vnet_rewrite_header_t * h0,
			   const vnet_rewrite_header_t * h1,
			   void *packet0, void *packet1, int most_likely_size)
{
  /* 0xfefe => poisoned adjacency => crash */
  ASSERT (h0->data_bytes != 0xfefe);
  ASSERT (h1->data_bytes != 0xfefe);
  if (PREDICT_TRUE
      (most_likely_size == h0->data_bytes
       && most_likely_size == h1->data_bytes))
    {
      clib_memcpy_fast ((u8 *) packet0 - most_likely_size,
			h0->data, most_likely_size);
      clib_memcpy_fast ((u8 *) packet1 - most_likely_size,
			h1->data, most_likely_size);
    }
  else
    {
      clib_memcpy_fast ((u8 *) packet0 - h0->data_bytes,
			h0->data, h0->data_bytes);
      clib_memcpy_fast ((u8 *) packet1 - h1->data_bytes,
			h1->data, h1->data_bytes);
    }
}

#define vnet_rewrite_one_header(rw0,p0,most_likely_size)	\
  _vnet_rewrite_one_header (&((rw0).rewrite_header), (p0),	\
			    (most_likely_size))

#define vnet_rewrite_two_headers(rw0,rw1,p0,p1,most_likely_size)	\
  _vnet_rewrite_two_headers (&((rw0).rewrite_header), &((rw1).rewrite_header), \
			     (p0), (p1),				\
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
