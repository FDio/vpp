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
 * vnet/buffer.h: vnet buffer flags
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

#ifndef included_vnet_buffer_h
#define included_vnet_buffer_h

#include <vlib/vlib.h>

#define foreach_vnet_buffer_field \
  _( 1, L4_CHECKSUM_COMPUTED)				\
  _( 2, L4_CHECKSUM_CORRECT)				\
  _( 3, VLAN_2_DEEP)					\
  _( 4, VLAN_1_DEEP)					\
  _( 8, SPAN_CLONE)					\
  _( 6, HANDOFF_NEXT_VALID)				\
  _( 7, LOCALLY_ORIGINATED)				\
  _( 8, IS_IP4)						\
  _( 9, IS_IP6)						\
  _(10, OFFLOAD_IP_CKSUM)				\
  _(11, OFFLOAD_TCP_CKSUM)				\
  _(12, OFFLOAD_UDP_CKSUM)

#define VNET_BUFFER_FLAGS_VLAN_BITS \
  (VNET_BUFFER_F_VLAN_1_DEEP | VNET_BUFFER_F_VLAN_2_DEEP)

enum
{
#define _(bit, name) VNET_BUFFER_F_##name  = (1 << LOG2_VLIB_BUFFER_FLAG_USER(bit)),
  foreach_vnet_buffer_field
#undef _
};

enum
{
#define _(bit, name) VNET_BUFFER_F_LOG2_##name  = LOG2_VLIB_BUFFER_FLAG_USER(bit),
  foreach_vnet_buffer_field
#undef _
};


#define foreach_buffer_opaque_union_subtype     \
_(ip)                                           \
_(swt)                                          \
_(l2)                                           \
_(l2t)                                          \
_(gre)                                          \
_(l2_classify)                                  \
_(handoff)                                      \
_(policer)                                      \
_(ipsec)					\
_(map)						\
_(map_t)					\
_(ip_frag)					\
_(tcp)

/*
 * vnet stack buffer opaque array overlay structure.
 * The vnet_buffer_opaque_t *must* be the same size as the
 * vlib_buffer_t "opaque" structure member, 32 bytes.
 *
 * When adding a union type, please add a stanza to
 * foreach_buffer_opaque_union_subtype (directly above).
 * Code in vnet_interface_init(...) verifies the size
 * of the union, and will announce any deviations in an
 * impossible-to-miss manner.
 */
typedef struct
{
  u32 sw_if_index[VLIB_N_RX_TX];
  i16 l2_hdr_offset;
  i16 l3_hdr_offset;
  i16 l4_hdr_offset;

  union
  {
    /* IP4/6 buffer opaque. */
    struct
    {
      /* Adjacency from destination IP address lookup [VLIB_TX].
         Adjacency from source IP address lookup [VLIB_RX].
         This gets set to ~0 until source lookup is performed. */
      u32 adj_index[VLIB_N_RX_TX];

      union
      {
	struct
	{
	  /* Flow hash value for this packet computed from IP src/dst address
	     protocol and ports. */
	  u32 flow_hash;

	  /* next protocol */
	  u32 save_protocol;

	  /* Rewrite length */
	  u32 save_rewrite_length;

	  /* MFIB RPF ID */
	  u32 rpf_id;
	};

	/* ICMP */
	struct
	{
	  u8 type;
	  u8 code;
	  u32 data;
	} icmp;
      };

    } ip;

    /*
     * MPLS:
     * data copied from the MPLS header that was popped from the packet
     * during the look-up.
     */
    struct
    {
      u8 ttl;
      u8 exp;
      u8 first;
    } mpls;

    /* ip4-in-ip6 softwire termination, only valid there */
    struct
    {
      u8 swt_disable;
      u32 mapping_index;
    } swt;

    /* l2 bridging path, only valid there */
    struct opaque_l2
    {
      u32 feature_bitmap;
      u16 bd_index;		/* bridge-domain index */
      u8 l2_len;		/* ethernet header length */
      u8 shg;			/* split-horizon group */
      u16 l2fib_sn;		/* l2fib bd/int seq_num */
    } l2;

    /* l2tpv3 softwire encap, only valid there */
    struct
    {
      u32 pad[4];		/* do not overlay w/ ip.adj_index[0,1] */
      u8 next_index;
      u32 session_index;
    } l2t;

    struct
    {
      u32 src, dst;
    } gre;

    /* L2 classify */
    struct
    {
      struct opaque_l2 pad;
      union
      {
	u32 table_index;
	u32 opaque_index;
      };
      u64 hash;
    } l2_classify;

    /* IO - worker thread handoff */
    struct
    {
      u32 next_index;
    } handoff;

    /* vnet policer */
    struct
    {
      u32 pad[8 - VLIB_N_RX_TX - 1];	/* to end of opaque */
      u32 index;
    } policer;

    /* interface output features */
    struct
    {
      u32 flags;
      u32 sad_index;
    } ipsec;

    /* MAP */
    struct
    {
      u16 mtu;
    } map;

    /* MAP-T */
    struct
    {
      u32 map_domain_index;
      struct
      {
	u32 saddr, daddr;
	u16 frag_offset;	//Fragmentation header offset
	u16 l4_offset;		//L4 header overall offset
	u8 l4_protocol;		//The final protocol number
      } v6;			//Used by ip6_map_t only
      u16 checksum_offset;	//L4 checksum overall offset
      u16 mtu;			//Exit MTU
    } map_t;

    /* IP Fragmentation */
    struct
    {
      u16 header_offset;
      u16 mtu;
      u8 next_index;
      u8 flags;			//See ip_frag.h
    } ip_frag;

    /* COP - configurable junk filter(s) */
    struct
    {
      /* Current configuration index. */
      u32 current_config_index;
    } cop;

    /* LISP */
    struct
    {
      /* overlay address family */
      u16 overlay_afi;
    } lisp;

    /* Driver rx feature */
    struct
    {
      u32 saved_next_index;		/**< saved by drivers for short-cut */
      u16 buffer_advance;
    } device_input_feat;

    /* TCP */
    struct
    {
      u32 connection_index;
      u32 seq_number;
      u32 seq_end;
      u32 ack_number;
      u16 hdr_offset;		/**< offset relative to ip hdr */
      u16 data_offset;		/**< offset relative to ip hdr */
      u16 data_len;		/**< data len */
      u8 flags;
    } tcp;

    /* SNAT */
    struct
    {
      u32 flags;
    } snat;

    u32 unused[6];
  };
} vnet_buffer_opaque_t;

/*
 * The opaque field of the vlib_buffer_t is intepreted as a
 * vnet_buffer_opaque_t. Hence it should be big enough to accommodate one.
 */
STATIC_ASSERT (sizeof (vnet_buffer_opaque_t) <=
	       STRUCT_SIZE_OF (vlib_buffer_t, opaque),
	       "VNET buffer meta-data too large for vlib_buffer");

#define vnet_buffer(b) ((vnet_buffer_opaque_t *) (b)->opaque)

/* Full cache line (64 bytes) of additional space */
typedef struct
{
  union
  {
  };
} vnet_buffer_opaque2_t;



#endif /* included_vnet_buffer_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
