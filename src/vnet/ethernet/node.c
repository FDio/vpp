/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 * ethernet_node.c: ethernet packet processing
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

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/p2p_ethernet.h>
#include <vnet/devices/pipe/pipe.h>
#include <vppinfra/sparse_vec.h>
#include <vnet/l2/l2_bvi.h>


#define foreach_ethernet_input_next		\
  _ (PUNT, "error-punt")			\
  _ (DROP, "error-drop")			\
  _ (LLC, "llc-input")				\
  _ (IP4_INPUT, "ip4-input")			\
  _ (IP4_INPUT_NCS, "ip4-input-no-checksum")

typedef enum
{
#define _(s,n) ETHERNET_INPUT_NEXT_##s,
  foreach_ethernet_input_next
#undef _
    ETHERNET_INPUT_N_NEXT,
} ethernet_input_next_t;

typedef struct
{
  u8 packet_data[32];
  u16 frame_flags;
  ethernet_input_frame_t frame_data;
} ethernet_input_trace_t;

static u8 *
format_ethernet_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ethernet_input_trace_t *t = va_arg (*va, ethernet_input_trace_t *);
  u32 indent = format_get_indent (s);

  if (t->frame_flags)
    {
      s = format (s, "frame: flags 0x%x", t->frame_flags);
      if (t->frame_flags & ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX)
	s = format (s, ", hw-if-index %u, sw-if-index %u",
		    t->frame_data.hw_if_index, t->frame_data.sw_if_index);
      s = format (s, "\n%U", format_white_space, indent);
    }
  s = format (s, "%U", format_ethernet_header, t->packet_data);

  return s;
}

extern vlib_node_registration_t ethernet_input_node;

typedef enum
{
  ETHERNET_INPUT_VARIANT_ETHERNET,
  ETHERNET_INPUT_VARIANT_ETHERNET_TYPE,
  ETHERNET_INPUT_VARIANT_NOT_L2,
} ethernet_input_variant_t;


// Parse the ethernet header to extract vlan tags and innermost ethertype
static_always_inline void
parse_header (ethernet_input_variant_t variant,
	      vlib_buffer_t * b0,
	      u16 * type,
	      u16 * orig_type,
	      u16 * outer_id, u16 * inner_id, u32 * match_flags)
{
  u8 vlan_count;

  if (variant == ETHERNET_INPUT_VARIANT_ETHERNET
      || variant == ETHERNET_INPUT_VARIANT_NOT_L2)
    {
      ethernet_header_t *e0;

      e0 = (void *) (b0->data + b0->current_data);

      vnet_buffer (b0)->l2_hdr_offset = b0->current_data;
      b0->flags |= VNET_BUFFER_F_L2_HDR_OFFSET_VALID;

      vlib_buffer_advance (b0, sizeof (e0[0]));

      *type = clib_net_to_host_u16 (e0->type);
    }
  else if (variant == ETHERNET_INPUT_VARIANT_ETHERNET_TYPE)
    {
      // here when prior node was LLC/SNAP processing
      u16 *e0;

      e0 = (void *) (b0->data + b0->current_data);

      vlib_buffer_advance (b0, sizeof (e0[0]));

      *type = clib_net_to_host_u16 (e0[0]);
    }

  // save for distinguishing between dot1q and dot1ad later
  *orig_type = *type;

  // default the tags to 0 (used if there is no corresponding tag)
  *outer_id = 0;
  *inner_id = 0;

  *match_flags = SUBINT_CONFIG_VALID | SUBINT_CONFIG_MATCH_0_TAG;
  vlan_count = 0;

  // check for vlan encaps
  if (ethernet_frame_is_tagged (*type))
    {
      ethernet_vlan_header_t *h0;
      u16 tag;

      *match_flags = SUBINT_CONFIG_VALID | SUBINT_CONFIG_MATCH_1_TAG;

      h0 = (void *) (b0->data + b0->current_data);

      tag = clib_net_to_host_u16 (h0->priority_cfi_and_id);

      *outer_id = tag & 0xfff;
      if (0 == *outer_id)
	*match_flags &= ~SUBINT_CONFIG_MATCH_1_TAG;

      *type = clib_net_to_host_u16 (h0->type);

      vlib_buffer_advance (b0, sizeof (h0[0]));
      vlan_count = 1;

      if (*type == ETHERNET_TYPE_VLAN)
	{
	  // Double tagged packet
	  *match_flags = SUBINT_CONFIG_VALID | SUBINT_CONFIG_MATCH_2_TAG;

	  h0 = (void *) (b0->data + b0->current_data);

	  tag = clib_net_to_host_u16 (h0->priority_cfi_and_id);

	  *inner_id = tag & 0xfff;

	  *type = clib_net_to_host_u16 (h0->type);

	  vlib_buffer_advance (b0, sizeof (h0[0]));
	  vlan_count = 2;
	  if (*type == ETHERNET_TYPE_VLAN)
	    {
	      // More than double tagged packet
	      *match_flags = SUBINT_CONFIG_VALID | SUBINT_CONFIG_MATCH_3_TAG;

	      vlib_buffer_advance (b0, sizeof (h0[0]));
	      vlan_count = 3;	// "unknown" number, aka, 3-or-more
	    }
	}
    }
  ethernet_buffer_set_vlan_count (b0, vlan_count);
}

// Determine the subinterface for this packet, given the result of the
// vlan table lookups and vlan header parsing. Check the most specific
// matches first.
static_always_inline void
identify_subint (vnet_hw_interface_t * hi,
		 vlib_buffer_t * b0,
		 u32 match_flags,
		 main_intf_t * main_intf,
		 vlan_intf_t * vlan_intf,
		 qinq_intf_t * qinq_intf,
		 u32 * new_sw_if_index, u8 * error0, u32 * is_l2)
{
  u32 matched;

  matched = eth_identify_subint (hi, match_flags, main_intf, vlan_intf,
				 qinq_intf, new_sw_if_index, error0, is_l2);

  if (matched)
    {

      // Perform L3 my-mac filter
      // A unicast packet arriving on an L3 interface must have a dmac matching the interface mac.
      // This is required for promiscuous mode, else we will forward packets we aren't supposed to.
      if (!(*is_l2))
	{
	  ethernet_header_t *e0;
	  e0 = (void *) (b0->data + vnet_buffer (b0)->l2_hdr_offset);

	  if (!(ethernet_address_cast (e0->dst_address)))
	    {
	      if (!eth_mac_equal ((u8 *) e0, hi->hw_address))
		{
		  *error0 = ETHERNET_ERROR_L3_MAC_MISMATCH;
		}
	    }
	}

      // Check for down subinterface
      *error0 = (*new_sw_if_index) != ~0 ? (*error0) : ETHERNET_ERROR_DOWN;
    }
}

static_always_inline void
determine_next_node (ethernet_main_t * em,
		     ethernet_input_variant_t variant,
		     u32 is_l20,
		     u32 type0, vlib_buffer_t * b0, u8 * error0, u8 * next0)
{
  vnet_buffer (b0)->l3_hdr_offset = b0->current_data;
  b0->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;

  if (PREDICT_FALSE (*error0 != ETHERNET_ERROR_NONE))
    {
      // some error occurred
      *next0 = ETHERNET_INPUT_NEXT_DROP;
    }
  else if (is_l20)
    {
      // record the L2 len and reset the buffer so the L2 header is preserved
      u32 eth_start = vnet_buffer (b0)->l2_hdr_offset;
      vnet_buffer (b0)->l2.l2_len = b0->current_data - eth_start;
      *next0 = em->l2_next;
      ASSERT (vnet_buffer (b0)->l2.l2_len ==
	      ethernet_buffer_header_size (b0));
      vlib_buffer_advance (b0, -(vnet_buffer (b0)->l2.l2_len));

      // check for common IP/MPLS ethertypes
    }
  else if (type0 == ETHERNET_TYPE_IP4)
    {
      *next0 = em->l3_next.input_next_ip4;
    }
  else if (type0 == ETHERNET_TYPE_IP6)
    {
      *next0 = em->l3_next.input_next_ip6;
    }
  else if (type0 == ETHERNET_TYPE_MPLS)
    {
      *next0 = em->l3_next.input_next_mpls;

    }
  else if (em->redirect_l3)
    {
      // L3 Redirect is on, the cached common next nodes will be
      // pointing to the redirect node, catch the uncommon types here
      *next0 = em->redirect_l3_next;
    }
  else
    {
      // uncommon ethertype, check table
      u32 i0;
      i0 = sparse_vec_index (em->l3_next.input_next_by_type, type0);
      *next0 = vec_elt (em->l3_next.input_next_by_type, i0);
      *error0 =
	i0 ==
	SPARSE_VEC_INVALID_INDEX ? ETHERNET_ERROR_UNKNOWN_TYPE : *error0;

      // The table is not populated with LLC values, so check that now.
      // If variant is variant_ethernet then we came from LLC processing. Don't
      // go back there; drop instead using by keeping the drop/bad table result.
      if ((type0 < 0x600) && (variant == ETHERNET_INPUT_VARIANT_ETHERNET))
	{
	  *next0 = ETHERNET_INPUT_NEXT_LLC;
	}
    }
}


/* following vector code relies on following assumptions */
STATIC_ASSERT_OFFSET_OF (vlib_buffer_t, current_data, 0);
STATIC_ASSERT_OFFSET_OF (vlib_buffer_t, current_length, 2);
STATIC_ASSERT_OFFSET_OF (vlib_buffer_t, flags, 4);
STATIC_ASSERT (STRUCT_OFFSET_OF (vnet_buffer_opaque_t, l2_hdr_offset) ==
	       STRUCT_OFFSET_OF (vnet_buffer_opaque_t, l3_hdr_offset) - 2,
	       "l3_hdr_offset must follow l2_hdr_offset");

static_always_inline void
eth_input_adv_and_flags_x4 (vlib_buffer_t ** b, i16 adv, u32 flags, int is_l3)
{
#ifdef CLIB_HAVE_VEC256
  /* to reduce number of small loads/stores we are loading first 64 bits
     of each buffer metadata into 256-bit register so we can advance
     current_data, current_length and flags.
     Observed saving of this code is ~2 clocks per packet */
  u64x4 r, radv;

  /* vector if signed 16 bit integers used in signed vector add operation
     to advnce current_data and current_length */
  u32x8 flags4 = { 0, flags, 0, flags, 0, flags, 0, flags };
  i16x16 adv4 = {
    adv, -adv, 0, 0, adv, -adv, 0, 0,
    adv, -adv, 0, 0, adv, -adv, 0, 0
  };

  /* load 4 x 64 bits */
  r = u64x4_gather (b[0], b[1], b[2], b[3]);

  /* set flags */
  r |= (u64x4) flags4;

  /* advance buffer */
  radv = (u64x4) ((i16x16) r + adv4);

  /* write 4 x 64 bits */
  u64x4_scatter (is_l3 ? radv : r, b[0], b[1], b[2], b[3]);

  /* use old current_data as l2_hdr_offset and new current_data as
     l3_hdr_offset */
  r = (u64x4) u16x16_blend (r, radv << 16, 0xaa);

  /* store both l2_hdr_offset and l3_hdr_offset in single store operation */
  u32x8_scatter_one ((u32x8) r, 0, &vnet_buffer (b[0])->l2_hdr_offset);
  u32x8_scatter_one ((u32x8) r, 2, &vnet_buffer (b[1])->l2_hdr_offset);
  u32x8_scatter_one ((u32x8) r, 4, &vnet_buffer (b[2])->l2_hdr_offset);
  u32x8_scatter_one ((u32x8) r, 6, &vnet_buffer (b[3])->l2_hdr_offset);

  if (is_l3)
    {
      ASSERT (b[0]->current_data == vnet_buffer (b[0])->l3_hdr_offset);
      ASSERT (b[1]->current_data == vnet_buffer (b[1])->l3_hdr_offset);
      ASSERT (b[2]->current_data == vnet_buffer (b[2])->l3_hdr_offset);
      ASSERT (b[3]->current_data == vnet_buffer (b[3])->l3_hdr_offset);

      ASSERT (b[0]->current_data - vnet_buffer (b[0])->l2_hdr_offset == adv);
      ASSERT (b[1]->current_data - vnet_buffer (b[1])->l2_hdr_offset == adv);
      ASSERT (b[2]->current_data - vnet_buffer (b[2])->l2_hdr_offset == adv);
      ASSERT (b[3]->current_data - vnet_buffer (b[3])->l2_hdr_offset == adv);
    }
  else
    {
      ASSERT (b[0]->current_data == vnet_buffer (b[0])->l2_hdr_offset);
      ASSERT (b[1]->current_data == vnet_buffer (b[1])->l2_hdr_offset);
      ASSERT (b[2]->current_data == vnet_buffer (b[2])->l2_hdr_offset);
      ASSERT (b[3]->current_data == vnet_buffer (b[3])->l2_hdr_offset);

      ASSERT (b[0]->current_data - vnet_buffer (b[0])->l3_hdr_offset == -adv);
      ASSERT (b[1]->current_data - vnet_buffer (b[1])->l3_hdr_offset == -adv);
      ASSERT (b[2]->current_data - vnet_buffer (b[2])->l3_hdr_offset == -adv);
      ASSERT (b[3]->current_data - vnet_buffer (b[3])->l3_hdr_offset == -adv);
    }

#else
  vnet_buffer (b[0])->l2_hdr_offset = b[0]->current_data;
  vnet_buffer (b[1])->l2_hdr_offset = b[1]->current_data;
  vnet_buffer (b[2])->l2_hdr_offset = b[2]->current_data;
  vnet_buffer (b[3])->l2_hdr_offset = b[3]->current_data;
  vnet_buffer (b[0])->l3_hdr_offset = b[0]->current_data + adv;
  vnet_buffer (b[1])->l3_hdr_offset = b[1]->current_data + adv;
  vnet_buffer (b[2])->l3_hdr_offset = b[2]->current_data + adv;
  vnet_buffer (b[3])->l3_hdr_offset = b[3]->current_data + adv;

  if (is_l3)
    {
      vlib_buffer_advance (b[0], adv);
      vlib_buffer_advance (b[1], adv);
      vlib_buffer_advance (b[2], adv);
      vlib_buffer_advance (b[3], adv);
    }

  b[0]->flags |= flags;
  b[1]->flags |= flags;
  b[2]->flags |= flags;
  b[3]->flags |= flags;
#endif

  if (!is_l3)
    {
      vnet_buffer (b[0])->l2.l2_len = adv;
      vnet_buffer (b[1])->l2.l2_len = adv;
      vnet_buffer (b[2])->l2.l2_len = adv;
      vnet_buffer (b[3])->l2.l2_len = adv;
    }
}

static_always_inline void
eth_input_adv_and_flags_x1 (vlib_buffer_t ** b, i16 adv, u32 flags, int is_l3)
{
  vnet_buffer (b[0])->l2_hdr_offset = b[0]->current_data;
  vnet_buffer (b[0])->l3_hdr_offset = b[0]->current_data + adv;

  if (is_l3)
    vlib_buffer_advance (b[0], adv);
  b[0]->flags |= flags;
  if (!is_l3)
    vnet_buffer (b[0])->l2.l2_len = adv;
}


static_always_inline void
eth_input_get_etype_and_tags (vlib_buffer_t * b, u16 * etype, u64 * tags,
			      u64 * dmacs, int maybe_tagged, int dmac_check)
{
  ethernet_header_t *e;
  e = vlib_buffer_get_current (b);
  etype[0] = e->type;

  if (maybe_tagged)
    tags[0] = *(u64 *) (e + 1);

  if (dmac_check)
    dmacs[0] = *(u64 *) e;
}


/* process frame of buffers, store ethertype into array and update
   buffer metadata fields depending on interface being l2 or l3 assuming that
   packets are untagged. For tagged packets those fields are updated later.
   Optionally store Destionation MAC address and tag data into arrays
   for further processing */

STATIC_ASSERT (VLIB_FRAME_SIZE % 8 == 0,
	       "VLIB_FRAME_SIZE must be power of 8");
static_always_inline void
eth_input_process_frame (vlib_main_t * vm, vnet_hw_interface_t * hi,
			 u32 * buffer_indices, u32 n_packets, int is_l3,
			 int maybe_tagged, int dmac_check)
{
  ethernet_main_t *em = &ethernet_main;
  eth_input_per_thread_data_t *d;
  u16 et_ip4 = clib_host_to_net_u16 (ETHERNET_TYPE_IP4);
  u16 et_ip6 = clib_host_to_net_u16 (ETHERNET_TYPE_IP6);
  u16 et_mpls = clib_host_to_net_u16 (ETHERNET_TYPE_MPLS);
  u16 et_vlan = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
  u16 et_dot1ad = clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD);
  u16 ids[VLIB_FRAME_SIZE], *id;
  u16 *etype;
  u64 *tags, *dmacs;
  u32 *from;
  vlib_buffer_t *b[20];
  int adv = sizeof (ethernet_header_t);
  i32 n_left = n_packets;

  u32 flags = VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
    VNET_BUFFER_F_L3_HDR_OFFSET_VALID;

  d = vec_elt_at_index (em->per_thread_data, vm->thread_index);
  etype = d->etypes;
  tags = d->tags_unsorted;
  dmacs = d->dmacs;
  from = buffer_indices;

  while (n_left >= 20)
    {
      vlib_buffer_t **ph = b + 16, **pd = b + 8;
      vlib_get_buffers (vm, from, b, 4);
      vlib_get_buffers (vm, from + 8, pd, 4);
      vlib_get_buffers (vm, from + 16, ph, 4);

      vlib_prefetch_buffer_header (ph[0], LOAD);
      vlib_prefetch_buffer_data (pd[0], LOAD);
      eth_input_get_etype_and_tags (b[0], etype + 0, tags + 0, dmacs + 0,
				    maybe_tagged, dmac_check);

      vlib_prefetch_buffer_header (ph[1], LOAD);
      vlib_prefetch_buffer_data (pd[1], LOAD);
      eth_input_get_etype_and_tags (b[1], etype + 1, tags + 1, dmacs + 1,
				    maybe_tagged, dmac_check);

      vlib_prefetch_buffer_header (ph[2], LOAD);
      vlib_prefetch_buffer_data (pd[2], LOAD);
      eth_input_get_etype_and_tags (b[2], etype + 2, tags + 2, dmacs + 2,
				    maybe_tagged, dmac_check);

      vlib_prefetch_buffer_header (ph[3], LOAD);
      vlib_prefetch_buffer_data (pd[3], LOAD);
      eth_input_get_etype_and_tags (b[3], etype + 3, tags + 3, dmacs + 3,
				    maybe_tagged, dmac_check);

      eth_input_adv_and_flags_x4 (b, adv, flags, is_l3);

      /* next */
      n_left -= 4;
      etype += 4;
      tags += 4;
      dmacs += 4;
      from += 4;
    }
  while (n_left >= 4)
    {
      vlib_get_buffers (vm, from, b, 4);
      eth_input_get_etype_and_tags (b[0], etype + 0, tags + 0, dmacs + 0,
				    maybe_tagged, dmac_check);
      eth_input_get_etype_and_tags (b[1], etype + 1, tags + 1, dmacs + 1,
				    maybe_tagged, dmac_check);
      eth_input_get_etype_and_tags (b[2], etype + 2, tags + 2, dmacs + 2,
				    maybe_tagged, dmac_check);
      eth_input_get_etype_and_tags (b[3], etype + 3, tags + 3, dmacs + 3,
				    maybe_tagged, dmac_check);
      eth_input_adv_and_flags_x4 (b, adv, flags, is_l3);

      /* next */
      n_left -= 4;
      etype += 4;
      tags += 4;
      dmacs += 4;
      from += 4;
    }
  while (n_left)
    {
      vlib_get_buffers (vm, from, b, 1);
      eth_input_get_etype_and_tags (b[0], etype + 0, tags + 0, dmacs + 0,
				    maybe_tagged, dmac_check);
      eth_input_adv_and_flags_x1 (b, adv, flags, is_l3);

      /* next */
      n_left -= 1;
      etype += 1;
      tags += 1;
      dmacs += 4;
      from += 1;
    }

  if (dmac_check)
    {
      u64 mask = clib_net_to_host_u64 (0xFFFFFFFFFFFF0000);
      u64 igbit = clib_net_to_host_u64 (0x0100000000000000);
      u64 hwaddr = (*(u64 *) hi->hw_address) & mask;
      u64 *dmac = d->dmacs;
      u8 *dmac_bad = d->dmacs_bad;

      n_left = n_packets;

#ifdef CLIB_HAVE_VEC256
      u64x4 igbit4 = u64x4_splat (igbit);
      u64x4 mask4 = u64x4_splat (mask);
      u64x4 hwaddr4 = u64x4_splat (hwaddr);
      while (n_left >= 0)
	{
	  u64x4 r0, r1;
	  r0 = u64x4_load_unaligned (dmac + 0) & mask4;
	  r1 = u64x4_load_unaligned (dmac + 4) & mask4;

	  r0 = (r0 != hwaddr4) & ((r0 & igbit4) == 0);
	  r1 = (r1 != hwaddr4) & ((r1 & igbit4) == 0);

	  *(u32 *) (dmac_bad + 0) = u8x32_msb_mask ((u8x32) (r0));
	  *(u32 *) (dmac_bad + 4) = u8x32_msb_mask ((u8x32) (r1));

	  /* next */
	  dmac += 8;
	  dmac_bad += 8;
	  n_left -= 8;
	}
#else
      while (n_left > 0)
	{
	  u64 r0, r1, r2, r3;
	  r0 = dmac[0] & mask;
	  r1 = dmac[1] & mask;
	  r2 = dmac[2] & mask;
	  r3 = dmac[3] & mask;

	  r0 = (r0 != hwaddr) && ((r0 & igbit) == 0);
	  r1 = (r1 != hwaddr) && ((r1 & igbit) == 0);
	  r2 = (r2 != hwaddr) && ((r2 & igbit) == 0);
	  r3 = (r3 != hwaddr) && ((r3 & igbit) == 0);

	  dmac_bad[0] = r0;
	  dmac_bad[1] = r1;
	  dmac_bad[2] = r2;
	  dmac_bad[3] = r3;

	  /* next */
	  dmac += 4;
	  dmac_bad += 4;
	  n_left -= 4;
	}
#endif
    }

/* ethertype based sort, for known ethertypes. Unknown packets are put
   into separate bucket so they can be processed later. Optionally
   known ethertyes match (l2 interface case) or tagged packets match
   (l3 interface without sub-interfaces case) can be turned off and such
   packets will fall into unknown bucket */

  etype = d->etypes;
  n_left = n_packets;
  id = ids;

#if defined (CLIB_HAVE_VEC512)
  u16x32 et32_ip4 = u16x32_splat (et_ip4);
  u16x32 et32_ip6 = u16x32_splat (et_ip6);
  u16x32 et32_mpls = u16x32_splat (et_mpls);
  u16x32 et32_vlan = u16x32_splat (et_vlan);
  u16x32 et32_dot1ad = u16x32_splat (et_dot1ad);
  u16x32 id32_ip4 = u16x32_splat (ETYPE_ID_IP4);
  u16x32 id32_ip6 = u16x32_splat (ETYPE_ID_IP6);
  u16x32 id32_mpls = u16x32_splat (ETYPE_ID_MPLS);
  u16x32 id32_vlan = u16x32_splat (ETYPE_ID_VLAN);
  u16x32 id32_dot1ad = u16x32_splat (ETYPE_ID_DOT1AD);

  while (n_left > 0)
    {
      u16x32 r = { 0 };
      u16x32 e32 = u16x32_load_unaligned (etype);
      if (is_l3)
	{
	  r += (e32 == et32_ip4) & id32_ip4;
	  r += (e32 == et32_ip6) & id32_ip6;
	  r += (e32 == et32_mpls) & id32_mpls;
	}
      if (maybe_tagged)
	{
	  r += (e32 == et32_vlan) & id32_vlan;
	  r += (e32 == et32_dot1ad) & id32_dot1ad;
	}
      u16x32_store_unaligned (r, id);
      etype += 32;
      id += 32;
      n_left -= 32;
    }
#elif defined (CLIB_HAVE_VEC256)
  u16x16 et16_ip4 = u16x16_splat (et_ip4);
  u16x16 et16_ip6 = u16x16_splat (et_ip6);
  u16x16 et16_mpls = u16x16_splat (et_mpls);
  u16x16 et16_vlan = u16x16_splat (et_vlan);
  u16x16 et16_dot1ad = u16x16_splat (et_dot1ad);
  u16x16 id16_ip4 = u16x16_splat (ETYPE_ID_IP4);
  u16x16 id16_ip6 = u16x16_splat (ETYPE_ID_IP6);
  u16x16 id16_mpls = u16x16_splat (ETYPE_ID_MPLS);
  u16x16 id16_vlan = u16x16_splat (ETYPE_ID_VLAN);
  u16x16 id16_dot1ad = u16x16_splat (ETYPE_ID_DOT1AD);

  while (n_left > 0)
    {
      u16x16 r = { 0 };
      u16x16 e16 = u16x16_load_unaligned (etype);
      if (is_l3)
	{
	  r += (e16 == et16_ip4) & id16_ip4;
	  r += (e16 == et16_ip6) & id16_ip6;
	  r += (e16 == et16_mpls) & id16_mpls;
	}
      if (maybe_tagged)
	{
	  r += (e16 == et16_vlan) & id16_vlan;
	  r += (e16 == et16_dot1ad) & id16_dot1ad;
	}
      u16x16_store_unaligned (r, id);
      etype += 16;
      id += 16;
      n_left -= 16;
    }
#elif defined (CLIB_HAVE_VEC128)
  u16x8 et8_ip4 = u16x8_splat (et_ip4);
  u16x8 et8_ip6 = u16x8_splat (et_ip6);
  u16x8 et8_mpls = u16x8_splat (et_mpls);
  u16x8 et8_vlan = u16x8_splat (et_vlan);
  u16x8 et8_dot1ad = u16x8_splat (et_dot1ad);
  u16x8 id8_ip4 = u16x8_splat (ETYPE_ID_IP4);
  u16x8 id8_ip6 = u16x8_splat (ETYPE_ID_IP6);
  u16x8 id8_mpls = u16x8_splat (ETYPE_ID_MPLS);
  u16x8 id8_vlan = u16x8_splat (ETYPE_ID_VLAN);
  u16x8 id8_dot1ad = u16x8_splat (ETYPE_ID_DOT1AD);

  while (n_left > 0)
    {
      u16x8 r = { 0 };
      u16x8 e8 = u16x8_load_unaligned (etype);
      if (is_l3)
	{
	  r += (e8 == et8_ip4) & id8_ip4;
	  r += (e8 == et8_ip6) & id8_ip6;
	  r += (e8 == et8_mpls) & id8_mpls;
	}
      if (maybe_tagged)
	{
	  r += (e8 == et8_vlan) & id8_vlan;
	  r += (e8 == et8_dot1ad) & id8_dot1ad;
	}
      u16x8_store_unaligned (r, id);
      etype += 8;
      id += 8;
      n_left -= 8;
    }
#else
  while (n_left)
    {
      if (sort_known && etype[0] == et_ip4)
	id[0] = ETYPE_ID_IP4;
      else if (sort_known && etype[0] == et_ip6)
	id[0] = ETYPE_ID_IP6;
      else if (sort_known && etype[0] == et_mpls)
	id[0] = ETYPE_ID_MPLS;
      else if (maybe_tagged && etype[0] == et_vlan)
	id[0] = ETYPE_ID_VLAN;
      else if (maybe_tagged && etype[0] == et_dot1ad)
	id[0] = ETYPE_ID_DOT1AD;
      else
	id[0] = ETYPE_ID_UNKNOWN;

      etype += 1;
      id += 1;
      n_left -= 1;
    }
#endif

  n_left = n_packets;
  etype = d->etypes;
  id = ids;
  tags = d->tags_unsorted;
  from = buffer_indices;
  u8 *dmacs_bad = d->dmacs_bad;

  clib_memset_u16 (d->n_bufs_by_etype, 0, ETYPE_N_IDS);
  clib_memset_u8 (d->have_bad_dmacs, 0, ETYPE_N_IDS);
  while (n_left)
    {
      u16 x, y;
      x = id[0];
      y = d->n_bufs_by_etype[x];

#ifdef CLIB_HAVE_VEC512
      if (n_left >= 32 &&
	  u16x32_is_all_equal (u16x32_load_unaligned (id), id[0]))
	{
	  clib_memcpy_fast (&d->bufs_by_etype[x][y], from, 32 * sizeof (u32));
	  if (dmac_check)
	    {
	      u8x32 r = u8x32_load_unaligned (dmacs_bad);
	      u8x32_store_unaligned (r, &d->dmacs_bad_by_etype[x][y]);
	      d->have_bad_dmacs[x] |= u8x32_is_all_zero (r);
	    }
	  if (x == ETYPE_ID_UNKNOWN)
	    clib_memcpy_fast (d->etypes + y, etype, 32 * sizeof (u32));
	  else if (maybe_tagged && x == ETYPE_ID_VLAN)
	    clib_memcpy_fast (d->tags_vlan + y, tags, 32 * sizeof (u64));
	  else if (maybe_tagged && x == ETYPE_ID_DOT1AD)
	    clib_memcpy_fast (d->tags_dot1ad + y, tags, 32 * sizeof (u64));

	  d->n_bufs_by_etype[x] += 32;

	  /* next */
	  n_left -= 32;
	  etype += 32;
	  id += 32;
	  tags += 32;
	  from += 32;
	  continue;
	}
#endif
#ifdef CLIB_HAVE_VEC256
      if (n_left >= 16 &&
	  u16x16_is_all_equal (u16x16_load_unaligned (id), id[0]))
	{
	  clib_memcpy_fast (&d->bufs_by_etype[x][y], from, 16 * sizeof (u32));
	  if (dmac_check)
	    {
	      u8x16 r = u8x16_load_unaligned (dmacs_bad);
	      u8x16_store_unaligned (r, &d->dmacs_bad_by_etype[x][y]);
	      d->have_bad_dmacs[x] |= u8x16_is_all_zero (r);
	    }
	  if (x == ETYPE_ID_UNKNOWN)
	    clib_memcpy_fast (d->etypes + y, etype, 16 * sizeof (u16));
	  else if (maybe_tagged && x == ETYPE_ID_VLAN)
	    clib_memcpy_fast (d->tags_vlan + y, tags, 16 * sizeof (u64));
	  else if (maybe_tagged && x == ETYPE_ID_DOT1AD)
	    clib_memcpy_fast (d->tags_dot1ad + y, tags, 16 * sizeof (u64));

	  d->n_bufs_by_etype[x] += 16;

	  /* next */
	  n_left -= 16;
	  etype += 16;
	  id += 16;
	  tags += 16;
	  from += 16;
	  continue;
	}
#endif
#ifdef CLIB_HAVE_VEC128
      if (n_left >= 8 &&
	  u16x8_is_all_equal (u16x8_load_unaligned (id), id[0]))
	{
	  clib_memcpy_fast (&d->bufs_by_etype[x][y], from, 8 * sizeof (u32));
	  if (dmac_check)
	    {
	      u64 r = *(u64 *) dmacs_bad;
	      *((u64 *) & d->dmacs_bad_by_etype[x][y]) = r;
	      d->have_bad_dmacs[x] |= (r != 0);
	    }
	  if (x == ETYPE_ID_UNKNOWN)
	    clib_memcpy_fast (d->etypes + y, etype, 8 * sizeof (u16));
	  else if (maybe_tagged && x == ETYPE_ID_VLAN)
	    clib_memcpy_fast (d->tags_vlan + y, tags, 8 * sizeof (u64));
	  else if (maybe_tagged && x == ETYPE_ID_DOT1AD)
	    clib_memcpy_fast (d->tags_dot1ad + y, tags, 8 * sizeof (u64));

	  d->n_bufs_by_etype[x] += 8;

	  /* next */
	  n_left -= 8;
	  etype += 8;
	  id += 8;
	  tags += 8;
	  from += 8;
	  continue;
	}
#endif
      d->bufs_by_etype[x][y] = from[0];
      if (dmac_check)
	{
	  d->dmacs_bad_by_etype[x][y] = dmacs_bad[0];
	  d->have_bad_dmacs[x] |= dmacs_bad[0];
	}
      if (x == ETYPE_ID_UNKNOWN)
	d->etypes[y] = etype[0];
      else if (maybe_tagged && x == ETYPE_ID_VLAN)
	d->tags_vlan[y] = tags[0];
      else if (maybe_tagged && x == ETYPE_ID_DOT1AD)
	d->tags_dot1ad[y] = tags[0];

      d->n_bufs_by_etype[x]++;

      /* next */
      n_left -= 1;
      etype += 1;
      id += 1;
      tags += 1;
      from += 1;
    }
}

static_always_inline u16
eth_input_next_by_type (u16 etype)
{
  ethernet_main_t *em = &ethernet_main;
  u32 i0 = sparse_vec_index (em->l3_next.input_next_by_type, etype);
  return vec_elt (em->l3_next.input_next_by_type, i0);
}

static_always_inline void
eth_input_tag_lookup (vnet_hw_interface_t * hi, etype_id_t id, u64 tag,
		      u16 * next, u32 * new_sw_if_index, u32 * is_l2,
		      u8 * err, u8 * n_tags)
{
  ethernet_main_t *em = &ethernet_main;
  main_intf_t *mif = vec_elt_at_index (em->main_intfs, hi->hw_if_index);
  vlan_intf_t *vif;
  qinq_intf_t *qif;
  vlan_table_t *vlan_table;
  qinq_table_t *qinq_table;
  u16 *t = (u16 *) & tag;
  u16 vlan1 = clib_net_to_host_u16 (t[0]) & 0xFFF;
  u16 vlan2 = clib_net_to_host_u16 (t[2]) & 0xFFF;
  u16 type = clib_net_to_host_u16 (t[1]);
  u32 matched;

  vlan_table = vec_elt_at_index (em->vlan_pool, id == ETYPE_ID_DOT1AD ?
				 mif->dot1ad_vlans : mif->dot1q_vlans);
  vif = &vlan_table->vlans[vlan1];
  qinq_table = vec_elt_at_index (em->qinq_pool, vif->qinqs);
  qif = &qinq_table->vlans[vlan2];
  *err = ETHERNET_ERROR_NONE;

  if (type == ETHERNET_TYPE_VLAN)
    {
      type = clib_net_to_host_u16 (t[3]);
      *n_tags = 2;
      matched = eth_identify_subint (hi, SUBINT_CONFIG_VALID |
				     SUBINT_CONFIG_MATCH_2_TAG, mif, vif,
				     qif, new_sw_if_index, err, is_l2);
    }
  else
    {
      *n_tags = 1;
      matched = eth_identify_subint (hi, SUBINT_CONFIG_VALID |
				     SUBINT_CONFIG_MATCH_1_TAG, mif, vif,
				     qif, new_sw_if_index, err, is_l2);
    }

  if (matched && new_sw_if_index[0] == ~0)
    err[0] = ETHERNET_ERROR_DOWN;

  if (PREDICT_FALSE (*err != ETHERNET_ERROR_NONE))
    next[0] = ETHERNET_INPUT_NEXT_DROP;
  else if (*is_l2)
    next[0] = em->l2_next;
  else if (type == ETHERNET_TYPE_IP4)
    next[0] = em->l3_next.input_next_ip4;
  else if (type == ETHERNET_TYPE_IP6)
    next[0] = em->l3_next.input_next_ip6;
  else if (type == ETHERNET_TYPE_MPLS)
    next[0] = em->l3_next.input_next_mpls;
  else if (em->redirect_l3)
    next[0] = em->redirect_l3_next;
  else
    {
      next[0] = eth_input_next_by_type (type);
      if (next[0] == ETHERNET_INPUT_NEXT_PUNT)
	*err = ETHERNET_ERROR_UNKNOWN_TYPE;
    }
}

static_always_inline u32
eth_input_update_tagged (vlib_main_t * vm, vlib_node_runtime_t * node, u32 bi,
			 u32 sw_if_index, u16 * next, u16 len, i16 adv,
			 u8 err, u8 dmac_bad, int check_dmac)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vlib_buffer_advance (b, adv);
  vnet_buffer (b)->l2.l2_len = len;
  vnet_buffer (b)->l3_hdr_offset = vnet_buffer (b)->l2_hdr_offset + len;

  if (check_dmac && dmac_bad)
    {
      err = ETHERNET_ERROR_L3_MAC_MISMATCH;
      next[0] = ETHERNET_INPUT_NEXT_PUNT;
    }

  if (err == 0)
    vnet_buffer (b)->sw_if_index[VLIB_RX] = sw_if_index;
  else
    b->error = node->errors[err];
  return vlib_buffer_length_in_chain (vm, b);
}

static_always_inline void
eth_input_process_tagged (vlib_main_t * vm, vlib_node_runtime_t * n,
			  vnet_hw_interface_t * hi, etype_id_t id,
			  int main_is_l3, int check_dmac)
{
  ethernet_main_t *em = &ethernet_main;
  vnet_main_t *vnm = vnet_get_main ();
  main_intf_t *mif = vec_elt_at_index (em->main_intfs, hi->hw_if_index);
  eth_input_per_thread_data_t *d;
  u64 tag1_mask = clib_net_to_host_u64 (0xffffffff00000000);
  u64 tag2_mask = clib_net_to_host_u64 (0xffffffffffffffff);
  u64 *tags, last_tag, xormask;
  u32 *bi, sw_if_index, is_l2, n_left, n_packets, n_bytes;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u16 len, next_index;
  i16 adv;
  u8 *dmac_bad, err, n_tags, one_sw_if_index = 1;

  d = vec_elt_at_index (em->per_thread_data, vm->thread_index);
  n_left = d->n_bufs_by_etype[id];
  dmac_bad = d->dmacs_bad_by_etype[id];

  if (n_left == 0)
    return;

  n_left = d->n_bufs_by_etype[id];
  bi = d->bufs_by_etype[id];

  /* vlan pool index 0 means invalid vlan table so we just need to ship
     packets to error-pount with proper error set */
  if ((id == ETYPE_ID_DOT1AD ? mif->dot1ad_vlans : mif->dot1q_vlans) == 0)
    {
      while (n_left)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi[0]);
	  b->error = n->errors[ETHERNET_ERROR_UNKNOWN_VLAN];
	  if (main_is_l3)
	    vlib_buffer_advance (b, -(int) sizeof (ethernet_header_t));

	  /* next */
	  n_left -= 1;
	  bi += 1;
	}
      next_index = ETHERNET_INPUT_NEXT_PUNT;
      goto enqueue;
    }

  tags = (id == ETYPE_ID_DOT1AD) ? d->tags_dot1ad : d->tags_vlan;

  last_tag = tags[0];

  eth_input_tag_lookup (hi, id, last_tag, &next_index, &sw_if_index,
			&is_l2, &err, &n_tags);
  len = sizeof (ethernet_header_t) + n_tags * sizeof (ethernet_vlan_header_t);
  if (main_is_l3)
    adv = is_l2 ? -(int) sizeof (ethernet_header_t) :
      n_tags * sizeof (ethernet_vlan_header_t);
  else
    adv = is_l2 ? 0 : len;
  xormask = (n_tags == 2) ? tag2_mask : tag1_mask;
  n_packets = n_bytes = 0;

  while (n_left)
    {
      u64 x = last_tag ^ tags[0];
      if ((x & xormask) != 0)
	{
	  last_tag = tags[0];
	  if (err == 0)
	    {
	      if (is_l2 == 0)
		n_bytes += n_packets * len;

	      vlib_increment_combined_counter
		(vnm->interface_main.combined_sw_if_counters
		 + VNET_INTERFACE_COUNTER_RX,
		 vm->thread_index, sw_if_index, n_packets, n_bytes);
	    }
	  eth_input_tag_lookup (hi, id, last_tag, &next_index,
				&sw_if_index, &is_l2, &err, &n_tags);
	  len = sizeof (ethernet_header_t) +
	    n_tags * sizeof (ethernet_vlan_header_t);
	  if (main_is_l3)
	    adv = is_l2 ? -(int) sizeof (ethernet_header_t) :
	      n_tags * sizeof (ethernet_vlan_header_t);
	  else
	    adv = is_l2 ? 0 : len;
	  xormask = (n_tags == 2) ? tag2_mask : tag1_mask;
	  n_packets = n_bytes = 0;
	  one_sw_if_index = 0;
	}

      x = (last_tag ^ tags[1]) | (last_tag ^ tags[2]) | (last_tag ^ tags[3]);
      if (n_left >= 4 && (x & xormask) == 0)
	{
	  if (n_left >= 8)
	    {
	      vlib_prefetch_buffer_with_index (vm, bi[4], LOAD);
	      vlib_prefetch_buffer_with_index (vm, bi[5], LOAD);
	      vlib_prefetch_buffer_with_index (vm, bi[6], LOAD);
	      vlib_prefetch_buffer_with_index (vm, bi[7], LOAD);
	    }

	  next[0] = next[1] = next[2] = next[3] = next_index;
	  n_bytes += eth_input_update_tagged (vm, n, bi[0], sw_if_index,
					      next + 0, len, adv, err,
					      dmac_bad[0], check_dmac);
	  n_bytes += eth_input_update_tagged (vm, n, bi[1], sw_if_index,
					      next + 1, len, adv, err,
					      dmac_bad[1], check_dmac);
	  n_bytes += eth_input_update_tagged (vm, n, bi[2], sw_if_index,
					      next + 2, len, adv, err,
					      dmac_bad[2], check_dmac);
	  n_bytes += eth_input_update_tagged (vm, n, bi[3], sw_if_index,
					      next + 3, len, adv, err,
					      dmac_bad[3], check_dmac);
	  n_packets += 4;

	  /* next */
	  n_left -= 4;
	  tags += 4;
	  bi += 4;
	  dmac_bad += 4;
	  next += 4;
	  continue;
	}

      next[0] = next_index;
      n_bytes += eth_input_update_tagged (vm, n, bi[0], sw_if_index, next,
					  len, adv, err, dmac_bad[0],
					  check_dmac);
      n_packets += 1;

      /* next */
      n_left -= 1;
      tags += 1;
      dmac_bad += 1;
      bi += 1;
      next += 1;
    }

  if (err == 0)
    {
      if (is_l2 == 0)
	n_bytes += n_packets * len;
      vlib_increment_combined_counter
	(vnm->interface_main.combined_sw_if_counters
	 + VNET_INTERFACE_COUNTER_RX,
	 vm->thread_index, sw_if_index, n_packets, n_bytes);
    }

enqueue:
  if (one_sw_if_index)
    vlib_buffer_enqueue_to_single_next (vm, n, d->bufs_by_etype[id],
					next_index, d->n_bufs_by_etype[id]);
  else
    vlib_buffer_enqueue_to_next (vm, n, d->bufs_by_etype[id], nexts,
				 d->n_bufs_by_etype[id]);
}

static_always_inline void
eth_input_enqueue_untagged_l2 (vlib_main_t * vm, vlib_node_runtime_t * node)
{
  ethernet_main_t *em = &ethernet_main;
  eth_input_per_thread_data_t *d;
  etype_id_t id;

  d = vec_elt_at_index (em->per_thread_data, vm->thread_index);

  /* L2 case - untagged packets are not sorted so we can just ship
     them to l2_next */
  id = ETYPE_ID_UNKNOWN;
  if (d->n_bufs_by_etype[id])
    {
      vlib_buffer_enqueue_to_single_next (vm, node, d->bufs_by_etype[id],
					  em->l2_next,
					  d->n_bufs_by_etype[id]);
    }
}

static_always_inline void
eth_input_enq (vlib_main_t * vm, vlib_node_runtime_t * node,
	       eth_input_per_thread_data_t * d, etype_id_t id, u16 next_index)
{
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  if (d->have_bad_dmacs[id])
    {
      int i;

      for (i = 0; i < d->n_bufs_by_etype[id]; i++)
	{
	  if (d->dmacs_bad_by_etype[id][i])
	    {
	      vlib_buffer_t *b;
	      b = vlib_get_buffer (vm, d->bufs_by_etype[id][i]);
	      b->error = node->errors[ETHERNET_ERROR_L3_MAC_MISMATCH];
	      next[i] = ETHERNET_INPUT_NEXT_PUNT;
	    }
	  else
	    next[i] = next_index;
	}

      vlib_buffer_enqueue_to_next (vm, node, d->bufs_by_etype[id], nexts,
				   d->n_bufs_by_etype[id]);
    }
  else
    vlib_buffer_enqueue_to_single_next (vm, node, d->bufs_by_etype[id],
					next_index, d->n_bufs_by_etype[id]);
}

static_always_inline void
eth_input_enq_unknown (vlib_main_t * vm, vlib_node_runtime_t * node,
		       eth_input_per_thread_data_t * d, int check_dmac)
{
  etype_id_t id = ETYPE_ID_UNKNOWN;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 n_left = d->n_bufs_by_etype[id];
  u16 *etype = d->etypes;
  u32 *bufs = d->bufs_by_etype[id];
  u8 *dmac_bad = d->dmacs_bad_by_etype[id];
  u16 curr_etype, curr_next;

  curr_etype = etype[0];
  curr_next = eth_input_next_by_type (clib_host_to_net_u16 (etype[0]));

  while (n_left)
    {
#ifdef CLIB_HAVE_VEC256
      if (n_left >= 16 &&
	  u16x16_is_all_equal (u16x16_load_unaligned (etype), curr_etype))
	{
	  u16x16_store_unaligned (u16x16_splat (curr_next), next);

	  if (curr_next == ETHERNET_INPUT_NEXT_PUNT)
	    for (int i = 0; i < 16; i++)
	      {
		vlib_buffer_t *b = vlib_get_buffer (vm, bufs[i]);
		b->error = node->errors[ETHERNET_ERROR_UNKNOWN_TYPE];
	      }
	  else if (check_dmac &&
		   u8x16_is_all_zero (u8x16_load_unaligned (dmac_bad)) != 0)
	    for (int i = 0; i < 16; i++)
	      if (dmac_bad[i])
		{
		  vlib_buffer_t *b = vlib_get_buffer (vm, bufs[i]);
		  b->error = node->errors[ETHERNET_ERROR_L3_MAC_MISMATCH];
		  next[i] = ETHERNET_INPUT_NEXT_PUNT;
		}

	  /* next */
	  next += 16;
	  etype += 16;
	  bufs += 16;
	  dmac_bad += 16;
	  n_left -= 16;
	  continue;
	}
#endif
#ifdef CLIB_HAVE_VEC128
      if (n_left >= 8 &&
	  u16x8_is_all_equal (u16x8_load_unaligned (etype), curr_etype))
	{
	  u16x8_store_unaligned (u16x8_splat (curr_next), next);

	  if (curr_next == ETHERNET_INPUT_NEXT_PUNT)
	    for (int i = 0; i < 8; i++)
	      {
		vlib_buffer_t *b = vlib_get_buffer (vm, bufs[i]);
		b->error = node->errors[ETHERNET_ERROR_UNKNOWN_TYPE];
	      }
	  else if (check_dmac && (*((u64 *) dmac_bad) != 0))
	    for (int i = 0; i < 8; i++)
	      if (dmac_bad[i])
		{
		  vlib_buffer_t *b = vlib_get_buffer (vm, bufs[i]);
		  b->error = node->errors[ETHERNET_ERROR_L3_MAC_MISMATCH];
		  next[i] = ETHERNET_INPUT_NEXT_PUNT;
		}

	  /* next */
	  next += 8;
	  etype += 8;
	  bufs += 8;
	  dmac_bad += 8;
	  n_left -= 8;
	  continue;
	}
#endif
      if (curr_etype != etype[0])
	{
	  curr_etype = etype[0];
	  curr_next = eth_input_next_by_type
	    (clib_host_to_net_u16 (etype[0]));
	}
      next[0] = curr_next;
      if (next[0] == ETHERNET_INPUT_NEXT_PUNT)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, bufs[0]);
	  b->error = node->errors[ETHERNET_ERROR_UNKNOWN_TYPE];
	}
      else if (check_dmac && dmac_bad[0])
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, bufs[0]);
	  b->error = node->errors[ETHERNET_ERROR_L3_MAC_MISMATCH];
	  next[0] = ETHERNET_INPUT_NEXT_PUNT;
	}

      /* next */
      next += 1;
      etype += 1;
      dmac_bad += 1;
      bufs += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, d->bufs_by_etype[id],
			       nexts, d->n_bufs_by_etype[id]);
}

static_always_inline void
eth_input_enqueue_untagged_l3 (vlib_main_t * vm, vlib_node_runtime_t * node,
			       int ip4_cksum_ok)
{
  ethernet_main_t *em = &ethernet_main;
  eth_input_per_thread_data_t *d;
  etype_id_t id;
  u32 next_index;

  d = vec_elt_at_index (em->per_thread_data, vm->thread_index);

  id = ETYPE_ID_IP4;
  if (d->n_bufs_by_etype[id])
    {
      next_index = em->l3_next.input_next_ip4;
      if (next_index == ETHERNET_INPUT_NEXT_IP4_INPUT && ip4_cksum_ok)
	next_index = ETHERNET_INPUT_NEXT_IP4_INPUT_NCS;

      eth_input_enq (vm, node, d, id, next_index);
    }

  id = ETYPE_ID_IP6;
  if (d->n_bufs_by_etype[id])
    eth_input_enq (vm, node, d, id, em->l3_next.input_next_ip6);

  id = ETYPE_ID_MPLS;
  if (d->n_bufs_by_etype[id])
    eth_input_enq (vm, node, d, id, em->l3_next.input_next_mpls);

  id = ETYPE_ID_UNKNOWN;
  if (d->n_bufs_by_etype[id] == 0)
    return;

  if (em->redirect_l3)
    eth_input_enq (vm, node, d, id, em->redirect_l3_next);
  else if (d->have_bad_dmacs[id])
    eth_input_enq_unknown (vm, node, d, /* check_dmac */ 1);
  else
    eth_input_enq_unknown (vm, node, d, /* check_dmac */ 0);
}

static_always_inline void
eth_input_single_int (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vnet_hw_interface_t * hi, u32 * from, u32 n_pkts,
		      int ip4_cksum_ok)
{
  ethernet_main_t *em = &ethernet_main;
  ethernet_interface_t *ei;
  ei = pool_elt_at_index (em->interfaces, hi->hw_instance);
  main_intf_t *intf0 = vec_elt_at_index (em->main_intfs, hi->hw_if_index);
  subint_config_t *subint0 = &intf0->untagged_subint;

  int maybe_tagged = intf0->dot1q_vlans || intf0->dot1ad_vlans;
  int main_is_l3 = (subint0->flags & SUBINT_CONFIG_L2) == 0;
  int promisc = (ei->flags & ETHERNET_INTERFACE_FLAG_ACCEPT_ALL) != 0;

  if (main_is_l3)
    {
      /* main interface is L3, we dont expect tagged packets and interface
         is not in promisc node, so we dont't need to check DMAC */
      int is_l3 = 1;

      if (maybe_tagged == 0 && promisc == 0)
	eth_input_process_frame (vm, hi, from, n_pkts, is_l3, 0, 0);
      else if (promisc == 0)
	/* subinterfaces but not in promisc mode so DMAC check is
	   not needed */
	eth_input_process_frame (vm, hi, from, n_pkts, is_l3, 1, 0);
      else
	/* subinterfaces and promisc mode so DMAC check is needed */
	eth_input_process_frame (vm, hi, from, n_pkts, is_l3, 1, 1);

      eth_input_enqueue_untagged_l3 (vm, node, ip4_cksum_ok);

      if (promisc == 0)
	{
	  eth_input_process_tagged (vm, node, hi, ETYPE_ID_VLAN, is_l3,
				    /* dmac_check */ 0);

	  eth_input_process_tagged (vm, node, hi, ETYPE_ID_DOT1AD, is_l3,
				    /* dmac_check */ 0);
	}
      else
	{
	  eth_input_process_tagged (vm, node, hi, ETYPE_ID_VLAN, is_l3,
				    /* dmac_check */ 1);
	  eth_input_process_tagged (vm, node, hi, ETYPE_ID_DOT1AD, is_l3,
				    /* dmac_check */ 1);
	}
    }
  else
    {
      /* untagged packets are treated as L2 */
      int is_l3 = 0;
      if (maybe_tagged == 0)
	/* Simple L2 case, no subinterfaces so tagged packets
	   are treated as unknown and dropped */
	eth_input_process_frame (vm, hi, from, n_pkts, is_l3, 0, 0);
      else
	/* We have sub-intrfaces which may be in l3 mode, so we need
	   to perform DMAC check */
	eth_input_process_frame (vm, hi, from, n_pkts, is_l3, 1, 1);

      eth_input_enqueue_untagged_l2 (vm, node);

      eth_input_process_tagged (vm, node, hi, ETYPE_ID_VLAN,
				is_l3, /* check_dmac */ 1);
      eth_input_process_tagged (vm, node, hi, ETYPE_ID_DOT1AD,
				is_l3, /* check_dmac */ 1);
    }
}

static_always_inline void
ethernet_input_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * from_frame)
{
  u32 *from, n_left;
  if ((node->flags & VLIB_NODE_FLAG_TRACE) == 0)
    return;

  from = vlib_frame_vector_args (from_frame);
  n_left = from_frame->n_vectors;

  while (n_left)
    {
      ethernet_input_trace_t *t0;
      vlib_buffer_t *b0 = vlib_get_buffer (vm, from[0]);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, sizeof (ethernet_input_trace_t));
	  clib_memcpy_fast (t0->packet_data, b0->data + b0->current_data,
			    sizeof (t0->packet_data));
	  t0->frame_flags = from_frame->flags;
	  clib_memcpy_fast (&t0->frame_data,
			    vlib_frame_scalar_args (from_frame),
			    sizeof (ethernet_input_frame_t));
	}
      from += 1;
      n_left -= 1;
    }
}

static_always_inline void
ethernet_input_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       u32 * from, u32 n_packets,
		       ethernet_input_variant_t variant)
{
  vnet_main_t *vnm = vnet_get_main ();
  ethernet_main_t *em = &ethernet_main;
  vlib_node_runtime_t *error_node;
  u32 n_left_from, next_index, *to_next;
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u32 thread_index = vm->thread_index;
  u32 cached_sw_if_index = ~0;
  u32 cached_is_l2 = 0;		/* shut up gcc */
  vnet_hw_interface_t *hi = NULL;	/* used for main interface only */

  if (variant != ETHERNET_INPUT_VARIANT_ETHERNET)
    error_node = vlib_node_get_runtime (vm, ethernet_input_node.index);
  else
    error_node = node;

  n_left_from = n_packets;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u8 next0, next1, error0, error1;
	  u16 type0, orig_type0, type1, orig_type1;
	  u16 outer_id0, inner_id0, outer_id1, inner_id1;
	  u32 match_flags0, match_flags1;
	  u32 old_sw_if_index0, new_sw_if_index0, len0, old_sw_if_index1,
	    new_sw_if_index1, len1;
	  vnet_hw_interface_t *hi0, *hi1;
	  main_intf_t *main_intf0, *main_intf1;
	  vlan_intf_t *vlan_intf0, *vlan_intf1;
	  qinq_intf_t *qinq_intf0, *qinq_intf1;
	  u32 is_l20, is_l21;
	  ethernet_header_t *e0, *e1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *b2, *b3;

	    b2 = vlib_get_buffer (vm, from[2]);
	    b3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (b2, STORE);
	    vlib_prefetch_buffer_header (b3, STORE);

	    CLIB_PREFETCH (b2->data, sizeof (ethernet_header_t), LOAD);
	    CLIB_PREFETCH (b3->data, sizeof (ethernet_header_t), LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  error0 = error1 = ETHERNET_ERROR_NONE;
	  e0 = vlib_buffer_get_current (b0);
	  type0 = clib_net_to_host_u16 (e0->type);
	  e1 = vlib_buffer_get_current (b1);
	  type1 = clib_net_to_host_u16 (e1->type);

	  /* Set the L2 header offset for all packets */
	  vnet_buffer (b0)->l2_hdr_offset = b0->current_data;
	  vnet_buffer (b1)->l2_hdr_offset = b1->current_data;
	  b0->flags |= VNET_BUFFER_F_L2_HDR_OFFSET_VALID;
	  b1->flags |= VNET_BUFFER_F_L2_HDR_OFFSET_VALID;

	  /* Speed-path for the untagged case */
	  if (PREDICT_TRUE (variant == ETHERNET_INPUT_VARIANT_ETHERNET
			    && !ethernet_frame_is_any_tagged_x2 (type0,
								 type1)))
	    {
	      main_intf_t *intf0;
	      subint_config_t *subint0;
	      u32 sw_if_index0, sw_if_index1;

	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	      is_l20 = cached_is_l2;

	      /* This is probably wholly unnecessary */
	      if (PREDICT_FALSE (sw_if_index0 != sw_if_index1))
		goto slowpath;

	      /* Now sw_if_index0 == sw_if_index1  */
	      if (PREDICT_FALSE (cached_sw_if_index != sw_if_index0))
		{
		  cached_sw_if_index = sw_if_index0;
		  hi = vnet_get_sup_hw_interface (vnm, sw_if_index0);
		  intf0 = vec_elt_at_index (em->main_intfs, hi->hw_if_index);
		  subint0 = &intf0->untagged_subint;
		  cached_is_l2 = is_l20 = subint0->flags & SUBINT_CONFIG_L2;
		}

	      if (PREDICT_TRUE (is_l20 != 0))
		{
		  vnet_buffer (b0)->l3_hdr_offset =
		    vnet_buffer (b0)->l2_hdr_offset +
		    sizeof (ethernet_header_t);
		  vnet_buffer (b1)->l3_hdr_offset =
		    vnet_buffer (b1)->l2_hdr_offset +
		    sizeof (ethernet_header_t);
		  b0->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
		  b1->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
		  next0 = em->l2_next;
		  vnet_buffer (b0)->l2.l2_len = sizeof (ethernet_header_t);
		  next1 = em->l2_next;
		  vnet_buffer (b1)->l2.l2_len = sizeof (ethernet_header_t);
		}
	      else
		{
		  if (!ethernet_address_cast (e0->dst_address) &&
		      (hi->hw_address != 0) &&
		      !eth_mac_equal ((u8 *) e0, hi->hw_address))
		    error0 = ETHERNET_ERROR_L3_MAC_MISMATCH;
		  if (!ethernet_address_cast (e1->dst_address) &&
		      (hi->hw_address != 0) &&
		      !eth_mac_equal ((u8 *) e1, hi->hw_address))
		    error1 = ETHERNET_ERROR_L3_MAC_MISMATCH;
		  vlib_buffer_advance (b0, sizeof (ethernet_header_t));
		  determine_next_node (em, variant, 0, type0, b0,
				       &error0, &next0);
		  vlib_buffer_advance (b1, sizeof (ethernet_header_t));
		  determine_next_node (em, variant, 0, type1, b1,
				       &error1, &next1);
		}
	      goto ship_it01;
	    }

	  /* Slow-path for the tagged case */
	slowpath:
	  parse_header (variant,
			b0,
			&type0,
			&orig_type0, &outer_id0, &inner_id0, &match_flags0);

	  parse_header (variant,
			b1,
			&type1,
			&orig_type1, &outer_id1, &inner_id1, &match_flags1);

	  old_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  old_sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  eth_vlan_table_lookups (em,
				  vnm,
				  old_sw_if_index0,
				  orig_type0,
				  outer_id0,
				  inner_id0,
				  &hi0,
				  &main_intf0, &vlan_intf0, &qinq_intf0);

	  eth_vlan_table_lookups (em,
				  vnm,
				  old_sw_if_index1,
				  orig_type1,
				  outer_id1,
				  inner_id1,
				  &hi1,
				  &main_intf1, &vlan_intf1, &qinq_intf1);

	  identify_subint (hi0,
			   b0,
			   match_flags0,
			   main_intf0,
			   vlan_intf0,
			   qinq_intf0, &new_sw_if_index0, &error0, &is_l20);

	  identify_subint (hi1,
			   b1,
			   match_flags1,
			   main_intf1,
			   vlan_intf1,
			   qinq_intf1, &new_sw_if_index1, &error1, &is_l21);

	  // Save RX sw_if_index for later nodes
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	    error0 !=
	    ETHERNET_ERROR_NONE ? old_sw_if_index0 : new_sw_if_index0;
	  vnet_buffer (b1)->sw_if_index[VLIB_RX] =
	    error1 !=
	    ETHERNET_ERROR_NONE ? old_sw_if_index1 : new_sw_if_index1;

	  // Check if there is a stat to take (valid and non-main sw_if_index for pkt 0 or pkt 1)
	  if (((new_sw_if_index0 != ~0)
	       && (new_sw_if_index0 != old_sw_if_index0))
	      || ((new_sw_if_index1 != ~0)
		  && (new_sw_if_index1 != old_sw_if_index1)))
	    {

	      len0 = vlib_buffer_length_in_chain (vm, b0) + b0->current_data
		- vnet_buffer (b0)->l2_hdr_offset;
	      len1 = vlib_buffer_length_in_chain (vm, b1) + b1->current_data
		- vnet_buffer (b1)->l2_hdr_offset;

	      stats_n_packets += 2;
	      stats_n_bytes += len0 + len1;

	      if (PREDICT_FALSE
		  (!(new_sw_if_index0 == stats_sw_if_index
		     && new_sw_if_index1 == stats_sw_if_index)))
		{
		  stats_n_packets -= 2;
		  stats_n_bytes -= len0 + len1;

		  if (new_sw_if_index0 != old_sw_if_index0
		      && new_sw_if_index0 != ~0)
		    vlib_increment_combined_counter (vnm->
						     interface_main.combined_sw_if_counters
						     +
						     VNET_INTERFACE_COUNTER_RX,
						     thread_index,
						     new_sw_if_index0, 1,
						     len0);
		  if (new_sw_if_index1 != old_sw_if_index1
		      && new_sw_if_index1 != ~0)
		    vlib_increment_combined_counter (vnm->
						     interface_main.combined_sw_if_counters
						     +
						     VNET_INTERFACE_COUNTER_RX,
						     thread_index,
						     new_sw_if_index1, 1,
						     len1);

		  if (new_sw_if_index0 == new_sw_if_index1)
		    {
		      if (stats_n_packets > 0)
			{
			  vlib_increment_combined_counter
			    (vnm->interface_main.combined_sw_if_counters
			     + VNET_INTERFACE_COUNTER_RX,
			     thread_index,
			     stats_sw_if_index,
			     stats_n_packets, stats_n_bytes);
			  stats_n_packets = stats_n_bytes = 0;
			}
		      stats_sw_if_index = new_sw_if_index0;
		    }
		}
	    }

	  if (variant == ETHERNET_INPUT_VARIANT_NOT_L2)
	    is_l20 = is_l21 = 0;

	  determine_next_node (em, variant, is_l20, type0, b0, &error0,
			       &next0);
	  determine_next_node (em, variant, is_l21, type1, b1, &error1,
			       &next1);

	ship_it01:
	  b0->error = error_node->errors[error0];
	  b1->error = error_node->errors[error1];

	  // verify speculative enqueue
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u8 error0, next0;
	  u16 type0, orig_type0;
	  u16 outer_id0, inner_id0;
	  u32 match_flags0;
	  u32 old_sw_if_index0, new_sw_if_index0, len0;
	  vnet_hw_interface_t *hi0;
	  main_intf_t *main_intf0;
	  vlan_intf_t *vlan_intf0;
	  qinq_intf_t *qinq_intf0;
	  ethernet_header_t *e0;
	  u32 is_l20;

	  // Prefetch next iteration
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *p2;

	      p2 = vlib_get_buffer (vm, from[1]);
	      vlib_prefetch_buffer_header (p2, STORE);
	      CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, LOAD);
	    }

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  error0 = ETHERNET_ERROR_NONE;
	  e0 = vlib_buffer_get_current (b0);
	  type0 = clib_net_to_host_u16 (e0->type);

	  /* Set the L2 header offset for all packets */
	  vnet_buffer (b0)->l2_hdr_offset = b0->current_data;
	  b0->flags |= VNET_BUFFER_F_L2_HDR_OFFSET_VALID;

	  /* Speed-path for the untagged case */
	  if (PREDICT_TRUE (variant == ETHERNET_INPUT_VARIANT_ETHERNET
			    && !ethernet_frame_is_tagged (type0)))
	    {
	      main_intf_t *intf0;
	      subint_config_t *subint0;
	      u32 sw_if_index0;

	      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      is_l20 = cached_is_l2;

	      if (PREDICT_FALSE (cached_sw_if_index != sw_if_index0))
		{
		  cached_sw_if_index = sw_if_index0;
		  hi = vnet_get_sup_hw_interface (vnm, sw_if_index0);
		  intf0 = vec_elt_at_index (em->main_intfs, hi->hw_if_index);
		  subint0 = &intf0->untagged_subint;
		  cached_is_l2 = is_l20 = subint0->flags & SUBINT_CONFIG_L2;
		}


	      if (PREDICT_TRUE (is_l20 != 0))
		{
		  vnet_buffer (b0)->l3_hdr_offset =
		    vnet_buffer (b0)->l2_hdr_offset +
		    sizeof (ethernet_header_t);
		  b0->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
		  next0 = em->l2_next;
		  vnet_buffer (b0)->l2.l2_len = sizeof (ethernet_header_t);
		}
	      else
		{
		  if (!ethernet_address_cast (e0->dst_address) &&
		      (hi->hw_address != 0) &&
		      !eth_mac_equal ((u8 *) e0, hi->hw_address))
		    error0 = ETHERNET_ERROR_L3_MAC_MISMATCH;
		  vlib_buffer_advance (b0, sizeof (ethernet_header_t));
		  determine_next_node (em, variant, 0, type0, b0,
				       &error0, &next0);
		}
	      goto ship_it0;
	    }

	  /* Slow-path for the tagged case */
	  parse_header (variant,
			b0,
			&type0,
			&orig_type0, &outer_id0, &inner_id0, &match_flags0);

	  old_sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  eth_vlan_table_lookups (em,
				  vnm,
				  old_sw_if_index0,
				  orig_type0,
				  outer_id0,
				  inner_id0,
				  &hi0,
				  &main_intf0, &vlan_intf0, &qinq_intf0);

	  identify_subint (hi0,
			   b0,
			   match_flags0,
			   main_intf0,
			   vlan_intf0,
			   qinq_intf0, &new_sw_if_index0, &error0, &is_l20);

	  // Save RX sw_if_index for later nodes
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] =
	    error0 !=
	    ETHERNET_ERROR_NONE ? old_sw_if_index0 : new_sw_if_index0;

	  // Increment subinterface stats
	  // Note that interface-level counters have already been incremented
	  // prior to calling this function. Thus only subinterface counters
	  // are incremented here.
	  //
	  // Interface level counters include packets received on the main
	  // interface and all subinterfaces. Subinterface level counters
	  // include only those packets received on that subinterface
	  // Increment stats if the subint is valid and it is not the main intf
	  if ((new_sw_if_index0 != ~0)
	      && (new_sw_if_index0 != old_sw_if_index0))
	    {

	      len0 = vlib_buffer_length_in_chain (vm, b0) + b0->current_data
		- vnet_buffer (b0)->l2_hdr_offset;

	      stats_n_packets += 1;
	      stats_n_bytes += len0;

	      // Batch stat increments from the same subinterface so counters
	      // don't need to be incremented for every packet.
	      if (PREDICT_FALSE (new_sw_if_index0 != stats_sw_if_index))
		{
		  stats_n_packets -= 1;
		  stats_n_bytes -= len0;

		  if (new_sw_if_index0 != ~0)
		    vlib_increment_combined_counter
		      (vnm->interface_main.combined_sw_if_counters
		       + VNET_INTERFACE_COUNTER_RX,
		       thread_index, new_sw_if_index0, 1, len0);
		  if (stats_n_packets > 0)
		    {
		      vlib_increment_combined_counter
			(vnm->interface_main.combined_sw_if_counters
			 + VNET_INTERFACE_COUNTER_RX,
			 thread_index,
			 stats_sw_if_index, stats_n_packets, stats_n_bytes);
		      stats_n_packets = stats_n_bytes = 0;
		    }
		  stats_sw_if_index = new_sw_if_index0;
		}
	    }

	  if (variant == ETHERNET_INPUT_VARIANT_NOT_L2)
	    is_l20 = 0;

	  determine_next_node (em, variant, is_l20, type0, b0, &error0,
			       &next0);

	ship_it0:
	  b0->error = error_node->errors[error0];

	  // verify speculative enqueue
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  // Increment any remaining batched stats
  if (stats_n_packets > 0)
    {
      vlib_increment_combined_counter
	(vnm->interface_main.combined_sw_if_counters
	 + VNET_INTERFACE_COUNTER_RX,
	 thread_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
      node->runtime_data[0] = stats_sw_if_index;
    }
}

VLIB_NODE_FN (ethernet_input_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_pkts = frame->n_vectors;

  ethernet_input_trace (vm, node, frame);

  if (frame->flags & ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX)
    {
      ethernet_input_frame_t *ef = vlib_frame_scalar_args (frame);
      int ip4_cksum_ok = (frame->flags & ETH_INPUT_FRAME_F_IP4_CKSUM_OK) != 0;
      vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, ef->hw_if_index);
      eth_input_single_int (vm, node, hi, from, n_pkts, ip4_cksum_ok);
    }
  else
    ethernet_input_inline (vm, node, from, n_pkts,
			   ETHERNET_INPUT_VARIANT_ETHERNET);
  return n_pkts;
}

VLIB_NODE_FN (ethernet_input_type_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  u32 *from = vlib_frame_vector_args (from_frame);
  u32 n_packets = from_frame->n_vectors;
  ethernet_input_trace (vm, node, from_frame);
  ethernet_input_inline (vm, node, from, n_packets,
			 ETHERNET_INPUT_VARIANT_ETHERNET_TYPE);
  return n_packets;
}

VLIB_NODE_FN (ethernet_input_not_l2_node) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * from_frame)
{
  u32 *from = vlib_frame_vector_args (from_frame);
  u32 n_packets = from_frame->n_vectors;
  ethernet_input_trace (vm, node, from_frame);
  ethernet_input_inline (vm, node, from, n_packets,
			 ETHERNET_INPUT_VARIANT_NOT_L2);
  return n_packets;
}


// Return the subinterface config struct for the given sw_if_index
// Also return via parameter the appropriate match flags for the
// configured number of tags.
// On error (unsupported or not ethernet) return 0.
static subint_config_t *
ethernet_sw_interface_get_config (vnet_main_t * vnm,
				  u32 sw_if_index,
				  u32 * flags, u32 * unsupported)
{
  ethernet_main_t *em = &ethernet_main;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  main_intf_t *main_intf;
  vlan_table_t *vlan_table;
  qinq_table_t *qinq_table;
  subint_config_t *subint = 0;

  hi = vnet_get_sup_hw_interface (vnm, sw_if_index);

  if (!hi || (hi->hw_class_index != ethernet_hw_interface_class.index))
    {
      *unsupported = 0;
      goto done;		// non-ethernet interface
    }

  // ensure there's an entry for the main intf (shouldn't really be necessary)
  vec_validate (em->main_intfs, hi->hw_if_index);
  main_intf = vec_elt_at_index (em->main_intfs, hi->hw_if_index);

  // Locate the subint for the given ethernet config
  si = vnet_get_sw_interface (vnm, sw_if_index);

  if (si->type == VNET_SW_INTERFACE_TYPE_P2P)
    {
      p2p_ethernet_main_t *p2pm = &p2p_main;
      u32 p2pe_sw_if_index =
	p2p_ethernet_lookup (hi->hw_if_index, si->p2p.client_mac);
      if (p2pe_sw_if_index == ~0)
	{
	  pool_get (p2pm->p2p_subif_pool, subint);
	  si->p2p.pool_index = subint - p2pm->p2p_subif_pool;
	}
      else
	subint = vec_elt_at_index (p2pm->p2p_subif_pool, si->p2p.pool_index);
      *flags = SUBINT_CONFIG_P2P;
    }
  else if (si->type == VNET_SW_INTERFACE_TYPE_PIPE)
    {
      pipe_t *pipe;

      pipe = pipe_get (sw_if_index);
      subint = &pipe->subint;
      *flags = SUBINT_CONFIG_P2P;
    }
  else if (si->sub.eth.flags.default_sub)
    {
      subint = &main_intf->default_subint;
      *flags = SUBINT_CONFIG_MATCH_1_TAG |
	SUBINT_CONFIG_MATCH_2_TAG | SUBINT_CONFIG_MATCH_3_TAG;
    }
  else if ((si->sub.eth.flags.no_tags) || (si->sub.eth.raw_flags == 0))
    {
      // if no flags are set then this is a main interface
      // so treat as untagged
      subint = &main_intf->untagged_subint;
      *flags = SUBINT_CONFIG_MATCH_0_TAG;
    }
  else
    {
      // one or two tags
      // first get the vlan table
      if (si->sub.eth.flags.dot1ad)
	{
	  if (main_intf->dot1ad_vlans == 0)
	    {
	      // Allocate a vlan table from the pool
	      pool_get (em->vlan_pool, vlan_table);
	      main_intf->dot1ad_vlans = vlan_table - em->vlan_pool;
	    }
	  else
	    {
	      // Get ptr to existing vlan table
	      vlan_table =
		vec_elt_at_index (em->vlan_pool, main_intf->dot1ad_vlans);
	    }
	}
      else
	{			// dot1q
	  if (main_intf->dot1q_vlans == 0)
	    {
	      // Allocate a vlan table from the pool
	      pool_get (em->vlan_pool, vlan_table);
	      main_intf->dot1q_vlans = vlan_table - em->vlan_pool;
	    }
	  else
	    {
	      // Get ptr to existing vlan table
	      vlan_table =
		vec_elt_at_index (em->vlan_pool, main_intf->dot1q_vlans);
	    }
	}

      if (si->sub.eth.flags.one_tag)
	{
	  *flags = si->sub.eth.flags.exact_match ?
	    SUBINT_CONFIG_MATCH_1_TAG :
	    (SUBINT_CONFIG_MATCH_1_TAG |
	     SUBINT_CONFIG_MATCH_2_TAG | SUBINT_CONFIG_MATCH_3_TAG);

	  if (si->sub.eth.flags.outer_vlan_id_any)
	    {
	      // not implemented yet
	      *unsupported = 1;
	      goto done;
	    }
	  else
	    {
	      // a single vlan, a common case
	      subint =
		&vlan_table->vlans[si->sub.eth.
				   outer_vlan_id].single_tag_subint;
	    }

	}
      else
	{
	  // Two tags
	  *flags = si->sub.eth.flags.exact_match ?
	    SUBINT_CONFIG_MATCH_2_TAG :
	    (SUBINT_CONFIG_MATCH_2_TAG | SUBINT_CONFIG_MATCH_3_TAG);

	  if (si->sub.eth.flags.outer_vlan_id_any
	      && si->sub.eth.flags.inner_vlan_id_any)
	    {
	      // not implemented yet
	      *unsupported = 1;
	      goto done;
	    }

	  if (si->sub.eth.flags.inner_vlan_id_any)
	    {
	      // a specific outer and "any" inner
	      // don't need a qinq table for this
	      subint =
		&vlan_table->vlans[si->sub.eth.
				   outer_vlan_id].inner_any_subint;
	      if (si->sub.eth.flags.exact_match)
		{
		  *flags = SUBINT_CONFIG_MATCH_2_TAG;
		}
	      else
		{
		  *flags = SUBINT_CONFIG_MATCH_2_TAG |
		    SUBINT_CONFIG_MATCH_3_TAG;
		}
	    }
	  else
	    {
	      // a specific outer + specifc innner vlan id, a common case

	      // get the qinq table
	      if (vlan_table->vlans[si->sub.eth.outer_vlan_id].qinqs == 0)
		{
		  // Allocate a qinq table from the pool
		  pool_get (em->qinq_pool, qinq_table);
		  vlan_table->vlans[si->sub.eth.outer_vlan_id].qinqs =
		    qinq_table - em->qinq_pool;
		}
	      else
		{
		  // Get ptr to existing qinq table
		  qinq_table =
		    vec_elt_at_index (em->qinq_pool,
				      vlan_table->vlans[si->sub.
							eth.outer_vlan_id].
				      qinqs);
		}
	      subint = &qinq_table->vlans[si->sub.eth.inner_vlan_id].subint;
	    }
	}
    }

done:
  return subint;
}

static clib_error_t *
ethernet_sw_interface_up_down (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  subint_config_t *subint;
  u32 dummy_flags;
  u32 dummy_unsup;
  clib_error_t *error = 0;

  // Find the config for this subinterface
  subint =
    ethernet_sw_interface_get_config (vnm, sw_if_index, &dummy_flags,
				      &dummy_unsup);

  if (subint == 0)
    {
      // not implemented yet or not ethernet
      goto done;
    }

  subint->sw_if_index =
    ((flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? sw_if_index : ~0);

done:
  return error;
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION (ethernet_sw_interface_up_down);


#ifndef CLIB_MARCH_VARIANT
// Set the L2/L3 mode for the subinterface
void
ethernet_sw_interface_set_l2_mode (vnet_main_t * vnm, u32 sw_if_index, u32 l2)
{
  subint_config_t *subint;
  u32 dummy_flags;
  u32 dummy_unsup;
  int is_port;
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);

  is_port = !(sw->type == VNET_SW_INTERFACE_TYPE_SUB);

  // Find the config for this subinterface
  subint =
    ethernet_sw_interface_get_config (vnm, sw_if_index, &dummy_flags,
				      &dummy_unsup);

  if (subint == 0)
    {
      // unimplemented or not ethernet
      goto done;
    }

  // Double check that the config we found is for our interface (or the interface is down)
  ASSERT ((subint->sw_if_index == sw_if_index) | (subint->sw_if_index == ~0));

  if (l2)
    {
      subint->flags |= SUBINT_CONFIG_L2;
      if (is_port)
	subint->flags |=
	  SUBINT_CONFIG_MATCH_0_TAG | SUBINT_CONFIG_MATCH_1_TAG
	  | SUBINT_CONFIG_MATCH_2_TAG | SUBINT_CONFIG_MATCH_3_TAG;
    }
  else
    {
      subint->flags &= ~SUBINT_CONFIG_L2;
      if (is_port)
	subint->flags &=
	  ~(SUBINT_CONFIG_MATCH_1_TAG | SUBINT_CONFIG_MATCH_2_TAG
	    | SUBINT_CONFIG_MATCH_3_TAG);
    }

done:
  return;
}

/*
 * Set the L2/L3 mode for the subinterface regardless of port
 */
void
ethernet_sw_interface_set_l2_mode_noport (vnet_main_t * vnm,
					  u32 sw_if_index, u32 l2)
{
  subint_config_t *subint;
  u32 dummy_flags;
  u32 dummy_unsup;

  /* Find the config for this subinterface */
  subint =
    ethernet_sw_interface_get_config (vnm, sw_if_index, &dummy_flags,
				      &dummy_unsup);

  if (subint == 0)
    {
      /* unimplemented or not ethernet */
      goto done;
    }

  /*
   * Double check that the config we found is for our interface (or the
   * interface is down)
   */
  ASSERT ((subint->sw_if_index == sw_if_index) | (subint->sw_if_index == ~0));

  if (l2)
    {
      subint->flags |= SUBINT_CONFIG_L2;
    }
  else
    {
      subint->flags &= ~SUBINT_CONFIG_L2;
    }

done:
  return;
}
#endif

static clib_error_t *
ethernet_sw_interface_add_del (vnet_main_t * vnm,
			       u32 sw_if_index, u32 is_create)
{
  clib_error_t *error = 0;
  subint_config_t *subint;
  u32 match_flags;
  u32 unsupported = 0;

  // Find the config for this subinterface
  subint =
    ethernet_sw_interface_get_config (vnm, sw_if_index, &match_flags,
				      &unsupported);

  if (subint == 0)
    {
      // not implemented yet or not ethernet
      if (unsupported)
	{
	  // this is the NYI case
	  error = clib_error_return (0, "not implemented yet");
	}
      goto done;
    }

  if (!is_create)
    {
      subint->flags = 0;
      return error;
    }

  // Initialize the subint
  if (subint->flags & SUBINT_CONFIG_VALID)
    {
      // Error vlan already in use
      error = clib_error_return (0, "vlan is already in use");
    }
  else
    {
      // Note that config is L3 by default
      subint->flags = SUBINT_CONFIG_VALID | match_flags;
      subint->sw_if_index = ~0;	// because interfaces are initially down
    }

done:
  return error;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ethernet_sw_interface_add_del);

static char *ethernet_error_strings[] = {
#define ethernet_error(n,c,s) s,
#include "error.def"
#undef ethernet_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ethernet_input_node) = {
  .name = "ethernet-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .scalar_size = sizeof (ethernet_input_frame_t),
  .n_errors = ETHERNET_N_ERROR,
  .error_strings = ethernet_error_strings,
  .n_next_nodes = ETHERNET_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ETHERNET_INPUT_NEXT_##s] = n,
    foreach_ethernet_input_next
#undef _
  },
  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_ethernet_input_trace,
  .unformat_buffer = unformat_ethernet_header,
};

VLIB_REGISTER_NODE (ethernet_input_type_node) = {
  .name = "ethernet-input-type",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_next_nodes = ETHERNET_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ETHERNET_INPUT_NEXT_##s] = n,
    foreach_ethernet_input_next
#undef _
  },
};

VLIB_REGISTER_NODE (ethernet_input_not_l2_node) = {
  .name = "ethernet-input-not-l2",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .n_next_nodes = ETHERNET_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ETHERNET_INPUT_NEXT_##s] = n,
    foreach_ethernet_input_next
#undef _
  },
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
void
ethernet_set_rx_redirect (vnet_main_t * vnm,
			  vnet_hw_interface_t * hi, u32 enable)
{
  // Insure all packets go to ethernet-input (i.e. untagged ipv4 packets
  // don't go directly to ip4-input)
  vnet_hw_interface_rx_redirect_to_node
    (vnm, hi->hw_if_index, enable ? ethernet_input_node.index : ~0);
}


/*
 * Initialization and registration for the next_by_ethernet structure
 */

clib_error_t *
next_by_ethertype_init (next_by_ethertype_t * l3_next)
{
  l3_next->input_next_by_type = sparse_vec_new
    ( /* elt bytes */ sizeof (l3_next->input_next_by_type[0]),
     /* bits in index */ BITS (((ethernet_header_t *) 0)->type));

  vec_validate (l3_next->sparse_index_by_input_next_index,
		ETHERNET_INPUT_NEXT_DROP);
  vec_validate (l3_next->sparse_index_by_input_next_index,
		ETHERNET_INPUT_NEXT_PUNT);
  l3_next->sparse_index_by_input_next_index[ETHERNET_INPUT_NEXT_DROP] =
    SPARSE_VEC_INVALID_INDEX;
  l3_next->sparse_index_by_input_next_index[ETHERNET_INPUT_NEXT_PUNT] =
    SPARSE_VEC_INVALID_INDEX;

  /*
   * Make sure we don't wipe out an ethernet registration by mistake
   * Can happen if init function ordering constraints are missing.
   */
  if (CLIB_DEBUG > 0)
    {
      ethernet_main_t *em = &ethernet_main;
      ASSERT (em->next_by_ethertype_register_called == 0);
    }

  return 0;
}

// Add an ethertype -> next index mapping to the structure
clib_error_t *
next_by_ethertype_register (next_by_ethertype_t * l3_next,
			    u32 ethertype, u32 next_index)
{
  u32 i;
  u16 *n;
  ethernet_main_t *em = &ethernet_main;

  if (CLIB_DEBUG > 0)
    {
      ethernet_main_t *em = &ethernet_main;
      em->next_by_ethertype_register_called = 1;
    }

  /* Setup ethernet type -> next index sparse vector mapping. */
  n = sparse_vec_validate (l3_next->input_next_by_type, ethertype);
  n[0] = next_index;

  /* Rebuild next index -> sparse index inverse mapping when sparse vector
     is updated. */
  vec_validate (l3_next->sparse_index_by_input_next_index, next_index);
  for (i = 1; i < vec_len (l3_next->input_next_by_type); i++)
    l3_next->
      sparse_index_by_input_next_index[l3_next->input_next_by_type[i]] = i;

  // do not allow the cached next index's to be updated if L3
  // redirect is enabled, as it will have overwritten them
  if (!em->redirect_l3)
    {
      // Cache common ethertypes directly
      if (ethertype == ETHERNET_TYPE_IP4)
	{
	  l3_next->input_next_ip4 = next_index;
	}
      else if (ethertype == ETHERNET_TYPE_IP6)
	{
	  l3_next->input_next_ip6 = next_index;
	}
      else if (ethertype == ETHERNET_TYPE_MPLS)
	{
	  l3_next->input_next_mpls = next_index;
	}
    }
  return 0;
}


static clib_error_t *
ethernet_input_init (vlib_main_t * vm)
{
  ethernet_main_t *em = &ethernet_main;
  __attribute__ ((unused)) vlan_table_t *invalid_vlan_table;
  __attribute__ ((unused)) qinq_table_t *invalid_qinq_table;

  ethernet_setup_node (vm, ethernet_input_node.index);
  ethernet_setup_node (vm, ethernet_input_type_node.index);
  ethernet_setup_node (vm, ethernet_input_not_l2_node.index);

  next_by_ethertype_init (&em->l3_next);

  // Initialize pools and vector for vlan parsing
  vec_validate (em->main_intfs, 10);	// 10 main interfaces
  pool_alloc (em->vlan_pool, 10);
  pool_alloc (em->qinq_pool, 1);

  // The first vlan pool will always be reserved for an invalid table
  pool_get (em->vlan_pool, invalid_vlan_table);	// first id = 0
  // The first qinq pool will always be reserved for an invalid table
  pool_get (em->qinq_pool, invalid_qinq_table);	// first id = 0

  return 0;
}

VLIB_INIT_FUNCTION (ethernet_input_init);

void
ethernet_register_input_type (vlib_main_t * vm,
			      ethernet_type_t type, u32 node_index)
{
  ethernet_main_t *em = &ethernet_main;
  ethernet_type_info_t *ti;
  u32 i;

  {
    clib_error_t *error = vlib_call_init_function (vm, ethernet_init);
    if (error)
      clib_error_report (error);
  }

  ti = ethernet_get_type_info (em, type);
  ti->node_index = node_index;
  ti->next_index = vlib_node_add_next (vm,
				       ethernet_input_node.index, node_index);
  i = vlib_node_add_next (vm, ethernet_input_type_node.index, node_index);
  ASSERT (i == ti->next_index);

  i = vlib_node_add_next (vm, ethernet_input_not_l2_node.index, node_index);
  ASSERT (i == ti->next_index);

  // Add the L3 node for this ethertype to the next nodes structure
  next_by_ethertype_register (&em->l3_next, type, ti->next_index);

  // Call the registration functions for other nodes that want a mapping
  l2bvi_register_input_type (vm, type, node_index);
}

void
ethernet_register_l2_input (vlib_main_t * vm, u32 node_index)
{
  ethernet_main_t *em = &ethernet_main;
  u32 i;

  em->l2_next =
    vlib_node_add_next (vm, ethernet_input_node.index, node_index);

  /*
   * Even if we never use these arcs, we have to align the next indices...
   */
  i = vlib_node_add_next (vm, ethernet_input_type_node.index, node_index);

  ASSERT (i == em->l2_next);

  i = vlib_node_add_next (vm, ethernet_input_not_l2_node.index, node_index);
  ASSERT (i == em->l2_next);
}

// Register a next node for L3 redirect, and enable L3 redirect
void
ethernet_register_l3_redirect (vlib_main_t * vm, u32 node_index)
{
  ethernet_main_t *em = &ethernet_main;
  u32 i;

  em->redirect_l3 = 1;
  em->redirect_l3_next = vlib_node_add_next (vm,
					     ethernet_input_node.index,
					     node_index);
  /*
   * Change the cached next nodes to the redirect node
   */
  em->l3_next.input_next_ip4 = em->redirect_l3_next;
  em->l3_next.input_next_ip6 = em->redirect_l3_next;
  em->l3_next.input_next_mpls = em->redirect_l3_next;

  /*
   * Even if we never use these arcs, we have to align the next indices...
   */
  i = vlib_node_add_next (vm, ethernet_input_type_node.index, node_index);

  ASSERT (i == em->redirect_l3_next);

  i = vlib_node_add_next (vm, ethernet_input_not_l2_node.index, node_index);

  ASSERT (i == em->redirect_l3_next);
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
