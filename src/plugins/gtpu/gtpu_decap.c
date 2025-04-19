/*
 * decap.c: gtpu tunnel decap packet processing
 *
 * Copyright (c) 2017 Intel and/or its affiliates.
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

#include <vlib/vlib.h>
#include <gtpu/gtpu.h>

extern vlib_node_registration_t gtpu4_input_node;
extern vlib_node_registration_t gtpu6_input_node;

typedef struct {
  u32 next_index;
  u32 tunnel_index;
  u32 error;
  u32 teid;
  gtpu_header_t header;
  u8 forwarding_type;
} gtpu_rx_trace_t;

static u8 * format_gtpu_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gtpu_rx_trace_t * t = va_arg (*args, gtpu_rx_trace_t *);

  if (t->tunnel_index != ~0)
    {
      s = format (s, "GTPU decap from gtpu_tunnel%d ", t->tunnel_index);
      switch (t->forwarding_type)
	{
	case GTPU_FORWARD_BAD_HEADER:
	  s = format (s, "forwarding bad-header ");
	  break;
	case GTPU_FORWARD_UNKNOWN_TEID:
	  s = format (s, "forwarding unknown-teid ");
	  break;
	case GTPU_FORWARD_UNKNOWN_TYPE:
	  s = format (s, "forwarding unknown-type ");
	  break;
	}
      s = format (s, "teid %u, ", t->teid);
    }
  else
    {
      s = format (s, "GTPU decap error - tunnel for teid %u does not exist, ",
		  t->teid);
    }
  s = format (s, "next %d error %d, ", t->next_index, t->error);
  s = format (s, "flags: 0x%x, type: %d, length: %d", t->header.ver_flags,
	      t->header.type, t->header.length);
  return s;
}

always_inline u32
validate_gtpu_fib (vlib_buffer_t *b, gtpu_tunnel_t *t, u32 is_ip4)
{
  return t->encap_fib_index == vlib_buffer_get_ip_fib_index (b, is_ip4);
}

// Gets run with every input
always_inline uword
gtpu_input (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame,
             u32 is_ip4)
{
  u32 n_left_from, next_index, * from, * to_next;
  gtpu_main_t * gtm = &gtpu_main;
  vnet_main_t * vnm = gtm->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 last_tunnel_index = ~0;
  gtpu4_tunnel_key_t last_key4;
  gtpu6_tunnel_key_t last_key6;
  u32 pkts_decapsulated = 0;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;

  if (is_ip4)
    last_key4.as_u64 = ~0;
  else
    clib_memset (&last_key6, 0xff, sizeof (last_key6));

  // Where is the framevector coming from
  from = vlib_frame_vector_args (from_frame);
  // number of packets left in frame
  n_left_from = from_frame->n_vectors;

  // whats the next node it needs to go to
  next_index = node->cached_next_index;
  // stats from the next interface
  stats_sw_if_index = node->runtime_data[0];
  // number of packets processed
  stats_n_packets = stats_n_bytes = 0;

  // run until no more packets left in vectorframe
  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      // get vectorframe to process
      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);
      // while there are still more than 4 packets left in frame and more than
      // two packets in current frame
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  // buffer index for loading packet data
	  u32 bi0, bi1;
	  // vlib packet buffer
	  vlib_buffer_t * b0, * b1;
	  // next operation to do with the packet
	  u32 next0, next1;
	  // IP4 header type
	  ip4_header_t *ip4_0, *ip4_1;
	  ip6_header_t *ip6_0, *ip6_1;
	  gtpu_header_t *gtpu0, *gtpu1;
	  i32 gtpu_hdr_len0, gtpu_hdr_len1;
	  uword * p0, * p1;
          u32 tunnel_index0, tunnel_index1;
          gtpu_tunnel_t * t0, * t1, * mt0 = NULL, * mt1 = NULL;
          gtpu4_tunnel_key_t key4_0, key4_1;
          gtpu6_tunnel_key_t key6_0, key6_1;
          u32 error0, error1;
	  u32 sw_if_index0, sw_if_index1, len0, len1;
          u8 has_space0, has_space1;
          u8 ver0, ver1;
	  udp_header_t *udp0, *udp1;
	  ip_csum_t sum0, sum1;
	  u32 old0, old1;
	  gtpu_ext_header_t ext = { .type = 0, .len = 0, .pad = 0 };
	  gtpu_ext_header_t *ext0, *ext1;
	  bool is_fast_track0, is_fast_track1;
	  ext0 = ext1 = &ext;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    // prefetch 3 and 4
	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	  }

	  // getting buffer index from vectorframe
	  bi0 = from[0];
	  bi1 = from[1];
	  // pre inserting the packets for the next node
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  // forward in vectorframe
	  from += 2;
	  // forward next node
	  to_next += 2;
	  // decimate message counter for next node
	  n_left_to_next -= 2;
	  // decimate message counter for current progessing node
	  n_left_from -= 2;

	  // load packets into buffer
	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

          /* udp leaves current_data pointing at the gtpu header */
	  // get pointers to the beginnings of the gtpu frame
	  gtpu0 = vlib_buffer_get_current (b0);
	  gtpu1 = vlib_buffer_get_current (b1);
	  if (is_ip4)
	    {
	      ip4_0 = (void *) ((u8 *) gtpu0 - sizeof (udp_header_t) -
				sizeof (ip4_header_t));
	      ip4_1 = (void *) ((u8 *) gtpu1 - sizeof (udp_header_t) -
				sizeof (ip4_header_t));
	    }
	  else
	    {
	      ip6_0 = (void *) ((u8 *) gtpu0 - sizeof (udp_header_t) -
				sizeof (ip6_header_t));
	      ip6_1 = (void *) ((u8 *) gtpu1 - sizeof (udp_header_t) -
				sizeof (ip6_header_t));
	    }
	  udp0 = (void *) ((u8 *) gtpu0 - sizeof (udp_header_t));
	  udp1 = (void *) ((u8 *) gtpu1 - sizeof (udp_header_t));

	  tunnel_index0 = ~0;
	  error0 = 0;

	  tunnel_index1 = ~0;
	  error1 = 0;

	  /* speculatively load gtp header version field */
	  ver0 = gtpu0->ver_flags;
	  ver1 = gtpu1->ver_flags;

	  /*
           * Manipulate gtpu header
           * TBD: Manipulate Sequence Number and N-PDU Number
           * TBD: Manipulate Next Extension Header
           */

	  /* Perform all test assuming the packet has the needed space.
	   * Check if version 1, not PT, not reserved.
	   * Check message type 255.
	   */
	  is_fast_track0 =
	    ((ver0 & (GTPU_VER_MASK | GTPU_PT_BIT | GTPU_RES_BIT)) ==
	     (GTPU_V1_VER | GTPU_PT_BIT));
	  is_fast_track0 = is_fast_track0 & (gtpu0->type == 255);

	  is_fast_track1 =
	    ((ver1 & (GTPU_VER_MASK | GTPU_PT_BIT | GTPU_RES_BIT)) ==
	     (GTPU_V1_VER | GTPU_PT_BIT));
	  is_fast_track1 = is_fast_track1 & (gtpu1->type == 255);

	  /* Make the header overlap the end of the gtpu_header_t, so
	   * that it starts with the same Next extension header as the
	   * gtpu_header_t.
	   * This means that the gtpu_ext_header_t (ext) has the type
	   * from the previous header and the length from the current one.
	   * Works both for the first gtpu_header_t and all following
	   * gtpu_ext_header_t extensions.
	   * Copy the ext data if the E bit is set, else use the 0 value.
	   */
	  ext0 = (ver0 & GTPU_E_BIT) ?
			 (gtpu_ext_header_t *) &gtpu0->next_ext_type :
			 &ext;
	  ext1 = (ver1 & GTPU_E_BIT) ?
			 (gtpu_ext_header_t *) &gtpu1->next_ext_type :
			 &ext;

	  /* One or more of the E, S and PN flags are set, so all 3 fields
	   * must be present:
	   * The gtpu_header_t contains the Sequence number, N-PDU number and
	   * Next extension header type.
	   * If E is not set subtract 4 bytes from the header.
	   * Then add the length of the extension. 0 * 4 if E is not set,
	   * else it's the ext->len from the gtp extension. Length is multiple
	   * of 4 always.
	   * Note: This length is only valid if the header itself is valid,
	   * so it must be verified before use.
	   */
	  gtpu_hdr_len0 = sizeof (gtpu_header_t) -
			  (((ver0 & GTPU_E_S_PN_BIT) == 0) * 4) +
			  ext0->len * 4;
	  gtpu_hdr_len1 = sizeof (gtpu_header_t) -
			  (((ver1 & GTPU_E_S_PN_BIT) == 0) * 4) +
			  ext1->len * 4;

	  /* Get the next extension, unconditionally.
	   * If E was not set in the gtp header ext->len is zero.
	   * If E was set ext0 will now point to the packet buffer.
	   * If the gtp packet is illegal this might point outside the buffer.
	   * TBD check the updated for ext0->type != 0, and continue removing
	   * extensions. Only for clarity, will be optimized away.
	   */
	  ext0 += ext0->len * 4 / sizeof (*ext0);
	  ext1 += ext1->len * 4 / sizeof (*ext1);

	  /* Check the space, if this is true then ext0 points to a valid
	   * location in the buffer as well.
	   */
	  has_space0 = vlib_buffer_has_space (b0, gtpu_hdr_len0);
	  has_space1 = vlib_buffer_has_space (b1, gtpu_hdr_len1);

	  /* Diverge the packet paths for 0 and 1 */
	  if (PREDICT_FALSE ((!is_fast_track0) | (!has_space0)))
	    {
	      /* Not fast path. ext0 and gtpu_hdr_len0 might be wrong */

	      /* GCC will hopefully fix the duplicate compute */
	      if (PREDICT_FALSE (
		    !((ver0 & (GTPU_VER_MASK | GTPU_PT_BIT | GTPU_RES_BIT)) ==
		      (GTPU_V1_VER | GTPU_PT_BIT)) |
		    (!has_space0)))
		{
		  /* The header or size is wrong */
		  error0 =
		    has_space0 ? GTPU_ERROR_BAD_VER : GTPU_ERROR_TOO_SMALL;
		  next0 = GTPU_INPUT_NEXT_DROP;

		  /* This is an unsupported/bad packet.
		   * Check if it is to be forwarded.
		   */
		  if (is_ip4)
		    tunnel_index0 = gtm->bad_header_forward_tunnel_index_ipv4;
		  else
		    tunnel_index0 = gtm->bad_header_forward_tunnel_index_ipv6;

		  if (PREDICT_FALSE (tunnel_index0 != ~0))
		    goto forward0;

		  goto trace0;
		}
	      /*  Correct version and has the space. It can only be unknown
	       * message type.
	       */
	      error0 = GTPU_ERROR_UNSUPPORTED_TYPE;
	      next0 = GTPU_INPUT_NEXT_DROP;

	      /* This is an error/nonstandard packet
	       * Check if it is to be forwarded. */
	      if (is_ip4)
		tunnel_index0 = gtm->unknown_type_forward_tunnel_index_ipv4;
	      else
		tunnel_index0 = gtm->unknown_type_forward_tunnel_index_ipv6;

	      if (PREDICT_FALSE (tunnel_index0 != ~0))
		goto forward0;

	      /* The packet is ipv6/not forwarded */
	      goto trace0;
	    }

	  /* Manipulate packet 0 */
          if (is_ip4) {
            key4_0.src = ip4_0->src_address.as_u32;
            key4_0.teid = gtpu0->teid;

	    /* Make sure GTPU tunnel exist according to packet SourceIP and
	     * teid SourceIP identify a GTPU path, and teid identify a tunnel
	     * in a given GTPU path */
	    if (PREDICT_FALSE (key4_0.as_u64 != last_key4.as_u64))
	      {
		p0 = hash_get (gtm->gtpu4_tunnel_by_key, key4_0.as_u64);
		if (PREDICT_FALSE (p0 == NULL))
		  {
		    error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
		    next0 = GTPU_INPUT_NEXT_DROP;
		    /* This is a standard packet, but no tunnel was found.
		     * Check if it is to be forwarded. */
		    tunnel_index0 =
		      gtm->unknown_teid_forward_tunnel_index_ipv4;
		    if (PREDICT_FALSE (tunnel_index0 != ~0))
		      goto forward0;
		    goto trace0;
		  }
		last_key4.as_u64 = key4_0.as_u64;
		tunnel_index0 = last_tunnel_index = p0[0];
	      }
	    else // when the address of the packet is the same as the packet
		 // before ... saving lookup in table
	      tunnel_index0 = last_tunnel_index;
	    // tunnel index in vpp
	    t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);

	    /* Validate GTPU tunnel encap-fib index against packet */
	    if (PREDICT_FALSE (validate_gtpu_fib (b0, t0, is_ip4) == 0))
	      {
		error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
		next0 = GTPU_INPUT_NEXT_DROP;
		tunnel_index0 = gtm->unknown_teid_forward_tunnel_index_ipv4;
		if (PREDICT_FALSE (tunnel_index0 != ~0))
		  goto forward0;
		goto trace0;
	      }

	    /* Validate GTPU tunnel SourceIP against packet DestinationIP */
	    if (PREDICT_TRUE (ip4_0->dst_address.as_u32 == t0->src.ip4.as_u32))
	      goto next0; /* valid packet */
	    if (PREDICT_FALSE (ip4_address_is_multicast (&ip4_0->dst_address)))
	      {
		key4_0.src = ip4_0->dst_address.as_u32;
		key4_0.teid = gtpu0->teid;
		/* Make sure mcast GTPU tunnel exist by packet DIP and teid */
		p0 = hash_get (gtm->gtpu4_tunnel_by_key, key4_0.as_u64);
		if (PREDICT_TRUE (p0 != NULL))
		  {
		    mt0 = pool_elt_at_index (gtm->tunnels, p0[0]);
		    goto next0; /* valid packet */
		  }
	      }
	    error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
	    next0 = GTPU_INPUT_NEXT_DROP;
	    tunnel_index0 = gtm->unknown_teid_forward_tunnel_index_ipv4;
	    if (PREDICT_FALSE (tunnel_index0 != ~0))
	      goto forward0;
	    goto trace0;

         } else /* !is_ip4 */ {
            key6_0.src.as_u64[0] = ip6_0->src_address.as_u64[0];
            key6_0.src.as_u64[1] = ip6_0->src_address.as_u64[1];
            key6_0.teid = gtpu0->teid;

 	    /* Make sure GTPU tunnel exist according to packet SIP and teid
 	     * SIP identify a GTPU path, and teid identify a tunnel in a given GTPU path */
            if (PREDICT_FALSE (memcmp(&key6_0, &last_key6, sizeof(last_key6)) != 0))
              {
                p0 = hash_get_mem (gtm->gtpu6_tunnel_by_key, &key6_0);
                if (PREDICT_FALSE (p0 == NULL))
                  {
                    error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
                    next0 = GTPU_INPUT_NEXT_DROP;
		    /* This is a standard packet, but no tunnel was found.
		     * Check if it is to be forwarded. */
		    tunnel_index0 =
		      gtm->unknown_teid_forward_tunnel_index_ipv6;
		    if (PREDICT_FALSE (tunnel_index0 != ~0))
		      goto forward0;
		    goto trace0;
		  }
		clib_memcpy_fast (&last_key6, &key6_0, sizeof (key6_0));
		tunnel_index0 = last_tunnel_index = p0[0];
	      }
	    else
	      tunnel_index0 = last_tunnel_index;
	    t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);

	    /* Validate GTPU tunnel encap-fib index against packet */
	    if (PREDICT_FALSE (validate_gtpu_fib (b0, t0, is_ip4) == 0))
	      {
		error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
		next0 = GTPU_INPUT_NEXT_DROP;
		tunnel_index0 = gtm->unknown_teid_forward_tunnel_index_ipv6;
		if (PREDICT_FALSE (tunnel_index0 != ~0))
		  goto forward0;
		goto trace0;
	      }

	    /* Validate GTPU tunnel SIP against packet DIP */
	    if (PREDICT_TRUE (ip6_address_is_equal (&ip6_0->dst_address,
						    &t0->src.ip6)))
		goto next0; /* valid packet */
	    if (PREDICT_FALSE (ip6_address_is_multicast (&ip6_0->dst_address)))
	      {
		key6_0.src.as_u64[0] = ip6_0->dst_address.as_u64[0];
		key6_0.src.as_u64[1] = ip6_0->dst_address.as_u64[1];
		key6_0.teid = gtpu0->teid;
		p0 = hash_get_mem (gtm->gtpu6_tunnel_by_key, &key6_0);
		if (PREDICT_TRUE (p0 != NULL))
		  {
		    mt0 = pool_elt_at_index (gtm->tunnels, p0[0]);
		    goto next0; /* valid packet */
		  }
	      }
	    error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
	    next0 = GTPU_INPUT_NEXT_DROP;
	    tunnel_index0 = gtm->unknown_teid_forward_tunnel_index_ipv6;
	    if (PREDICT_FALSE (tunnel_index0 != ~0))
	      goto forward0;
	    goto trace0;
          }
	forward0:
	  /* Get the tunnel */
	  t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);

	  /* Validate GTPU tunnel encap-fib index against packet */
	  if (PREDICT_FALSE (validate_gtpu_fib (b0, t0, is_ip4) == 0))
	    {
	      error0 = GTPU_ERROR_NO_ERROR_TUNNEL;
	      next0 = GTPU_INPUT_NEXT_DROP;
	      goto trace0;
	    }

	  /* Clear the error, next0 will be overwritten by the tunnel */
	  error0 = 0;

	  if (is_ip4)
	    {
	      /* Forward packet instead. Push the IP+UDP header */
	      gtpu_hdr_len0 =
		-(i32) (sizeof (udp_header_t) + sizeof (ip4_header_t));
	      /* Backup the IP4 checksum and address */
	      sum0 = ip4_0->checksum;
	      old0 = ip4_0->dst_address.as_u32;

	      /* Update IP address of the packet using the src from the tunnel
	       */
	      ip4_0->dst_address.as_u32 = t0->src.ip4.as_u32;

	      /* Fix the IP4 checksum */
	      sum0 = ip_csum_update (sum0, old0, ip4_0->dst_address.as_u32,
				     ip4_header_t,
				     dst_address /* changed member */);
	      ip4_0->checksum = ip_csum_fold (sum0);
	    }
	  else
	    {
	      /* Forward packet instead. Push the IP+UDP header */
	      gtpu_hdr_len0 =
		-(i32) (sizeof (udp_header_t) + sizeof (ip6_header_t));
	      /* IPv6 UDP checksum is mandatory */
	      int bogus = 0;
	      udp0->checksum =
		ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip6_0, &bogus);
	      if (udp0->checksum == 0)
		udp0->checksum = 0xffff;
	    }

	next0:
	  /* Pop/Remove gtpu header from buffered package or push existing
	   * IP+UDP header back to the buffer*/
	  vlib_buffer_advance (b0, gtpu_hdr_len0);

	  // where does it need to go in the graph next
	  next0 = t0->decap_next_index;
	  // interface index the package is on
	  sw_if_index0 = t0->sw_if_index;
	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  // Next three lines are for forwarding the payload to L2
	  // subinterfaces
	  /* Required to make the l2 tag push / pop code work on l2 subifs */
	  if (PREDICT_TRUE (next0 == GTPU_INPUT_NEXT_L2_INPUT))
	    vnet_update_l2_len (b0);

	  /* Set packet input sw_if_index to unicast GTPU tunnel for learning
	   */
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index0;
	  // in case its a multicast packet set different interface index
	  sw_if_index0 = (mt0) ? mt0->sw_if_index : sw_if_index0;

	  // Update stats
	  pkts_decapsulated++;
	  stats_n_packets += 1;
	  stats_n_bytes += len0;

	  /* Batch stats increment on the same gtpu tunnel so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = sw_if_index0;
	    }

        trace0:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              gtpu_rx_trace_t *tr
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->tunnel_index = tunnel_index0;
              tr->teid = has_space0 ? clib_net_to_host_u32(gtpu0->teid) : ~0;

	      if (vlib_buffer_has_space (b0, 4))
		{
		  tr->header.ver_flags = gtpu0->ver_flags;
		  tr->header.type = gtpu0->type;
		  tr->header.length = clib_net_to_host_u16 (gtpu0->length);
		}
	    }

	  /* End of processing for packet 0, start for packet 1 */
	  if (PREDICT_FALSE ((!is_fast_track1) | (!has_space1)))
	    {
	      /* Not fast path. ext1 and gtpu_hdr_len1 might be wrong */

	      /* GCC will hopefully fix the duplicate compute */
	      if (PREDICT_FALSE (
		    !((ver1 & (GTPU_VER_MASK | GTPU_PT_BIT | GTPU_RES_BIT)) ==
		      (GTPU_V1_VER | GTPU_PT_BIT)) |
		    (!has_space1)))
		{
		  /* The header or size is wrong */
		  error1 =
		    has_space1 ? GTPU_ERROR_BAD_VER : GTPU_ERROR_TOO_SMALL;
		  next1 = GTPU_INPUT_NEXT_DROP;

		  /* This is an unsupported/bad packet.
		   * Check if it is to be forwarded.
		   */
		  if (is_ip4)
		    tunnel_index1 = gtm->bad_header_forward_tunnel_index_ipv4;
		  else
		    tunnel_index1 = gtm->bad_header_forward_tunnel_index_ipv6;

		  if (PREDICT_FALSE (tunnel_index1 != ~0))
		    goto forward1;

		  goto trace1;
		}
	      /* Correct version and has the space. It can only be unknown
	       * message type.
	       */
	      error1 = GTPU_ERROR_UNSUPPORTED_TYPE;
	      next1 = GTPU_INPUT_NEXT_DROP;

	      /* This is an error/nonstandard packet
	       * Check if it is to be forwarded. */
	      if (is_ip4)
		tunnel_index1 = gtm->unknown_type_forward_tunnel_index_ipv4;
	      else
		tunnel_index1 = gtm->unknown_type_forward_tunnel_index_ipv6;

	      if (PREDICT_FALSE (tunnel_index1 != ~0))
		goto forward1;

	      /* The packet is ipv6/not forwarded */
	      goto trace1;
	    }

          /* Manipulate packet 1 */
          if (is_ip4) {
            key4_1.src = ip4_1->src_address.as_u32;
            key4_1.teid = gtpu1->teid;

 	    /* Make sure GTPU tunnel exist according to packet SIP and teid
 	     * SIP identify a GTPU path, and teid identify a tunnel in a given GTPU path */
	    if (PREDICT_FALSE (key4_1.as_u64 != last_key4.as_u64))
              {
                p1 = hash_get (gtm->gtpu4_tunnel_by_key, key4_1.as_u64);
                if (PREDICT_FALSE (p1 == NULL))
                  {
                    error1 = GTPU_ERROR_NO_SUCH_TUNNEL;
                    next1 = GTPU_INPUT_NEXT_DROP;
		    tunnel_index1 =
		      gtm->unknown_teid_forward_tunnel_index_ipv4;
		    if (PREDICT_FALSE (tunnel_index1 != ~0))
		      goto forward1;
		    goto trace1;
		  }
		last_key4.as_u64 = key4_1.as_u64;
		tunnel_index1 = last_tunnel_index = p1[0];
	      }
	    else
	      tunnel_index1 = last_tunnel_index;
	    t1 = pool_elt_at_index (gtm->tunnels, tunnel_index1);

	    /* Validate GTPU tunnel encap-fib index against packet */
	    if (PREDICT_FALSE (validate_gtpu_fib (b1, t1, is_ip4) == 0))
	      {
		error1 = GTPU_ERROR_NO_SUCH_TUNNEL;
		next1 = GTPU_INPUT_NEXT_DROP;
		tunnel_index1 = gtm->unknown_teid_forward_tunnel_index_ipv4;
		if (PREDICT_FALSE (tunnel_index1 != ~0))
		  goto forward1;
		goto trace1;
	      }

	    /* Validate GTPU tunnel SIP against packet DIP */
	    if (PREDICT_TRUE (ip4_1->dst_address.as_u32 == t1->src.ip4.as_u32))
	      goto next1; /* valid packet */
	    if (PREDICT_FALSE (ip4_address_is_multicast (&ip4_1->dst_address)))
	      {
		key4_1.src = ip4_1->dst_address.as_u32;
		key4_1.teid = gtpu1->teid;
		/* Make sure mcast GTPU tunnel exist by packet DIP and teid */
		p1 = hash_get (gtm->gtpu4_tunnel_by_key, key4_1.as_u64);
		if (PREDICT_TRUE (p1 != NULL))
		  {
		    mt1 = pool_elt_at_index (gtm->tunnels, p1[0]);
		    goto next1; /* valid packet */
		  }
	      }
	    error1 = GTPU_ERROR_NO_SUCH_TUNNEL;
	    next1 = GTPU_INPUT_NEXT_DROP;
	    tunnel_index1 = gtm->unknown_teid_forward_tunnel_index_ipv4;
	    if (PREDICT_FALSE (tunnel_index1 != ~0))
	      goto forward1;
	    goto trace1;

         } else /* !is_ip4 */ {
            key6_1.src.as_u64[0] = ip6_1->src_address.as_u64[0];
            key6_1.src.as_u64[1] = ip6_1->src_address.as_u64[1];
            key6_1.teid = gtpu1->teid;

 	    /* Make sure GTPU tunnel exist according to packet SIP and teid
 	     * SIP identify a GTPU path, and teid identify a tunnel in a given GTPU path */
            if (PREDICT_FALSE (memcmp(&key6_1, &last_key6, sizeof(last_key6)) != 0))
              {
                p1 = hash_get_mem (gtm->gtpu6_tunnel_by_key, &key6_1);

                if (PREDICT_FALSE (p1 == NULL))
                  {
                    error1 = GTPU_ERROR_NO_SUCH_TUNNEL;
                    next1 = GTPU_INPUT_NEXT_DROP;
		    tunnel_index1 =
		      gtm->unknown_teid_forward_tunnel_index_ipv6;
		    if (PREDICT_FALSE (tunnel_index1 != ~0))
		      goto forward1;
		    goto trace1;
		  }

		clib_memcpy_fast (&last_key6, &key6_1, sizeof (key6_1));
		tunnel_index1 = last_tunnel_index = p1[0];
	      }
	    else
	      tunnel_index1 = last_tunnel_index;
	    t1 = pool_elt_at_index (gtm->tunnels, tunnel_index1);

	    /* Validate GTPU tunnel encap-fib index against packet */
	    if (PREDICT_FALSE (validate_gtpu_fib (b1, t1, is_ip4) == 0))
	      {
		error1 = GTPU_ERROR_NO_SUCH_TUNNEL;
		next1 = GTPU_INPUT_NEXT_DROP;
		tunnel_index1 = gtm->unknown_teid_forward_tunnel_index_ipv6;
		if (PREDICT_FALSE (tunnel_index1 != ~0))
		  goto forward1;
		goto trace1;
	      }

	    /* Validate GTPU tunnel SIP against packet DIP */
	    if (PREDICT_TRUE (ip6_address_is_equal (&ip6_1->dst_address,
						    &t1->src.ip6)))
		goto next1; /* valid packet */
	    if (PREDICT_FALSE (ip6_address_is_multicast (&ip6_1->dst_address)))
	      {
		key6_1.src.as_u64[0] = ip6_1->dst_address.as_u64[0];
		key6_1.src.as_u64[1] = ip6_1->dst_address.as_u64[1];
		key6_1.teid = gtpu1->teid;
		p1 = hash_get_mem (gtm->gtpu6_tunnel_by_key, &key6_1);
		if (PREDICT_TRUE (p1 != NULL))
		  {
		    mt1 = pool_elt_at_index (gtm->tunnels, p1[0]);
		    goto next1; /* valid packet */
		  }
	      }
	    error1 = GTPU_ERROR_NO_SUCH_TUNNEL;
	    next1 = GTPU_INPUT_NEXT_DROP;
	    tunnel_index1 = gtm->unknown_teid_forward_tunnel_index_ipv6;
	    if (PREDICT_FALSE (tunnel_index1 != ~0))
	      goto forward1;
	    goto trace1;
	  }
	forward1:

	  /* Get the tunnel */
	  t1 = pool_elt_at_index (gtm->tunnels, tunnel_index1);

	  /* Validate GTPU tunnel encap-fib index against packet */
	  if (PREDICT_FALSE (validate_gtpu_fib (b1, t1, is_ip4) == 0))
	    {
	      error1 = GTPU_ERROR_NO_ERROR_TUNNEL;
	      next1 = GTPU_INPUT_NEXT_DROP;
	      goto trace1;
	    }

	  /* Clear the error, next0 will be overwritten by the tunnel */
	  error1 = 0;

	  if (is_ip4)
	    {
	      /* Forward packet instead. Push the IP+UDP header */
	      gtpu_hdr_len1 =
		-(i32) (sizeof (udp_header_t) + sizeof (ip4_header_t));

	      /* Backup the IP4 checksum and address */
	      sum1 = ip4_1->checksum;
	      old1 = ip4_1->dst_address.as_u32;

	      /* Update IP address of the packet using the src from the tunnel
	       */
	      ip4_1->dst_address.as_u32 = t1->src.ip4.as_u32;

	      /* Fix the IP4 checksum */
	      sum1 = ip_csum_update (sum1, old1, ip4_1->dst_address.as_u32,
				     ip4_header_t,
				     dst_address /* changed member */);
	      ip4_1->checksum = ip_csum_fold (sum1);
	    }
	  else
	    {
	      /* Forward packet instead. Push the IP+UDP header */
	      gtpu_hdr_len1 =
		-(i32) (sizeof (udp_header_t) + sizeof (ip6_header_t));

	      /* IPv6 UDP checksum is mandatory */
	      int bogus = 0;
	      udp1->checksum =
		ip6_tcp_udp_icmp_compute_checksum (vm, b1, ip6_1, &bogus);
	      if (udp1->checksum == 0)
		udp1->checksum = 0xffff;
	    }

	next1:
	  /* Pop gtpu header / push IP+UDP header  */
	  vlib_buffer_advance (b1, gtpu_hdr_len1);

          next1 = t1->decap_next_index;
          sw_if_index1 = t1->sw_if_index;
          len1 = vlib_buffer_length_in_chain (vm, b1);

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          if (PREDICT_TRUE(next1 == GTPU_INPUT_NEXT_L2_INPUT))
            vnet_update_l2_len (b1);

          /* Set packet input sw_if_index to unicast GTPU tunnel for learning */
          vnet_buffer(b1)->sw_if_index[VLIB_RX] = sw_if_index1;
	  sw_if_index1 = (mt1) ? mt1->sw_if_index : sw_if_index1;

          pkts_decapsulated ++;
          stats_n_packets += 1;
          stats_n_bytes += len1;

	  /* Batch stats increment on the same gtpu tunnel so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index1 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len1;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len1;
	      stats_sw_if_index = sw_if_index1;
	    }

        trace1:
          b1->error = error1 ? node->errors[error1] : 0;

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
              gtpu_rx_trace_t *tr
                = vlib_add_trace (vm, node, b1, sizeof (*tr));
              tr->next_index = next1;
              tr->error = error1;
              tr->tunnel_index = tunnel_index1;
              tr->teid = has_space1 ? clib_net_to_host_u32(gtpu1->teid) : ~0;
	      if (vlib_buffer_has_space (b1, 4))
		{
		  tr->header.ver_flags = gtpu1->ver_flags;
		  tr->header.type = gtpu1->type;
		  tr->header.length = clib_net_to_host_u16 (gtpu1->length);
		}
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      /* In case there are less than 4 packets left in frame and packets in
	 current frame aka single processing */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
	  u32 next0;
          ip4_header_t * ip4_0;
          ip6_header_t * ip6_0;
          gtpu_header_t * gtpu0;
	  i32 gtpu_hdr_len0;
	  uword * p0;
          u32 tunnel_index0;
          gtpu_tunnel_t * t0, * mt0 = NULL;
          gtpu4_tunnel_key_t key4_0;
          gtpu6_tunnel_key_t key6_0;
          u32 error0;
	  u32 sw_if_index0, len0;
          u8 has_space0;
          u8 ver0;
	  udp_header_t *udp0;
	  ip_csum_t sum0;
	  u32 old0;
	  gtpu_ext_header_t ext = { .type = 0, .len = 0, .pad = 0 };
	  gtpu_ext_header_t *ext0;
	  bool is_fast_track0;
	  ext0 = &ext;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

          /* udp leaves current_data pointing at the gtpu header */
          gtpu0 = vlib_buffer_get_current (b0);
          if (is_ip4) {
            ip4_0 = (void *)((u8*)gtpu0 - sizeof(udp_header_t) - sizeof(ip4_header_t));
          } else {
            ip6_0 = (void *)((u8*)gtpu0 - sizeof(udp_header_t) - sizeof(ip6_header_t));
          }
	  udp0 = (void *) ((u8 *) gtpu0 - sizeof (udp_header_t));

	  tunnel_index0 = ~0;
	  error0 = 0;

	  /* speculatively load gtp header version field */
	  ver0 = gtpu0->ver_flags;
	  /*
           * Manipulate gtpu header
           * TBD: Manipulate Sequence Number and N-PDU Number
           * TBD: Manipulate Next Extension Header
           */

	  is_fast_track0 =
	    ((ver0 & (GTPU_VER_MASK | GTPU_PT_BIT | GTPU_RES_BIT)) ==
	     (GTPU_V1_VER | GTPU_PT_BIT));
	  is_fast_track0 = is_fast_track0 & (gtpu0->type == 255);

	  ext0 = (ver0 & GTPU_E_BIT) ?
			 (gtpu_ext_header_t *) &gtpu0->next_ext_type :
			 &ext;

	  gtpu_hdr_len0 = sizeof (gtpu_header_t) -
			  (((ver0 & GTPU_E_S_PN_BIT) == 0) * 4) +
			  ext0->len * 4;

	  ext0 += ext0->len * 4 / sizeof (*ext0);

	  has_space0 = vlib_buffer_has_space (b0, gtpu_hdr_len0);

	  if (PREDICT_FALSE ((!is_fast_track0) | (!has_space0)))
	    {
	      /* Not fast path. ext0 and gtpu_hdr_len0 might be wrong */

	      /* GCC will hopefully fix the duplicate compute */
	      if (PREDICT_FALSE (
		    !((ver0 & (GTPU_VER_MASK | GTPU_PT_BIT | GTPU_RES_BIT)) ==
		      (GTPU_V1_VER | GTPU_PT_BIT)) |
		    (!has_space0)))
		{
		  /* The header or size is wrong */
		  error0 =
		    has_space0 ? GTPU_ERROR_BAD_VER : GTPU_ERROR_TOO_SMALL;
		  next0 = GTPU_INPUT_NEXT_DROP;

		  /* This is an unsupported/bad packet.
		   * Check if it is to be forwarded.
		   */
		  if (is_ip4)
		    tunnel_index0 = gtm->bad_header_forward_tunnel_index_ipv4;
		  else
		    tunnel_index0 = gtm->bad_header_forward_tunnel_index_ipv6;

		  if (PREDICT_FALSE (tunnel_index0 != ~0))
		    goto forward00;

		  goto trace00;
		}
	      /* Correct version and has the space. It can only be unknown
	       * message type
	       */
	      error0 = GTPU_ERROR_UNSUPPORTED_TYPE;
	      next0 = GTPU_INPUT_NEXT_DROP;

	      /* This is an error/nonstandard packet
	       * Check if it is to be forwarded. */
	      if (is_ip4)
		tunnel_index0 = gtm->unknown_type_forward_tunnel_index_ipv4;
	      else
		tunnel_index0 = gtm->unknown_type_forward_tunnel_index_ipv6;

	      if (PREDICT_FALSE (tunnel_index0 != ~0))
		goto forward00;

	      /* The packet is ipv6/not forwarded */
	      goto trace00;
	    }

	  if (is_ip4)
	    {
	      key4_0.src = ip4_0->src_address.as_u32;
	      key4_0.teid = gtpu0->teid;

	      /* Make sure GTPU tunnel exist according to packet SIP and teid
	       * SIP identify a GTPU path, and teid identify a tunnel in a
	       * given GTPU path */
	      if (PREDICT_FALSE (key4_0.as_u64 != last_key4.as_u64))
		{
		  // Cache miss, so try normal lookup now.
		  p0 = hash_get (gtm->gtpu4_tunnel_by_key, key4_0.as_u64);
		  if (PREDICT_FALSE (p0 == NULL))
		    {
		      error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
		      next0 = GTPU_INPUT_NEXT_DROP;

		      /* This is a standard packet, but no tunnel was found.
		       * Check if it is to be forwarded. */
		      tunnel_index0 =
			gtm->unknown_teid_forward_tunnel_index_ipv4;
		      if (PREDICT_FALSE (tunnel_index0 != ~0))
			goto forward00;
		      goto trace00;
		    }
		  // Update the key/tunnel cache for normal packets
		  last_key4.as_u64 = key4_0.as_u64;
		  tunnel_index0 = last_tunnel_index = p0[0];
		}
	      else
		tunnel_index0 = last_tunnel_index;
	      t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);

	      /* Validate GTPU tunnel encap-fib index against packet */
	      if (PREDICT_FALSE (validate_gtpu_fib (b0, t0, is_ip4) == 0))
		{
		  error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
		  next0 = GTPU_INPUT_NEXT_DROP;
		  tunnel_index0 = gtm->unknown_teid_forward_tunnel_index_ipv4;
		  if (PREDICT_FALSE (tunnel_index0 != ~0))
		    goto forward00;
		  goto trace00;
		}

	      /* Validate GTPU tunnel SIP against packet DIP */
	      if (PREDICT_TRUE (ip4_0->dst_address.as_u32 ==
				t0->src.ip4.as_u32))
		goto next00; /* valid packet */
	      if (PREDICT_FALSE (
		    ip4_address_is_multicast (&ip4_0->dst_address)))
		{
		  key4_0.src = ip4_0->dst_address.as_u32;
		  key4_0.teid = gtpu0->teid;
		  /* Make sure mcast GTPU tunnel exist by packet DIP and teid
		   */
		  p0 = hash_get (gtm->gtpu4_tunnel_by_key, key4_0.as_u64);
		  if (PREDICT_TRUE (p0 != NULL))
		    {
		      mt0 = pool_elt_at_index (gtm->tunnels, p0[0]);
		      goto next00; /* valid packet */
		    }
		}
	      error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
	      next0 = GTPU_INPUT_NEXT_DROP;
	      tunnel_index0 = gtm->unknown_teid_forward_tunnel_index_ipv4;
	      if (PREDICT_FALSE (tunnel_index0 != ~0))
		goto forward00;
	      goto trace00;
	    }
	  else /* !is_ip4 */
	    {
	      key6_0.src.as_u64[0] = ip6_0->src_address.as_u64[0];
	      key6_0.src.as_u64[1] = ip6_0->src_address.as_u64[1];
	      key6_0.teid = gtpu0->teid;

	      /* Make sure GTPU tunnel exist according to packet SIP and teid
	       * SIP identify a GTPU path, and teid identify a tunnel in a
	       * given GTPU path */
	      if (PREDICT_FALSE (
		    memcmp (&key6_0, &last_key6, sizeof (last_key6)) != 0))
		{
		  p0 = hash_get_mem (gtm->gtpu6_tunnel_by_key, &key6_0);
		  if (PREDICT_FALSE (p0 == NULL))
		    {
		      error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
		      next0 = GTPU_INPUT_NEXT_DROP;
		      tunnel_index0 =
			gtm->unknown_teid_forward_tunnel_index_ipv6;
		      if (PREDICT_FALSE (tunnel_index0 != ~0))
			goto forward00;
		      goto trace00;
		    }
		  clib_memcpy_fast (&last_key6, &key6_0, sizeof (key6_0));
		  tunnel_index0 = last_tunnel_index = p0[0];
		}
	      else
		tunnel_index0 = last_tunnel_index;
	      t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);

	      /* Validate GTPU tunnel encap-fib index against packet */
	      if (PREDICT_FALSE (validate_gtpu_fib (b0, t0, is_ip4) == 0))
		{
		  error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
		  next0 = GTPU_INPUT_NEXT_DROP;
		  tunnel_index0 = gtm->unknown_teid_forward_tunnel_index_ipv6;
		  if (PREDICT_FALSE (tunnel_index0 != ~0))
		    goto forward00;
		  goto trace00;
		}

	      /* Validate GTPU tunnel SIP against packet DIP */
	      if (PREDICT_TRUE (
		    ip6_address_is_equal (&ip6_0->dst_address, &t0->src.ip6)))
		goto next00; /* valid packet */
	    if (PREDICT_FALSE (ip6_address_is_multicast (&ip6_0->dst_address)))
	      {
		key6_0.src.as_u64[0] = ip6_0->dst_address.as_u64[0];
		key6_0.src.as_u64[1] = ip6_0->dst_address.as_u64[1];
		key6_0.teid = gtpu0->teid;
		p0 = hash_get_mem (gtm->gtpu6_tunnel_by_key, &key6_0);
		if (PREDICT_TRUE (p0 != NULL))
		  {
		    mt0 = pool_elt_at_index (gtm->tunnels, p0[0]);
		    goto next00; /* valid packet */
		  }
	      }
	    error0 = GTPU_ERROR_NO_SUCH_TUNNEL;
	    next0 = GTPU_INPUT_NEXT_DROP;
	    tunnel_index0 = gtm->unknown_teid_forward_tunnel_index_ipv6;
	    if (PREDICT_FALSE (tunnel_index0 != ~0))
	      goto forward00;
	    goto trace00;
	    }

	/* This can only be reached via goto */
	forward00:
	  // Get the tunnel
	  t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);

	  /* Validate GTPU tunnel encap-fib index against packet */
	  if (PREDICT_FALSE (validate_gtpu_fib (b0, t0, is_ip4) == 0))
	    {
	      error0 = GTPU_ERROR_NO_ERROR_TUNNEL;
	      next0 = GTPU_INPUT_NEXT_DROP;
	      goto trace00;
	    }

	  /* Clear the error, next0 will be overwritten by the tunnel */
	  error0 = 0;

	  if (is_ip4)
	    {
	      /* Forward packet instead. Push the IP+UDP header */
	      gtpu_hdr_len0 =
		-(i32) (sizeof (udp_header_t) + sizeof (ip4_header_t));
	      /* Backup the IP4 checksum and address */
	      sum0 = ip4_0->checksum;
	      old0 = ip4_0->dst_address.as_u32;

	      /* Update IP address of the packet using the src from the tunnel
	       */
	      ip4_0->dst_address.as_u32 = t0->src.ip4.as_u32;

	      /* Fix the IP4 checksum */
	      sum0 = ip_csum_update (sum0, old0, ip4_0->dst_address.as_u32,
				     ip4_header_t,
				     dst_address /* changed member */);
	      ip4_0->checksum = ip_csum_fold (sum0);
	    }
	  else
	    {
	      /* Forward packet instead. Push the IP+UDP header */
	      gtpu_hdr_len0 =
		-(i32) (sizeof (udp_header_t) + sizeof (ip6_header_t));

	      /* IPv6 UDP checksum is mandatory */
	      int bogus = 0;
	      udp0->checksum =
		ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip6_0, &bogus);
	      if (udp0->checksum == 0)
		udp0->checksum = 0xffff;
	    }

	next00:
	  /* Pop gtpu header / push IP+UDP header */
	  vlib_buffer_advance (b0, gtpu_hdr_len0);

	  next0 = t0->decap_next_index;
	  sw_if_index0 = t0->sw_if_index;
	  len0 = vlib_buffer_length_in_chain (vm, b0);

          /* Required to make the l2 tag push / pop code work on l2 subifs */
          if (PREDICT_TRUE(next0 == GTPU_INPUT_NEXT_L2_INPUT))
            vnet_update_l2_len (b0);

          /* Set packet input sw_if_index to unicast GTPU tunnel for learning */
          vnet_buffer(b0)->sw_if_index[VLIB_RX] = sw_if_index0;
	  sw_if_index0 = (mt0) ? mt0->sw_if_index : sw_if_index0;

          pkts_decapsulated ++;
          stats_n_packets += 1;
          stats_n_bytes += len0;

	  /* Batch stats increment on the same gtpu tunnel so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = sw_if_index0;
	    }

        trace00:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              gtpu_rx_trace_t *tr
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->tunnel_index = tunnel_index0;
              tr->teid = has_space0 ? clib_net_to_host_u32(gtpu0->teid) : ~0;
	      if (vlib_buffer_has_space (b0, 4))
		{
		  tr->header.ver_flags = gtpu0->ver_flags;
		  tr->header.type = gtpu0->type;
		  tr->header.length = clib_net_to_host_u16 (gtpu0->length);
		}
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  /* Do we still need this now that tunnel tx stats is kept? */
  vlib_node_increment_counter (vm, is_ip4?
			       gtpu4_input_node.index:gtpu6_input_node.index,
                               GTPU_ERROR_DECAPSULATED,
                               pkts_decapsulated);

  /* Increment any remaining batch stats */
  if (stats_n_packets)
    {
      vlib_increment_combined_counter
	(im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
	 thread_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
      node->runtime_data[0] = stats_sw_if_index;
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (gtpu4_input_node) (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
	return gtpu_input(vm, node, from_frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (gtpu6_input_node) (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
	return gtpu_input(vm, node, from_frame, /* is_ip4 */ 0);
}

static char * gtpu_error_strings[] = {
#define gtpu_error(n,s) s,
#include <gtpu/gtpu_error.def>
#undef gtpu_error
#undef _
};

VLIB_REGISTER_NODE (gtpu4_input_node) = {
  .name = "gtpu4-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = GTPU_N_ERROR,
  .error_strings = gtpu_error_strings,

  .n_next_nodes = GTPU_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [GTPU_INPUT_NEXT_##s] = n,
    foreach_gtpu_input_next
#undef _
  },

//temp  .format_buffer = format_gtpu_header,
  .format_trace = format_gtpu_rx_trace,
  // $$$$ .unformat_buffer = unformat_gtpu_header,
};

VLIB_REGISTER_NODE (gtpu6_input_node) = {
  .name = "gtpu6-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = GTPU_N_ERROR,
  .error_strings = gtpu_error_strings,

  .n_next_nodes = GTPU_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [GTPU_INPUT_NEXT_##s] = n,
    foreach_gtpu_input_next
#undef _
  },

//temp  .format_buffer = format_gtpu_header,
  .format_trace = format_gtpu_rx_trace,
  // $$$$ .unformat_buffer = unformat_gtpu_header,
};

typedef enum {
  IP_GTPU_BYPASS_NEXT_DROP,
  IP_GTPU_BYPASS_NEXT_GTPU,
  IP_GTPU_BYPASS_N_NEXT,
} ip_vxan_bypass_next_t;

/* this function determines if a udp packet is actually gtpu and needs
   forwarding to gtpu_input */
always_inline uword
ip_gtpu_bypass_inline (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * frame,
			u32 is_ip4)
{
  gtpu_main_t * gtm = &gtpu_main;
  u32 * from, * to_next, n_left_from, n_left_to_next, next_index;
  vlib_node_runtime_t * error_node = vlib_node_get_runtime (vm, ip4_input_node.index);
  vtep4_key_t last_vtep4;	/* last IPv4 address / fib index
				   matching a local VTEP address */
  vtep6_key_t last_vtep6;	/* last IPv6 address / fib index
				   matching a local VTEP address */
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  if (is_ip4)
    vtep4_key_init (&last_vtep4);
  else
    vtep6_key_init (&last_vtep6);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
      	{
      	  vlib_buffer_t * b0, * b1;
      	  ip4_header_t * ip40, * ip41;
      	  ip6_header_t * ip60, * ip61;
      	  udp_header_t * udp0, * udp1;
      	  u32 bi0, ip_len0, udp_len0, flags0, next0;
      	  u32 bi1, ip_len1, udp_len1, flags1, next1;
      	  i32 len_diff0, len_diff1;
      	  u8 error0, good_udp0, proto0;
      	  u8 error1, good_udp1, proto1;

	  /* Prefetch next iteration. */
	  {
	    vlib_prefetch_buffer_header (b[2], LOAD);
	    vlib_prefetch_buffer_header (b[3], LOAD);

	    CLIB_PREFETCH (b[2]->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (b[3]->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
	  }

      	  bi0 = to_next[0] = from[0];
      	  bi1 = to_next[1] = from[1];
      	  from += 2;
      	  n_left_from -= 2;
      	  to_next += 2;
      	  n_left_to_next -= 2;

	  b0 = b[0];
	  b1 = b[1];
	  b += 2;
	  if (is_ip4)
	    {
	      ip40 = vlib_buffer_get_current (b0);
	      ip41 = vlib_buffer_get_current (b1);
	    }
	  else
	    {
	      ip60 = vlib_buffer_get_current (b0);
	      ip61 = vlib_buffer_get_current (b1);
	    }

	  /* Setup packet for next IP feature */
	  vnet_feature_next(&next0, b0);
	  vnet_feature_next(&next1, b1);

	  if (is_ip4)
	    {
	      /* Treat IP frag packets as "experimental" protocol for now
		 until support of IP frag reassembly is implemented */
	      proto0 = ip4_is_fragment(ip40) ? 0xfe : ip40->protocol;
	      proto1 = ip4_is_fragment(ip41) ? 0xfe : ip41->protocol;
	    }
	  else
	    {
	      proto0 = ip60->protocol;
	      proto1 = ip61->protocol;
	    }

	  /* Process packet 0 */
	  if (proto0 != IP_PROTOCOL_UDP)
	    goto exit0; /* not UDP packet */

	  if (is_ip4)
	    udp0 = ip4_next_header (ip40);
	  else
	    udp0 = ip6_next_header (ip60);

	  if (udp0->dst_port != clib_host_to_net_u16 (UDP_DST_PORT_GTPU))
	    goto exit0; /* not GTPU packet */

	  /* Validate DIP against VTEPs*/
	  if (is_ip4)
	    {
#ifdef CLIB_HAVE_VEC512
	      if (!vtep4_check_vector (&gtm->vtep_table, b0, ip40, &last_vtep4,
				       &gtm->vtep4_u512))
#else
	      if (!vtep4_check (&gtm->vtep_table, b0, ip40, &last_vtep4))
#endif
		goto exit0;	/* no local VTEP for GTPU packet */
	    }
	  else
	    {
	      if (!vtep6_check (&gtm->vtep_table, b0, ip60, &last_vtep6))
		goto exit0;	/* no local VTEP for GTPU packet */
	    }

	  flags0 = b0->flags;
	  good_udp0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_udp0 |= udp0->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip4)
	    ip_len0 = clib_net_to_host_u16 (ip40->length);
	  else
	    ip_len0 = clib_net_to_host_u16 (ip60->payload_length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);
	  len_diff0 = ip_len0 - udp_len0;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp0))
	    {
	      if ((flags0 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
	        {
		  if (is_ip4)
		    flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
		  else
		    flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);
		  good_udp0 =
		    (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
	        }
	    }

	  if (is_ip4)
	    {
	      error0 = good_udp0 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP4_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error0 = good_udp0 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP6_ERROR_UDP_LENGTH;
	    }

	  next0 = error0 ?
	    IP_GTPU_BYPASS_NEXT_DROP : IP_GTPU_BYPASS_NEXT_GTPU;
	  b0->error = error0 ? error_node->errors[error0] : 0;

	  /* gtpu-input node expect current at GTPU header */
	  if (is_ip4)
	    vlib_buffer_advance (b0, sizeof(ip4_header_t)+sizeof(udp_header_t));
	  else
	    vlib_buffer_advance (b0, sizeof(ip6_header_t)+sizeof(udp_header_t));

	exit0:
	  /* Process packet 1 */
	  if (proto1 != IP_PROTOCOL_UDP)
	    goto exit1; /* not UDP packet */

	  if (is_ip4)
	    udp1 = ip4_next_header (ip41);
	  else
	    udp1 = ip6_next_header (ip61);

	  if (udp1->dst_port != clib_host_to_net_u16 (UDP_DST_PORT_GTPU))
	    goto exit1; /* not GTPU packet */

	  /* Validate DIP against VTEPs*/
	  if (is_ip4)
	    {
#ifdef CLIB_HAVE_VEC512
	      if (!vtep4_check_vector (&gtm->vtep_table, b1, ip41, &last_vtep4,
				       &gtm->vtep4_u512))
#else
              if (!vtep4_check (&gtm->vtep_table, b1, ip41, &last_vtep4))
#endif
                goto exit1;	/* no local VTEP for GTPU packet */
	    }
	  else
	    {
              if (!vtep6_check (&gtm->vtep_table, b1, ip61, &last_vtep6))
                goto exit1;	/* no local VTEP for GTPU packet */
	    }

	  flags1 = b1->flags;
	  good_udp1 = (flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_udp1 |= udp1->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip4)
	    ip_len1 = clib_net_to_host_u16 (ip41->length);
	  else
	    ip_len1 = clib_net_to_host_u16 (ip61->payload_length);
	  udp_len1 = clib_net_to_host_u16 (udp1->length);
	  len_diff1 = ip_len1 - udp_len1;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp1))
	    {
	      if ((flags1 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
	        {
		  if (is_ip4)
		    flags1 = ip4_tcp_udp_validate_checksum (vm, b1);
		  else
		    flags1 = ip6_tcp_udp_icmp_validate_checksum (vm, b1);
		  good_udp1 =
		    (flags1 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
	        }
	    }

	  if (is_ip4)
	    {
	      error1 = good_udp1 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error1 = (len_diff1 >= 0) ? error1 : IP4_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error1 = good_udp1 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error1 = (len_diff1 >= 0) ? error1 : IP6_ERROR_UDP_LENGTH;
	    }

	  next1 = error1 ?
	    IP_GTPU_BYPASS_NEXT_DROP : IP_GTPU_BYPASS_NEXT_GTPU;
	  b1->error = error1 ? error_node->errors[error1] : 0;

	  /* gtpu-input node expect current at GTPU header */
	  if (is_ip4)
	    vlib_buffer_advance (b1, sizeof(ip4_header_t)+sizeof(udp_header_t));
	  else
	    vlib_buffer_advance (b1, sizeof(ip6_header_t)+sizeof(udp_header_t));

	exit1:
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * b0;
	  ip4_header_t * ip40;
	  ip6_header_t * ip60;
	  udp_header_t * udp0;
      	  u32 bi0, ip_len0, udp_len0, flags0, next0;
	  i32 len_diff0;
	  u8 error0, good_udp0, proto0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = b[0];
	  b++;
	  if (is_ip4)
	    ip40 = vlib_buffer_get_current (b0);
	  else
	    ip60 = vlib_buffer_get_current (b0);

	  /* Setup packet for next IP feature */
	  vnet_feature_next(&next0, b0);

	  if (is_ip4)
	    /* Treat IP4 frag packets as "experimental" protocol for now
	       until support of IP frag reassembly is implemented */
	    proto0 = ip4_is_fragment(ip40) ? 0xfe : ip40->protocol;
	  else
	    proto0 = ip60->protocol;

	  if (proto0 != IP_PROTOCOL_UDP)
	    goto exit; /* not UDP packet */

	  if (is_ip4)
	    udp0 = ip4_next_header (ip40);
	  else
	    udp0 = ip6_next_header (ip60);

	  if (udp0->dst_port != clib_host_to_net_u16 (UDP_DST_PORT_GTPU))
	    goto exit; /* not GTPU packet */

	  /* Validate DIP against VTEPs*/
	  if (is_ip4)
	    {
#ifdef CLIB_HAVE_VEC512
	      if (!vtep4_check_vector (&gtm->vtep_table, b0, ip40, &last_vtep4,
				       &gtm->vtep4_u512))
#else
              if (!vtep4_check (&gtm->vtep_table, b0, ip40, &last_vtep4))
#endif
                goto exit;	/* no local VTEP for GTPU packet */
	    }
	  else
	    {
              if (!vtep6_check (&gtm->vtep_table, b0, ip60, &last_vtep6))
                goto exit;	/* no local VTEP for GTPU packet */
	    }

	  flags0 = b0->flags;
	  good_udp0 = (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;

	  /* Don't verify UDP checksum for packets with explicit zero checksum. */
	  good_udp0 |= udp0->checksum == 0;

	  /* Verify UDP length */
	  if (is_ip4)
	    ip_len0 = clib_net_to_host_u16 (ip40->length);
	  else
	    ip_len0 = clib_net_to_host_u16 (ip60->payload_length);
	  udp_len0 = clib_net_to_host_u16 (udp0->length);
	  len_diff0 = ip_len0 - udp_len0;

	  /* Verify UDP checksum */
	  if (PREDICT_FALSE (!good_udp0))
	    {
	      if ((flags0 & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
	        {
		  if (is_ip4)
		    flags0 = ip4_tcp_udp_validate_checksum (vm, b0);
		  else
		    flags0 = ip6_tcp_udp_icmp_validate_checksum (vm, b0);
		  good_udp0 =
		    (flags0 & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
	        }
	    }

	  if (is_ip4)
	    {
	      error0 = good_udp0 ? 0 : IP4_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP4_ERROR_UDP_LENGTH;
	    }
	  else
	    {
	      error0 = good_udp0 ? 0 : IP6_ERROR_UDP_CHECKSUM;
	      error0 = (len_diff0 >= 0) ? error0 : IP6_ERROR_UDP_LENGTH;
	    }

	  next0 = error0 ?
	    IP_GTPU_BYPASS_NEXT_DROP : IP_GTPU_BYPASS_NEXT_GTPU;
	  b0->error = error0 ? error_node->errors[error0] : 0;

	  /* gtpu-input node expect current at GTPU header */
	  if (is_ip4)
	    vlib_buffer_advance (b0, sizeof(ip4_header_t)+sizeof(udp_header_t));
	  else
	    vlib_buffer_advance (b0, sizeof(ip6_header_t)+sizeof(udp_header_t));

	exit:
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (ip4_gtpu_bypass_node) (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  return ip_gtpu_bypass_inline (vm, node, frame, /* is_ip4 */ 1);
}

VLIB_REGISTER_NODE (ip4_gtpu_bypass_node) = {
  .name = "ip4-gtpu-bypass",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP_GTPU_BYPASS_N_NEXT,
  .next_nodes = {
    [IP_GTPU_BYPASS_NEXT_DROP] = "error-drop",
    [IP_GTPU_BYPASS_NEXT_GTPU] = "gtpu4-input",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_forward_next_trace,
};

#ifndef CLIB_MARCH_VARIANT
/* Dummy init function to get us linked in. */
clib_error_t * ip4_gtpu_bypass_init (vlib_main_t * vm)
{ return 0; }

VLIB_INIT_FUNCTION (ip4_gtpu_bypass_init);
#endif /* CLIB_MARCH_VARIANT */

VLIB_NODE_FN (ip6_gtpu_bypass_node) (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  return ip_gtpu_bypass_inline (vm, node, frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (ip6_gtpu_bypass_node) = {
  .name = "ip6-gtpu-bypass",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP_GTPU_BYPASS_N_NEXT,
  .next_nodes = {
    [IP_GTPU_BYPASS_NEXT_DROP] = "error-drop",
    [IP_GTPU_BYPASS_NEXT_GTPU] = "gtpu6-input",
  },

  .format_buffer = format_ip6_header,
  .format_trace = format_ip6_forward_next_trace,
};

#ifndef CLIB_MARCH_VARIANT
/* Dummy init function to get us linked in. */
clib_error_t * ip6_gtpu_bypass_init (vlib_main_t * vm)
{ return 0; }

VLIB_INIT_FUNCTION (ip6_gtpu_bypass_init);

#define foreach_gtpu_flow_error					\
  _(NONE, "no error")							\
  _(PAYLOAD_ERROR, "Payload type errors")							\
  _(IP_CHECKSUM_ERROR, "Rx ip checksum errors")				\
  _(IP_HEADER_ERROR, "Rx ip header errors")				\
  _(UDP_CHECKSUM_ERROR, "Rx udp checksum errors")				\
  _(UDP_LENGTH_ERROR, "Rx udp length errors")

typedef enum
{
#define _(f,s) GTPU_FLOW_ERROR_##f,
  foreach_gtpu_flow_error
#undef _
#define gtpu_error(n,s) GTPU_FLOW_ERROR_##n,
#include <gtpu/gtpu_error.def>
#undef gtpu_error
    GTPU_FLOW_N_ERROR,
} gtpu_flow_error_t;

static char *gtpu_flow_error_strings[] = {
#define _(n,s) s,
  foreach_gtpu_flow_error
#undef _
#define gtpu_error(n,s) s,
#include <gtpu/gtpu_error.def>
#undef gtpu_error
#undef _

};

#define gtpu_local_need_csum_check(_b)                                        \
  (!(_b->flags & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED ||                        \
     (_b->flags & VNET_BUFFER_F_OFFLOAD &&                                    \
      vnet_buffer (_b)->oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)))

#define gtpu_local_csum_is_valid(_b)                                          \
  ((_b->flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT ||                          \
    (_b->flags & VNET_BUFFER_F_OFFLOAD &&                                     \
     vnet_buffer (_b)->oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)) != 0)

static_always_inline u8
gtpu_validate_udp_csum (vlib_main_t * vm, vlib_buffer_t *b)
{
  u32 flags = b->flags;
  enum { offset = sizeof(ip4_header_t) + sizeof(udp_header_t)};

  /* Verify UDP checksum */
  if ((flags & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
  {
    vlib_buffer_advance (b, -offset);
    flags = ip4_tcp_udp_validate_checksum (vm, b);
    vlib_buffer_advance (b, offset);
  }

  return (flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
}

static_always_inline u8
gtpu_check_ip (vlib_buffer_t *b, u16 payload_len)
{
  ip4_header_t * ip4_hdr = vlib_buffer_get_current(b) - 
      sizeof(ip4_header_t) - sizeof(udp_header_t);
  u16 ip_len = clib_net_to_host_u16 (ip4_hdr->length);
  u16 expected = payload_len + sizeof(ip4_header_t) + sizeof(udp_header_t);
  return ip_len > expected || ip4_hdr->ttl == 0 || ip4_hdr->ip_version_and_header_length != 0x45;
}

static_always_inline u8
gtpu_check_ip_udp_len (vlib_buffer_t *b)
{
  ip4_header_t * ip4_hdr = vlib_buffer_get_current(b) - 
      sizeof(ip4_header_t) - sizeof(udp_header_t);
  udp_header_t * udp_hdr = vlib_buffer_get_current(b) - sizeof(udp_header_t);
  u16 ip_len = clib_net_to_host_u16 (ip4_hdr->length);
  u16 udp_len = clib_net_to_host_u16 (udp_hdr->length);
  return udp_len > ip_len;
}

static_always_inline u8
gtpu_err_code (u8 ip_err0, u8 udp_err0, u8 csum_err0)
{
  u8 error0 = GTPU_FLOW_ERROR_NONE;
  if (ip_err0)
    error0 =  GTPU_FLOW_ERROR_IP_HEADER_ERROR;
  if (udp_err0)
    error0 =  GTPU_FLOW_ERROR_UDP_LENGTH_ERROR;
  if (csum_err0)
    error0 =  GTPU_FLOW_ERROR_UDP_CHECKSUM_ERROR;
  return error0;
}


always_inline uword
gtpu_flow_input (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  gtpu_main_t * gtm = &gtpu_main;
  vnet_main_t * vnm = gtm->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 pkts_decapsulated = 0;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u8 ip_err0, ip_err1, udp_err0, udp_err1, csum_err0, csum_err1;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          u32 bi0, bi1;
      	  vlib_buffer_t * b0, * b1;
      	  u32 next0, next1;
          gtpu_header_t * gtpu0, * gtpu1;
          u32 gtpu_hdr_len0, gtpu_hdr_len1;
          u32 tunnel_index0, tunnel_index1;
          gtpu_tunnel_t * t0, * t1;
          u32 error0, error1;
	        u32 sw_if_index0, sw_if_index1, len0, len1;
          u8 has_space0 = 0, has_space1 = 0;
          u8 ver0, ver1;
	  gtpu_ext_header_t ext = { .type = 0, .len = 0, .pad = 0 };
	  gtpu_ext_header_t *ext0, *ext1;
	  bool is_fast_track0, is_fast_track1;
	  ext0 = ext1 = &ext;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (p3->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
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

	  /* udp leaves current_data pointing at the gtpu header */
	  gtpu0 = vlib_buffer_get_current (b0);
	  gtpu1 = vlib_buffer_get_current (b1);

	  len0 = vlib_buffer_length_in_chain (vm, b0);
	  len1 = vlib_buffer_length_in_chain (vm, b1);

	  tunnel_index0 = ~0;
	  error0 = 0;

	  tunnel_index1 = ~0;
	  error1 = 0;

	  ip_err0 = gtpu_check_ip (b0, len0);
	  udp_err0 = gtpu_check_ip_udp_len (b0);
	  ip_err1 = gtpu_check_ip (b1, len1);
	  udp_err1 = gtpu_check_ip_udp_len (b1);

	  if (PREDICT_FALSE (gtpu_local_need_csum_check (b0)))
	    csum_err0 = !gtpu_validate_udp_csum (vm, b0);
	  else
	    csum_err0 = !gtpu_local_csum_is_valid (b0);
	  if (PREDICT_FALSE (gtpu_local_need_csum_check (b1)))
	    csum_err1 = !gtpu_validate_udp_csum (vm, b1);
	  else
	    csum_err1 = !gtpu_local_csum_is_valid (b1);

	  /* speculatively load gtp header version field */
	  ver0 = gtpu0->ver_flags;
	  ver1 = gtpu1->ver_flags;

	  /*
	   * Manipulate gtpu header
	   * TBD: Manipulate Sequence Number and N-PDU Number
	   * TBD: Manipulate Next Extension Header
	   */
	  is_fast_track0 =
	    ((ver0 & (GTPU_VER_MASK | GTPU_PT_BIT | GTPU_RES_BIT)) ==
	     (GTPU_V1_VER | GTPU_PT_BIT));
	  is_fast_track0 = is_fast_track0 & (gtpu0->type == 255);

	  is_fast_track1 =
	    ((ver1 & (GTPU_VER_MASK | GTPU_PT_BIT | GTPU_RES_BIT)) ==
	     (GTPU_V1_VER | GTPU_PT_BIT));
	  is_fast_track1 = is_fast_track1 & (gtpu1->type == 255);

	  ext0 = (ver0 & GTPU_E_BIT) ?
			 (gtpu_ext_header_t *) &gtpu0->next_ext_type :
			 &ext;
	  ext1 = (ver1 & GTPU_E_BIT) ?
			 (gtpu_ext_header_t *) &gtpu1->next_ext_type :
			 &ext;

	  gtpu_hdr_len0 = sizeof (gtpu_header_t) -
			  (((ver0 & GTPU_E_S_PN_BIT) == 0) * 4) +
			  ext0->len * 4;
	  gtpu_hdr_len1 = sizeof (gtpu_header_t) -
			  (((ver1 & GTPU_E_S_PN_BIT) == 0) * 4) +
			  ext1->len * 4;

	  /* Only for clarity, will be optimized away */
	  ext0 += ext0->len * 4 / sizeof (*ext0);
	  ext1 += ext1->len * 4 / sizeof (*ext1);

	  has_space0 = vlib_buffer_has_space (b0, gtpu_hdr_len0);
	  has_space1 = vlib_buffer_has_space (b1, gtpu_hdr_len1);

	  if (ip_err0 || udp_err0 || csum_err0)
	    {
	      next0 = GTPU_INPUT_NEXT_DROP;
	      error0 = gtpu_err_code (ip_err0, udp_err0, csum_err0);
	      goto trace0;
	    }

	  /* Diverge the packet paths for 0 and 1 */
	  if (PREDICT_FALSE ((!is_fast_track0) | (!has_space0)))
	    {
	      /* Not fast path. ext0 and gtpu_hdr_len0 might be wrong */

	      /* GCC will hopefully fix the duplicate compute */
	      if (PREDICT_FALSE (
		    !((ver0 & (GTPU_VER_MASK | GTPU_PT_BIT | GTPU_RES_BIT)) ==
		      (GTPU_V1_VER | GTPU_PT_BIT)) |
		    (!has_space0)))
		{
		  /* The header or size is wrong */
		  error0 =
		    has_space0 ? GTPU_ERROR_BAD_VER : GTPU_ERROR_TOO_SMALL;
		  next0 = GTPU_INPUT_NEXT_DROP;
		  goto trace0;
		}
	      /* Correct version and has the space. It can only be unknown
	       * message type.
	       */
	      error0 = GTPU_ERROR_UNSUPPORTED_TYPE;
	      next0 = GTPU_INPUT_NEXT_DROP;

	      /* The packet is not forwarded */
	      goto trace0;
	    }

	  /* Manipulate packet 0 */
	  ASSERT (b0->flow_id != 0);
	  tunnel_index0 = b0->flow_id - gtm->flow_id_start;
	  t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);
	  b0->flow_id = 0;

	  /* Pop gtpu header */
	  vlib_buffer_advance (b0, gtpu_hdr_len0);

	  /* assign the next node */
	  if (PREDICT_FALSE (t0->decap_next_index !=
			     GTPU_INPUT_NEXT_IP4_INPUT) &&
	      (t0->decap_next_index != GTPU_INPUT_NEXT_IP6_INPUT))
	    {
	      error0 = GTPU_FLOW_ERROR_PAYLOAD_ERROR;
	      next0 = GTPU_INPUT_NEXT_DROP;
	      goto trace0;
	    }
	  next0 = t0->decap_next_index;

	  sw_if_index0 = t0->sw_if_index;

	  /* Set packet input sw_if_index to unicast GTPU tunnel for learning
	   */
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index0;

	  pkts_decapsulated++;
	  stats_n_packets += 1;
	  stats_n_bytes += len0;

	  /* Batch stats increment on the same gtpu tunnel so counter
	      is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter (
		  im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		  thread_index, stats_sw_if_index, stats_n_packets,
		  stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = sw_if_index0;
	    }

trace0:
          b0->error = error0 ? node->errors[error0] : 0;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              gtpu_rx_trace_t *tr
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->tunnel_index = tunnel_index0;
              tr->teid = has_space0 ? clib_net_to_host_u32(gtpu0->teid) : ~0;
	      if (vlib_buffer_has_space (b0, 4))
		{
		  tr->header.ver_flags = gtpu0->ver_flags;
		  tr->header.type = gtpu0->type;
		  tr->header.length = clib_net_to_host_u16 (gtpu0->length);
		}
	    }

	  if (ip_err1 || udp_err1 || csum_err1)
	    {
	      next1 = GTPU_INPUT_NEXT_DROP;
	      error1 = gtpu_err_code (ip_err1, udp_err1, csum_err1);
	      goto trace1;
	    }

	  /*
	   * Manipulate gtpu header
	   * TBD: Manipulate Sequence Number and N-PDU Number
	   * TBD: Manipulate Next Extension Header
	   */
	  if (PREDICT_FALSE ((!is_fast_track1) | (!has_space1)))
	    {
	      /* Not fast path. ext1 and gtpu_hdr_len1 might be wrong */

	      /* GCC will hopefully fix the duplicate compute */
	      if (PREDICT_FALSE (
		    !((ver1 & (GTPU_VER_MASK | GTPU_PT_BIT | GTPU_RES_BIT)) ==
		      (GTPU_V1_VER | GTPU_PT_BIT)) |
		    (!has_space1)))
		{
		  /* The header or size is wrong */
		  error1 =
		    has_space1 ? GTPU_ERROR_BAD_VER : GTPU_ERROR_TOO_SMALL;
		  next1 = GTPU_INPUT_NEXT_DROP;
		  goto trace1;
		}
	      /* Correct version and has the space. It can only be unknown
	       * message type.
	       */
	      error1 = GTPU_ERROR_UNSUPPORTED_TYPE;
	      next1 = GTPU_INPUT_NEXT_DROP;

	      /* The packet is not forwarded */
	      goto trace1;
	    }

	  /* Manipulate packet 1 */
	  ASSERT (b1->flow_id != 0);
	  tunnel_index1 = b1->flow_id - gtm->flow_id_start;
	  t1 = pool_elt_at_index (gtm->tunnels, tunnel_index1);
	  b1->flow_id = 0;

	  /* Pop gtpu header */
	  vlib_buffer_advance (b1, gtpu_hdr_len1);

	  /* assign the next node */
	  if (PREDICT_FALSE (t1->decap_next_index !=
			     GTPU_INPUT_NEXT_IP4_INPUT) &&
	      (t1->decap_next_index != GTPU_INPUT_NEXT_IP6_INPUT))
	    {
	      error1 = GTPU_FLOW_ERROR_PAYLOAD_ERROR;
	      next1 = GTPU_INPUT_NEXT_DROP;
	      goto trace1;
	    }
	  next1 = t1->decap_next_index;

	  sw_if_index1 = t1->sw_if_index;

	  /* Required to make the l2 tag push / pop code work on l2 subifs */
	  /* This won't happen in current implementation as only
	      ipv4/udp/gtpu/IPV4 type packets can be matched */
	  if (PREDICT_FALSE (next1 == GTPU_INPUT_NEXT_L2_INPUT))
	    vnet_update_l2_len (b1);

	  /* Set packet input sw_if_index to unicast GTPU tunnel for learning
	   */
	  vnet_buffer (b1)->sw_if_index[VLIB_RX] = sw_if_index1;

	  pkts_decapsulated++;
	  stats_n_packets += 1;
	  stats_n_bytes += len1;

	  /* Batch stats increment on the same gtpu tunnel so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index1 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len1;
	      if (stats_n_packets)
		vlib_increment_combined_counter (
		  im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		  thread_index, stats_sw_if_index, stats_n_packets,
		  stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len1;
	      stats_sw_if_index = sw_if_index1;
	    }

trace1:
          b1->error = error1 ? node->errors[error1] : 0;

          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
            {
              gtpu_rx_trace_t *tr
                = vlib_add_trace (vm, node, b1, sizeof (*tr));
              tr->next_index = next1;
              tr->error = error1;
              tr->tunnel_index = tunnel_index1;
              tr->teid = has_space1 ? clib_net_to_host_u32(gtpu1->teid) : ~0;
	      if (vlib_buffer_has_space (b1, 4))
		{
		  tr->header.ver_flags = gtpu1->ver_flags;
		  tr->header.type = gtpu1->type;
		  tr->header.length = clib_net_to_host_u16 (gtpu1->length);
		}
	    }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, next0,
					   next1);
}

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          u32 next0;
          gtpu_header_t * gtpu0;
          u32 gtpu_hdr_len0;
          u32 error0;
          u32 tunnel_index0;
          gtpu_tunnel_t * t0;
          u32 sw_if_index0, len0;
          u8 has_space0 = 0;
          u8 ver0;
	  gtpu_ext_header_t ext = { .type = 0, .len = 0, .pad = 0 };
	  gtpu_ext_header_t *ext0;
	  bool is_fast_track0;
	  ext0 = &ext;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  tunnel_index0 = ~0;
	  error0 = 0;

	  ip_err0 = gtpu_check_ip (b0, len0);
	  udp_err0 = gtpu_check_ip_udp_len (b0);
	  if (PREDICT_FALSE (gtpu_local_need_csum_check (b0)))
	    csum_err0 = !gtpu_validate_udp_csum (vm, b0);
	  else
	    csum_err0 = !gtpu_local_csum_is_valid (b0);

	  /* udp leaves current_data pointing at the gtpu header */
	  gtpu0 = vlib_buffer_get_current (b0);

	  /* speculatively load gtp header version field */
	  ver0 = gtpu0->ver_flags;

	  /*
	   * Manipulate gtpu header
	   * TBD: Manipulate Sequence Number and N-PDU Number
	   * TBD: Manipulate Next Extension Header
	   */
	  is_fast_track0 =
	    ((ver0 & (GTPU_VER_MASK | GTPU_PT_BIT | GTPU_RES_BIT)) ==
	     (GTPU_V1_VER | GTPU_PT_BIT));
	  is_fast_track0 = is_fast_track0 & (gtpu0->type == 255);

	  ext0 = (ver0 & GTPU_E_BIT) ?
			 (gtpu_ext_header_t *) &gtpu0->next_ext_type :
			 &ext;

	  gtpu_hdr_len0 = sizeof (gtpu_header_t) -
			  (((ver0 & GTPU_E_S_PN_BIT) == 0) * 4) +
			  ext0->len * 4;
	  ext0 += ext0->len * 4 / sizeof (*ext0);

	  has_space0 = vlib_buffer_has_space (b0, gtpu_hdr_len0);

	  if (ip_err0 || udp_err0 || csum_err0)
	    {
	      next0 = GTPU_INPUT_NEXT_DROP;
	      error0 = gtpu_err_code (ip_err0, udp_err0, csum_err0);
	      goto trace00;
	    }

	  if (PREDICT_FALSE ((!is_fast_track0) | (!has_space0)))
	    {
	      /* Not fast path. ext0 and gtpu_hdr_len0 might be wrong */

	      /* GCC will hopefully fix the duplicate compute */
	      if (PREDICT_FALSE (
		    !((ver0 & (GTPU_VER_MASK | GTPU_PT_BIT | GTPU_RES_BIT)) ==
		      (GTPU_V1_VER | GTPU_PT_BIT)) |
		    (!has_space0)))
		{
		  /* The header or size is wrong */
		  error0 =
		    has_space0 ? GTPU_ERROR_BAD_VER : GTPU_ERROR_TOO_SMALL;
		  next0 = GTPU_INPUT_NEXT_DROP;
		  goto trace00;
		}
	      /* Correct version and has the space. It can only be unknown
	       * message type.
	       */
	      error0 = GTPU_ERROR_UNSUPPORTED_TYPE;
	      next0 = GTPU_INPUT_NEXT_DROP;

	      /* The packet is not forwarded */
	      goto trace00;
	    }

	  ASSERT (b0->flow_id != 0);
	  tunnel_index0 = b0->flow_id - gtm->flow_id_start;
	  t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);
	  b0->flow_id = 0;

	  /* Pop gtpu header */
	  vlib_buffer_advance (b0, gtpu_hdr_len0);

	  /* assign the next node */
	  if (PREDICT_FALSE (t0->decap_next_index !=
			     GTPU_INPUT_NEXT_IP4_INPUT) &&
	      (t0->decap_next_index != GTPU_INPUT_NEXT_IP6_INPUT))
	    {
	      error0 = GTPU_FLOW_ERROR_PAYLOAD_ERROR;
	      next0 = GTPU_INPUT_NEXT_DROP;
	      goto trace00;
	    }
	  next0 = t0->decap_next_index;

	  sw_if_index0 = t0->sw_if_index;

	  /* Set packet input sw_if_index to unicast GTPU tunnel for learning
	   */
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index0;

	  pkts_decapsulated++;
	  stats_n_packets += 1;
	  stats_n_bytes += len0;

	  /* Batch stats increment on the same gtpu tunnel so counter
	     is not incremented per packet */
	  if (PREDICT_FALSE (sw_if_index0 != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len0;
	      if (stats_n_packets)
		vlib_increment_combined_counter (
		  im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
		  thread_index, stats_sw_if_index, stats_n_packets,
		  stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len0;
	      stats_sw_if_index = sw_if_index0;
	    }
  trace00:
            b0->error = error0 ? node->errors[error0] : 0;

            if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
              {
                gtpu_rx_trace_t *tr
                  = vlib_add_trace (vm, node, b0, sizeof (*tr));
                tr->next_index = next0;
                tr->error = error0;
                tr->tunnel_index = tunnel_index0;
                tr->teid = has_space0 ? clib_net_to_host_u32(gtpu0->teid) : ~0;
		if (vlib_buffer_has_space (b0, 4))
		  {
		    tr->header.ver_flags = gtpu0->ver_flags;
		    tr->header.type = gtpu0->type;
		    tr->header.length = clib_net_to_host_u16 (gtpu0->length);
		  }
	      }
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					     n_left_to_next, bi0, next0);
  }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    /* Do we still need this now that tunnel tx stats is kept? */
    vlib_node_increment_counter (vm, gtpu4_flow_input_node.index,
                               GTPU_ERROR_DECAPSULATED,
                               pkts_decapsulated);

    /* Increment any remaining batch stats */
    if (stats_n_packets)
      {
        vlib_increment_combined_counter
    	(im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    	 thread_index, stats_sw_if_index, stats_n_packets, stats_n_bytes);
        node->runtime_data[0] = stats_sw_if_index;
      }

    return from_frame->n_vectors;
}

VLIB_NODE_FN (gtpu4_flow_input_node) (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * from_frame)
{
	return gtpu_flow_input(vm, node, from_frame);
}


#ifndef CLIB_MULTIARCH_VARIANT
VLIB_REGISTER_NODE (gtpu4_flow_input_node) = {
  .name = "gtpu4-flow-input",
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),

  .format_trace = format_gtpu_rx_trace,

  .n_errors = GTPU_FLOW_N_ERROR,
  .error_strings = gtpu_flow_error_strings,

  .n_next_nodes = GTPU_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [GTPU_INPUT_NEXT_##s] = n,
    foreach_gtpu_input_next
#undef _

  },
};
#endif

#endif /* CLIB_MARCH_VARIANT */
