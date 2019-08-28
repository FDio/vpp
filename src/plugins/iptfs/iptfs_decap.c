/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019, LabN Consulting, L.L.C.
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * May 23 2019, Christian Hopps <chopps@labn.net>
 */
#include <stddef.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ipsec/esp.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>
#include <vppinfra/vec.h>
#include <iptfs/ipsec_iptfs.h>

///* XXX: disable this for now */
// #undef iptfs_pkt_debug_s
// #undef IPTFS_DEBUG_CORRUPTION
// #define iptfs_pkt_debug_s(x, ...) iptfs_pkt_debug (__VA_ARGS__)

/* _ (DROP, "error-drop")                 \ */
#define foreach_iptfs_decap_next                                                                   \
  _ (DROP, "drop")                                                                                 \
  _ (IP4_INPUT, "ip4-input-no-checksum")                                                           \
  _ (IP6_INPUT, "ip6-input")
#define _(v, s) IPTFS_DECAP_NEXT_##v,
typedef enum
{
  foreach_iptfs_decap_next
#undef _
    IPTFS_DECAP_N_NEXT,
} iptfs_decap_next_t;

#define foreach_iptfs_decap_error                                                                  \
  _ (RX_REUSED, "IPTFS-decap-ok outer decap re-used")                                              \
  _ (SKIP_ALL_PAD, "IPTFS-decap-ok skip all pad in fragment sequence")                             \
  _ (DROP_PARTIAL, "IPTFS-decap-warn missed start of packet")                                      \
  _ (SKIP_ALL_FRAG, "IPTFS-decap-warn Skipped all fragment packet")                                \
  _ (SHORT_HEADER, "IPTFS-decap-err No space for header")                                          \
  _ (NEXT_PARTIAL_ZERO, "IPTFS-decap-err next-in-seq partial w/ 0 offset")                         \
  _ (BAD_DATABLOCK, "IPTFS-decap-error bad DataBlock")                                             \
  _ (NO_MEM, "IPTFS-decap-error no buffer memory")                                                 \
  _ (FRAG_DONT_FRAG, "IPTFS-decap-err Fragments received in dont-fragment mode")                   \
  _ (WRONG_VERSION, "IPTFS-decap-err unsupported IPTFS packet format")

typedef enum
{
#define _(sym, str) IPTFS_DECAP_ERROR_##sym,
  foreach_iptfs_decap_error
#undef _
    IPTFS_DECAP_N_ERROR,
} iptfs_decap_error_t;

static char *iptfs_decap_error_strings[] = {
#define _(sym, string) string,
  foreach_iptfs_decap_error
#undef _
};

static inline void
iptfs_decap_trace_new_buffer (vlib_main_t *vm, vlib_node_runtime_t *node, u32 next_index,
			      vlib_buffer_t *b, u32 esp_seq, u16 block_number)
{
  uword n_trace = vlib_get_trace_count (vm, node);
  if (PREDICT_FALSE (n_trace))
    {
      (void) vlib_trace_buffer (vm, node, next_index, b, /* follow_chain */ 0);
      iptfs_decapped_packet_trace_store (vm, node, b, esp_seq, block_number);
      vlib_set_trace_count (vm, node, n_trace - 1);
    }
}

static inline vlib_buffer_t *
iptfs_decap_new_buffer_min (vlib_main_t *vm, u32 *bi)
{
  u32 n = vlib_buffer_alloc (vm, bi, 1);
  if (PREDICT_FALSE ((!n)))
    {
      clib_warning ("%s: Failed to get packet buffer", __FUNCTION__);
      vlib_node_increment_counter (vm, iptfs_decap_node.index, IPTFS_DECAP_ERROR_NO_MEM, 1);
      return NULL;
    }

  iptfs_pkt_debug ("%s: new buffer %u", __FUNCTION__, *bi);

  /* Get a buffer to copy packet into */
  vlib_buffer_t *newb = vlib_get_buffer (vm, *bi);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (newb);
  newb->flags = 0;
  newb->current_data = 0;
  newb->current_length = 0;

  return newb;
}

static inline vlib_buffer_t *
iptfs_decap_new_buffer (vlib_main_t *vm, u32 *bi)
{

  vlib_buffer_t *newb = iptfs_decap_new_buffer_min (vm, bi);
  if (!newb)
    return NULL;

  vnet_buffer_opaque_t *newbdata = vnet_buffer (newb);
  /* XXX should we copy the encap buffer's value? */
  // vnet_buffer (b0)->sw_if_index[VLIB_RX];
  newbdata->sw_if_index[VLIB_RX] = 0;	/* local0 */
  newbdata->sw_if_index[VLIB_TX] = ~0u; /* default VRF */

  return newb;
}

static inline vlib_buffer_t *
iptfs_decap_new_frag_buffer (vlib_main_t *vm, iptfs_sa_data_t *satd, u32 rx_sw_if_index)
{
  ASSERT (satd->tfs_rx.frag_bi == ~0u);
  ASSERT (satd->tfs_rx.frag_lastb == NULL);
  ASSERT (!satd->tfs_rx.frag_nseq);
  vlib_buffer_t *b = iptfs_decap_new_buffer (vm, &satd->tfs_rx.frag_bi);
  /*
   * gpz 250322 We have to set rx sw_if_index now based on encap packet
   * otherwise ip4-input will throw it away.
   * For non-fragmented packets it seems to be already set (reused encap
   * packet?) but TBD need to see if there are further issues with
   * multiple user packets in one encap packet.
   */
  vnet_buffer (b)->sw_if_index[VLIB_RX] = rx_sw_if_index;
  return satd->tfs_rx.frag_lastb = b;
}

static inline void
iptfs_decap_forget_frag_buffer (iptfs_sa_data_t *satd)
{
  satd->tfs_rx.frag_bi = ~0u;
  satd->tfs_rx.frag_lastb = NULL;
  satd->tfs_rx.frag_nseq = 0;
}

static inline void
iptfs_decap_free_frag_buffer (vlib_main_t *vm, iptfs_sa_data_t *satd)
{
  vlib_buffer_free_one (vm, satd->tfs_rx.frag_bi);
  iptfs_decap_forget_frag_buffer (satd);
}

/*
 * Validates the IPTFS header and at least 1 byte of space.
 * Returns the block offset.
 */
static inline u32
iptfs_decap_validate_advance (vlib_main_t *vm, vlib_node_runtime_t *node, iptfs_sa_data_t *satd,
			      vlib_buffer_t *b)
{
  ipsec_iptfs_basic_header_t *h = vlib_buffer_get_current (b);

  u16 hlen = sizeof (*h);
  if (PREDICT_FALSE (b->current_length < (hlen + 1)))
    {
    nohspace:
      iptfs_debug ("%s: Drop No Header Room", __FUNCTION__);
      b->error = node->errors[IPTFS_DECAP_ERROR_SHORT_HEADER];
      goto tracebad;
    }
  if (PREDICT_FALSE (h->subtype > IPTFS_SUBTYPE_LAST))
    {
      iptfs_debug ("Unknown IPTFS Subtype %d", h->subtype);
      b->error = node->errors[IPTFS_DECAP_ERROR_WRONG_VERSION];
      goto tracebad;
    }
  if (h->subtype == IPTFS_SUBTYPE_CC)
    {
      hlen = sizeof (ipsec_iptfs_cc_header_t);
      if (PREDICT_FALSE (b->current_length < (hlen + 1)))
	goto nohspace;
    }

  /* trace prior to advance */
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
    if (!satd->tfs_no_pad_trace || (*((u8 *) h + hlen) & 0xF0) != 0)
      iptfs_encapped_packet_trace_store (vm, node, b, ~0u, 0, 0, false);

  vlib_buffer_advance (b, hlen);
  u16 offset = clib_net_to_host_unaligned_mem_u16 (&h->block_offset);
  if (offset && PREDICT_TRUE (offset < b->current_length))
    /* Prefetch the next datablock */
    CLIB_PREFETCH ((void *) CACHE_LINE_MASK (vlib_buffer_get_current (b) + offset),
		   CLIB_CACHE_LINE_BYTES, LOAD);
  return offset;

tracebad:
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) && (b->flags & VLIB_BUFFER_IS_TRACED)))
    iptfs_encapped_packet_trace_store (vm, node, b, ~0u, 0, 0, true);
  return ~0u;
}

static inline void
iptfs_prefetch_before_advance (vlib_buffer_t *b, u16 offset)
{
  if (PREDICT_FALSE (offset >= b->current_length))
    return;

  /* Prefetch the next datablock */
  CLIB_PREFETCH ((void *) CACHE_LINE_MASK (vlib_buffer_get_current (b) + offset),
		 CLIB_CACHE_LINE_BYTES, LOAD);
}

static_always_inline u16
iptfs_decap_min_hdr_to_cacheline (u8 *data, u16 current_length, u16 min_hdr_len, u8 nlines)
{
  u16 bytes_in_cache = CACHE_LINE_MASK_BYTES (data) + (nlines * CLIB_CACHE_LINE_BYTES) - data;
  u16 len = clib_max (min_hdr_len, bytes_in_cache);
  return clib_min (len, current_length);
}

static inline bool
iptfs_decap_validate_header_data_adv (vlib_main_t *vm, vlib_node_runtime_t *node,
				      iptfs_sa_data_t *satd, vlib_buffer_t *b0, u32 *offsetp,
				      IPTFS_DBG_ARG (u8 **dbg))
{

  if ((*offsetp = iptfs_decap_validate_advance (vm, node, satd, b0)) == ~0u)
    return false;

  u32 offset = *offsetp;
  u64 b0_esp_seq = vnet_buffer (b0)->ipsec.iptfs_esp_seq;

#ifdef IPTFS_DEBUG
  u8 *dbd = vlib_buffer_get_current (b0);
  if (offset == 0)
    iptfs_pkt_debug_s (dbg,
		       "%s: Decap Packet Prefetch Loop: offset: %u cdata %u "
		       "clen %u remaining %d firstbytes: %x %x ip4-len %d esp-seq "
		       "0x%llx",
		       __FUNCTION__, offset, b0->current_data, b0->current_length,
		       b0->current_length - offset, dbd[0], dbd[1], (dbd[2] << 8) + dbd[3],
		       b0_esp_seq);
  else
    iptfs_pkt_debug_s (dbg,
		       "%s: Decap Packet Prefetch Loop: offset: %u cdata %u "
		       "clen %u remaining %d firstbytes: %x %x esp-seq "
		       "0x%llx",
		       __FUNCTION__, offset, b0->current_data, b0->current_length,
		       b0->current_length - offset, dbd[0], dbd[1], b0_esp_seq);
#endif

  u8 dontfrag = satd->tfs_df;
  if (dontfrag && offset)
    {
      clib_warning ("%s: fragment offset (%u) with don't frag configured id: %x", __FUNCTION__,
		    offset);
      b0->error = node->errors[IPTFS_DECAP_ERROR_FRAG_DONT_FRAG];
      return false;
    }

  /*
   * Grab any inprogress buffer
   */

  vlib_buffer_t *newb =
    (satd->tfs_rx.frag_bi == ~0u) ? NULL : vlib_get_buffer (vm, satd->tfs_rx.frag_bi);

  if (offset && !newb)
    {
      iptfs_pkt_debug_t (IPTFS_PT_DBG_DECAP, "offset %u", offset);

      /*
       * We have an offset (partial packet at start) but no in progress
       * so advance to the offset.
       */
      if (offset >= b0->current_length)
	{
	  iptfs_pkt_debug_s (dbg, "%s: no previous and offset %u past end of payload %u.",
			     __FUNCTION__, offset, b0->current_length);
	  b0->error = node->errors[IPTFS_DECAP_ERROR_SKIP_ALL_FRAG];
	  return false;
	}
      iptfs_pkt_debug_s (dbg, "%s: no previous and offset %u advancing past partial", __FUNCTION__,
			 offset);

      vlib_buffer_advance (b0, offset);
      /* offset invalid as we had no in-progress and skipped over it */
      /* Pick the largest number as this shouldn't be used */
      *offsetp = ~0;
    }
  /* else !offset || newb */
  else if (newb)
    {
      /*
       * we have a in-progress, make sure this new buffer is right for
       * it.
       */

      /*
       * Handle all-pad packet insertion in sequence
       */
      if (!offset && 0 == *(u8 *) vlib_buffer_get_current (b0) &&
	  b0_esp_seq == satd->tfs_rx.frag_nseq)
	{
	  b0->error = node->errors[IPTFS_DECAP_ERROR_SKIP_ALL_PAD];
	  satd->tfs_rx.frag_nseq++;
	  iptfs_pkt_debug_s (dbg,
			     "%s: received all-pad in fragment sequence "
			     "advancing expected seqno to %llu",
			     __FUNCTION__, satd->tfs_rx.frag_nseq);

	  return false;
	}

      iptfs_pkt_debug_t (IPTFS_PT_DBG_DECAP, "Have inprogress. offset %u", offset);

      if (!offset || b0_esp_seq != satd->tfs_rx.frag_nseq)
	{
	  /*
	   * There's no offset, so no partial packet, OR this buffer is
	   * not the next (expected) in sequence.
	   */

	  /* Free buffer */
	  newb = NULL;
	  iptfs_decap_free_frag_buffer (vm, satd);

	  /* offset is past the payload just skip the payload */
	  if (offset >= b0->current_length)
	    {
	      // This isn't really that crazy we missed some packets and
	      // the one we received is a continuation of one.
	      // ASSERT (b0_esp_seq != satd->tfs_rx.frag_nseq);
	      iptfs_pkt_debug_s (dbg, "%s: %llu past in progress sequence %llu", __FUNCTION__,
				 b0_esp_seq, satd->tfs_rx.frag_nseq);
	      b0->error = node->errors[IPTFS_DECAP_ERROR_DROP_PARTIAL];
	      return false;
	    }
	  /* advance past any partial (wrong seq) */
	  if (!offset)
	    {
	      if (b0_esp_seq == satd->tfs_rx.frag_nseq)
		{
		  /*
		   * Something is wrong, we expected a packet
		   * continuation, the sequence is correct, but the
		   * offset is 0. Drop this packet.
		   */
		  iptfs_pkt_debug_s (dbg, "%s: missing partial in next-in-seq packet %llu",
				     __FUNCTION__, satd->tfs_rx.frag_nseq);

		  b0->error = node->errors[IPTFS_DECAP_ERROR_NEXT_PARTIAL_ZERO];
		  return false;
		}
	      /*
	       * This case is fine, we had an in-progress, but
	       * missed the next in sequence, this packet is just
	       * starting a new packet.
	       */
	      iptfs_pkt_debug_s (dbg,
				 "%s: missed next-in-seq packet %llu "
				 "for reassembly, current w/ offset 0 is %llu",
				 __FUNCTION__, satd->tfs_rx.frag_nseq, b0_esp_seq);
	    }
	  else
	    {
	      iptfs_pkt_debug_s (dbg,
				 "%s: %llu is beyond in progress sequence %llu "
				 "advancing to next datablock at offset %u",
				 __FUNCTION__, b0_esp_seq, satd->tfs_rx.frag_nseq, offset);

	      vlib_buffer_advance (b0, offset);
	      /* offset is now invalid as we've tossed the in-progress*/
	      /* Pick the largest number as this shouldn't be used */
	      *offsetp = ~0;
	    }
	}
    }
  return true;
}

/*
 * Get the next node and some lengths based on the datablock type
 */
typedef struct
{
  u32 u;
  bool b;
} u32_and_bool_t;

static inline u32_and_bool_t
iptfs_decap_get_next_len (vlib_node_runtime_t *node, u32 thread_index, u32 sa_index,
			  vlib_buffer_t *newb, vlib_buffer_t *b0, u8 *plen_off, u16 *min_hdr_len)
{
  u8 type;
  if (newb)
    type = *(u8 *) vlib_buffer_get_current (newb);
  else
    type = *(u8 *) vlib_buffer_get_current (b0);
  switch (type & 0xF0)
    {
    case 0:
      return (u32_and_bool_t) { IPTFS_DECAP_NEXT_DROP, true };
    case 0x40:
      *plen_off = offsetof (ip4_header_t, length);
      *min_hdr_len = sizeof (ip4_header_t);
      return (u32_and_bool_t) { IPTFS_DECAP_NEXT_IP4_INPUT, false };
    case 0x60:
      *plen_off = offsetof (ip6_header_t, payload_length);
      *min_hdr_len = sizeof (ip6_header_t);
      return (u32_and_bool_t) { IPTFS_DECAP_NEXT_IP6_INPUT, false };
    default:
      iptfs_dump_debug_strings (true);
      clib_warning ("%s: Bad datablock id: %x", __FUNCTION__, type & 0xF0);
      ASSERT (0);
      b0->error = node->errors[IPTFS_DECAP_ERROR_BAD_DATABLOCK];
      return (u32_and_bool_t) { IPTFS_DECAP_NEXT_DROP, false };
    }
}

static inline u16
iptfs_decap_get_inprogress_plen (vlib_main_t *vm, vlib_buffer_t *newb, vlib_buffer_t *b0,
				 u16 min_hdr_len, u8 plen_off, u16 *plenp, IPTFS_DBG_ARG (u8 **dbg))
{
  u8 *olddata = vlib_buffer_get_current (newb);
  u8 *data = vlib_buffer_get_current (b0);

  u16 plen;

  /* XXX need to assert that at least a header worth in newb prior to chaining
   */

  /* If the in-progress buffer contains the length */
  if (newb->current_length >= plen_off + 2)
    {
      iptfs_pkt_debug_s (dbg,
			 "%s: in-progress (length %u) contains "
			 "length offset %u + 2",
			 __FUNCTION__, newb->current_length, plen_off);
      plen = (olddata[plen_off] << 8) + olddata[plen_off + 1];
    }
  else
    {
      plen = 0;
      /* If the in-progress buffer has 1 byte of the length */
      if (newb->current_length == plen_off + 1)
	{
	  iptfs_pkt_debug_s (dbg,
			     "%s: length offset %u straddles "
			     "in-progress (length %u)",
			     __FUNCTION__, plen_off, newb->current_length);
	  plen = olddata[plen_off] << 8;
	  if (PREDICT_FALSE (!b0->current_length))
	    goto dropnolen;
	  plen += data[0];
	}
      else
	{
	  /* In-progress buffer does not contain the length */
	  iptfs_pkt_debug_s (dbg,
			     "%s: length offset %u past "
			     "in-progress (length %u)",
			     __FUNCTION__, plen_off, newb->current_length);
	  plen_off -= newb->current_length;

	  /*
	   * It's not OK for the new continuing on packet to not
	   * be long enough to hold the length
	   */
	  if ((b0->current_length < plen_off + 2))
	    {
	    dropnolen:
	      clib_warning ("%s: second datablock also missing "
			    "length field",
			    __FUNCTION__);
	    dropinprogress:
	      clib_warning ("%s: bad datablock: newb "
			    "current_length %u "
			    "b0 current_length %u "
			    "plen_off %u plen %u",
			    __FUNCTION__, newb->current_length, b0->current_length, plen_off, plen);

	      /* Drop outer packet. */
	      return false;
	    }
	  plen = (data[plen_off] << 8) + data[plen_off + 1];
	}
    }
  /* Add ipv6 header length to packet length */
  if (min_hdr_len == sizeof (ip6_header_t))
    plen += sizeof (ip6_header_t);

  /* plen now contains the inner packet length */
  if (plen < min_hdr_len)
    {
      clib_warning ("%s: inner packet length %u less than "
		    "minimum required %u",
		    __FUNCTION__, plen, min_hdr_len);
      goto dropinprogress;
    }

  /* If we've collected the inner packet length or more -- bad */
  u16 newblen = vlib_buffer_length_in_chain (vm, newb);
  ASSERT (plen > newblen);
  if (plen <= newblen)
    {
      /* XXX this split of the string here messes up emacs
      indention */
      clib_warning ("%s: already captured more than enough data "
		    "%u than inner packet length %u",
		    __FUNCTION__, newb->current_length, plen);

      goto dropinprogress;
    }

  *plenp = plen;
  return true;
}

static inline bool
iptfs_decap_append_data_inp (vlib_main_t *vm, u32 thread_index, u32 sa_index, iptfs_sa_data_t *satd,
			     vlib_buffer_t *b0, u16 plen, u16 real_plen, u16 min_hdr_len,
			     vlib_buffer_t *newb, vlib_buffer_t *lastb, u16 *advanced,
			     bool *owned_source, IPTFS_DBG_ARG (u8 **dbg))
{
  u8 *data = vlib_buffer_get_current (b0);

  *owned_source = false;
  if (advanced)
    *advanced = 0;

  clib_memcpy_fast (vlib_buffer_put_uninit (newb, plen), data, plen);
  iptfs_inc_x_counter (IPTFS_CNT_DECAP_TX_COPIED, thread_index, sa_index, plen);
  return true;
}

static inline uword
iptfs_decap_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 freebufs[VLIB_FRAME_SIZE], *freebi = freebufs;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b, **eb;
  u32 nexti, allpad = 0, n_vectors;
  u32 *to[IPTFS_DECAP_N_NEXT] = {};
  u32 *eto[IPTFS_DECAP_N_NEXT] = {};
  IPTFS_DBG_ARG (u8 * *dbg) = iptfs_next_debug_string ();
  u32 thread_index = vlib_get_thread_index ();
  u32 npkts = 0;

#ifdef IPTFS_DEBUG
  uint minfetch = clib_min (sizeof (ip4_and_esp_header_t), sizeof (ip6_and_esp_header_t));
  iptfs_pkt_debug_s (dbg, "%s: pre-reorder count: %d", __FUNCTION__, frame->n_vectors);
#endif

  u32 *from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, frame->n_vectors);
  n_vectors = frame->n_vectors;

  iptfs_pkt_debug_s (dbg, "%s: Enter with %u packets", __FUNCTION__, n_vectors);

  b = bufs;
  eb = b + n_vectors;

  u32 sa_index = ~0u;
  iptfs_sa_data_t *satd = NULL;

  while (b < eb)
    {
      /*
       * We really want to customize this to maybe do 1 datablock per
       * buffer at a time, to so that we can prefetch the next datablock
       * once we have the offset.
       *
       * This will only be important I think when we aren't doing memcpy.
       */
      FOREACH_PREFETCH_WITH_DATA (b, eb, IPTFS_N_PREFETCH_DECAP, LOAD)
      {
	vlib_buffer_t *b0 = *b;
	u16 block_number = 0;
	u32 offset;

	iptfs_pkt_debug_s (dbg,
			   "%s: Decap Packet Prefetch Loop: mark %u, cacheline bytes %u, "
			   "minfetch %u b->current_data %d b->current_length %d",
			   __FUNCTION__, offsetof (vlib_buffer_t, second_half),
			   CLIB_CACHE_LINE_BYTES, minfetch, b0->current_data, b0->current_length);

	/* XXX we want to know if this is the case */
	ASSERT ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);

	/* Clear any user flags e.g., cksum offload in case we reuse */
	b0->flags &= VLIB_BUFFER_FLAGS_ALL;
	// b0->error = 0;
	// XXX: we need something better here. Zero appears to cause assertion
	// in vlib code, but we don't want to track this drop as an error.
	b0->error = node->errors[IPTFS_DECAP_ERROR_RX_REUSED];

	/* --------------------------------- */
	/* Validate outer packet header data */
	/* --------------------------------- */
	if (sa_index != vnet_buffer (b0)->ipsec.sad_index)
	  {
	    sa_index = vnet_buffer (b0)->ipsec.sad_index;
	    satd = iptfs_get_sa_data (sa_index);

	    /*
	     * XXX apparently we commonly get 10 prefetches prior to a stall of
	     * the execution unit, so this code is questionable, that said it's
	     * only done on SA switch, in the menatime we are using prefetches
	     * per buffer on that SA. It does mean that if we interleave
	     * packets between SAs this code will suck.
	     *
	     * We probably simply want to mark most of these as extended
	     * counters and not enable them by default.
	     */

	    iptfs_prefetch_pcounter (IPTFS_PCNT_DECAP_RX, thread_index, sa_index);

	    iptfs_prefetch_pcounter (IPTFS_PCNT_DECAP_TX, thread_index, sa_index);

	    iptfs_prefetch_x_pcounter (IPTFS_PCNT_DECAP_RX_PAD_DATABLOCK, thread_index, sa_index);
	    iptfs_prefetch_x_counter (IPTFS_CNT_DECAP_RX_ENDS_WITH_FRAG, thread_index, sa_index);

	    /*
	     * Don't prefetch condition where we aren't doing much
	     * iptfs_prefetch_counter (IPTFS_CNT_DECAP_RX_ALL_PAD,
	     * thread_index, sa_index);
	     *
	     * Don't prefetch error path counters
	     * iptfs_prefetch_x_counter (IPTFS_CNT_DECAP_RX_NO_REUSE,
	     *    thread_index, sa_index);
	     */

	    iptfs_prefetch_x_counter (IPTFS_CNT_DECAP_TX_CHAINED, thread_index, sa_index);
	    iptfs_prefetch_x_counter (IPTFS_CNT_DECAP_TX_INDIRECT, thread_index, sa_index);
	    iptfs_prefetch_x_counter (IPTFS_CNT_DECAP_TX_REUSED, thread_index, sa_index);
	    iptfs_prefetch_x_counter (IPTFS_CNT_DECAP_TX_COPIED, thread_index, sa_index);
	    iptfs_prefetch_x_pcounter (IPTFS_PCNT_DECAP_TX_HDR_COPY, thread_index, sa_index);
	  }

	iptfs_inc_pcounter (IPTFS_PCNT_DECAP_RX, thread_index, sa_index, 1,
			    vlib_buffer_length_in_chain (vm, b0));

	if (!iptfs_decap_validate_header_data_adv (vm, node, satd, b0, &offset, dbg))
	  goto pktdrop;

	vlib_buffer_t *newb, *lastb;
	if (satd->tfs_rx.frag_bi == ~0u)
	  newb = lastb = NULL;
	else
	  {
	    newb = vlib_get_buffer (vm, satd->tfs_rx.frag_bi);
	    lastb = satd->tfs_rx.frag_lastb;
	  }

	/* This means we should have no in progress either */
	if (offset == ~0u)
	  {
	    ASSERT (!newb);
	    block_number++;
	  }

	/* ---------------------------------- */
	/* Process the current packet content */
	/* ---------------------------------- */

	/* If we have a newb it's a partial in progress, get type from that */
	ASSERT (!newb || newb->current_length > 0);

	/*
	 * Any in-progress has passed the v4/v6 test and isn't pad
	 * We shift it right a nibble to tell the difference between
	 * new and old below.
	 */

	u32 ndb = 0;

	/* Offset is only valid on first trip through. */

	while (b0->current_length)
	  {
	    u32 nexti;
	    u16 plen, min_hdr_len;
	    u8 plen_off;

	    ndb++;

	    ASSERT ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);

	    if (newb)
	      {
		iptfs_pkt_debug_s (dbg, "%s: in-progress", __FUNCTION__);
		iptfs_pkt_debug_t (IPTFS_PT_DBG_DECAP, "in-progress");
	      }

	    u32_and_bool_t rv = iptfs_decap_get_next_len (node, thread_index, sa_index, newb, b0,
							  &plen_off, &min_hdr_len);
	    if ((nexti = rv.u) == IPTFS_DECAP_NEXT_DROP)
	      {
		if (PREDICT_FALSE (!rv.b))
		  goto pktdrop;

		if (ndb == 1)
		  allpad++;
		else
		  {
		    /*
		     * This is an odd case, we should have got this below when
		     * we finished the previous datablock and pre-checked for
		     * pad afterwards, we want to catch it there b/c then we
		     * re-use this buffer instead of having to free it here.
		     */
		    iptfs_inc_x_pcounter (IPTFS_PCNT_DECAP_RX_PAD_DATABLOCK_EXC, thread_index,
					  sa_index, 1, b0->current_length);
		  }
		/*
		 * nothing wrong with this packet so no reason to drop and
		 * report an error
		 */
		*freebi++ = from[b - bufs];
		goto pktdone;
	      }

	    if (newb)
	      {

		/* ------------------ */
		/* We are in-progress */
		/* ------------------ */

		if (!iptfs_decap_get_inprogress_plen (vm, newb, b0, min_hdr_len, plen_off, &plen,
						      dbg))
		  {
		    b0->error = node->errors[IPTFS_DECAP_ERROR_BAD_DATABLOCK];
		    /* Free in progress buffer */
		    newb = lastb = NULL;
		    iptfs_decap_free_frag_buffer (vm, satd);
		    goto pktdrop;
		  }

		/* adjust plen for what we already have */
		u32 newblen = vlib_buffer_length_in_chain (vm, newb);
		plen -= newblen;

		/*
		 * Technically we should verify offset == plen; however, we
		 * aren't throwing out the Robustness Principle as is currently
		 * (2019) in fashion, all we make sure of is that offset is at
		 * least as large as plen.
		 *
		 * If we add some alignment requirements then plen could very
		 * well be less than the offset.
		 */
		if (offset != plen)
		  {
		    iptfs_debug ("%s: offset %u != remaining inner packet length %u ", __FUNCTION__,
				 offset, plen);
		    iptfs_dump_debug_strings (false);
		    ASSERT (0); /* XXX debug */
		    ASSERT (offset == plen);
		    if (offset < plen)
		      {
			/* Free in progress buffer */
			newb = lastb = NULL;
			iptfs_decap_free_frag_buffer (vm, satd);
			b0->error = node->errors[IPTFS_DECAP_ERROR_BAD_DATABLOCK];
			goto pktdrop;
		      }
		  }

		/* ---------------------------------------------- */
		/* copy inner packet in from current outer packet */
		/* ---------------------------------------------- */

		if (plen > b0->current_length)
		  {
		    /* There's more packet data coming, copy what we have */

		    iptfs_pkt_debug_s (dbg,
				       "%s: remaining datablock length %u "
				       "beyond current payload %u",
				       __FUNCTION__, plen, b0->current_length);
		    iptfs_pkt_debug_t (IPTFS_PT_DBG_DECAP,
				       "remaining datablock length %u "
				       "beyond current payload %u",
				       plen, b0->current_length);
		    /*
		     * We don't have the full packet so copy/append the data
		     * from this buffer. We will be done with this buffer at
		     * the exit from this block.
		     */

		    /* Advance the expected ESP seqno */
		    satd->tfs_rx.frag_nseq++;

		    bool owned_source;
		    (void) iptfs_decap_append_data_inp (vm, thread_index, sa_index, satd, b0,
							b0->current_length, plen, min_hdr_len, newb,
							lastb, NULL, &owned_source, dbg);

		    if (owned_source)
		      goto pktdone;

		    /* There's no error to report in pktdrop, just free the
		     * buffer */
		    *freebi++ = from[b - bufs];
		    goto pktdone;
		  }

	      inprogressallthere:
		/*
		 * Here we have a in-progress newb that we will fill *and* a b0
		 * that contains the rest of the packet (and possibly more)
		 */
		iptfs_pkt_debug_t (IPTFS_PT_DBG_DECAP, "in-progress, all there");

		iptfs_prefetch_before_advance (b0, offset);

		iptfs_pkt_debug_s (dbg,
				   "%s: completing reassembly of IP (last "
				   "chunk %d) next datablock offset %u",
				   __FUNCTION__, plen, offset);

		bool owned_source;
		u16 advanced;
		if (!iptfs_decap_append_data_inp (vm, thread_index, sa_index, satd, b0, plen, plen,
						  min_hdr_len, newb, lastb, &advanced,
						  &owned_source, dbg))
		  ;
		else
		  {
		    /* Good to go! */
		    ASSERT (nexti == IPTFS_DECAP_NEXT_IP4_INPUT ||
			    nexti == IPTFS_DECAP_NEXT_IP6_INPUT);
		    iptfs_inc_pcounter (IPTFS_PCNT_DECAP_TX, thread_index, sa_index, 1,
					vlib_buffer_length_in_chain (vm, newb));
		    if (!(newb->flags & VLIB_BUFFER_IS_TRACED))
		      iptfs_decap_trace_new_buffer (
			vm, node, nexti, newb, (vnet_buffer (b0)->ipsec.iptfs_esp_seq & 0xFFFFFFFF),
			block_number);

		    vlib_put_get_next_frame_a (vm, node, nexti, to, eto);
		    *to[nexti]++ = satd->tfs_rx.frag_bi;
		    npkts++;

		    /* Forget in progress buffer as it's going to next node */
		    iptfs_decap_forget_frag_buffer (satd);

		    iptfs_pkt_debug_t (IPTFS_PT_DBG_DECAP, "dispatched to next node");
		  }

		/* If we have chained this to the end then we are done */
		if (owned_source)
		  goto pktdone;

		/* next datablock */
		vlib_buffer_advance (b0, offset - advanced);

		/* Offset is no longer valid */
		offset = ~0u;
		newb = lastb = NULL;
		block_number++;

		continue;
	      }

	    /*
	     *-------------------------------------------------------
	     * No in-progress:
	     *-------------------------------------------------------
	     */

	    ASSERT (!newb);

	    u8 *b0data = vlib_buffer_get_current (b0);
	    /*
	     * See if the datablock length is present in this payload
	     * and then if the full packet in in the payload. If not
	     * then save what's there in a new buffer and quit.
	     */
	    plen = 0;
	    if ((b0->current_length < plen_off + 2) ||
		(b0->current_length <
		 (plen = (b0data[plen_off] << 8) + b0data[plen_off + 1] +
			 /* Add ipv6 header length to packet length */
			 (min_hdr_len == sizeof (ip6_header_t) ? sizeof (ip6_header_t) : 0))))
	      {
		/* ----------------------------------------- */
		/* Buffer does not contain the entire packet */
		/* ----------------------------------------- */
		iptfs_pkt_debug_t (IPTFS_PT_DBG_DECAP,
				   "Buffer doesn't contain entire packet, "
				   "sw_if_index[VLIB_RX] %u",
				   vnet_buffer (b0)->sw_if_index[VLIB_RX]);

		if (satd->tfs_df)
		  {
		    clib_warning ("%s: datablock beyond payload in "
				  "dont fragment mode.",
				  __FUNCTION__);
		    b0->error = node->errors[IPTFS_DECAP_ERROR_FRAG_DONT_FRAG];
		    goto pktdrop;
		  }

		/* If we have the inner length might as well verify it's
		 * semi-valid */
		if ((b0->current_length >= plen_off + 2) && plen < min_hdr_len)
		  goto badinnerlen;

		ASSERT (satd->tfs_rx.frag_bi == ~0u);

		/*
		 * Critical point here: this is the one of two places we
		 * allocate an in-progress buffer (i.e., a fragment). We are
		 * copying the packet data to the head of this buffer, so there
		 * will "always" be space to complete the packet later (always
		 * == buffers > max MTU)
		 *
		 * We only re-use packets that had no offset.
		 *
		 * We allocate another in-progress at the very end, but in this
		 * case we actually know we have all the data.
		 */

		if (!(newb = iptfs_decap_new_frag_buffer (vm, satd,
							  vnet_buffer (b0)->sw_if_index[VLIB_RX])))
		  {
		    b0->error = node->errors[IPTFS_DECAP_ERROR_NO_MEM];
		    goto pktdrop;
		  }

		/* XXX we probably want to do something with tracing here
		 */

		/* Save the in-progress buffer and the current ESP seqno */
		satd->tfs_rx.frag_nseq = vnet_buffer (b0)->ipsec.iptfs_esp_seq + 1;

#ifdef IPTFS_DEBUG
		if (!plen)
		  iptfs_pkt_debug_s (dbg, "%s: datablock length offset %u+1 beyond payload %u",
				     __FUNCTION__, plen_off, b0->current_length);
		else
		  iptfs_pkt_debug_s (dbg, "%s: datablock of length %u beyond payload %u",
				     __FUNCTION__, plen, b0->current_length);
#endif

		if (!satd->tfs_decap_chaining || (plen && plen < IPTFS_DECAP_MIN_CHAIN_LEN))
		  {
		    clib_memcpy_fast (vlib_buffer_put_uninit (newb, b0->current_length), b0data,
				      b0->current_length);
		    iptfs_inc_x_counter (IPTFS_CNT_DECAP_TX_COPIED, thread_index, sa_index,
					 b0->current_length);
		  }
		else
		  {
		    /*
		     * We copy at *least* an ipv4/ipv6 header length up to
		     * the cacheline size, if available to copy
		     */
		    u16 copylen;

		    if (plen && plen < IPTFS_DECAP_MIN_CHAIN_LEN)
		      copylen = clib_min (b0->current_length, plen);
		    else
		      copylen = iptfs_decap_min_hdr_to_cacheline (b0data, b0->current_length,
								  min_hdr_len, 1);

		    clib_memcpy_fast (vlib_buffer_put_uninit (newb, copylen), b0data, copylen);
		    iptfs_inc_x_pcounter (IPTFS_PCNT_DECAP_TX_HDR_COPY, thread_index, sa_index,
					  copylen < min_hdr_len ? 0 : 1, copylen);
		    if (copylen < b0->current_length)
		      {
			/*
			 * We've got at least the header copied in so just
			 * chain the rest
			 */
			vlib_buffer_advance (b0, copylen);
			newb->next_buffer = from[b - bufs];
			newb->total_length_not_including_first_buffer = b0->current_length;
			newb->flags |= VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID;
			lastb = satd->tfs_rx.frag_lastb = b0;

			/* we've owned the buffer now so don't drop it */
			iptfs_inc_x_counter (IPTFS_CNT_DECAP_RX_ENDS_WITH_FRAG, thread_index,
					     sa_index, 1);
			iptfs_inc_x_counter (IPTFS_CNT_DECAP_TX_CHAINED, thread_index, sa_index, 1);
			goto pktdone;
		      }
		  }
		/*
		 * we are done with this buffer as we aren't re-using it
		 */
		iptfs_inc_x_counter (IPTFS_CNT_DECAP_RX_ENDS_WITH_FRAG, thread_index, sa_index, 1);
		iptfs_inc_x_counter (IPTFS_CNT_DECAP_RX_NO_REUSE, thread_index, sa_index, 1);
		*freebi++ = from[b - bufs];
		goto pktdone;
	      }

	    /*
	     * XXX need to peek at next nibble as if it's a pad we don't
	     * need an indirect to point at the datablock, check putting
	     * this elsewhere too.
	     */

	    /* ----------------------------------------------------------- */
	    /* Here we have no in-progress, and the entire packet is in b0 */
	    /* ----------------------------------------------------------- */
	    iptfs_pkt_debug_t (IPTFS_PT_DBG_DECAP,
			       "entire packet is in b0, "
			       "sw_if_index[VLIB_RX] %u",
			       vnet_buffer (b0)->sw_if_index[VLIB_RX]);

	    /* See if the length is bogus */
	    if (plen < min_hdr_len)
	      {
	      badinnerlen:
		clib_warning ("%s: bogus inner packet length %u min_hdr_len %u.", __FUNCTION__,
			      plen, min_hdr_len);
		b0->error = node->errors[IPTFS_DECAP_ERROR_BAD_DATABLOCK];
		goto pktdrop;
	      }

	    /* Good to go! */
	    iptfs_pkt_debug_s (dbg, "%s: IP packet len: %d in thread %u", __FUNCTION__, plen,
			       thread_index);

	    /* See if we are done or just have pad at the end */
	    if (b0->current_length == plen || ((b0data[plen] & 0xF0) == 0))
	      {
		/*
		 * Here we have no in-progress, the entire packet in b0 and
		 * nothing after.
		 */
		ASSERT (b0->current_length >= plen);
		/* Set length to the IP packet to eliminate any pad */
		iptfs_pkt_debug_s (dbg, "%s: Reusing old buffer for last", __FUNCTION__);
		if (b0->current_length > plen)
		  {
		    iptfs_inc_x_pcounter (IPTFS_PCNT_DECAP_RX_PAD_DATABLOCK, thread_index, sa_index,
					  1, b0->current_length - plen);
		    iptfs_pkt_debug_s (dbg, "%s: Remaining pad datablock len: %d", __FUNCTION__,
				       b0->current_length - plen);
		  }
		b0->current_length = plen;
		vnet_buffer (b0)->sw_if_index[VLIB_TX] = 0; /* default VRF */
		ASSERT (nexti == IPTFS_DECAP_NEXT_IP4_INPUT || nexti == IPTFS_DECAP_NEXT_IP6_INPUT);

		iptfs_inc_x_counter (IPTFS_CNT_DECAP_TX_REUSED, thread_index, sa_index, 1);
		iptfs_inc_pcounter (IPTFS_PCNT_DECAP_TX, thread_index, sa_index, 1,
				    vlib_buffer_length_in_chain (vm, b0));
		vlib_put_get_next_frame_a (vm, node, nexti, to, eto);
		*to[nexti]++ = from[b - bufs];
		npkts++;

		/* See if we should start tracing b0 now */
		if (!(b0->flags & VLIB_BUFFER_IS_TRACED))
		  iptfs_decap_trace_new_buffer (
		    vm, node, nexti, b0, (vnet_buffer (b0)->ipsec.iptfs_esp_seq & 0xFFFFFFFF),
		    block_number);
		goto pktdone;
	      }

	    /*
	     * Here we have no in-progress, the entire packet in b0, but
	     * something is following the packet, allocate an empty in-progress
	     * and then re-use the above in-progress code.
	     *
	     * This is the second location of in progress allocation.
	     */
	    if (!(newb =
		    iptfs_decap_new_frag_buffer (vm, satd, vnet_buffer (b0)->sw_if_index[VLIB_RX])))
	      {
		b0->error = node->errors[IPTFS_DECAP_ERROR_NO_MEM];
		goto pktdrop;
	      }
	    lastb = newb;

	    /*
	     * pretend like we had an offset equal to the packet we are
	     * consuming
	     */
	    offset = plen;

	    iptfs_pkt_debug_s (dbg,
			       "%s: Pretending we have inprogress with new "
			       "packet plen %u",
			       __FUNCTION__, plen);

	    goto inprogressallthere;
	  }
	/*
	 * We finished using this buffer and didn't re-use iterate
	 * so cleanup and drop (free) it.
	 */
	iptfs_inc_x_counter (IPTFS_CNT_DECAP_RX_NO_REUSE, thread_index, sa_index, 1);
	*freebi++ = from[b - bufs];
	goto pktdone;

      pktdrop:
	nexti = IPTFS_DECAP_NEXT_DROP;
	vlib_put_get_next_frame_a (vm, node, nexti, to, eto);
	*to[nexti]++ = vlib_get_buffer_index (vm, b0);
	npkts++;
      pktdone:;
      }
      END_FOREACH_PREFETCH;
    }

  /* Put any next frames we've used */
  for (uint i = 0; i < IPTFS_DECAP_N_NEXT; i++)
    vlib_put_next_frame_with_cnt (vm, node, i, to[i], eto[i], ~0);

  if (allpad)
    iptfs_inc_counter (IPTFS_CNT_DECAP_RX_ALL_PAD, thread_index, sa_index, allpad);

  /* Free all the buffers that we are not re-using */
  vlib_buffer_free (vm, freebufs, freebi - freebufs);

  /* Count packets we drop as processed */
  npkts += freebi - freebufs;

  return npkts;
}

VLIB_NODE_FN (iptfs_decap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return iptfs_decap_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (iptfs_decap_node) = {
    .name = "iptfs-decap",
    // We have 2 things to trace, the pkt we are decap'ing and the decap'd
    // pkt We are only originating packet trace for the latter, we have a bit
    // in the trace data to indicate this is a decap and DTRT based on that.

    .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED | VLIB_NODE_FLAG_IS_HANDOFF,
    .vector_size = sizeof (u32),
    .format_trace = format_iptfs_packet_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN (iptfs_decap_error_strings),
    .error_strings = iptfs_decap_error_strings,

    .n_next_nodes = IPTFS_DECAP_N_NEXT,

    /* edit / add dispositions here */
    .next_nodes =
	{
#define _(s, n) [IPTFS_DECAP_NEXT_##s] = n,
	    foreach_iptfs_decap_next
#undef _
	},
};
