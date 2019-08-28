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
#include <vppinfra/error.h>
#include <vppinfra/vec.h>
#include <iptfs/ipsec_iptfs.h>

///* XXX: disable this for now */
// #undef iptfs_pkt_debug_s
// #undef IPTFS_DEBUG_CORRUPTION
// #define iptfs_pkt_debug_s(x, ...)

/* _ (DROP, "error-drop")                 \ */
#define foreach_iptfs_decap_reorder_next                                                           \
  _ (DROP, "drop")                                                                                 \
  _ (DECAP, "iptfs-decap")
#define _(v, s) IPTFS_DECAP_REORDER_NEXT_##v,
typedef enum
{
  foreach_iptfs_decap_reorder_next
#undef _
    IPTFS_DECAP_REORDER_N_NEXT,
} iptfs_decap_reorder_next_t;

#define foreach_iptfs_decap_reorder_error                                                          \
  _ (SKIP_ALL_PAD, "IPTFS-decap-reorder-ok skip all pad in fragment sequence")                     \
  _ (RX_CONGEST_DROP, "IPTFS-reorder-warn payloads drop due to decap tx thread congested")         \
  _ (RX_MISSED_SEQ, "IPTFS-reorder-warn missed packets (pre-arrival drops)")                       \
  _ (RX_BAD_SEQ, "IPTFS-reorder-warn old/dup sequence packet dropped")                             \
  _ (SHORT_HEADER, "IPTFS-reorder-err no space for header")                                        \
  _ (WRONG_VERSION, "IPTFS-reorder-err unsupported packet format")

typedef enum
{
#define _(sym, str) IPTFS_DECAP_REORDER_ERROR_##sym,
  foreach_iptfs_decap_reorder_error
#undef _
    IPTFS_DECAP_REORDER_N_ERROR,
} iptfs_decap_reorder_error_t;

static char *iptfs_decap_reorder_error_strings[] = {
#define _(sym, string) string,
  foreach_iptfs_decap_reorder_error
#undef _
};

#define vec_shift(v, n)                                                                            \
  do                                                                                               \
    {                                                                                              \
      if ((n) == vec_len (v))                                                                      \
	vec_reset_length (v);                                                                      \
      else                                                                                         \
	vec_delete (v, n, 0);                                                                      \
    }                                                                                              \
  while (0)

static inline u64
iptfs_cc_end_time (iptfs_sa_data_t *satd, iptfs_cc_data_t *cc)
{
  return (cc->le_start_time + cc->le_rrtt_clks);
}

static inline u64
iptfs_cc_capture_event (vlib_main_t *vm, iptfs_sa_data_t *satd, u64 clock_now)
{
  iptfs_cc_data_t *cc = &satd->tfs_rx.cc_data;
  /* Copy more complex from iptfs_cc_process_drops if we enable it */

  /*
   * RFC 5348: Section 5.2 talks about estimating the arrival times for
   * lost packets. We need the arrival time of the largest sequence number
   * we have received. To keep things simple we'll just use the latest we
   * actually received in-order and ignore the ones in the window. If we
   * have sever re-ordering it's probably systematic and so this should
   * average out, otherwise if it's not then it's an anomaly and won't
   * matter in the end either since we do so much averaging.
   */

  /*
   * Make sure we aren't capturing the event too early
   *
   * This may not be to spec, the spec talks about advertising the loss event
   * interval immediately if the loss interval is shrinking (p > p_prev). That
   * means it will slow down faster, but we are high rate this is probably not
   * that important.
   */
  ASSERT (iptfs_cc_end_time (satd, cc) <= clock_now);

  /*
   * Our next sequence number is one more than the last one we processed in
   * order, so the time for nextseq-1 is in recv_clock.
   */

  u64 largest_seq = satd->tfs_rx.nextseq - 1;
  u64 clks_per_seq = (clock_now - cc->le_start_good_time) / (largest_seq - cc->le_start_good_seq);

  /* Determine which sequence number starts the next event */
  ASSERT (cc->le_rrtt_clks);

  /*
   * Somehow this is getting to be 0, we need to figure this out
   * I think this is b/c we are trying to recalculate too soon.
   */

  ASSERT (clks_per_seq);
  uint nseq = (cc->le_rrtt_clks + clks_per_seq - 1) / clks_per_seq;
  ASSERT (nseq);

  u64 new_start_seq = cc->le_start_seq + nseq;

  /* We are done with this loss event, run the algorithm */
  cc->le_start_time = 0;

  /*
   * If RTT changes we may actually calculate a new start older than the end of
   * the last sequence. So in this case just ignore this capture event
   *
   * The return value actually should not be used.
   */
  if (new_start_seq <= cc->le_prev_end_seq)
    return cc->le_prev_end_seq + 1;

  ASSERT (new_start_seq - 1 >= cc->le_prev_end_seq);

  u64 new_end_seq = new_start_seq - 1;

#if IPTFS_ENABLE_CC_EVENT_LOGS
  ELOG_TYPE_DECLARE (cc_cap_le) = {
    .format = "cc-cap-le start %u ivall %u clks/seq %u rttclks %u nseq %u",
    .format_args = "i4i4i4i4i4",
  };
  u32 *esd = IPTFS_ELOG_CURRENT_THREAD (cc_cap_le);
  *esd++ = cc->le_start_seq;
  *esd++ = largest_seq - cc->le_start_good_seq;
  *esd++ = clks_per_seq;
  *esd++ = cc->le_rrtt_clks;
  *esd++ = nseq;
#endif
  /*
   * RFC5348: Move I_1 described by CC data to I_2 and rerun loss rate
   * calculation.
   */

  ASSERT (new_end_seq >= cc->le_prev_end_seq);
  uint I_1 = new_end_seq - cc->le_prev_end_seq;
  uint ilen = vec_len (cc->li_ints);
  cc->le_prev_end_seq = new_end_seq;

#if IPTFS_CC_DEBUG
  iptfs_debug ("Capturing Loss Event: end seq %llu I_1 %u ilen %u "
	       "rtts-in-ival %u nseq-in-rtt %u",
	       new_end_seq, I_1, ilen,
	       (clock_now - cc->le_start_good_time + satd->tfs_rx.cc_rrtt_clks - 1) /
		 satd->tfs_rx.cc_rrtt_clks,
	       nseq);
#endif

  /* If we are full of loss-intervals the pop the least recent one */
  if (ilen == LOSS_INT_MAX)
    (void) vec_pop (cc->li_ints);
  /* XXX We need to use a ring here this is silly shifting */
  vec_insert (cc->li_ints, 1, 0);
  cc->li_ints[0] = I_1;

  /* Increment the generation number */
  cc->li_gen++;

#if IPTFS_ENABLE_CC_EVENT_LOGS
  ilen = vec_len (cc->li_ints);
  u32 *ints = cc->li_ints;
  ELOG_TYPE_DECLARE (cc_cap_le_int1) = {
    .format = "cc-cap-le-int1 gen %u %u %u %u %u",
    .format_args = "i4i4i4i4i4",
  };
  esd = IPTFS_ELOG_CURRENT_THREAD (cc_cap_le_int1);
  *esd++ = cc->li_gen;
  for (int i = 0; i < 4; i++)
    if (i < ilen)
      *esd++ = *ints++;
    else
      *esd++ = ~0;

  ELOG_TYPE_DECLARE (cc_cap_le_int2) = {
    .format = "cc-cap-le-int2 gen %u %u %u %u %u",
    .format_args = "i4i4i4i4i4",
  };
  esd = IPTFS_ELOG_CURRENT_THREAD (cc_cap_le_int2);
  *esd++ = cc->li_gen;
  for (int i = 4; i < 8; i++)
    if (i < ilen)
      *esd++ = *ints++;
    else
      *esd++ = ~0;
#endif
  return new_start_seq;
}

static inline void
iptfs_cc_check_recalc (vlib_main_t *vm, iptfs_sa_data_t *satd, u64 clock_now)
{
  iptfs_cc_data_t *cc = &satd->tfs_rx.cc_data;

  if (cc->li_last_gen == cc->li_gen)
    {
      /*
       * We run the calculation every RTT -- need to do this to allow no-drop
       * intervals to begin to adjust things faster
       */
      if (cc->li_last_recalc + satd->tfs_rx.cc_rrtt_clks > clock_now)
	return;
    }

  /* run calculation */
  uint k = vec_len (cc->li_ints);
  if (!k)
    {
      /* We need at least one real loss event */
      satd->tfs_rx.cc_llrate_net = 0;
      goto done;
    }

  /* Maybe should count the packets in the window but... */
  u64 I_0 = satd->tfs_rx.nextseq - cc->le_prev_end_seq;

/*
 * RFC5348: Section 8.4: 1, 1, 1, 1, .75, .5, .25, .25, which can be done
 * with shifts.
 *
 * However this is done only every RTT at most and int multiplication is not
 * that much more expensive than shifts.
 */
#define BASE_DIVISOR 10
  const uint w[] = {
    (uint) (1.0 * BASE_DIVISOR), (uint) (1.0 * BASE_DIVISOR), (uint) (1.0 * BASE_DIVISOR),
    (uint) (1.0 * BASE_DIVISOR), (uint) (0.8 * BASE_DIVISOR), (uint) (0.6 * BASE_DIVISOR),
    (uint) (0.4 * BASE_DIVISOR), (uint) (0.2 * BASE_DIVISOR),
  };

  u64 I_tot0 = I_0 * BASE_DIVISOR;
  u64 W_tot = BASE_DIVISOR;
  for (int i = 0; i < k - 1; i++)
    {
      I_tot0 += (w[i + 1] * cc->li_ints[i]);
      W_tot += w[i + 1];
    }

  u64 I_tot1 = 0;
  for (int i = 0; i < k; i++)
    I_tot1 += (cc->li_ints[i] * w[i]);

  /*
   * We never time out the old intervals, so recover can take a long time it
   * seems. Also, we might consider instead of going to full-rate when we a
   * transition from p != 0 to p == 0, pushing a 0xFFFFFFFF as a LE interval.
   */
  u64 I_tot = clib_max (I_tot0, I_tot1);
  u64 I_mean = I_tot / W_tot;

#if IPTFS_CC_DEBUG
  iptfs_debug ("CC RECALC: I_tot0 %lu I_tot1 %lu I_mean %lu (W_tot %u)", I_tot0, I_tot1, I_mean,
	       W_tot);
#endif

  /*
   * XXX We might consider instead of just sending 0 we push the current I_0
   * value on the I_x stack, or shrink the stack, otherwise a long stretch of
   * good can constantly be affected by very old loss intervals.
   */
  /* If this is larger than 32 bits just move to 0 (no drops) */
  if (I_mean > 0xFFFFFFFF)
    I_mean = 0;

  /* This is where we update the value we advertise */
  satd->tfs_rx.cc_llrate_net = clib_host_to_net_u32 (I_mean);

done:
  /* Save when we ran this */
  cc->li_last_gen = cc->li_gen;
  cc->li_last_recalc = clock_now;
}

/*
 * Check to see if we should do a capture of the loss-event now. Also check
 * to see if we should do a run.
 */
static inline void
iptfs_cc_check_capture_and_run (vlib_main_t *vm, iptfs_sa_data_t *satd, u64 clock_now)
{
  iptfs_cc_data_t *cc = &satd->tfs_rx.cc_data;

  ASSERT (satd->tfs_cc);

  /* We are in a loss event -- see if we should capture it */
  if (cc->le_start_time && iptfs_cc_end_time (satd, cc) < clock_now)
    (void) iptfs_cc_capture_event (vm, satd, clock_now);

  iptfs_cc_check_recalc (vm, satd, clock_now);
}

/*
 * Handle drops on an SA, this will start a loss-event or continue to consume
 * on that loss-event.
 */
static inline bool
iptfs_cc_process_drops (vlib_main_t *vm, iptfs_sa_data_t *satd, u64 clock_now, u64 start_drop_seq,
			u64 last_drop_seq)
{
  if (!satd->tfs_cc)
    return false;

  if (PREDICT_FALSE (!satd->tfs_rx.cc_rrtt))
    return false;

  /*
   * We are going to assume fixed-rate mode here
   */
  ASSERT (satd->tfs_mode_type == IPTFS_MODE_TYPE_FIXED_RATE);

  /*
   * Check to make sure we are not in a previous drop sequence, this can happen
   * when we advance to the end of a loss-event algorithmically but then
   * receive packets in that window.
   */
  iptfs_cc_data_t *cc = &satd->tfs_rx.cc_data;
  if (start_drop_seq <= cc->le_prev_end_seq)
    return true;

  /*
   * If we have no loss event, start one.
   */
  if (!cc->le_start_time)
    {
      cc->le_start_time = clock_now;
      cc->le_rrtt_clks = satd->tfs_rx.cc_rrtt_clks;
      cc->le_end_time = cc->le_start_time + cc->le_rrtt_clks;
      cc->le_start_seq = start_drop_seq;
      cc->le_start_good_time = satd->tfs_rx.recv_clock;
      cc->le_start_good_seq = satd->tfs_rx.recv_seq;
#if IPTFS_CC_DEBUG
      iptfs_debug ("Starting Loss Event: rtt_clks %llu start/prevend seq "
		   "%llu/%llu (d: %llu) good start seq %llu start/end time "
		   "%llu/%llu (d: %lld), start good time %llu",
		   satd->tfs_rx.cc_rrtt_clks, cc->le_start_seq, cc->le_prev_end_seq,
		   cc->le_start_seq - cc->le_prev_end_seq, cc->le_start_good_seq, cc->le_start_time,
		   cc->le_end_time, cc->le_end_time - cc->le_start_time, cc->le_start_good_time);
#endif
    }

  /* Same check as above to catch earlier packets */
  if (start_drop_seq <= cc->le_start_seq)
    return true;

  /*
   * Return if we are still collecting drops in this loss-event
   */
  if (cc->le_end_time > clock_now)
    return true;

#if IPTFS_CC_DEBUG
  iptfs_debug ("Ending Loss Event: clock now %llu (d: %lld) start/prevend seq "
	       "%llu/%llu (d: %lld) good startseq %llu start/end time "
	       "%llu/%llu (d: %lld), start good time %llu",
	       clock_now, clock_now - cc->le_end_time, cc->le_start_seq, cc->le_prev_end_seq,
	       cc->le_start_seq - cc->le_prev_end_seq, cc->le_start_good_seq, cc->le_start_time,
	       cc->le_end_time, cc->le_end_time - cc->le_start_time, cc->le_start_good_time);
#endif

  u64 new_start_seq = iptfs_cc_capture_event (vm, satd, clock_now);
  if (last_drop_seq > new_start_seq)
    {
      /*
       * The new interval starts somewhere inside our dropped range. Start a
       * new loss interval event, immediately after the one we just ended.
       */
      /* XXX If things run super slow should we use a loop here? */
      cc->le_start_time = cc->le_end_time;
      cc->le_rrtt_clks = satd->tfs_rx.cc_rrtt_clks;
      cc->le_end_time = cc->le_start_time + cc->le_rrtt_clks;
      cc->le_start_seq = new_start_seq;
      ASSERT (cc->le_start_seq > cc->le_prev_end_seq);
      cc->le_start_good_time = satd->tfs_rx.recv_clock;
      cc->le_start_good_seq = satd->tfs_rx.recv_seq;

#if IPTFS_CC_DEBUG
      iptfs_debug ("Starting Loss Event while ending Loss Event: rtt_clks %llu "
		   "start/prevend seq %llu/%llu (d: %lld) good start seq %llu "
		   "start/end "
		   "time %llu/%llu (d: %lld), start good time %llu",
		   satd->tfs_rx.cc_rrtt_clks, cc->le_start_seq, cc->le_prev_end_seq,
		   cc->le_start_seq - cc->le_prev_end_seq, cc->le_start_good_seq, cc->le_start_time,
		   cc->le_end_time, cc->le_end_time - cc->le_start_time, cc->le_start_good_time);
#endif
    }
  return true;
}

static inline u32
iptfs_reorder_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
		      vlib_buffer_t **tobufs, u64 clock_now)
{
  ipsec_iptfs_main_t *tfsm = &ipsec_iptfs_main;
  iptfs_thread_main_t *tm = vec_elt_at_index (tfsm->workers_main, vlib_get_thread_index ());
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs, **eb = bufs + frame->n_vectors;
  // u32 *to = tobufs, *eto = tobufs + VLIB_FRAME_SIZE +
  // IPTFS_MAX_REORDER_WINDOW;
  vlib_buffer_t **to = tobufs;
  // vlib_buffer_t **eto = to + VLIB_FRAME_SIZE + IPTFS_MAX_REORDER_WINDOW;
  u32 *from;
  u32 *dropto = NULL;
  u32 *edropto = NULL;
  IPTFS_DBG_ARG (u8 * *dbg) = iptfs_next_debug_string ();

  /*
   * Comment (A) The decap reorder process is not thread safe. Currently this
   * works b/c we always receive a tunnel's packets on the same thread given
   * there are no differentiators for HW to place the packets in different
   * queues.
   *
   * If we have multiple rx-queue threads and an SAs ingress packets somehow
   * get sorted into different buckets we will need to deal with this.
   *
   * XXX This could also happen if the tunnel packets are received on multiple
   * different interfaces (e.g., due to ECMP along the tunnel path), this is
   * also a likely time to see reordering, unfortunately.
   */

  from = vlib_frame_vector_args (frame);

  vlib_get_buffers (vm, from, bufs, frame->n_vectors);

  /*
   * Take the time once because the protocol is only reporting delay in
   * milliseconds and this node can run multiple times with full vector of
   * packets in less than 1 millisecond.
   */
  while (b < eb)
    {
      FOREACH_PREFETCH_WITH_DATA (b, eb, IPTFS_N_PREFETCH_DECAP_REORDER, LOAD)
      {
	/* XXX from[b - bufs] */
	vlib_buffer_t *b0 = *b;
	u32 bi0 = vlib_get_buffer_index (vm, b0);
	iptfs_sa_data_t *satd = iptfs_get_sa_data (vnet_buffer (b0)->ipsec.sad_index);
	u64 b0_esp_seq = vnet_buffer (b0)->ipsec.iptfs_esp_seq;
	u8 winlen;
	u8 checkrecurse;

	if (PREDICT_FALSE (!satd->tfs_rx.nextseq))
	  satd->tfs_rx.nextseq = b0_esp_seq;

	if (PREDICT_FALSE (b0_esp_seq < satd->tfs_rx.nextseq))
	  {
	    iptfs_pkt_debug_s (dbg,
			       "%s: dropping passed by or duplicate sequence %llu "
			       "expecting %llu",
			       __FUNCTION__, b0_esp_seq, satd->tfs_rx.nextseq);
	    vlib_put_get_next_frame (vm, node, IPTFS_DECAP_REORDER_NEXT_DROP, dropto, edropto, ~0);
	    (*b)->error = node->errors[IPTFS_DECAP_REORDER_ERROR_RX_BAD_SEQ];
	    *dropto++ = bi0;
	    continue;
	  }

	ASSERT (!(checkrecurse = 0));
      again:
	if (PREDICT_TRUE (b0_esp_seq == satd->tfs_rx.nextseq))
	  {
	    /*
	     * got what we wanted.
	     */
	    winlen = vec_len (satd->tfs_rx.win);

#if IPTFS_DECAP_REORDER_DEBUG
	    iptfs_pkt_debug_s (dbg,
			       "%s: receiving waited for sequence %llu "
			       "current window len %u",
			       __FUNCTION__, b0_esp_seq, winlen);
#endif

	    /* Send this one it's way */
	    satd->tfs_rx.nextseq++;
	    /* XXX why are we getting the buffer again? */
	    iptfs_assert (vlib_get_buffer (vm, bi0) == *b);
	    *to++ = vlib_get_buffer (vm, bi0);

	    if (PREDICT_TRUE (!winlen))
	      continue;

	    u32 *rent = satd->tfs_rx.win;
	    u32 *erent = rent + winlen;

	    /* first add now consecutive */
	    // [A] [B]
	    //        ^
	    // [N] [M] [~]
	    //            ^
	    // [Z] [Y] [~] [X]
	    //                ^
	    for (; rent < erent && *rent != ~0u; rent++)
	      {
		satd->tfs_rx.nextseq++;
		*to++ = vlib_get_buffer (vm, *rent);
	      }
	    if (rent == erent)
	      {
		//  [A] [B]
		// ^
		/* We have no more ahead */
		vec_reset_length (satd->tfs_rx.win);
		continue;
	      }
	    // [N] [M] [~]
	    //           ^
	    // [Z] [Y] [~] [X]
	    //            ^
	    u8 handled = rent - satd->tfs_rx.win;
	    u8 left = erent - rent;
	    ASSERT (left > 1);
	    /* We have more ahead, next must be nil and represents our
	     * tfs_rx.nextseq */

	    iptfs_pkt_debug_s (dbg, "%s: shift reorder window handled %u leftover %u", __FUNCTION__,
			       handled, left);

	    vec_shift (satd->tfs_rx.win, handled);

#if IPTFS_DECAP_REORDER_COMMENT
	    // [Z] [Y] [~] [X]
	    //            ^
	    // [N] [M] [~]
	    //            ^
	    clib_memcpy (satd->tfs_rx.win, rent + 1, sizeof (*rent) * (left - 1));
	    rent = satd->tfs_rx.win + left - 1;
	    // [Z] [Y] [Z] [Y]
	    // [N] [M] [M]
	    clib_memset (rent, ~0, sizeof (*rent) * (erent - rent));
	    // [~] [~] [Z] [Y]
	    // [~] [M] [M]
	    vec_reset_length (left - 1);
	    // [Z] [Y]
	    // [M] [M]
#endif
	    continue;
	  }

	/*
	 * we are receiving future sequence number.
	 */
	u32 *rent = satd->tfs_rx.win;

	//
	//          -x-----               case A:
	//              -x-----           case B
	//                  =======
	//  [7] [6] [5] [4] [3] [2] [1] 0
	//      -x-----                   case C:
	//                  -x-----       case D:
	//                  -----x-       case E:
	//

	//
	//          -x---------               case B:
	//              -x---------           case C:
	//                  -x---------       case D:
	//      -x---------                   case E:
	//                      ===========
	//  [9] [8] [7] [6] [5] [4] [3] [2] [1] 0
	//                      -x---------   case A:
	//                          -x---------
	//                               -x---------
	//
	//
	//          -x---------               case B:
	//              -x---------           case C:
	//                  -x---------       case D:
	//      -x---------                   case E:
	//                  ===========
	//  [9] [8] [7] [6] [5] [4] [3] [2] [1] 0
	//                      -x---------   case A:
	//                          -x---------
	//                               -x---------
	//

	u64 distance = b0_esp_seq - satd->tfs_rx.nextseq;
	winlen = vec_len (satd->tfs_rx.win);

	iptfs_pkt_debug_s (dbg,
			   "%s: receiving future seqno %llu "
			   "expecting %llu winlen %u distance %lld beyond %lld",
			   __FUNCTION__, b0_esp_seq, satd->tfs_rx.nextseq, winlen, distance,
			   distance - satd->tfs_rewin);

	/* Case A: Fits in the window */
	if (distance <= satd->tfs_rewin)
	  {
	    iptfs_pkt_debug_s (dbg, "%s: fits in our window, set and done", __FUNCTION__);
	    /* change distance to index into window array */
	    distance--;
	    vec_validate_init_empty (satd->tfs_rx.win, distance, ~0);
	    satd->tfs_rx.win[distance] = bi0;
	    // recv 2: [b0]
	    //          2   1
	    // recv 3: [b0] [~]
	    //          3    2   1
	    continue;
	  }

	/*
	 * we've exceeded the window, by "beyond" packets.
	 */

	ASSERT (!checkrecurse);

	/*
	 * We known our new expected sequence number will need to move
	 * by at least the number we are beyond, and the window holds packets
	 * that are 1 past the nextseq.
	 *
	 * {ns+2}{ns+1}
	 * [ A ] [ B ] {nextseq}
	 *                      ^
	 * So beyond 1
	 * {ns+1}{nextseq}
	 * [ A ]  [ B ]
	 *             ^
	 * So beyond 2
	 * {nextseq}{ns-1}
	 *   [ A ]  [ B ]
	 *        ^
	 * So beyond 3
	 * {nextseq}{ns-1}
	 *          [ A ] [ B ]
	 *        ^
	 *
	 * 1) So first drop/send beyond - 1 of the window and shift it.
	 * Increase nextseq by beyond-1. The beyond drop slot (if present)
	 * represents the nextseq we are now expecting.
	 *
	 * increment nextseq by one for the last of beyond, now points at first
	 * slot.
	 *
	 * 2) If there is no window left add the last +1 to the nextseq
	 * expected for and we are done. (hint: winlen <= beyond - 1 i.e.,
	 * winlen < beyond)
	 *
	 *
	 * 3) So there is window left, shift it into nextseq.
	 *
	 * 3a) If that slot was not present (~0), we are done.
	 *
	 * 3b) That slot was present send it, and increment lastseq to point at
	 * next slot and repeat to (3).
	 *
	 * 4) we are done.
	 *
	 * The algorithm above and code below can be optimized by close
	 * examination hinted at above.
	 */

	/* at minimum we have to move to the next sequence number. */
	u64 beyond = distance - satd->tfs_rewin;
	ASSERT (beyond);

	iptfs_pkt_debug_s (dbg,
			   "%s: doesn't fit in window (%u cursz: %u): beyond: %llu "
			   "new nextseq %llu",
			   __FUNCTION__, satd->tfs_rewin, winlen, beyond,
			   satd->tfs_rx.nextseq + beyond);

	/* (1) */
	u32 missed = 0;
	u64 start_drop_seq = satd->tfs_rx.nextseq;
	u64 last_drop_seq = satd->tfs_rx.nextseq;

	iptfs_pkt_debug_s (dbg, "%s: dropping current expected nextseq %llu", __FUNCTION__,
			   satd->tfs_rx.nextseq);
	missed++;
	satd->tfs_rx.nextseq++;

	/* we want to leave the first slot of window as next seq for
	consumption after the next conditional */
	beyond--;

	/* If we are still beyond consume some slots until first slot is
	   current nextseq or window is empty */
	if (beyond)
	  {
	    uint i, nent = clib_min (winlen, beyond);
	    u32 last;
	    rent = satd->tfs_rx.win;
	    for (i = 0; i < nent; i++, rent++)
	      {
		last = *rent;
		if (last == ~0u)
		  {
		    missed++;
		    last_drop_seq = satd->tfs_rx.nextseq + i;

		    iptfs_pkt_debug_s (dbg,
				       "%s: dropping empty window slot for missing "
				       "sequence %llu",
				       __FUNCTION__, satd->tfs_rx.nextseq + i);
		  }
		else
		  {
		    iptfs_pkt_debug_s (dbg, "%s: sending window slot for sequence %llu",
				       __FUNCTION__, satd->tfs_rx.nextseq + i);
		    *to++ = vlib_get_buffer (vm, last);
		  }
	      }

	    /* Remove them from the array */
	    if (nent)
	      vec_shift (satd->tfs_rx.win, nent);

	    /* track any extra we are missing */
	    if (winlen < beyond)
	      {
		uint extra_drops = beyond - winlen;
		missed += extra_drops;
		last_drop_seq = satd->tfs_rx.nextseq + nent + extra_drops - 1;
	      }

	    satd->tfs_rx.nextseq += beyond;

	    winlen = vec_len (satd->tfs_rx.win);
	    iptfs_pkt_debug_s (dbg, "%s: 2) new winlen %u", __FUNCTION__, winlen);
	  }

	ASSERT (missed);
	/*
	 * 260403 gpz if "beyond" above is very large (e.g., due to
	 * pathological sequence computations), "missed" can be absurd
	 * and the counter here can yield bizarre values.
	 */
	vlib_node_increment_counter (vm, node->node_index, IPTFS_DECAP_REORDER_ERROR_RX_MISSED_SEQ,
				     missed);

	if (iptfs_cc_process_drops (vm, satd, clock_now, start_drop_seq, last_drop_seq))
	  {
	    /* Remember this SA for later processing */
	    u32 sa_index = iptfs_sa_data_to_index (satd);
	    if (vec_search (tm->cc_decap_run, sa_index) == ~0)
	      vec_add1 (tm->cc_decap_run, sa_index);
	  }

#if IPTFS_DECAP_REORDER_DEBUG
	// XXX really need a better way to rate-limit do this */
	iptfs_pkt_debug_s (dbg, "%s: [thread %u]: Missed packets %u (check ethernet errors)",
			   __FUNCTION__, vlib_get_thread_index (), missed);
#endif

	/* (2) or (3) Now send everything in the window until we can't */
	rent = satd->tfs_rx.win;
	u32 *erent = rent + winlen;
	u32 last = ~0u;
	for (; rent < erent; rent++)
	  {
	    if ((last = *rent) == ~0u)
	      {
		/* (3a) this empty slot is now the nexseq drop it from the
		   window */
		rent++;
		break;
	      }
	    /* (3b) this slot was present, consume it and move to nextseq */
	    satd->tfs_rx.nextseq++;
	    *to++ = vlib_get_buffer (vm, last);
	    iptfs_pkt_debug_s (dbg, "%s: 3b) sending %llu from window next was %llu now %llu",
			       __FUNCTION__,
			       vnet_buffer (vlib_get_buffer (vm, last))->ipsec.iptfs_esp_seq,
			       satd->tfs_rx.nextseq - 1, satd->tfs_rx.nextseq);
	  }
	if (rent != satd->tfs_rx.win)
	  vec_shift (satd->tfs_rx.win, rent - satd->tfs_rx.win);
	if (last == ~0u)
	  {
	    /* droped out b/c slot was not present or winlen == 0. */
#ifdef IPTFS_DEBUG
	    if (erent == satd->tfs_rx.win)
	      /* (2) */
	      iptfs_pkt_debug_s (dbg, "%s: 2) no window left new seq %llu", __FUNCTION__,
				 satd->tfs_rx.nextseq);
	    else
	      /* (3a) */
	      iptfs_pkt_debug_s (dbg,
				 "%s: 3a) shifted empty slot to expecting "
				 "%llu goto start",
				 __FUNCTION__, satd->tfs_rx.nextseq);
#endif
	    /* And run the code again now that it fits */
	    ASSERT (checkrecurse = 1);
	    goto again;
	  }

	/* (4) */
	iptfs_pkt_debug_s (dbg, "%s: 4) cleaned out window new next %llu", __FUNCTION__,
			   satd->tfs_rx.nextseq);

	/* And run the code again now that it fits */
	ASSERT (checkrecurse = 1);
	goto again;
      }
      END_FOREACH_PREFETCH;
    }

  /* Drop any we have queued for dropping */
  if (dropto)
    {
      iptfs_pkt_debug_s (dbg, "%s: Dropping %d", __FUNCTION__,
			 VLIB_FRAME_SIZE - (edropto - dropto));
      vlib_put_next_frame_with_cnt (vm, node, IPTFS_DECAP_REORDER_NEXT_DROP, dropto, edropto, ~0);
    }

  /*
   * We also want to check for any satd that is done waiting for it's loss
   * event to complete, and then run the loss-interval algorithm.
   *
   * We run this in reverse order to allow for deleting if our effective loss
   * becomes so small it should be treated as none.
   */
  for (int i = vec_len (tm->cc_decap_run) - 1; i >= 0; i--)
    iptfs_cc_check_capture_and_run (vm, iptfs_get_sa_data (tm->cc_decap_run[i]), clock_now);

  iptfs_pkt_debug_s (dbg, "%s: Returning %d", __FUNCTION__, to - tobufs);

  return to - tobufs;
}

static inline uword
iptfs_decap_reorder_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE + IPTFS_MAX_REORDER_WINDOW];
  vlib_buffer_t **b, **eb;
  u32 handoff[VLIB_FRAME_SIZE + IPTFS_MAX_REORDER_WINDOW], *h = handoff;
  u16 threads[VLIB_FRAME_SIZE + IPTFS_MAX_REORDER_WINDOW], *t = threads;
  u32 *to = NULL, *eto = NULL;
  u32 n_vectors, n_enq;

  u64 now = clib_cpu_time_now ();

  n_vectors = iptfs_reorder_inline (vm, node, frame, bufs, now);

  /*
   * Hand the buffers off to decap-worker
   */

  u32 sa_index = ~0u;
  iptfs_sa_data_t *satd = NULL;
  u32 this_thread_index = vlib_get_thread_index ();
  u32 thread_index = ~0u;
  u32 local_xmit_delay = 0;
  for (b = bufs, eb = b + n_vectors; b < eb; b++)
    {
      vlib_buffer_t *b0 = *b;
      if (b + 1 < eb)
	{
	  vlib_buffer_t *b1 = *(b + 1);
	  vlib_prefetch_buffer_header (b1, LOAD);
	}

      u32 new_sa_index = vnet_buffer (b0)->ipsec.sad_index;
      if (sa_index != new_sa_index)
	{
	  sa_index = new_sa_index;
	  satd = iptfs_get_sa_data (sa_index);
	  thread_index = satd->tfs_rx.decap_thread_index;

	  if (satd->tfs_cc)
	    {
	      u32 out_sa_index = satd->tfs_rx.cc_out_sa_index;
	      if (PREDICT_FALSE (out_sa_index == ~0))
		{
		  iptfs_warn ("No outbound SA association for CC mode on "
			      "inbound SA %u",
			      sa_index);
		  local_xmit_delay = IPTFS_CC_DELAY_MAX;
		}
	      else
		{
		  /* update the SATD clocks per usec */
		  iptfs_update_clocks_per_usec (vm, satd);

		  iptfs_sa_data_t *out_satd = iptfs_get_sa_data (out_sa_index);
		  local_xmit_delay = iptfs_get_cpu_usec (out_satd, out_satd->tfs_tx.pdelay);
		}
	    }
	}

      /*
       * For CC, track the time of the largest sequence number in this batch.
       */
      if (satd->tfs_cc)
	{
	  satd->tfs_rx.recv_clock = now;
	  satd->tfs_rx.recv_seq = vnet_buffer (b0)->ipsec.iptfs_esp_seq;
	}

      /* Track CC data here now that things are in order */

      /*
       * We need to capture this RX CC data here, prior to processing the
       * actual user traffic so our tunnel rate is not affected by the users
       * offered load
       */
      if (satd->tfs_cc && (b + 1 < eb))
	{
	  vlib_buffer_t *b1 = *(b + 1);
	  vlib_prefetch_buffer_data (b1, LOAD);
	}
      if (satd->tfs_cc && b0->current_length > sizeof (ipsec_iptfs_cc_header_t))
	{
	  ipsec_iptfs_cc_header_t *cch = vlib_buffer_get_current (*b);
	  if (cch->subtype == IPTFS_SUBTYPE_CC)
	    {
	      /*
	       * Update their RTT for Loss-Int calculation
	       */
	      u32 rrtt, echo_delay, xmit_delay;
	      iptfs_cc_get_rtt_and_delays (cch, &rrtt, &echo_delay, &xmit_delay);
	      {
		u32 old_rrtt = satd->tfs_rx.cc_rrtt;
		u32 rrtt_clks;
		if (!rrtt)
		  {
		    /* We don't allow RTT to be returned to 0 */
		    if (old_rrtt)
		      iptfs_debug ("Sender is trying to set RTT to 0, keep old "
				   "value of %u",
				   satd->tfs_rx.cc_rrtt);
		  }
		else if (old_rrtt != rrtt)
		  {
		    rrtt_clks = rrtt * satd->clocks_per_usec;
		    satd->tfs_rx.cc_rrtt_clks = rrtt_clks;
		    satd->tfs_rx.cc_rrtt = rrtt;
		  }
	      }

	      /* XXX would be nice to not have to use satd in usec calc */
	      /* XXX this is a division per packet vs per vector */
	      u64 now_tval = iptfs_get_cpu_tval (now);

	      {
		u32 old_tval, unused;
		iptfs_rx_get_lastvals (satd, &old_tval, &unused);

		/* Do not update the clock if we receive the same value */
		if (old_tval != cch->tval)
		  iptfs_rx_set_lastvals (satd, cch->tval, now_tval);
	      }

	      /*
	       * Calculate our RTT, we calculate both the actual RTT from the
	       * actual delay value, and compare that to the fixed xmit_delay
	       * value and take the larger of the two.
	       */

	      u32 fixed_rtt = xmit_delay + local_xmit_delay;
	      u32 our_tval = cch->techo;
	      u32 lrtt;

	      if (PREDICT_FALSE (!our_tval && !echo_delay))
		lrtt = fixed_rtt;
	      else
		{
		  if (now_tval < our_tval)
		    now_tval += (1ull << 32);

		  /* 4096 seconds since we last looked? */
		  ASSERT (now_tval > our_tval);

		  u32 actual_tval;
		  if (now_tval >= our_tval)
		    actual_tval = (now_tval - our_tval);
		  else
		    {
		      iptfs_warn ("more than 4B usec RTT!");
		      actual_tval = 0xFFFFFF;
		    }

		  u32 actual = iptfs_tval_to_usec (satd, actual_tval);
		  iptfs_rx_set_delay_actual_for_show (satd, echo_delay, xmit_delay, actual);

		  if (actual >= echo_delay)
		    lrtt = actual - echo_delay;
		  else
		    {
#if IPTFS_CC_DEBUG
		      iptfs_debug ("Actual RTT %u is less than indicated echo "
				   "delay %u!",
				   actual, echo_delay);
#endif
		      lrtt = 1;
		    }

		  /* XXX debug remove */
		  ASSERT (lrtt <= IPTFS_CC_RTT_MAX);

		  if (lrtt > IPTFS_CC_RTT_MAX)
		    {
		      iptfs_debug ("Actual RTT %u is larger than the max allowed "
				   "%u (actual %u - echo_delay %u)",
				   actual, IPTFS_CC_RTT_MAX, actual, echo_delay);
		      lrtt = IPTFS_CC_RTT_MAX;
		    }
		  if (fixed_rtt > lrtt)
		    {
#if IPTFS_CC_DEBUG
		      iptfs_debug ("Calculated RTT %u is less than transmission "
				   "RTT %u (lcl "
				   "%u, rmt: %u), choosing larger fixed xmit RTT",
				   lrtt, fixed_rtt, local_xmit_delay, xmit_delay);
#endif
		      lrtt = fixed_rtt;
		    }
		}
	      iptfs_rx_set_loss_info (satd, lrtt, clib_net_to_host_u32 (cch->loss_rate), now);
	    }
	}

      u32 bi0 = vlib_get_buffer_index (vm, b0);
      if (thread_index == this_thread_index)
	{
	  vlib_put_get_next_frame (vm, node, IPTFS_DECAP_REORDER_NEXT_DECAP, to, eto, ~0);
	  *to++ = bi0;
	}
      else
	{
	  /* Hand it off */
	  *h++ = bi0;
	  *t++ = thread_index;
	}
    }

  /*
   * send remaining directs
   */
  if (to)
    vlib_put_next_frame_with_cnt (vm, node, IPTFS_DECAP_REORDER_NEXT_DECAP, to, eto, ~0);

  if ((n_vectors = h - handoff) == 0)
    /* Always state we processed what we were given? */
    return frame->n_vectors;

  /* Enqueue buffers to threads */

  u32 fqi = ipsec_iptfs_main.decap_frame_queue;
  n_enq = clib_min (n_vectors, VLIB_FRAME_SIZE);
  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fqi, handoff, threads, n_enq);
  if (n_vectors > VLIB_FRAME_SIZE)
    n_enq += vlib_buffer_enqueue_to_thread (vm, node, fqi, &handoff[VLIB_FRAME_SIZE],
					    &threads[VLIB_FRAME_SIZE], n_vectors - VLIB_FRAME_SIZE);

  if (PREDICT_FALSE (n_enq < n_vectors))
    {
      ELOG_TYPE_DECLARE (decap_drop) = {
	.format = "decap-handoff dropped %d of %d",
	.format_args = "i4i4",
      };
      u32 *esd = IPTFS_ELOG_DEFAULT_TRACK (decap_drop);
      esd[0] = n_vectors - n_enq;
      esd[1] = n_vectors;

      vlib_node_increment_counter (vm, node->node_index, IPTFS_DECAP_REORDER_ERROR_RX_CONGEST_DROP,
				   n_vectors - n_enq);
    }

  ELOG_TYPE_DECLARE (decap_handoff) = {
    .format = "decap-handoff %d",
    .format_args = "i4",
  };
  u32 *esd = IPTFS_ELOG_CURRENT_THREAD (decap_handoff);
  esd[0] = n_enq;

  /* Always state we processed what we were given? */
  return frame->n_vectors;
}

VLIB_NODE_FN (iptfs_decap_reorder_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return iptfs_decap_reorder_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (iptfs_decap_reorder_node) = {
    .name = "iptfs-decap-reorder",
    .vector_size = sizeof (u32),
    .format_trace = format_iptfs_header_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    /* XXX this is actually not true for any packets we drop, they will be
       double counted */
    .flags = VLIB_NODE_FLAG_IS_OUTPUT,

    .n_errors = ARRAY_LEN (iptfs_decap_reorder_error_strings),
    .error_strings = iptfs_decap_reorder_error_strings,

    .n_next_nodes = IPTFS_DECAP_REORDER_N_NEXT,

    /* edit / add dispositions here */
    .next_nodes =
	{
#define _(s, n) [IPTFS_DECAP_REORDER_NEXT_##s] = n,
	    foreach_iptfs_decap_reorder_next
#undef _
	},
};
